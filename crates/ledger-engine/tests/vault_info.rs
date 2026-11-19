//! vault_info against answers of Clio.
//!
//! The objects are two real devnet vaults with their share issuances and the
//! owner of the second one, and the answers Clio gave for them
//! (tests/fixtures/vault-info-devnet.json, public ledger data). The server holds
//! the second vault from its snapshot at ledger 1000 and serves ledgers 1001 and
//! 1002; the first vault is created in ledger 1002. Error cases follow what
//! public Clio answered on the same requests, except the last one, which Clio's
//! code doesn't reach the same way.

// An integration test is a crate of its own, outside `cfg(test)`: the workspace
// ban on unwrap (for code that parses untrusted data) does not apply to it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use ledger_engine::api::Engine;
use ledger_engine::history::HistoryReader;
use ledger_engine::ledger::{Change, StateChange};
use ledger_engine::state::StateStore;
use serde_json::{Map, Value, json};
use witness_core::ledger::LedgerHeader;

type Hash = [u8; 32];

struct Vault {
    id: String,
    owner: String,
    objects: Vec<(Hash, Vec<u8>)>,
    clio: Value,
}

fn hash(v: &Value) -> Hash {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn fixture() -> Vec<Vault> {
    let raw = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-info-devnet.json"),
    )
    .unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    v["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Vault {
            id: x["vault_id"].as_str().unwrap().to_owned(),
            owner: x["owner"].as_str().unwrap().to_owned(),
            objects: vec![
                (hash(&x["vault_id"]), bytes(&x["vault_binary"])),
                (hash(&x["issuance_index"]), bytes(&x["issuance_binary"])),
                (hash(&x["owner_index"]), bytes(&x["owner_binary"])),
            ],
            clio: x["clio_vault_info"].clone(),
        })
        .collect()
}

fn header(seq: u32, parent: &Hash) -> Vec<u8> {
    let mut h = vec![0u8; 118];
    h[..4].copy_from_slice(&seq.to_be_bytes());
    h[12..44].copy_from_slice(parent);
    h
}

/// Snapshot at 1000 with the second vault and its owner; ledger 1001 changes
/// nothing; ledger 1002 creates the first vault and its issuance, without its
/// owner.
fn server(dir: &Path, v: &[Vault]) -> Engine {
    std::fs::create_dir_all(dir.join("history")).unwrap();
    let e = Engine {
        state: Arc::new(StateStore::open(&dir.join("state")).unwrap()),
        blocks: HistoryReader::open(&dir.join("history")).unwrap(),
        network_id: 2,
        started: Instant::now(),
        confirmer: None,
        quorum: Default::default(),
    };
    let h0 = header(1000, &[0; 32]);
    let h1 = header(1001, &LedgerHeader::parse(&h0).unwrap().hash());
    let h2 = header(1002, &LedgerHeader::parse(&h1).unwrap().hash());
    e.state
        .load_snapshot(
            1000,
            &h0,
            v[1].objects.iter().map(|(k, d)| Ok((*k, d.clone()))),
        )
        .unwrap();
    let mut created: Vec<StateChange> = v[0].objects[..2]
        .iter()
        .map(|(k, d)| StateChange {
            key: *k,
            change: Change::Created,
            data: d.clone(),
        })
        .collect();
    created.sort_by_key(|c| c.key);
    e.state.apply(1001, &h1, &[]).unwrap();
    e.state.apply(1002, &h2, &created).unwrap();
    e.state.set_confirmed(1002).unwrap();
    e
}

fn ask(e: &Engine, p: Value) -> Result<Map<String, Value>, (String, i32, String)> {
    e.handle("vault_info", p.as_object().unwrap())
        .map_err(|r| (r.error.to_owned(), r.code, r.message))
}

/// Clio's answer with our ledger index in place of the devnet one.
fn expected(v: &Vault, at: u32) -> Map<String, Value> {
    let mut m = v.clio.as_object().unwrap().clone();
    m.insert("ledger_index".into(), json!(at));
    m
}

#[test]
fn answers_match_clio() {
    let dir = tempfile::tempdir().unwrap();
    let v = fixture();
    let e = server(dir.path(), &v);
    assert_eq!(
        ask(&e, json!({"vault_id": v[0].id})).unwrap(),
        expected(&v[0], 1002)
    );
    assert_eq!(
        ask(
            &e,
            json!({"vault_id": v[1].id.to_lowercase(), "ledger_index": 1001})
        )
        .unwrap(),
        expected(&v[1], 1001)
    );
    let seq = v[1].clio["vault"]["Sequence"].clone();
    assert_eq!(
        ask(
            &e,
            json!({"owner": v[1].owner, "seq": seq, "ledger_index": "validated"})
        )
        .unwrap(),
        expected(&v[1], 1002)
    );
    // The share issuance carries mpt_issuance_id, as in STLedgerEntry::getJson.
    let shares = &v[0].clio["vault"]["shares"];
    assert_eq!(shares["mpt_issuance_id"], v[0].clio["vault"]["ShareMPTID"]);
}

#[test]
fn errors_match_clio() {
    let dir = tempfile::tempdir().unwrap();
    let v = fixture();
    let e = server(dir.path(), &v);
    let malformed = || Err(("malformedRequest".into(), 5001, "Malformed request.".into()));
    let vault_missing = || Err(("entryNotFound".into(), 98, "vault object not found.".into()));
    let (id, owner) = (v[1].id.clone(), v[1].owner.clone());
    let seq = v[1].clio["vault"]["Sequence"].as_u64().unwrap();
    assert_eq!(ask(&e, json!({})), malformed());
    assert_eq!(
        ask(&e, json!({"vault_id": id, "owner": owner, "seq": seq})),
        malformed()
    );
    assert_eq!(ask(&e, json!({"owner": owner})), malformed());
    assert_eq!(ask(&e, json!({"seq": seq})), malformed());
    assert_eq!(ask(&e, json!({"vault_id": "zz"})), malformed());
    assert_eq!(ask(&e, json!({"vault_id": "00"})), malformed());
    assert_eq!(ask(&e, json!({"vault_id": 5})), malformed());
    assert_eq!(ask(&e, json!({"owner": owner, "seq": "5"})), malformed());
    assert_eq!(ask(&e, json!({"owner": owner, "seq": -1})), malformed());
    assert_eq!(
        ask(&e, json!({"owner": "xyz", "seq": 1})),
        Err(("malformedRequest".into(), 5001, "OwnerNotHexString".into()))
    );
    assert_eq!(
        ask(&e, json!({"vault_id": id, "ledger_index": "abc"})),
        Err(("invalidParams".into(), 31, "ledgerIndexMalformed".into()))
    );
    assert_eq!(
        ask(&e, json!({"vault_id": id, "ledger_index": 99_999_999})),
        Err(("lgrNotFound".into(), 21, "ledgerNotFound".into()))
    );
    // Created in 1002: not there in 1001.
    assert_eq!(
        ask(&e, json!({"vault_id": v[0].id, "ledger_index": 1001})),
        vault_missing()
    );
    assert_eq!(
        ask(&e, json!({"vault_id": "00".repeat(32)})),
        vault_missing()
    );
    assert_eq!(ask(&e, json!({"owner": owner, "seq": 1})), vault_missing());
    // An owner the ledger doesn't know.
    assert_eq!(
        ask(&e, json!({"owner": v[0].owner, "seq": 1})),
        Err(("entryNotFound".into(), 98, "Entry not found.".into()))
    );
    // A key that holds something other than a vault: the owner's account root.
    let root = hex::encode_upper(v[1].objects[2].0);
    assert_eq!(ask(&e, json!({"vault_id": root})), vault_missing());
}
