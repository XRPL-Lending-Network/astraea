//! State before the snapshot, read through the version index over cold history.
//!
//! Server A has a snapshot at ledger 1100, cold history 1001..1100 and a version
//! index over 1001..1080 (base state at 1000). Server B holds the same ledgers in
//! its hot state from a snapshot at 1000. On ledgers before A's snapshot, the four
//! methods that read objects by key must answer on A exactly as on B; everything
//! else stays out of reach.
//!
//! The objects are one real mainnet account with its owner directory and trust
//! lines (tests/fixtures/old-state-account.json, public ledger data).

// An integration test is a crate of its own, outside `cfg(test)`: the workspace
// ban on unwrap (for code that parses untrusted data) does not apply to it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use ledger_engine::api::Engine;
use ledger_engine::cold::{Cold, Kinds, write};
use ledger_engine::coldstate::{Build, VersionIndex, build};
use ledger_engine::history::HistoryReader;
use ledger_engine::ledger::{Change, Ledger, StateChange};
use ledger_engine::state::{ColdOldState, StateStore};
use serde_json::{Map, Value, json};
use witness_core::ledger::LedgerHeader;

type Hash = [u8; 32];
const SNAPSHOT_A: u32 = 1100;
const INDEX_LAST: u32 = 1080;

struct Fixture {
    account: String,
    root: (Hash, Vec<u8>),
    objects: Vec<(Hash, Vec<u8>)>,
}

fn fixture() -> Fixture {
    let raw = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/old-state-account.json"),
    )
    .unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let objects: Vec<(Hash, Vec<u8>)> = v["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            let k: Hash = hex::decode(o["index"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            (k, hex::decode(o["binary"].as_str().unwrap()).unwrap())
        })
        .collect();
    Fixture {
        account: v["account"].as_str().unwrap().to_string(),
        root: objects[0].clone(),
        objects,
    }
}

/// The account root with another Sequence: a valid object of the same shape.
fn with_sequence(root: &[u8], seq: u32) -> Vec<u8> {
    // LedgerEntryType (11 0061), Flags (22 + 4 bytes), then Sequence (24 + 4 bytes).
    assert_eq!(&root[..4], &[0x11, 0x00, 0x61, 0x22], "fixture root layout");
    assert_eq!(root[8], 0x24, "fixture root layout");
    let mut r = root.to_vec();
    r[9..13].copy_from_slice(&seq.to_be_bytes());
    r
}

const Z: Hash = [0xEE; 32];
const BUSY: Hash = [0xDD; 32];

/// Headers 1000..=1101, the changes of ledgers 1001..=1101 and the state after each.
#[allow(clippy::type_complexity)]
fn history(
    f: &Fixture,
) -> (
    Vec<Vec<u8>>,
    Vec<Vec<StateChange>>,
    BTreeMap<u32, BTreeMap<Hash, Vec<u8>>>,
) {
    let mut headers = Vec::new();
    let mut parent = [0u8; 32];
    for seq in 1000..=1101u32 {
        let mut h = vec![0u8; 118];
        h[..4].copy_from_slice(&seq.to_be_bytes());
        h[12..44].copy_from_slice(&parent);
        parent = LedgerHeader::parse(&h).unwrap().hash();
        headers.push(h);
    }
    let line = f.objects.last().unwrap().1.clone();
    let mut state: BTreeMap<Hash, Vec<u8>> = f.objects.iter().cloned().collect();
    let mut states = BTreeMap::new();
    states.insert(1000, state.clone());
    let mut changes = Vec::new();
    for seq in 1001..=1101u32 {
        let mut c = vec![StateChange {
            key: BUSY,
            change: if seq == 1001 {
                Change::Created
            } else {
                Change::Modified
            },
            data: line.clone(),
        }];
        if seq == 1020 || seq == 1060 {
            c.push(StateChange {
                key: f.root.0,
                change: Change::Modified,
                data: with_sequence(&f.root.1, seq * 7),
            });
        }
        if seq == 1030 {
            c.push(StateChange {
                key: Z,
                change: Change::Created,
                data: line.clone(),
            });
        }
        if seq == 1070 {
            c.push(StateChange {
                key: Z,
                change: Change::Deleted,
                data: vec![],
            });
        }
        c.sort_by_key(|x| x.key);
        for x in &c {
            if x.data.is_empty() {
                state.remove(&x.key);
            } else {
                state.insert(x.key, x.data.clone());
            }
        }
        states.insert(seq, state.clone());
        changes.push(c);
    }
    (headers, changes, states)
}

fn engine(dir: &Path) -> Engine {
    Engine {
        state: Arc::new(StateStore::open(&dir.join("state")).unwrap()),
        blocks: HistoryReader::open(&dir.join("history")).unwrap(),
        network_id: 0,
        started: Instant::now(),
        confirmer: None,
        quorum: Default::default(),
    }
}

fn snapshot(s: &StateStore, seq: u32, header: &[u8], objects: &BTreeMap<Hash, Vec<u8>>) {
    s.load_snapshot(
        seq,
        header,
        objects.iter().map(|(k, v)| Ok((*k, v.clone()))),
    )
    .unwrap();
}

/// Server A: snapshot at 1100, cold 1001..1100 with partition indexes, version
/// index 1001..1080 attached.
fn server_a(dir: &Path, f: &Fixture) -> Engine {
    let (headers, changes, states) = history(f);
    let hist = dir.join("history");
    std::fs::create_dir_all(&hist).unwrap();
    let ledgers: Vec<Ledger> = (1001..=SNAPSHOT_A)
        .map(|seq| Ledger {
            header: headers[(seq - 1000) as usize].clone(),
            transactions: vec![],
            changes: changes[(seq - 1001) as usize].clone(),
        })
        .collect();
    write(&hist, &ledgers, Kinds::Explicit).unwrap();
    let cold = Cold::open(&hist).unwrap();
    ledger_engine::coldindex::build(&hist, &cold, 1001, SNAPSHOT_A).unwrap();
    let idx = dir.join("index");
    build(
        &idx,
        &Build {
            cold: &cold,
            first: 1001,
            last: INDEX_LAST,
            base: states[&1000].iter().map(|(k, v)| (*k, v.clone())).collect(),
            spill_after: 1 << 20,
        },
    )
    .unwrap();
    let e = engine(dir);
    snapshot(
        &e.state,
        SNAPSHOT_A,
        &headers[(SNAPSHOT_A - 1000) as usize],
        &states[&SNAPSHOT_A],
    );
    e.state.apply(1101, &headers[101], &changes[100]).unwrap();
    e.state.set_confirmed(1101).unwrap();
    e.state.set_old_state(Arc::new(ColdOldState {
        index: VersionIndex::open(&idx).unwrap(),
        cold: Cold::open(&hist).unwrap(),
    }));
    e
}

/// Server B: the same ledgers in hot state, from a snapshot at 1000 through `last`.
fn server_b(dir: &Path, f: &Fixture, last: u32) -> Engine {
    let (headers, changes, states) = history(f);
    std::fs::create_dir_all(dir.join("history")).unwrap();
    let e = engine(dir);
    snapshot(&e.state, 1000, &headers[0], &states[&1000]);
    for seq in 1001..=last {
        e.state
            .apply(
                seq,
                &headers[(seq - 1000) as usize],
                &changes[(seq - 1001) as usize],
            )
            .unwrap();
    }
    e.state.set_confirmed(last).unwrap();
    e
}

fn params(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn requests(f: &Fixture, at: u32) -> Vec<(&'static str, Map<String, Value>)> {
    let acct = f.account.clone();
    vec![
        (
            "account_info",
            params(json!({"account": acct, "ledger_index": at})),
        ),
        (
            "account_info",
            params(json!({"account": acct, "ledger_index": at, "signer_lists": true})),
        ),
        (
            "ledger_entry",
            params(json!({"account_root": acct, "ledger_index": at})),
        ),
        (
            "ledger_entry",
            params(
                json!({"index": hex::encode_upper(f.root.0), "ledger_index": at, "binary": true}),
            ),
        ),
        (
            "ledger_entry",
            params(json!({"index": hex::encode_upper(Z), "ledger_index": at})),
        ),
        (
            "ledger_entry",
            params(
                json!({"index": hex::encode_upper(Z), "ledger_index": at, "include_deleted": true}),
            ),
        ),
        (
            "account_lines",
            params(json!({"account": acct, "ledger_index": at})),
        ),
        (
            "account_objects",
            params(json!({"account": acct, "ledger_index": at})),
        ),
    ]
}

fn answer(e: &Engine, method: &str, p: &Map<String, Value>) -> Value {
    match e.handle(method, p) {
        Ok(m) => Value::Object(m),
        Err(err) => json!({"error": err.error}),
    }
}

#[test]
fn four_methods_match_direct_state() {
    let f = fixture();
    let a_dir = tempfile::tempdir().unwrap();
    let a = server_a(a_dir.path(), &f);
    let mut compared = 0;
    for at in [
        1001u32, 1019, 1020, 1045, 1065, 1069, 1070, 1075, INDEX_LAST,
    ] {
        let b_dir = tempfile::tempdir().unwrap();
        let b = server_b(b_dir.path(), &f, at);
        for (method, p) in requests(&f, at) {
            let (x, y) = (answer(&a, method, &p), answer(&b, method, &p));
            assert_eq!(x, y, "{method} {p:?}");
            compared += 1;
        }
    }
    // The answers are real ones, not errors on both sides.
    let ok = answer(
        &a,
        "account_lines",
        &params(json!({"account": f.account, "ledger_index": 1045})),
    );
    assert!(
        ok["lines"].as_array().is_some_and(|l| !l.is_empty()),
        "{ok}"
    );
    let deleted = answer(
        &a,
        "ledger_entry",
        &params(
            json!({"index": hex::encode_upper(Z), "ledger_index": 1075, "include_deleted": true}),
        ),
    );
    assert_eq!(deleted["deleted_ledger_index"], 1070, "{deleted}");
    assert_eq!(compared, 72);
}

#[test]
fn ledger_data_below_snapshot_lgr_not_found() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let a = server_a(dir.path(), &f);
    for (method, p) in [
        ("ledger_data", params(json!({"ledger_index": 1050}))),
        (
            "account_offers",
            params(json!({"account": f.account, "ledger_index": 1050})),
        ),
    ] {
        assert_eq!(answer(&a, method, &p)["error"], "lgrNotFound", "{method}");
    }
    // The same methods still answer from the snapshot on.
    assert!(answer(&a, "ledger_data", &params(json!({"ledger_index": 1101})))["error"].is_null());
}

#[test]
fn beyond_manifest_lgr_not_found() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let a = server_a(dir.path(), &f);
    // Between the end of the index (1080) and the snapshot (1100): not served.
    for (method, p) in requests(&f, 1090) {
        assert_eq!(
            answer(&a, method, &p)["error"],
            "lgrNotFound",
            "{method} {p:?}"
        );
    }
    assert_eq!(
        answer(
            &a,
            "account_info",
            &params(json!({"account": f.account, "ledger_index": INDEX_LAST}))
        )["error"],
        Value::Null
    );
}

#[test]
fn server_info_shows_boundary() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let a = server_a(dir.path(), &f);
    let info = answer(&a, "server_info", &Map::new());
    assert_eq!(
        info["info"]["astraea"]["old_state_ledgers"],
        format!("1000-{INDEX_LAST}"),
        "{info}"
    );
    // Without an index the field is absent.
    let b_dir = tempfile::tempdir().unwrap();
    let b = server_b(b_dir.path(), &f, 1010);
    let info = answer(&b, "server_info", &Map::new());
    assert!(
        info["info"]["astraea"].get("old_state_ledgers").is_none(),
        "{info}"
    );
}
