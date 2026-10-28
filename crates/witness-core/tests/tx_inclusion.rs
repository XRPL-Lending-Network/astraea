//! Transaction inclusion proofs on a real mainnet ledger, 107 855 813:
//! 511 transactions, taken from a Clio server.
//!
//! It is the same ledger as in the evidence bundle `evidence-107855813.json`,
//! where its hash is confirmed by quorum. So the test walks the whole chain:
//! transaction → leaf → tree root in the header → header hash → the hash
//! signed by validators.

// Test code: a panic on unexpected data is exactly a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use witness_core::evidence::Bundle;
use witness_core::ledger::{HEADER_LEN, LedgerHeader};
use witness_core::shamap::{Hash, prove, root, tx_id, tx_leaf_hash, verify};
use witness_core::txproof::TxProof;

struct Tx {
    clio_hash: Hash,
    tx: Vec<u8>,
    meta: Vec<u8>,
}

struct Fixture {
    header: Vec<u8>,
    ledger_hash: Hash,
    transaction_hash: Hash,
    txs: Vec<Tx>,
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = b.split_at(n);
    *b = tail;
    head
}

fn u32le(b: &mut &[u8]) -> usize {
    u32::from_le_bytes(take(b, 4).try_into().unwrap()) as usize
}

/// Sample format: magic `XWTL\0\1`, header (118), ledger hash and transaction
/// root from Clio (32 each), the transaction count, then for each one: the hash
/// from Clio (32), length and transaction, length and metadata.
fn fixture() -> Fixture {
    let raw = zstd::decode_all(&include_bytes!("fixtures/ledger-107855813.xwtl.zst")[..]).unwrap();
    let mut b = &raw[..];
    assert_eq!(take(&mut b, 6), b"XWTL\x00\x01");
    let header = take(&mut b, HEADER_LEN).to_vec();
    let ledger_hash = take(&mut b, 32).try_into().unwrap();
    let transaction_hash = take(&mut b, 32).try_into().unwrap();
    let n = u32le(&mut b);
    let txs = (0..n)
        .map(|_| {
            let clio_hash = take(&mut b, 32).try_into().unwrap();
            let len = u32le(&mut b);
            let tx = take(&mut b, len).to_vec();
            let len = u32le(&mut b);
            let meta = take(&mut b, len).to_vec();
            Tx {
                clio_hash,
                tx,
                meta,
            }
        })
        .collect();
    assert!(b.is_empty());
    Fixture {
        header,
        ledger_hash,
        transaction_hash,
        txs,
    }
}

fn leaves(f: &Fixture) -> Vec<(Hash, Hash)> {
    f.txs
        .iter()
        .map(|t| {
            let id = tx_id(&t.tx);
            (id, tx_leaf_hash(&t.tx, &t.meta, &id))
        })
        .collect()
}

#[test]
fn header_hash_is_the_ledger_hash_confirmed_by_quorum() {
    let f = fixture();
    let h = LedgerHeader::parse(&f.header).unwrap();
    assert_eq!(h.sequence, 107_855_813);
    assert_eq!(
        h.hash(),
        f.ledger_hash,
        "header hash is the ledger hash from Clio"
    );
    assert_eq!(h.transaction_hash, f.transaction_hash);
    // The same hash is confirmed by quorum in the evidence bundle.
    let bundle: Bundle =
        serde_json::from_str(include_str!("fixtures/evidence-107855813.json")).unwrap();
    assert_eq!(hex::encode_upper(h.hash()), bundle.ledger_hash);
}

#[test]
fn transaction_ids_match_clio() {
    let f = fixture();
    assert_eq!(f.txs.len(), 511);
    for t in &f.txs {
        assert_eq!(tx_id(&t.tx), t.clio_hash);
    }
}

#[test]
fn tree_of_all_transactions_matches_the_header() {
    let f = fixture();
    let h = LedgerHeader::parse(&f.header).unwrap();
    assert_eq!(root(&leaves(&f)), h.transaction_hash);
}

#[test]
fn every_transaction_has_a_verifiable_path() {
    let f = fixture();
    let h = LedgerHeader::parse(&f.header).unwrap();
    let items = leaves(&f);
    let mut max_depth = 0;
    for (key, leaf) in &items {
        let path = prove(&items, key).unwrap();
        max_depth = max_depth.max(path.levels.len());
        assert!(verify(&path, key, leaf, &h.transaction_hash));
    }
    // 511 leaves in a tree with fan-out 16: depth 3 to 4.
    assert!((2..=5).contains(&max_depth), "{max_depth}");
}

#[test]
fn tampered_transaction_or_metadata_fails() {
    let f = fixture();
    let h = LedgerHeader::parse(&f.header).unwrap();
    let items = leaves(&f);
    let t = &f.txs[100];
    let key = tx_id(&t.tx);
    let path = prove(&items, &key).unwrap();

    let mut meta = t.meta.clone();
    let last = meta.len() - 1;
    meta[last] ^= 1;
    assert!(!verify(
        &path,
        &key,
        &tx_leaf_hash(&t.tx, &meta, &key),
        &h.transaction_hash
    ));

    // Another leaf's path does not fit this leaf.
    let other = prove(&items, &items[200].0).unwrap();
    assert!(!verify(&other, &key, &items[100].1, &h.transaction_hash));
}

#[test]
fn portable_proof_roundtrips_and_names_the_ledger() {
    let f = fixture();
    let items = leaves(&f);
    let t = &f.txs[42];
    let path = prove(&items, &tx_id(&t.tx)).unwrap();
    let proof = TxProof::new(&f.header, &t.tx, &t.meta, &path);
    let json = serde_json::to_string(&proof).unwrap();
    let back: TxProof = serde_json::from_str(&json).unwrap();
    let proven = back.verify().unwrap();
    assert_eq!(proven.ledger_index, 107_855_813);
    assert_eq!(proven.tx_hash, hex::encode_upper(t.clio_hash));
    assert_eq!(proven.ledger_hash, hex::encode_upper(f.ledger_hash));
    // A proof for one transaction is a couple of kilobytes, not the whole ledger.
    assert!(
        json.len() < t.tx.len() * 2 + t.meta.len() * 2 + 8_000,
        "{}",
        json.len()
    );

    let mut forged = back.clone();
    forged.meta.replace_range(
        10..11,
        if &forged.meta[10..11] == "0" {
            "1"
        } else {
            "0"
        },
    );
    assert!(forged.verify().is_err());
}
