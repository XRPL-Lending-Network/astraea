//! Early mainnet serialization forms: XRP amounts from 2013 with the 0x20 bit
//! set in the value, and an array element named by a non-object field. The
//! parser must get through them completely and return the original bytes;
//! the transaction roots match the headers.

// Test code: a panic on unexpected data is exactly a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use witness_core::ledger::LedgerHeader;
use witness_core::shamap::{root, tx_id, tx_leaf_hash};
use witness_core::stobject::{self, Field, types};

/// Reassembles an object from its parsed fields, descending into objects and
/// arrays: the result must match byte for byte.
fn rebuild(fs: &[Field<'_>], array: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fs {
        let t = f.id.type_code;
        if array || t == types::OBJECT || t == types::ARRAY {
            let (_, _, head_end) = stobject::head(f.raw, 0).unwrap();
            out.extend_from_slice(&f.raw[..head_end]);
            let inner_array = !array && t == types::ARRAY;
            let kids = if inner_array {
                stobject::items(f.value).unwrap()
            } else {
                stobject::fields(f.value).unwrap()
            };
            out.extend(rebuild(&kids, inner_array));
            out.push(*f.raw.last().unwrap());
        } else {
            out.extend_from_slice(f.raw);
        }
    }
    out
}

#[test]
fn early_mainnet_forms_parse_exactly() {
    let v: Value = serde_json::from_str(include_str!("fixtures/historical-forms.json")).unwrap();
    for l in v["ledgers"].as_array().unwrap() {
        let header =
            LedgerHeader::parse(&hex::decode(l["header"].as_str().unwrap()).unwrap()).unwrap();
        let mut leaves = Vec::new();
        for pair in l["txs"].as_array().unwrap() {
            let tx = hex::decode(pair[0].as_str().unwrap()).unwrap();
            let meta = hex::decode(pair[1].as_str().unwrap()).unwrap();
            for o in [&tx, &meta] {
                let fs =
                    stobject::fields(o).unwrap_or_else(|e| panic!("ledger {}: {e}", l["ledger"]));
                assert_eq!(&rebuild(&fs, false), o, "ledger {}", l["ledger"]);
            }
            let id = tx_id(&tx);
            leaves.push((id, tx_leaf_hash(&tx, &meta, &id)));
        }
        assert_eq!(
            root(&leaves),
            header.transaction_hash,
            "ledger {}",
            l["ledger"]
        );
    }
}

#[test]
fn mpt_amount_only_with_flag_only_first_byte() {
    // XRP from 2013: first byte 0x63, the 0x20 bit is part of the value, so 8 bytes.
    let xrp = [0x61, 0x63, 1, 2, 3, 4, 5, 6, 7];
    let fs = stobject::fields(&xrp).unwrap();
    assert_eq!(fs[0].value.len(), 8);
    // MPT: the first byte is flags alone, 0x60, and the amount is 33 bytes.
    let mut mpt = vec![0x61, 0x60];
    mpt.extend([0u8; 32]);
    assert_eq!(stobject::fields(&mpt).unwrap()[0].value.len(), 33);
}
