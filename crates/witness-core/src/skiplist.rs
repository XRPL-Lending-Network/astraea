//! Skip lists: the `LedgerHashes` objects the network keeps in ledger state.
//!
//! Every ledger updates two of them before its transactions run (they are not
//! in any transaction's metadata):
//! - the short list, key SHA-512Half(`0x0073`), holds the hashes of the
//!   previous 256 ledgers;
//! - when the previous ledger's index is a multiple of 256, its hash is
//!   appended to the long list of its group of 65536 ledgers, key
//!   SHA-512Half(`0x0073`, index >> 16 as u32). A group's list is never
//!   removed, so the latest state holds the hash of every 256th ledger back to
//!   the start of history.
//!
//! Any hash in either list is the hash of an earlier ledger of the same chain:
//! only the protocol writes these objects, and only with parent hashes. A
//! state proof of a list in a confirmed ledger therefore confirms every ledger
//! whose hash is in it, and a header chain of at most 255 ledgers reaches any
//! ledger from the next multiple of 256.

use crate::sha512_half;
use crate::shamap::Hash;
use crate::stobject::{self, FieldId, types};

/// `LedgerEntryType` of a skip list: `h`.
pub const LEDGER_HASHES: u16 = 0x0068;
/// The `Hashes` field (Vector256, code 2).
pub const HASHES: FieldId = FieldId::new(types::VECTOR256, 2);
/// Namespace of skip list keys: `s`.
const SPACE: [u8; 2] = [0x00, 0x73];

/// Key of the short list (the previous 256 ledgers).
pub fn short_key() -> Hash {
    sha512_half(&SPACE)
}

/// Key of the long list that holds the hash of ledger `seq` when `seq` is a
/// multiple of 256.
pub fn long_key(seq: u32) -> Hash {
    let mut b = SPACE.to_vec();
    b.extend_from_slice(&(seq >> 16).to_be_bytes());
    sha512_half(&b)
}

/// The first multiple of 256 at or after `seq`: the ledger whose hash a long
/// list holds and from which a chain reaches `seq`.
pub fn covering(seq: u32) -> u32 {
    seq.div_ceil(256) * 256
}

/// The hashes of a serialized `LedgerHashes` object.
pub fn hashes(object: &[u8]) -> Result<Vec<Hash>, String> {
    let fields = stobject::fields(object).map_err(|e| e.to_string())?;
    let kind = stobject::find(&fields, stobject::fields::LEDGER_ENTRY_TYPE)
        .and_then(|v| v.try_into().ok())
        .map(u16::from_be_bytes);
    if kind != Some(LEDGER_HASHES) {
        return Err("object is not a LedgerHashes entry".into());
    }
    let v = stobject::find(&fields, HASHES).ok_or("LedgerHashes has no Hashes field")?;
    match v.as_chunks::<32>() {
        (hashes, []) => Ok(hashes.to_vec()),
        _ => Err("Hashes is not a list of 32-byte hashes".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_covering_ledger() {
        // Keys as xrpld computes them (keylet::skip), checked against mainnet state.
        assert_eq!(
            hex::encode_upper(short_key()),
            "B4979A36CDC7F3D3D5C31A4EAE2AC7D7209DDA877588B9AFC66799692AB0D66B"
        );
        assert_eq!(long_key(87_000_064), long_key(86_966_272));
        assert_ne!(long_key(87_000_064), long_key(87_031_808));
        assert_eq!(covering(86_994_501), 86_994_688);
        assert_eq!(covering(86_994_688), 86_994_688);
    }

    #[test]
    fn hashes_of_an_object() {
        let mut o = vec![0x11, 0x00, 0x68];
        o.extend([0x02, 0x13, 64]);
        o.extend([1u8; 32]);
        o.extend([2u8; 32]);
        assert_eq!(hashes(&o).unwrap(), vec![[1u8; 32], [2u8; 32]]);
        o[2] = 0x61;
        assert!(hashes(&o).is_err());
    }
}
