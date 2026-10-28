//! The ledger header and its hash.
//!
//! The ledger hash, which is what validators sign, is SHA-512Half(`LWR\0`,
//! header). The header pins the roots of two trees (transactions and
//! state) and links to the previous ledger through the parent hash. So from
//! a confirmed ledger hash you can reach both its transactions and earlier
//! ledgers.
//!
//! Header serialization, all numbers big-endian, 118 bytes:
//! sequence (4), total drops (8), parent hash (32), transaction root (32),
//! state root (32), parent close time (4), close time (4),
//! close time resolution (1), close flags (1).

use crate::stobject::Error;
use crate::{HashPrefix, sha512_half};

pub const HEADER_LEN: usize = 118;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerHeader {
    pub sequence: u32,
    pub total_drops: u64,
    pub parent_hash: [u8; 32],
    pub transaction_hash: [u8; 32],
    pub account_hash: [u8; 32],
    pub parent_close_time: u32,
    pub close_time: u32,
    pub close_time_resolution: u8,
    pub close_flags: u8,
    hash: [u8; 32],
}

fn arr<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&b[at..at + N]);
    out
}

impl LedgerHeader {
    pub fn parse(raw: &[u8]) -> Result<LedgerHeader, Error> {
        if raw.len() != HEADER_LEN {
            return Err(Error::Malformed(format!(
                "ledger header is {} bytes, expected {HEADER_LEN}",
                raw.len()
            )));
        }
        let mut data = HashPrefix::LedgerMaster.to_bytes().to_vec();
        data.extend_from_slice(raw);
        Ok(LedgerHeader {
            sequence: u32::from_be_bytes(arr(raw, 0)),
            total_drops: u64::from_be_bytes(arr(raw, 4)),
            parent_hash: arr(raw, 12),
            transaction_hash: arr(raw, 44),
            account_hash: arr(raw, 76),
            parent_close_time: u32::from_be_bytes(arr(raw, 108)),
            close_time: u32::from_be_bytes(arr(raw, 112)),
            close_time_resolution: raw[116],
            close_flags: raw[117],
            hash: sha512_half(&data),
        })
    }

    /// The ledger hash, which is what validators sign.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}
