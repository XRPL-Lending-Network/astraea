//! Seal of a closed segment.
//!
//! A seal commits to the segment's content (the uncompressed bytes) and
//! references the hash of the previous seal. The seal chain makes the archive
//! immutable after the fact: replacing any segment, or removing one from the
//! middle, breaks every hash that follows.
//!
//! Compression is not part of the seal; it is a storage detail. A segment can
//! be recompressed at another level or with another codec without changing
//! the chain, and the check is always the same: decompress and compare the
//! content hash.
//!
//! A seal is plain JSON next to the segment, so it can be read by eye and
//! checked with any tool. The seal hash is SHA-512Half of its canonical JSON
//! without the `seal_hash` field; field order is fixed by the struct order.

use serde::{Deserialize, Serialize};
use witness_core::sha512_half;

pub const FORMAT: &str = "xrpl-witness/validations-segment/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    pub format: String,
    /// Which of our machines received these validations.
    pub source: String,
    /// Nominal range of the segment: [nominal_first, nominal_last].
    pub nominal_first: u32,
    pub nominal_last: u32,
    /// Lowest and highest ledgers among records from our network. Late
    /// validations from earlier ranges and early ones from the next range
    /// also land here.
    pub first_ledger: u32,
    pub last_ledger: u32,
    pub records: u64,
    /// How many of `records` are far from the network's current ledger:
    /// validations from other networks that leaked in through peer relaying,
    /// or ones that arrived very late. They are stored, but do not count
    /// toward completeness or the first/last ledgers.
    pub out_of_window: u64,
    /// The span this segment is responsible for keeping complete: from the
    /// ledger after the last one in the previous seal up to its own last
    /// ledger. Spans of adjacent segments meet with no gaps or overlaps, so
    /// archiver downtime shows up as a gap in the next seal instead of
    /// vanishing between them.
    pub coverage_first: u32,
    pub coverage_last: u32,
    /// Ledgers in the coverage span for which no validation arrived at all,
    /// as [from, to] ranges. A direct measure of completeness.
    pub missing_ledgers: Vec<[u32; 2]>,
    pub opened_ms: u64,
    pub sealed_ms: u64,
    /// Uncompressed size of the segment content.
    pub raw_bytes: u64,
    /// SHA-512Half of the uncompressed segment content, in hex.
    pub raw_hash: String,
    /// Hash of this source's previous seal; `None` for the very first one.
    pub prev_seal_hash: Option<String>,
    pub seal_hash: String,
}

impl Seal {
    /// Seal hash: over all fields except `seal_hash` itself.
    pub fn compute_hash(&self) -> String {
        let mut unsealed = self.clone();
        unsealed.seal_hash = String::new();
        let canonical = serde_json::to_vec(&unsealed).unwrap_or_default();
        hex::encode_upper(sha512_half(&canonical))
    }

    pub fn finalize(mut self) -> Seal {
        self.seal_hash = self.compute_hash();
        self
    }

    /// The seal has not been altered since it was sealed.
    pub fn is_intact(&self) -> bool {
        self.seal_hash == self.compute_hash()
    }
}

/// Ledgers in [first, last] that are not in `seen`, merged into ranges.
pub fn missing_ranges(first: u32, last: u32, seen: &[u32]) -> Vec<[u32; 2]> {
    let mut have: Vec<u32> = seen
        .iter()
        .copied()
        .filter(|l| (first..=last).contains(l))
        .collect();
    have.sort_unstable();
    have.dedup();

    let mut out = Vec::new();
    let mut expect = first;
    for l in have {
        if l > expect {
            out.push([expect, l - 1]);
        }
        expect = l.saturating_add(1);
    }
    if first <= last && expect <= last {
        out.push([expect, last]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal() -> Seal {
        Seal {
            format: FORMAT.into(),
            source: "archiver-a".into(),
            nominal_first: 1024,
            nominal_last: 2047,
            first_ledger: 1020,
            last_ledger: 2050,
            records: 87_000,
            out_of_window: 0,
            coverage_first: 1020,
            coverage_last: 2050,
            missing_ledgers: vec![],
            opened_ms: 1,
            sealed_ms: 2,
            raw_bytes: 3,
            raw_hash: "AB".into(),
            prev_seal_hash: None,
            seal_hash: String::new(),
        }
        .finalize()
    }

    #[test]
    fn seal_detects_tampering() {
        let s = seal();
        assert!(s.is_intact());
        let mut t = s.clone();
        t.records += 1;
        assert!(!t.is_intact());
    }

    #[test]
    fn seal_hash_survives_json_roundtrip() {
        let s = seal();
        let back: Seal = serde_json::from_str(&serde_json::to_string_pretty(&s).unwrap()).unwrap();
        assert!(back.is_intact());
        assert_eq!(back, s);
    }

    #[test]
    fn missing_ranges_merge_into_runs() {
        assert_eq!(
            missing_ranges(10, 20, &[10, 11, 12, 15, 20]),
            vec![[13, 14], [16, 19]]
        );
        assert_eq!(missing_ranges(10, 12, &[]), vec![[10, 12]]);
        assert_eq!(
            missing_ranges(10, 12, &[10, 11, 12, 99]),
            Vec::<[u32; 2]>::new()
        );
        assert_eq!(missing_ranges(10, 12, &[12]), vec![[10, 11]]);
    }
}
