//! Measures what an index "object to the ledgers that changed it" over cold
//! history would take, and how an object at an old ledger reads through it.
//! Writes nothing to the store.
//!
//! The candidate format stores, for each key, the ledgers as ascending deltas in
//! varints. A ledger number is enough to find the row, so no pointer into a
//! segment is kept: the price is decoding that row on every read, and this
//! measures the price too.

use std::collections::HashMap;
use std::io::Write;
use std::time::Instant;

use serde_json::{Value, json};

use crate::cold::Cold;
use crate::varint;

type Hash = [u8; 32];

/// Size of the blocks the encoded index is compressed in, as it would be read.
const BLOCK: usize = 64 << 10;
/// What a pointer into a segment costs per version: segment and offset.
const POINTER: u64 = 12;

/// Appends ascending `seqs` as deltas in varints; the first is absolute.
pub fn put_list(out: &mut Vec<u8>, seqs: &[u32]) {
    let mut last = 0;
    for &s in seqs {
        varint::put(out, u64::from(s - last));
        last = s;
    }
}

/// The ledger that holds a key's version at `at`: the last one not after it.
pub fn version_at(seqs: &[u32], at: u32) -> Option<u32> {
    match seqs.partition_point(|&s| s <= at) {
        0 => None,
        n => Some(seqs[n - 1]),
    }
}

/// How many partitions of `every` ledgers a key's ascending list touches.
pub fn partitions_of(seqs: &[u32], every: u32) -> u64 {
    let mut n = 0;
    let mut last = None;
    for s in seqs {
        let p = s / every;
        if last != Some(p) {
            n += 1;
            last = Some(p);
        }
    }
    n
}

/// Small deterministic generator: a measurement should be repeatable.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
}

fn percentiles(mut ms: Vec<f64>) -> Value {
    ms.sort_unstable_by(f64::total_cmp);
    let at = |q: f64| {
        ms.get(((ms.len() as f64 * q) as usize).min(ms.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0.0)
    };
    json!({
        "n": ms.len(),
        "p50_ms": at(0.5),
        "p90_ms": at(0.9),
        "p99_ms": at(0.99),
        "max_ms": ms.last().copied().unwrap_or(0.0),
    })
}

/// What to measure.
#[derive(Debug, Clone, Copy)]
pub struct Window {
    /// First ledger.
    pub from: u32,
    /// Last ledger.
    pub to: u32,
    /// Ledgers read at random before the pass, while they are the least cached.
    pub random_reads: usize,
    /// Objects read through the index after the pass.
    pub lookups: usize,
    /// Size of the partitions whose cost is reported.
    pub partition: u32,
}

/// Measures one window. `sample` gets each object read through the index: key,
/// ledger asked, ledger found and the object, empty if deleted there.
pub fn measure(
    cold: &Cold,
    w: Window,
    mut sample: impl FnMut(&Hash, u32, u32, &[u8]),
) -> Result<Value, String> {
    if w.from > w.to || !cold.contains(w.from) || !cold.contains(w.to) {
        return Err(format!("{}..={} is not in the cold history", w.from, w.to));
    }
    let span = u64::from(w.to - w.from) + 1;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ u64::from(w.from));

    let mut times = Vec::with_capacity(w.random_reads);
    for _ in 0..w.random_reads {
        let seq = w.from + rng.below(span) as u32;
        let t = Instant::now();
        cold.patches(seq)?
            .ok_or(format!("ledger {seq} is missing"))?;
        times.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let random = percentiles(times);

    let t = Instant::now();
    let mut lists: HashMap<Hash, Vec<u32>> = HashMap::new();
    let mut versions = 0u64;
    let mut data = 0u64;
    for seq in w.from..=w.to {
        let (_, patches) = cold
            .patches(seq)?
            .ok_or(format!("ledger {seq} is missing"))?;
        versions += patches.len() as u64;
        for (key, object) in patches {
            data += object.len() as u64;
            lists.entry(key).or_default().push(seq);
        }
        if u64::from(seq - w.from + 1).is_multiple_of(500_000) {
            eprintln!("{seq}: {versions} versions, {} keys", lists.len());
        }
    }
    let pass = t.elapsed().as_secs_f64();

    let mut keys: Vec<Hash> = lists.keys().copied().collect();
    keys.sort_unstable();

    let t = Instant::now();
    let mut seq_bytes = 0u64;
    let mut partition_keys = 0u64;
    let mut stream = Vec::with_capacity(BLOCK * 2);
    let mut compressed = 0u64;
    let mut counts = Vec::with_capacity(keys.len());
    let mut flush = |stream: &mut Vec<u8>| -> Result<(), String> {
        let mut z = zstd::Encoder::new(Vec::new(), 3).map_err(|e| e.to_string())?;
        z.write_all(stream).map_err(|e| e.to_string())?;
        compressed += z.finish().map_err(|e| e.to_string())?.len() as u64;
        stream.clear();
        Ok(())
    };
    let mut list = Vec::new();
    for key in &keys {
        let seqs = &lists[key];
        counts.push(seqs.len() as u64);
        partition_keys += partitions_of(seqs, w.partition);
        list.clear();
        put_list(&mut list, seqs);
        seq_bytes += list.len() as u64;
        stream.extend_from_slice(key);
        varint::put(&mut stream, seqs.len() as u64);
        stream.extend_from_slice(&list);
        if stream.len() >= BLOCK {
            flush(&mut stream)?;
        }
    }
    flush(&mut stream)?;
    let encode = t.elapsed().as_secs_f64();
    counts.sort_unstable();
    let count_at = |q: f64| {
        counts
            .get(((counts.len() as f64 * q) as usize).min(counts.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0)
    };

    let mut times = Vec::with_capacity(w.lookups);
    let mut sizes = Vec::with_capacity(w.lookups);
    for _ in 0..w.lookups {
        let Some(key) = keys.get(rng.below(keys.len() as u64) as usize) else {
            break;
        };
        let seqs = &lists[key];
        let at = seqs[0] + rng.below(u64::from(w.to - seqs[0]) + 1) as u32;
        let t = Instant::now();
        let seq = version_at(seqs, at).ok_or("no version")?;
        let (_, patches) = cold
            .patches(seq)?
            .ok_or(format!("ledger {seq} is missing"))?;
        let object = patches
            .iter()
            .find(|(k, _)| k == key)
            .ok_or(format!("ledger {seq} has no change of a key listed for it"))?;
        times.push(t.elapsed().as_secs_f64() * 1e3);
        sizes.push(patches.len() as f64);
        sample(key, at, seq, &object.1);
    }

    let k = keys.len() as u64;
    Ok(json!({
        "from": w.from,
        "to": w.to,
        "versions": versions,
        "keys": k,
        "object_bytes": data,
        "pass_seconds": pass,
        "encode_seconds": encode,
        "versions_per_key": {
            "p50": count_at(0.5),
            "p90": count_at(0.9),
            "p99": count_at(0.99),
            "p999": count_at(0.999),
            "max": counts.last().copied().unwrap_or(0),
        },
        "sizes": {
            "seq_varint_bytes": seq_bytes,
            "keys_32_bytes": k * 32,
            "raw_list_format": seq_bytes + k * 32,
            "zstd_64k_blocks": compressed,
            "with_pointers": versions * POINTER + k * 32,
            "partition_ledgers": w.partition,
            "partition_key_entries": partition_keys,
            "per_version": {
                "raw_list_format": (seq_bytes + k * 32) as f64 / versions.max(1) as f64,
                "zstd_64k_blocks": compressed as f64 / versions.max(1) as f64,
                "with_pointers": (versions * POINTER + k * 32) as f64 / versions.max(1) as f64,
            },
        },
        "random_row_read": random,
        "object_read_through_index": percentiles(times),
        "patches_in_rows_read": percentiles(sizes),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_take_the_expected_room() {
        let mut out = Vec::new();
        put_list(&mut out, &[100, 101, 400, 400 + (1 << 14)]);
        // 100, then 1, then 299 in two bytes, then 2^14 in three.
        assert_eq!(out, [100, 1, 0xAB, 0x02, 0x80, 0x80, 0x01]);
    }

    #[test]
    fn the_version_at_a_ledger_is_the_last_not_after_it() {
        let seqs = [10, 20, 30];
        assert_eq!(version_at(&seqs, 9), None);
        assert_eq!(version_at(&seqs, 10), Some(10));
        assert_eq!(version_at(&seqs, 29), Some(20));
        assert_eq!(version_at(&seqs, 31), Some(30));
    }

    #[test]
    fn partitions_are_counted_once_each() {
        assert_eq!(partitions_of(&[1, 2, 99, 100, 250], 100), 3);
        assert_eq!(partitions_of(&[], 100), 0);
    }
}
