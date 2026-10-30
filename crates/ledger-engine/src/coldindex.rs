//! Cold history indexes for the API: transaction by hash (XTXH),
//! account history (XACC v2) and ledger hash → sequence, over a contiguous
//! range of cold segments (a partition). There can be several partitions;
//! queries walk them in order.
//!
//! Files of the partition whose first ledger is F: `coldidx-F.xtxh`, `coldidx-F.xacc`,
//! `coldidx-F.lgr` (`XWLH\0\1`, u32 count, then the header hash and sequence
//! in ascending hash order) and the manifest `coldidx-F.json`, written last via
//! a temporary file and rename. They are read from disk (`txindex::TxHashFile`,
//! `AccountFile`). Memory holds only the per-ledger start offsets, a sparse
//! account directory and a sparse table of ledger hashes (every `LGR_SPARSE`-th);
//! for the full history that is tens of megabytes rather than gigabytes.
//!
//! Building is a single pass over the cold ledgers: the header chain is
//! checked, account lists are verified against the in-memory index before
//! writing, and every transaction is looked up through the file after writing.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};
use witness_core::sha512_half;

use crate::cold::{Cold, sync_write};
use crate::index::{AccountId, entries};
use crate::state::TxPosition;
use crate::txindex::{
    AccountFile, AccountIndex, Posting, TxHashFile, build_account_index_v2, build_tx_index_tops,
    top64,
};

type Res<T> = Result<T, String>;

const LGR_MAGIC: &[u8; 6] = b"XWLH\x00\x01";
/// Every how-many-th ledger hash is kept in memory; one pread covers the gap.
const LGR_SPARSE: usize = 256;

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn corrupt(what: impl std::fmt::Display) -> String {
    format!("corrupt_history: cold history index: {what}")
}

fn names(dir: &Path, first: u32) -> [PathBuf; 4] {
    ["xtxh", "xacc", "lgr", "json"].map(|e| dir.join(format!("coldidx-{first:010}.{e}")))
}

/// Builds an index partition for cold ledgers `first..=last` and publishes
/// it with a manifest. Returns the manifest.
pub fn build(dir: &Path, cold: &Cold, first: u32, last: u32) -> Res<Value> {
    if first > last {
        return Err("empty range".into());
    }
    let mut counts = Vec::with_capacity((last - first + 1) as usize);
    let mut tops: Vec<(u64, u32)> = Vec::new();
    let mut postings: BTreeMap<AccountId, Vec<Posting>> = BTreeMap::new();
    let mut hashes: Vec<([u8; 32], u32)> = Vec::with_capacity(counts.capacity());
    let mut parent: Option<[u8; 32]> = None;
    let mut ord = 0u32;
    for seq in first..=last {
        let l = cold
            .ledger(seq, false)?
            .ok_or(format!("ledger {seq} is not in the cold history"))?;
        let h = l.header()?;
        if h.sequence != seq || parent.is_some_and(|p| p != h.parent_hash) {
            return Err(format!("ledger {seq}: header chain is broken"));
        }
        parent = Some(h.hash());
        hashes.push((h.hash(), seq));
        let es = entries(&l)?;
        counts.push(es.len() as u32);
        for e in es {
            tops.push((top64(&e.id), ord));
            ord = ord
                .checked_add(1)
                .ok_or("more than 2^32 transactions in the partition")?;
            for a in e.accounts {
                postings.entry(a).or_default().push((seq, e.index));
            }
        }
    }
    for v in postings.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    let txs = tops.len();
    let xtxh = build_tx_index_tops(first, &counts, tops);
    let xacc = build_account_index_v2(first, &counts, &postings)?;
    // Account lists are checked against the in-memory index before writing.
    let ai = AccountIndex::open(&xacc)?;
    for (a, ps) in &postings {
        if ai.postings(a)? != *ps {
            return Err(format!(
                "account history {} does not match",
                hex::encode_upper(a)
            ));
        }
    }
    let accounts = postings.len();
    drop((ai, postings));
    hashes.sort_unstable();
    let mut lgr = LGR_MAGIC.to_vec();
    lgr.extend((hashes.len() as u32).to_le_bytes());
    for (h, s) in &hashes {
        lgr.extend(h);
        lgr.extend(s.to_le_bytes());
    }
    let [pt, pa, pl, pm] = names(dir, first);
    sync_write(&pt, &xtxh)?;
    sync_write(&pa, &xacc)?;
    sync_write(&pl, &lgr)?;
    // Every transaction must be found through the file before the manifest is published.
    let tf = TxHashFile::open(&pt)?;
    for seq in first..=last {
        let l = cold.ledger(seq, false)?.ok_or("ledger disappeared")?;
        for (p, (tx, _)) in l.transactions.iter().enumerate() {
            let id = witness_core::shamap::tx_id(tx);
            if !tf.candidates(&id)?.contains(&(seq, p as u32)) {
                return Err(format!(
                    "transaction {} not found in XTXH",
                    hex::encode_upper(id)
                ));
            }
        }
    }
    let file =
        |b: &[u8]| json!({"bytes": b.len(), "sha512half": hex::encode_upper(sha512_half(b))});
    let manifest = json!({
        "format": "astraea-coldidx/1",
        "first": first,
        "last": last,
        "ledgers": last - first + 1,
        "transactions": txs,
        "accounts": accounts,
        "files": {"xtxh": file(&xtxh), "xacc": file(&xacc), "lgr": file(&lgr)},
    });
    let m = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    sync_write(&pm, &m)?;
    fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
    Ok(manifest)
}

/// An index partition.
#[derive(Debug)]
pub struct ColdIndex {
    pub first: u32,
    pub last: u32,
    tx: TxHashFile,
    acc: AccountFile,
    lgr: fs::File,
    /// Hash of every `LGR_SPARSE`-th `.lgr` record.
    lgr_sparse: Vec<[u8; 32]>,
    /// Bytes of its files, from the manifest.
    bytes: u64,
}

impl ColdIndex {
    fn open(dir: &Path, m: &Value) -> Res<ColdIndex> {
        let num = |k: &str| m[k].as_u64().and_then(|v| u32::try_from(v).ok());
        let (Some(first), Some(last)) = (num("first"), num("last")) else {
            return Err(corrupt("range in the manifest"));
        };
        let [pt, pa, pl, _] = names(dir, first);
        for (p, k) in [(&pt, "xtxh"), (&pa, "xacc"), (&pl, "lgr")] {
            let len = fs::metadata(p).map_err(io)?.len();
            if Some(len) != m["files"][k]["bytes"].as_u64() {
                return Err(corrupt(format!("wrong size of {k}")));
            }
        }
        let tx = TxHashFile::open(&pt).map_err(corrupt)?;
        if (tx.first(), tx.last()) != (first, last) {
            return Err(corrupt("XTXH range does not match the manifest"));
        }
        let acc = AccountFile::open(&pa).map_err(corrupt)?;
        let lgr = fs::File::open(&pl).map_err(io)?;
        let b = pread(&lgr, 0, 10).map_err(|_| corrupt("ledger hashes: not XWLH"))?;
        if b.get(..6) != Some(LGR_MAGIC.as_slice()) {
            return Err(corrupt("ledger hashes: not XWLH"));
        }
        let n = u32::from_le_bytes([b[6], b[7], b[8], b[9]]) as usize;
        let len = lgr.metadata().map_err(io)?.len();
        if len != 10 + n as u64 * 36 || n != (last - first + 1) as usize {
            return Err(corrupt("ledger hashes: length"));
        }
        let mut lgr_sparse = Vec::with_capacity(n / LGR_SPARSE + 1);
        for k in (0..n).step_by(LGR_SPARSE) {
            let h = pread(&lgr, 10 + k as u64 * 36, 32)?;
            lgr_sparse.push(h.try_into().map_err(|_| corrupt("ledger hashes"))?);
        }
        let bytes = m["files"]
            .as_object()
            .map_or(0, |f| f.values().filter_map(|v| v["bytes"].as_u64()).sum());
        Ok(ColdIndex {
            first,
            last,
            tx,
            acc,
            lgr,
            lgr_sparse,
            bytes,
        })
    }

    fn ledger_by_hash(&self, h: &[u8; 32]) -> Res<Option<u32>> {
        let Some(k) = self.lgr_sparse.partition_point(|x| x <= h).checked_sub(1) else {
            return Ok(None);
        };
        let n = (self.last - self.first + 1) as usize;
        let from = k * LGR_SPARSE;
        let cnt = LGR_SPARSE.min(n - from);
        let b = pread(&self.lgr, 10 + from as u64 * 36, cnt * 36)?;
        let recs = b.as_chunks::<36>().0;
        Ok(recs
            .binary_search_by(|r| r[..32].cmp(h))
            .ok()
            .map(|i| u32::from_le_bytes(recs[i][32..].try_into().unwrap_or_default())))
    }
}

fn pread(f: &fs::File, at: u64, len: usize) -> Res<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut b = vec![0u8; len];
    f.read_exact_at(&mut b, at).map_err(io)?;
    Ok(b)
}

/// Index partitions in a directory, in ascending order.
#[derive(Debug, Default)]
pub struct ColdIndexes {
    parts: Vec<Arc<ColdIndex>>,
}

impl ColdIndexes {
    pub fn open(dir: &Path) -> Res<ColdIndexes> {
        ColdIndexes::open_with(dir, &ColdIndexes::default())
    }

    /// Like `open`, but partitions already open in `prev` are taken from there
    /// without reading, so publishing a new partition does not reread the others.
    pub fn open_with(dir: &Path, prev: &ColdIndexes) -> Res<ColdIndexes> {
        let mut parts = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return Ok(ColdIndexes::default());
        };
        for e in entries {
            let p = e.map_err(io)?.path();
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !(name.starts_with("coldidx-") && name.ends_with(".json")) {
                continue;
            }
            let known = name["coldidx-".len()..name.len() - ".json".len()]
                .parse::<u32>()
                .ok()
                .and_then(|f| prev.parts.iter().find(|x| x.first == f));
            if let Some(x) = known {
                parts.push(x.clone());
                continue;
            }
            let m: Value = serde_json::from_slice(&fs::read(&p).map_err(io)?).map_err(corrupt)?;
            if m["format"] != "astraea-coldidx/1" {
                return Err(corrupt(format!("{name}: unknown format")));
            }
            parts.push(Arc::new(ColdIndex::open(dir, &m)?));
        }
        parts.sort_by_key(|p| p.first);
        if parts.windows(2).any(|w| w[1].first <= w[0].last) {
            return Err(corrupt("partitions overlap"));
        }
        Ok(ColdIndexes { parts })
    }

    pub fn parts(&self) -> usize {
        self.parts.len()
    }

    /// Bytes of all partitions on disk.
    pub fn bytes(&self) -> u64 {
        self.parts.iter().map(|p| p.bytes).sum()
    }

    /// First ledger of the contiguous indexed history that reaches
    /// `end` (usually the last ledger before the hot history).
    pub fn first_contiguous_to(&self, end: u32) -> Option<u32> {
        let mut k = self
            .parts
            .iter()
            .rposition(|p| p.first <= end && end <= p.last)?;
        while k > 0 && self.parts[k - 1].last + 1 == self.parts[k].first {
            k -= 1;
        }
        Some(self.parts[k].first)
    }

    pub fn ledger_by_hash(&self, h: &[u8; 32]) -> Res<Option<u32>> {
        for p in &self.parts {
            if let Some(seq) = p.ledger_by_hash(h)? {
                return Ok(Some(seq));
            }
        }
        Ok(None)
    }

    /// Candidates (ledger, position) for a transaction hash.
    pub fn tx_candidates(&self, h: &[u8; 32]) -> Res<Vec<(u32, u32)>> {
        let mut out = Vec::new();
        for p in &self.parts {
            out.extend(p.tx.candidates(h)?);
        }
        Ok(out)
    }

    /// Account history in [lo, hi] inclusive: at most `limit` positions,
    /// ascending (`forward`) or descending, across all partitions.
    pub fn account_tx(
        &self,
        account: &AccountId,
        lo: TxPosition,
        hi: TxPosition,
        forward: bool,
        limit: usize,
    ) -> Res<Vec<TxPosition>> {
        let mut out = Vec::new();
        let parts: Box<dyn Iterator<Item = &Arc<ColdIndex>>> = if forward {
            Box::new(self.parts.iter())
        } else {
            Box::new(self.parts.iter().rev())
        };
        for p in parts {
            if out.len() >= limit {
                break;
            }
            crate::limits::check()?;
            let a = lo.max(TxPosition {
                ledger: p.first,
                index: 0,
            });
            let b = hi.min(TxPosition {
                ledger: p.last,
                index: u32::MAX,
            });
            if a > b {
                continue;
            }
            let got = p.acc.range(
                account,
                (a.ledger, a.index),
                (b.ledger, b.index),
                limit - out.len(),
                !forward,
            )?;
            out.extend(
                got.into_iter()
                    .map(|(ledger, index)| TxPosition { ledger, index }),
            );
        }
        Ok(out)
    }
}

/// Indexes next to the cold segments of a directory, shared between readers.
pub type Shared = Arc<ColdIndexes>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cold::{Kinds, write};
    use crate::ledger::Ledger;
    use witness_core::ledger::LedgerHeader;

    /// A chain of ledgers without transactions: the indexes are empty, but the
    /// hashes and the chain are checked.
    fn chain(first: u32, n: u32) -> Vec<Ledger> {
        let mut out = Vec::new();
        let mut parent = [0u8; 32];
        for k in 0..n {
            let mut header = vec![0u8; 118];
            header[..4].copy_from_slice(&(first + k).to_be_bytes());
            header[12..44].copy_from_slice(&parent);
            parent = LedgerHeader::parse(&header).unwrap().hash();
            out.push(Ledger {
                header,
                transactions: vec![],
                changes: vec![],
            });
        }
        out
    }

    #[test]
    fn partitions_route_ledger_hashes_and_contiguity() {
        let dir = tempfile::tempdir().unwrap();
        // More than LGR_SPARSE ledgers in a partition, so hashes go through the sparse table.
        let ls = chain(100, 600);
        write(dir.path(), &ls[..520], Kinds::Explicit).unwrap();
        write(dir.path(), &ls[520..], Kinds::Explicit).unwrap();
        let cold = Cold::open(dir.path()).unwrap();
        build(dir.path(), &cold, 620, 699).unwrap();
        let first = ColdIndexes::open(dir.path()).unwrap();
        assert_eq!(first.first_contiguous_to(699), Some(620));
        build(dir.path(), &cold, 100, 619).unwrap();
        let ix = ColdIndexes::open_with(dir.path(), &first).unwrap();
        assert_eq!(ix.parts(), 2);
        // A partition opened earlier carries over without being reread.
        assert!(Arc::ptr_eq(&ix.parts[1], &first.parts[0]));
        assert_eq!(ix.first_contiguous_to(699), Some(100));
        assert_eq!(ix.first_contiguous_to(698), Some(100));
        assert_eq!(ix.first_contiguous_to(700), None);
        for l in &ls {
            let h = l.header().unwrap();
            assert_eq!(ix.ledger_by_hash(&h.hash()).unwrap(), Some(h.sequence));
        }
        assert_eq!(ix.ledger_by_hash(&[7; 32]).unwrap(), None);
        assert!(build(dir.path(), &cold, 99, 105).is_err());
    }
}
