//! Serving pool of prepared blocks for Ledger Engine integration. Added when
//! ASTJ5 was connected to Astraea; not part of the frozen research package,
//! and it does not change the format or the other modules.
//!
//! `dense::Reader` keeps one prepared block behind `&mut self`: concurrent
//! readers of different blocks serialize and every switch re-prepares. The
//! pool keeps several prepared blocks under a byte budget, prepares different
//! blocks in parallel (at most `max_prepares` at a time), and concurrent
//! requests for the same block wait for one preparation. Verification before
//! a block is cached is the same as in `dense::Reader`: exact framing hashed
//! one ledger at a time against the directory SHA512Half, ledger sequence,
//! transaction roots and the internal parent chain.
use super::*;
use sha2::{Digest, Sha512};
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
enum Data {
    Prepared(Box<fast::Prepared>),
    Rows(Vec<Row>),
}
type Cell = Arc<OnceLock<Result<Arc<Mutex<Data>>, String>>>;
struct Slot {
    index: usize,
    cell: Cell,
    bytes: usize,
    used: u64,
}
pub struct Pool {
    file: std::fs::File,
    entries: Vec<Entry>,
    budget: usize,
    slots: Mutex<(Vec<Slot>, u64)>,
    preparing: (Mutex<usize>, Condvar),
    max_prepares: usize,
    loads: std::sync::atomic::AtomicUsize,
}
impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("blocks", &self.entries.len())
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}
fn data_bytes(d: &Data) -> usize {
    match d {
        Data::Prepared(f) => f.memory_bytes(),
        Data::Rows(rows) => rows
            .iter()
            .map(|r| {
                r.header.len()
                    + r.txs.iter().map(|(t, m)| t.len() + m.len()).sum::<usize>()
                    + r.patches.iter().map(|(_, v)| v.len() + 32).sum::<usize>()
            })
            .sum(),
    }
}
impl Pool {
    /// `budget` bounds the estimated bytes of cached prepared blocks; one
    /// block is always kept even if it alone exceeds the budget.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        budget: usize,
        max_prepares: usize,
    ) -> Res<Self> {
        let a = ArchiveFile::open(path)?;
        Ok(Self {
            file: a.file,
            entries: a.entries,
            budget,
            slots: Mutex::new((vec![], 0)),
            preparing: (Mutex::new(0), Condvar::new()),
            max_prepares: max_prepares.max(1),
            loads: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    pub fn first(&self) -> Option<u32> {
        self.entries.first().map(|e| e.first)
    }
    pub fn block_loads(&self) -> usize {
        self.loads.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn cached_bytes(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .iter()
            .map(|s| s.bytes)
            .sum()
    }
    /// Index of the block holding ledger `seq`: callers group reads by it.
    pub fn block_id(&self, seq: u32) -> Res<usize> {
        self.block_of(seq)
    }
    fn block_of(&self, seq: u32) -> Res<usize> {
        let i = self
            .entries
            .partition_point(|e| e.first <= seq)
            .checked_sub(1)
            .ok_or("ledger extent")?;
        let e = &self.entries[i];
        if u64::from(seq) >= u64::from(e.first) + e.count as u64 {
            return Err("ledger extent".into());
        }
        Ok(i)
    }
    fn load(&self, i: usize) -> Res<Data> {
        // At most `max_prepares` decodes at once: each allocates its payload
        // and decoded block.
        {
            let (m, cv) = &self.preparing;
            let mut n = m.lock().unwrap_or_else(|p| p.into_inner());
            while *n >= self.max_prepares {
                n = cv.wait(n).unwrap_or_else(|p| p.into_inner());
            }
            *n += 1;
        }
        let out = self.load_inner(i);
        let (m, cv) = &self.preparing;
        *m.lock().unwrap_or_else(|p| p.into_inner()) -= 1;
        cv.notify_one();
        out
    }
    fn load_inner(&self, i: usize) -> Res<Data> {
        let e = &self.entries[i];
        let mut payload = vec![0; e.length];
        self.file
            .read_exact_at(&mut payload, e.offset)
            .map_err(er)?;
        let mut p = Read::new(&payload);
        let data = match p.byte()? {
            1 => {
                let mut f = fast::Prepared::for_read(&payload[1..])?;
                if f.layout.len() != e.count {
                    return Err("block count".into());
                }
                let mut hash = Sha512::new();
                hash.update((e.count as u32).to_le_bytes());
                let mut previous: Option<LedgerHeader> = None;
                for k in 0..e.count {
                    let row = f.row(k)?;
                    if row.seq != e.first.checked_add(k as u32).ok_or("sequence overflow")? {
                        return Err("block sequence".into());
                    }
                    verify(std::slice::from_ref(&row))?;
                    let h = LedgerHeader::parse(&row.header).map_err(er)?;
                    if previous.as_ref().is_some_and(|p| h.parent_hash != p.hash()) {
                        return Err("chain gap".into());
                    }
                    previous = Some(h);
                    let bytes = rows_bytes(std::slice::from_ref(&row));
                    hash.update(&bytes[4..]);
                }
                if hash.finalize()[..32] != e.hash {
                    return Err("block identity".into());
                }
                Data::Prepared(Box::new(f))
            }
            0 => {
                let n = u64::from_le_bytes(p.take(8)?.try_into().map_err(er)?);
                if n > MAX as u64 {
                    return Err("raw limit".into());
                }
                let raw = zstd::bulk::decompress(&payload[p.p..], n as usize).map_err(er)?;
                if raw.len() != n as usize {
                    return Err("raw size".into());
                }
                let rows = load_rows(&raw)?;
                if rows.len() != e.count
                    || rows.first().is_none_or(|r| r.seq != e.first)
                    || sha512_half(&raw) != e.hash
                {
                    return Err("block identity".into());
                }
                verify(&rows)?;
                Data::Rows(rows)
            }
            _ => return Err("block mode".into()),
        };
        self.loads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(data)
    }
    /// Prepared block `i`, preparing it once for all concurrent callers.
    fn block(&self, i: usize) -> Res<Arc<Mutex<Data>>> {
        let cell = {
            let mut g = self.slots.lock().unwrap_or_else(|p| p.into_inner());
            g.1 += 1;
            let tick = g.1;
            if let Some(s) = g.0.iter_mut().find(|s| s.index == i) {
                s.used = tick;
                s.cell.clone()
            } else {
                let cell: Cell = Arc::new(OnceLock::new());
                g.0.push(Slot {
                    index: i,
                    cell: cell.clone(),
                    bytes: 0,
                    used: tick,
                });
                cell
            }
        };
        let got = cell
            .get_or_init(|| self.load(i).map(|d| Arc::new(Mutex::new(d))))
            .clone();
        let mut g = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        match &got {
            Err(_) => g.0.retain(|s| !Arc::ptr_eq(&s.cell, &cell)),
            Ok(d) => {
                let bytes = data_bytes(&d.lock().unwrap_or_else(|p| p.into_inner()));
                if let Some(s) = g.0.iter_mut().find(|s| Arc::ptr_eq(&s.cell, &cell)) {
                    s.bytes = bytes;
                }
                // Evict least recently used ready blocks over the budget.
                loop {
                    let total: usize = g.0.iter().map(|s| s.bytes).sum();
                    if total <= self.budget || g.0.len() <= 1 {
                        break;
                    }
                    let Some(k) =
                        g.0.iter()
                            .enumerate()
                            .filter(|(_, s)| s.bytes > 0 && !Arc::ptr_eq(&s.cell, &cell))
                            .min_by_key(|(_, s)| s.used)
                            .map(|(k, _)| k)
                    else {
                        break;
                    };
                    g.0.swap_remove(k);
                }
            }
        }
        got
    }
    pub fn ledger(&self, seq: u32) -> Res<Row> {
        let i = self.block_of(seq)?;
        let local = (seq - self.entries[i].first) as usize;
        let d = self.block(i)?;
        let mut d = d.lock().unwrap_or_else(|p| p.into_inner());
        match &mut *d {
            Data::Prepared(f) => f.row(local),
            Data::Rows(rows) => rows.get(local).cloned().ok_or("ledger extent".into()),
        }
    }
    /// Header of ledger `seq` only.
    pub fn header(&self, seq: u32) -> Res<Vec<u8>> {
        let i = self.block_of(seq)?;
        let local = (seq - self.entries[i].first) as usize;
        let d = self.block(i)?;
        let mut d = d.lock().unwrap_or_else(|p| p.into_inner());
        match &mut *d {
            Data::Prepared(f) => f.header(local),
            Data::Rows(rows) => rows
                .get(local)
                .map(|r| r.header.clone())
                .ok_or("ledger extent".into()),
        }
    }
    /// Ledger `seq` with transactions but no patches (`patches` is empty).
    pub fn ledger_txs(&self, seq: u32) -> Res<Row> {
        let i = self.block_of(seq)?;
        let local = (seq - self.entries[i].first) as usize;
        let d = self.block(i)?;
        let mut d = d.lock().unwrap_or_else(|p| p.into_inner());
        match &mut *d {
            Data::Prepared(f) => f.row_txs(local),
            Data::Rows(rows) => rows
                .get(local)
                .map(|r| Row {
                    seq: r.seq,
                    header: r.header.clone(),
                    txs: r.txs.clone(),
                    patches: Vec::new(),
                })
                .ok_or("ledger extent".into()),
        }
    }
    /// Transaction at original storage position `within` of ledger `seq`.
    pub fn tx(&self, seq: u32, within: usize) -> Res<(Vec<u8>, Vec<u8>)> {
        let i = self.block_of(seq)?;
        let local = (seq - self.entries[i].first) as usize;
        let d = self.block(i)?;
        let mut d = d.lock().unwrap_or_else(|p| p.into_inner());
        match &mut *d {
            Data::Prepared(f) => {
                let base: usize = f.layout.iter().take(local).map(|r| r.tx.len()).sum();
                if f.layout.get(local).is_none_or(|r| within >= r.tx.len()) {
                    return Err("TX extent".into());
                }
                f.tx(base + within)
            }
            Data::Rows(rows) => rows
                .get(local)
                .and_then(|r| r.txs.get(within))
                .cloned()
                .ok_or("TX extent".into()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn rows(first: u32, n: u32) -> Vec<Row> {
        let mut out: Vec<Row> = vec![];
        let mut parent = [0u8; 32];
        for k in 0..n {
            let mut header = vec![0u8; 118];
            header[..4].copy_from_slice(&(first + k).to_be_bytes());
            header[12..44].copy_from_slice(&parent);
            parent = LedgerHeader::parse(&header).unwrap().hash();
            out.push(Row {
                seq: first + k,
                header,
                txs: vec![],
                patches: vec![([k as u8; 32], vec![0x11, 0, 0x61, k as u8])],
            });
        }
        out
    }
    #[test]
    fn pool_reads_exact_rows_concurrently_under_budget() {
        let rs = rows(10, 50);
        let (archive, _) = pack_bounded(&rs, 8, MAX, Options::default()).unwrap();
        let dir = std::env::temp_dir().join(format!("astj5-pool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.astj");
        std::fs::write(&path, &archive).unwrap();
        let pool = Arc::new(Pool::open(&path, 1, 2).unwrap());
        let hs: Vec<_> = (0..4)
            .map(|t| {
                let (pool, rs) = (pool.clone(), rs.clone());
                std::thread::spawn(move || {
                    for k in 0..50 {
                        let r = &rs[(k * 7 + t) % 50];
                        assert_eq!(pool.ledger(r.seq).unwrap(), *r);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert!(pool.ledger(9).is_err() && pool.ledger(60).is_err());
        assert!(pool.slots.lock().unwrap().0.len() <= 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn header_and_transactions_read_without_patches() {
        let rs = rows(10, 20);
        let (archive, _) = pack_bounded(&rs, 8, MAX, Options::default()).unwrap();
        let dir = std::env::temp_dir().join(format!("astj5-pool-tx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.astj");
        std::fs::write(&path, &archive).unwrap();
        let pool = Pool::open(&path, 1 << 20, 2).unwrap();
        for r in &rs {
            assert_eq!(pool.header(r.seq).unwrap(), r.header);
            let t = pool.ledger_txs(r.seq).unwrap();
            assert_eq!((t.seq, &t.header, &t.txs), (r.seq, &r.header, &r.txs));
            assert!(t.patches.is_empty() && !r.patches.is_empty());
        }
        assert!(pool.header(30).is_err() && pool.ledger_txs(9).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
