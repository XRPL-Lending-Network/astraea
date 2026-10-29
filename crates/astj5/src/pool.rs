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
//!
//! JC06 blocks open with their shared section only, and a part compiles when
//! one of its ledgers is first read; the cached size of a block grows with its
//! compiled parts. `tx_with_index` reads one transaction that way.
//!
//! That check costs about as much as preparing the block. A seal
//! (`Pool::seal`) records, for every block that passed it, a digest of the
//! stored block bytes. With a seal set (`set_seal`), a block whose bytes still
//! match its digest is prepared without repeating the check; any other block is
//! checked in full as before. A JC06 block has a digest of its head (sizes and
//! shared section) and one per part: a read checks the head and the parts it
//! compiles, not the whole block.
use super::*;
use sha2::{Digest, Sha512};
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
enum Data {
    Prepared(Box<fast::Prepared>),
    Rows(Vec<Row>),
}
type Cell = Arc<OnceLock<Result<Arc<Mutex<Data>>, String>>>;
/// One transaction with the header of its ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAt {
    pub header: Vec<u8>,
    pub tx: Vec<u8>,
    pub meta: Vec<u8>,
}
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
    seal: Vec<Vec<[u8; 32]>>,
}
/// Seal digests of a block's stored bytes: the whole payload, or for JC06 the
/// head and then every part.
fn block_digests(hash: &[u8; 32], payload: &[u8]) -> Res<Vec<[u8; 32]>> {
    if payload.first() != Some(&2) {
        return Ok(vec![seal_digest(hash, payload)]);
    }
    let l = fast::frame_parts(&payload[1..])?;
    let mut out = vec![seal_digest(hash, &payload[..1 + l.head])];
    for (r, _) in l.parts {
        out.push(seal_digest(hash, &payload[1 + r.start..1 + r.end]));
    }
    Ok(out)
}
impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("blocks", &self.entries.len())
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}
fn compiled(d: &Data) -> usize {
    match d {
        Data::Prepared(f) => f.compiled_parts(),
        Data::Rows(_) => 0,
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
            seal: Vec::new(),
        })
    }
    /// Checks every block in full, on up to `threads` threads, and returns
    /// the seal: the digests of every block, in directory order.
    pub fn seal(&self, threads: usize) -> Res<Vec<Vec<[u8; 32]>>> {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let n = self.entries.len();
        let parts = std::thread::scope(|sc| {
            let workers: Vec<_> = (0..threads.clamp(1, n.max(1)))
                .map(|_| {
                    sc.spawn(|| -> Res<Vec<(usize, Vec<[u8; 32]>)>> {
                        let mut got = vec![];
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if i >= n {
                                return Ok(got);
                            }
                            let payload = self.payload(i)?;
                            self.decode(i, &payload, false)?;
                            got.push((i, block_digests(&self.entries[i].hash, &payload)?));
                        }
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| {
                    w.join()
                        .unwrap_or_else(|_| Err("seal worker panicked".into()))
                })
                .collect::<Vec<_>>()
        });
        let mut out = vec![vec![]; n];
        for p in parts {
            for (i, d) in p? {
                out[i] = d;
            }
        }
        Ok(out)
    }
    /// Sets the seal from `seal` (as returned by `seal` for this archive). A
    /// seal with the wrong number of digests is refused.
    pub fn set_seal(&mut self, seal: Vec<Vec<[u8; 32]>>) -> Res<()> {
        if seal.len() != self.entries.len() {
            return Err("seal does not match the archive's blocks".into());
        }
        self.seal = seal;
        Ok(())
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
        let payload = self.payload(i)?;
        let hash = &self.entries[i].hash;
        let seal = self.seal.get(i).map_or(&[][..], Vec::as_slice);
        // A JC06 block is trusted by its head here and by each part as it compiles.
        let parts = if payload.first() == Some(&2) && seal.len() > 1 {
            fast::frame_parts(&payload[1..])
                .ok()
                .filter(|l| {
                    l.parts.len() + 1 == seal.len()
                        && seal[0] == seal_digest(hash, &payload[..1 + l.head])
                })
                .map(|_| seal[1..].to_vec())
        } else {
            None
        };
        let sealed = parts.is_some() || (seal.len() == 1 && seal[0] == seal_digest(hash, &payload));
        let mut data = self.decode(i, &payload, sealed)?;
        if let (Some(digests), Data::Prepared(f)) = (parts, &mut data) {
            f.check_parts(*hash, digests)?;
        }
        self.loads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(data)
    }
    fn payload(&self, i: usize) -> Res<Vec<u8>> {
        let e = &self.entries[i];
        let mut payload = vec![0; e.length];
        self.file
            .read_exact_at(&mut payload, e.offset)
            .map_err(er)?;
        Ok(payload)
    }
    /// Block `i` from its stored bytes. `sealed`: the bytes match a seal digest,
    /// so only the framing is checked, not the hashes, roots and chain.
    fn decode(&self, i: usize, payload: &[u8], sealed: bool) -> Res<Data> {
        let e = &self.entries[i];
        let mut p = Read::new(payload);
        let data = match p.byte()? {
            mode @ (1 | 2) => {
                let mut f = if mode == 1 {
                    fast::Prepared::open(&payload[1..])?
                } else {
                    fast::Prepared::open_parts(&payload[1..])?
                };
                if f.ledger_count() != e.count {
                    return Err("block count".into());
                }
                if sealed {
                    for k in 0..e.count {
                        if f.seq(k)
                            != Some(e.first.checked_add(k as u32).ok_or("sequence overflow")?)
                        {
                            return Err("block sequence".into());
                        }
                    }
                    return Ok(Data::Prepared(Box::new(f)));
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
                if rows.len() != e.count || rows.first().is_none_or(|r| r.seq != e.first) {
                    return Err("block identity".into());
                }
                if !sealed {
                    if sha512_half(&raw) != e.hash {
                        return Err("block identity".into());
                    }
                    verify(&rows)?;
                }
                Data::Rows(rows)
            }
            _ => return Err("block mode".into()),
        };
        Ok(data)
    }
    /// Prepared block `i`, preparing it once for all concurrent callers.
    fn block(&self, i: usize) -> Res<(Cell, Arc<Mutex<Data>>)> {
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
        match &got {
            Err(_) => self
                .slots
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .0
                .retain(|s| !Arc::ptr_eq(&s.cell, &cell)),
            Ok(d) => {
                let bytes = data_bytes(&d.lock().unwrap_or_else(|p| p.into_inner()));
                self.resize(&cell, bytes);
            }
        }
        got.map(|d| (cell, d))
    }
    /// Records the size of a cached block and evicts least recently used ready
    /// blocks over the budget, never that one.
    fn resize(&self, cell: &Cell, bytes: usize) {
        let mut g = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(s) = g.0.iter_mut().find(|s| Arc::ptr_eq(&s.cell, cell)) {
            s.bytes = bytes;
        }
        loop {
            let total: usize = g.0.iter().map(|s| s.bytes).sum();
            if total <= self.budget || g.0.len() <= 1 {
                break;
            }
            let Some(k) =
                g.0.iter()
                    .enumerate()
                    .filter(|(_, s)| s.bytes > 0 && !Arc::ptr_eq(&s.cell, cell))
                    .min_by_key(|(_, s)| s.used)
                    .map(|(k, _)| k)
            else {
                break;
            };
            g.0.swap_remove(k);
        }
    }
    /// Runs `f` on the block holding ledger `seq` with the ledger's position in
    /// it; a block that compiled more parts on the way is measured again.
    fn with<T>(&self, seq: u32, f: impl FnOnce(&mut Data, usize) -> Res<T>) -> Res<T> {
        let i = self.block_of(seq)?;
        let local = (seq - self.entries[i].first) as usize;
        let (cell, d) = self.block(i)?;
        let (out, grown) = {
            let mut d = d.lock().unwrap_or_else(|p| p.into_inner());
            let before = compiled(&d);
            let out = f(&mut d, local);
            (out, (compiled(&d) != before).then(|| data_bytes(&d)))
        };
        if let Some(bytes) = grown {
            self.resize(&cell, bytes);
        }
        out
    }
    pub fn ledger(&self, seq: u32) -> Res<Row> {
        self.with(seq, |d, local| match d {
            Data::Prepared(f) => f.row(local),
            Data::Rows(rows) => rows.get(local).cloned().ok_or("ledger extent".into()),
        })
    }
    /// Header of ledger `seq` only.
    pub fn header(&self, seq: u32) -> Res<Vec<u8>> {
        self.with(seq, |d, local| match d {
            Data::Prepared(f) => f.header(local),
            Data::Rows(rows) => rows
                .get(local)
                .map(|r| r.header.clone())
                .ok_or("ledger extent".into()),
        })
    }
    /// Ledger `seq` with transactions but no patches (`patches` is empty).
    pub fn ledger_txs(&self, seq: u32) -> Res<Row> {
        self.with(seq, |d, local| match d {
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
        })
    }
    /// Transaction at original storage position `within` of ledger `seq`.
    pub fn tx(&self, seq: u32, within: usize) -> Res<(Vec<u8>, Vec<u8>)> {
        self.with(seq, |d, local| match d {
            Data::Prepared(f) => {
                let base: usize = (0..local).map(|k| f.txs_in(k).unwrap_or(0)).sum();
                if f.txs_in(local).is_none_or(|n| within >= n) {
                    return Err("TX extent".into());
                }
                f.tx(base + within)
            }
            Data::Rows(rows) => rows
                .get(local)
                .and_then(|r| r.txs.get(within))
                .cloned()
                .ok_or("TX extent".into()),
        })
    }
    /// Transaction of ledger `seq` whose metadata has TransactionIndex `index`,
    /// with the ledger's header; for a JC06 block only the part holding the
    /// ledger is compiled.
    pub fn tx_with_index(&self, seq: u32, index: u32) -> Res<Option<TxAt>> {
        self.with(seq, |d, local| match d {
            Data::Prepared(f) => match f.tx_with_index(local, index)? {
                Some((tx, meta)) => Ok(Some(TxAt {
                    header: f.header(local)?,
                    tx,
                    meta,
                })),
                None => Ok(None),
            },
            Data::Rows(rows) => {
                let r = rows.get(local).ok_or("ledger extent")?;
                Ok(r.txs
                    .iter()
                    .find(|(_, m)| matches!(**m, [0x20, 0x1C, a, b, c, d, ..] if u32::from_be_bytes([a, b, c, d]) == index))
                    .map(|(tx, meta)| TxAt {
                        header: r.header.clone(),
                        tx: tx.clone(),
                        meta: meta.clone(),
                    }))
            }
        })
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
    #[test]
    fn parts_are_compiled_as_their_ledgers_are_read() {
        let rs = rows(10, 40);
        let opt = Options {
            joint: true,
            adaptive: true,
            context_delta: true,
            split_shapes: true,
            chronological: true,
            cached_slots: true,
            hash_order: true,
            part_raw: 600,
            ..Options::default()
        };
        let (archive, stats) = pack_bounded(&rs, 20, MAX, opt).unwrap();
        assert!(stats.iter().all(|s| s.parts > 2));
        assert_eq!(unpack(&archive).unwrap(), rs);
        let dir = std::env::temp_dir().join(format!("astj5-pool-parts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.astj");
        std::fs::write(&path, &archive).unwrap();
        let seal = Pool::open(&path, 1 << 20, 2).unwrap().seal(2).unwrap();
        assert!(seal.iter().all(|d| d.len() > 3));
        let mut pool = Pool::open(&path, 1 << 20, 2).unwrap();
        pool.set_seal(seal.clone()).unwrap();
        assert_eq!(pool.header(31).unwrap(), rs[21].header);
        let one = pool.cached_bytes();
        assert_eq!(pool.ledger(12).unwrap(), rs[2]);
        assert!(pool.cached_bytes() > one);
        assert_eq!(pool.tx_with_index(15, 0).unwrap(), None);
        for r in &rs {
            assert_eq!(pool.ledger_txs(r.seq).unwrap().header, r.header);
        }
        // Unsealed, every block is checked in full.
        let full = Pool::open(&path, 1 << 20, 2).unwrap();
        assert_eq!(full.ledger(49).unwrap(), rs[39]);
        // A changed byte in the last part of the first block: under the seal only
        // reads that compile that part fail; unsealed, the whole block does.
        let e = &full.entries[0];
        let mut bad = archive.clone();
        bad[e.offset as usize + e.length - 1] ^= 1;
        std::fs::write(&path, &bad).unwrap();
        let mut pool = Pool::open(&path, 1 << 20, 2).unwrap();
        pool.set_seal(seal.clone()).unwrap();
        assert_eq!(pool.ledger(10).unwrap(), rs[0]);
        let err = pool.ledger(29).unwrap_err();
        assert!(err.contains("seal"), "{err}");
        assert_eq!(pool.ledger(30).unwrap(), rs[20]);
        assert!(Pool::open(&path, 1 << 20, 2).unwrap().ledger(10).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn seal_skips_the_check_only_for_unchanged_blocks() {
        for opts in [
            Options::default(),
            Options {
                joint: true,
                ..Options::default()
            },
        ] {
            let rs = rows(10, 24);
            let (archive, _) = pack_bounded(&rs, 8, MAX, opts).unwrap();
            let dir = std::env::temp_dir().join(format!(
                "astj5-pool-seal-{}-{}",
                std::process::id(),
                opts.joint
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("a.astj");
            std::fs::write(&path, &archive).unwrap();
            let seal = Pool::open(&path, 1 << 20, 2).unwrap().seal(3).unwrap();
            assert_eq!(seal.len(), 3);
            assert!(seal.iter().all(|d| d.len() == 1));
            let mut pool = Pool::open(&path, 1 << 20, 2).unwrap();
            assert!(pool.set_seal(seal[..2].to_vec()).is_err());
            pool.set_seal(seal.clone()).unwrap();
            for r in &rs {
                assert_eq!(pool.ledger(r.seq).unwrap(), *r);
            }
            // A changed byte in the middle block: its digest no longer matches,
            // so the block is checked in full and fails.
            let e = &pool.entries[1];
            let mut bad = archive.clone();
            bad[e.offset as usize + e.length - 1] ^= 1;
            std::fs::write(&path, &bad).unwrap();
            let mut pool = Pool::open(&path, 1 << 20, 2).unwrap();
            pool.set_seal(seal.clone()).unwrap();
            assert!(pool.ledger(10).is_ok() && pool.ledger(26).is_ok());
            assert!(pool.ledger(18).is_err());
            assert!(Pool::open(&path, 1 << 20, 2).unwrap().seal(2).is_err());
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
    #[test]
    fn a_seal_is_trusted_for_the_bytes_it_names() {
        // A wrong directory hash fails the full check; a digest over that hash
        // and the stored bytes skips it, which is why only `seal` should
        // produce one.
        let rs = rows(10, 8);
        let (archive, _) = pack_bounded(&rs, 8, MAX, Options::default()).unwrap();
        let dir = std::env::temp_dir().join(format!("astj5-pool-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.astj");
        std::fs::write(&path, &archive).unwrap();
        let mut pool = Pool::open(&path, 1 << 20, 2).unwrap();
        pool.entries[0].hash = [0; 32];
        assert!(pool.seal(1).is_err() && pool.ledger(12).is_err());
        let e = &pool.entries[0];
        let payload = archive[e.offset as usize..e.offset as usize + e.length].to_vec();
        let mut pool = Pool::open(&path, 1 << 20, 2).unwrap();
        pool.entries[0].hash = [0; 32];
        pool.set_seal(vec![vec![seal_digest(&[0; 32], &payload)]])
            .unwrap();
        assert_eq!(pool.ledger(12).unwrap(), rs[2]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
