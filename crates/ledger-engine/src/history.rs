//! Ledger history, format 2: transactions and state changes in
//! separate streams.
//!
//! The layout was chosen by measuring the alternatives:
//! - **transactions**: one frame per ledger (header and transactions with metadata),
//!   zstd with a dictionary, so a single transaction or an account_tx page is read
//!   without decompressing neighbouring ledgers (page p99 ~20 ms versus 383 ms with a
//!   shared block, a single tx 0.2 ms versus 5.8);
//! - **state changes**: blocks of `changes_group` ledgers, zstd-19, since
//!   they are read only when rebuilding and verifying state.
//!
//! Dictionaries are immutable files `dicts/<hash>.zdict`, named by the
//! SHA-512Half of their content. A transaction segment names its dictionary by
//! hash in its header, and the reader checks the file's hash. Changing the dictionary
//! means a new file and new segments; old segments are read with their own dictionary.
//! Tampering with dictionary bytes is detected.
//!
//! Files of a segment starting at ledger F:
//! - `txl-F.xwlt`: `XWLT\0\1`, dictionary hash (32 bytes, zeros for no dictionary),
//!   then frames back to back; a frame is zstd of (118-byte header, u32 n, n pairs
//!   (u32 length, transaction, u32 length, metadata));
//! - `txl-F.xwlt.idx`: `XWTI\0\1`, per frame `u32 ledger | u64 offset | u32 length`;
//! - `chg-F.xwlc`: `XWLC\0\1`, then blocks; a block is zstd of (u32 n, n pairs
//!   (u32 ledger, u32 length), each ledger's changes in `Ledger` format);
//! - `chg-F.xwlc.idx`: `XWCI\0\1`, per block `u32 first | u32 n | u64 offset | u32 length`.
//!
//! ASTJ5 cold segments (module `cold`, files `cold-*.{astj,asix,kinds,json}`)
//! in the same directory are read when a ledger is not in the hot segments; with
//! `with_cold_first`, before the hot ones (for checking the cold history).
//!
//! Writing a group: transaction frames first, fsync, index, fsync; then the
//! changes block the same way. A ledger is in the history only if both streams are
//! written: a transaction tail without changes left by a crash is not read and gets
//! rewritten in the next segment.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use witness_core::ledger::HEADER_LEN;
use witness_core::sha512_half;

use crate::ledger::Ledger;

const TX_MAGIC: &[u8; 6] = b"XWLT\x00\x01";
const TX_IDX_MAGIC: &[u8; 6] = b"XWTI\x00\x01";
/// Change blocks: full objects (format 2), or a diff against the previous
/// version and metadata (format 3, module `delta`).
const CH_MAGIC: &[u8; 6] = b"XWLC\x00\x01";
const CH_MAGIC_DELTA: &[u8; 6] = b"XWLC\x00\x02";
const CH_IDX_MAGIC: &[u8; 6] = b"XWCI\x00\x01";
const TX_ENTRY: usize = 4 + 8 + 4;
const CH_ENTRY: usize = 4 + 4 + 8 + 4;
const NO_DICT: [u8; 32] = [0; 32];
/// Decompressed transaction frames in the reader's cache.
const TX_CACHE: usize = 64;
const CH_CACHE: usize = 2;

type Res<T> = Result<T, String>;

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// `le32` with a bounds check: decompressed data comes from disk.
fn rd32(b: &[u8], at: usize) -> Res<u32> {
    b.get(at..at.saturating_add(4))
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
        .ok_or_else(|| corrupt(format!("record truncated at {at}")))
}

/// History corruption is a separate error, not "no such record".
fn corrupt(what: String) -> String {
    format!("corrupt_history: {what}")
}

/// A decompressed frame or block can never be larger than this: a changes block
/// of 128 ledgers is tens of megabytes.
const MAX_DECODED: usize = 256 << 20;

fn le64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// An immutable zstd dictionary.
#[derive(Debug, Clone)]
pub struct Dict {
    pub id: [u8; 32],
    pub bytes: Arc<Vec<u8>>,
}

fn dict_path(dir: &Path, id: &[u8; 32]) -> PathBuf {
    dir.join("dicts")
        .join(format!("{}.zdict", hex::encode_upper(id)))
}

impl Dict {
    /// Stores the dictionary under its hash name (via a temporary file, with fsync) and
    /// makes it current for new segments.
    pub fn store(dir: &Path, bytes: Vec<u8>) -> Res<Dict> {
        let id = sha512_half(&bytes);
        let dicts = dir.join("dicts");
        fs::create_dir_all(&dicts).map_err(io)?;
        let path = dict_path(dir, &id);
        if !path.exists() {
            let tmp = dicts.join(".new.zdict");
            let mut f = File::create(&tmp).map_err(io)?;
            f.write_all(&bytes).map_err(io)?;
            f.sync_all().map_err(io)?;
            fs::rename(&tmp, &path).map_err(io)?;
        }
        let tmp = dicts.join(".current");
        fs::write(&tmp, hex::encode_upper(id)).map_err(io)?;
        fs::rename(&tmp, dicts.join("current")).map_err(io)?;
        File::open(&dicts).and_then(|d| d.sync_all()).map_err(io)?;
        Ok(Dict {
            id,
            bytes: Arc::new(bytes),
        })
    }

    /// Dictionary by hash; the content hash must match the name.
    pub fn load(dir: &Path, id: &[u8; 32]) -> Res<Dict> {
        let bytes = fs::read(dict_path(dir, id))
            .map_err(|e| format!("dictionary {}: {e}", hex::encode_upper(id)))?;
        if sha512_half(&bytes) != *id {
            return Err(format!(
                "dictionary {}: content does not match the hash",
                hex::encode_upper(id)
            ));
        }
        Ok(Dict {
            id: *id,
            bytes: Arc::new(bytes),
        })
    }

    /// Current dictionary for new segments; `None` if there is none.
    pub fn current(dir: &Path) -> Res<Option<Dict>> {
        match fs::read_to_string(dir.join("dicts").join("current")) {
            Ok(s) => {
                let id: [u8; 32] = hex::decode(s.trim())
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or("dicts/current: not a hash")?;
                Ok(Some(Dict::load(dir, &id)?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Transaction frame: header, transaction count, pairs.
pub fn tx_frame(l: &Ledger) -> Vec<u8> {
    let size: usize = l
        .transactions
        .iter()
        .map(|(t, m)| t.len() + m.len() + 8)
        .sum();
    let mut out = Vec::with_capacity(HEADER_LEN + 4 + size);
    out.extend_from_slice(&l.header);
    out.extend_from_slice(&(l.transactions.len() as u32).to_le_bytes());
    for (t, m) in &l.transactions {
        out.extend_from_slice(&(t.len() as u32).to_le_bytes());
        out.extend_from_slice(t);
        out.extend_from_slice(&(m.len() as u32).to_le_bytes());
        out.extend_from_slice(m);
    }
    out
}

/// A ledger's changes in `Ledger::encode` format, without the header and transactions.
fn changes_part(l: &Ledger) -> Vec<u8> {
    let mut e = Ledger {
        header: Vec::new(),
        transactions: Vec::new(),
        changes: l.changes.clone(),
    }
    .encode();
    // encode without a header: u32 of 0 transactions, then the changes.
    e.drain(..4);
    e
}

/// A ledger from a transaction frame and a chunk of changes.
fn assemble(frame: &[u8], changes: Option<&[u8]>) -> Res<Ledger> {
    if frame.len() < HEADER_LEN + 4 {
        return Err("transaction frame truncated".into());
    }
    let mut body = frame.to_vec();
    match changes {
        Some(c) => body.extend_from_slice(c),
        None => body.extend_from_slice(&0u32.to_le_bytes()),
    }
    Ledger::decode(&body)
}

#[derive(Debug)]
struct Writer {
    tx: File,
    tx_idx: File,
    tx_offset: u64,
    ch: File,
    ch_idx: File,
    ch_offset: u64,
}

/// Writes history in groups of `changes_group` ledgers.
pub struct HistoryWriter {
    w: Writer,
    tx_comp: zstd::bulk::Compressor<'static>,
    changes_level: i32,
    changes_group: u32,
    delta: bool,
    /// Ledger sequence, the ledger itself and its changes record.
    pending: Vec<(u32, Ledger, Vec<u8>)>,
}

/// Previous version of an object as of a ledger: `(key, ledger) → object`.
pub type PrevAt = dyn Fn(&[u8; 32], u32) -> Res<Option<Vec<u8>>> + Send + Sync;

impl std::fmt::Debug for HistoryWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryWriter").finish_non_exhaustive()
    }
}

fn create_new(path: &Path, magic: &[u8]) -> Res<File> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(io)?;
    f.write_all(magic).map_err(io)?;
    Ok(f)
}

fn sync_dir(dir: &Path) -> Res<()> {
    File::open(dir).and_then(|d| d.sync_all()).map_err(io)
}

/// Second half of a journaled swap: rename whatever still has the `.new`
/// suffix, sync the directory, remove the marker.
fn finish_swap(dir: &Path, ch_path: &Path) -> Res<()> {
    for (new, to) in [
        (ch_path.with_extension("xwlc.new"), ch_path.to_path_buf()),
        (
            ch_path.with_extension("xwlc.idx.new"),
            ch_path.with_extension("xwlc.idx"),
        ),
    ] {
        if new.exists() {
            fs::rename(&new, &to).map_err(io)?;
        }
    }
    sync_dir(dir)?;
    fs::remove_file(ch_path.with_extension("swap")).map_err(io)?;
    sync_dir(dir)
}

impl HistoryWriter {
    /// A new segment starting at ledger `first`. A segment with the same start that
    /// has no complete record in the changes index is left over from a crash during
    /// the first group: a ledger is in the history only when both streams are written,
    /// so none was ever read from it and it can be replaced.
    /// If a complete group is there, the history already extends past `first`; such
    /// a call should not happen, and the files are left alone.
    pub fn create(
        dir: &Path,
        first: u32,
        changes_group: u32,
        tx_level: i32,
        changes_level: i32,
        dict: Option<&Dict>,
        delta: bool,
    ) -> Res<HistoryWriter> {
        fs::create_dir_all(dir).map_err(io)?;
        let base = |ext: &str| {
            dir.join(format!(
                "{}-{first:010}.{ext}",
                if ext.starts_with("xwlt") {
                    "txl"
                } else {
                    "chg"
                }
            ))
        };
        let (tx_path, tx_idx_path) = (base("xwlt"), base("xwlt.idx"));
        let (ch_path, ch_idx_path) = (base("xwlc"), base("xwlc.idx"));
        let no_group = fs::metadata(&ch_idx_path)
            .map(|m| m.len() < (CH_IDX_MAGIC.len() + CH_ENTRY) as u64)
            .unwrap_or(true);
        if (tx_path.exists() || tx_idx_path.exists() || ch_path.exists() || ch_idx_path.exists())
            && no_group
        {
            for p in [&tx_path, &tx_idx_path, &ch_path, &ch_idx_path] {
                let _ = fs::remove_file(p);
            }
        }
        let dict_id = dict.map_or(NO_DICT, |d| d.id);
        let mut tx = create_new(&tx_path, TX_MAGIC)?;
        tx.write_all(&dict_id).map_err(io)?;
        let tx_idx = create_new(&tx_idx_path, TX_IDX_MAGIC)?;
        let ch = create_new(&ch_path, if delta { CH_MAGIC_DELTA } else { CH_MAGIC })?;
        let ch_idx = create_new(&ch_idx_path, CH_IDX_MAGIC)?;
        sync_dir(dir)?;
        let tx_comp = match dict {
            Some(d) => zstd::bulk::Compressor::with_dictionary(tx_level, &d.bytes).map_err(io)?,
            None => zstd::bulk::Compressor::new(tx_level).map_err(io)?,
        };
        Ok(HistoryWriter {
            w: Writer {
                tx,
                tx_idx,
                tx_offset: (TX_MAGIC.len() + 32) as u64,
                ch,
                ch_idx,
                ch_offset: CH_MAGIC.len() as u64,
            },
            tx_comp,
            changes_level,
            changes_group: changes_group.max(1),
            delta,
            pending: Vec::new(),
        })
    }

    /// A ledger in `Ledger::encode` serialization. Format 3 changes need
    /// the previous version of objects: `prev` as of the ledger before this one.
    pub fn append(&mut self, sequence: u32, body: Vec<u8>, prev: Option<&PrevAt>) -> Res<()> {
        if let Some((last, ..)) = self.pending.last()
            && sequence != last + 1
        {
            return Err(format!("ledgers out of sequence: {last} → {sequence}"));
        }
        let l = Ledger::decode(&body)?;
        let record = if self.delta {
            let prev = prev.ok_or("format 3 changes need the previous version of objects")?;
            let at = sequence - 1;
            crate::delta::encode(&l, sequence, &|k| prev(k, at))?.0
        } else {
            changes_part(&l)
        };
        self.pending.push((sequence, l, record));
        if self.pending.len() as u32 >= self.changes_group {
            self.flush()?;
        }
        Ok(())
    }

    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Writes what has accumulated: transaction frames, then the changes block.
    pub fn flush(&mut self) -> Res<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let w = &mut self.w;
        let mut idx = Vec::with_capacity(self.pending.len() * TX_ENTRY);
        for (seq, l, _) in &self.pending {
            let z = self.tx_comp.compress(&tx_frame(l)).map_err(io)?;
            w.tx.write_all(&z).map_err(io)?;
            idx.extend_from_slice(&seq.to_le_bytes());
            idx.extend_from_slice(&w.tx_offset.to_le_bytes());
            idx.extend_from_slice(&(z.len() as u32).to_le_bytes());
            w.tx_offset += z.len() as u64;
        }
        w.tx.sync_data().map_err(io)?;
        w.tx_idx.write_all(&idx).map_err(io)?;
        w.tx_idx.sync_data().map_err(io)?;

        let mut raw = (self.pending.len() as u32).to_le_bytes().to_vec();
        for (seq, _, p) in &self.pending {
            raw.extend_from_slice(&seq.to_le_bytes());
            raw.extend_from_slice(&(p.len() as u32).to_le_bytes());
        }
        for (_, _, p) in &self.pending {
            raw.extend_from_slice(p);
        }
        let z = zstd::bulk::compress(&raw, self.changes_level).map_err(io)?;
        w.ch.write_all(&z).map_err(io)?;
        w.ch.sync_data().map_err(io)?;
        let mut e = Vec::with_capacity(CH_ENTRY);
        e.extend_from_slice(&self.pending[0].0.to_le_bytes());
        e.extend_from_slice(&(self.pending.len() as u32).to_le_bytes());
        e.extend_from_slice(&w.ch_offset.to_le_bytes());
        e.extend_from_slice(&(z.len() as u32).to_le_bytes());
        w.ch_idx.write_all(&e).map_err(io)?;
        w.ch_idx.sync_data().map_err(io)?;
        w.ch_offset += z.len() as u64;
        self.pending.clear();
        Ok(())
    }

    pub fn finish(mut self) -> Res<()> {
        self.flush()
    }
}

#[derive(Debug)]
struct Segment {
    /// Segment start, from the file name: known even while there are no frames.
    start: u32,
    tx_path: PathBuf,
    tx: File,
    dict: Option<Dict>,
    /// (ledger, offset, length), ascending.
    frames: Vec<(u32, u64, u32)>,
    ch: File,
    /// Format 3 changes: a diff, needs the previous version of objects.
    delta: bool,
    /// (first, n, offset, length).
    blocks: Vec<(u32, u32, u64, u32)>,
}

impl Segment {
    fn last(&self) -> Option<u32> {
        let t = self.frames.last().map(|f| f.0)?;
        let c = self.blocks.last().map(|b| b.0 + b.1 - 1)?;
        Some(t.min(c))
    }

    fn first(&self) -> Option<u32> {
        self.frames.first().map(|f| f.0)
    }
}

fn scan(dir: &Path) -> Res<Vec<Arc<Segment>>> {
    scan_with(dir, &[])
}

/// Directory scan; dictionaries from `known` are not reread.
fn scan_with(dir: &Path, known: &[Dict]) -> Res<Vec<Arc<Segment>>> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(out);
    };
    for e in entries {
        let tx_path = e.map_err(io)?.path();
        if tx_path.extension().is_none_or(|x| x != "xwlt") {
            continue;
        }
        let name = tx_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ch_path = dir.join(name.replace("txl-", "chg-").replace(".xwlt", ".xwlc"));
        let mut tx = File::open(&tx_path).map_err(io)?;
        let mut head = [0u8; 6 + 32];
        tx.read_exact(&mut head).map_err(io)?;
        if &head[..6] != TX_MAGIC {
            return Err(format!("{}: not a transaction segment", tx_path.display()));
        }
        let dict_id: [u8; 32] = head[6..].try_into().map_err(|_| "header")?;
        let dict = (dict_id != NO_DICT)
            .then(|| match known.iter().find(|d| d.id == dict_id) {
                Some(d) => Ok(d.clone()),
                None => Dict::load(dir, &dict_id),
            })
            .transpose()?;
        let idx = fs::read(tx_path.with_extension("xwlt.idx")).map_err(io)?;
        if !idx.starts_with(TX_IDX_MAGIC) {
            return Err(format!("{}: not a transaction index", tx_path.display()));
        }
        let frames: Vec<(u32, u64, u32)> = idx[6..]
            .as_chunks::<TX_ENTRY>()
            .0
            .iter()
            .map(|c| (le32(c, 0), le64(c, 4), le32(c, 12)))
            .collect();
        let mut ch = File::open(&ch_path).map_err(io)?;
        let mut magic = [0u8; 6];
        ch.read_exact(&mut magic).map_err(io)?;
        let delta = match &magic {
            m if m == CH_MAGIC => false,
            m if m == CH_MAGIC_DELTA => true,
            _ => return Err(format!("{}: not a changes segment", ch_path.display())),
        };
        let cidx = fs::read(ch_path.with_extension("xwlc.idx")).map_err(io)?;
        if !cidx.starts_with(CH_IDX_MAGIC) {
            return Err(format!("{}: not a changes index", ch_path.display()));
        }
        let blocks: Vec<(u32, u32, u64, u32)> = cidx[6..]
            .as_chunks::<CH_ENTRY>()
            .0
            .iter()
            .map(|c| (le32(c, 0), le32(c, 4), le64(c, 8), le32(c, 16)))
            .collect();
        let start = name
            .strip_prefix("txl-")
            .and_then(|r| r.strip_suffix(".xwlt"))
            .and_then(|f| f.parse::<u32>().ok())
            .ok_or(format!("{name}: segment name has no ledger sequence"))?;
        let tx_len = tx.metadata().map_err(io)?.len();
        let ch_len = ch.metadata().map_err(io)?.len();
        check_index(&name, start, &frames, tx_len, &blocks, ch_len)?;
        out.push(Arc::new(Segment {
            start,
            tx_path,
            tx,
            dict,
            frames,
            ch,
            delta,
            blocks,
        }));
    }
    out.sort_by_key(|s| s.first().unwrap_or(u32::MAX));
    Ok(out)
}

/// Checks that a segment's indexes are consistent: frame ledgers run consecutively
/// from the segment start, change groups are consecutive and non-empty, and frames
/// and blocks lie inside their files without overlapping. Otherwise the result is
/// `corrupt_history`, not a read past the data.
fn check_index(
    name: &str,
    start: u32,
    frames: &[(u32, u64, u32)],
    tx_len: u64,
    blocks: &[(u32, u32, u64, u32)],
    ch_len: u64,
) -> Res<()> {
    let bad = |what: String| Err(corrupt(format!("{name}: {what}")));
    let mut end = (TX_MAGIC.len() + 32) as u64;
    for (j, &(seq, off, len)) in frames.iter().enumerate() {
        if u64::from(seq) != u64::from(start) + j as u64 {
            return bad(format!(
                "frame {j} is ledger {seq}, expected {}",
                u64::from(start) + j as u64
            ));
        }
        if len == 0 || off < end || off + u64::from(len) > tx_len {
            return bad(format!(
                "frame of ledger {seq} is outside the file or overlaps"
            ));
        }
        end = off + u64::from(len);
    }
    let mut end = CH_MAGIC.len() as u64;
    let mut next = u64::from(start);
    for &(first, n, off, len) in blocks {
        if u64::from(first) != next || n == 0 {
            return bad(format!(
                "change group from {first} for {n} is not consecutive"
            ));
        }
        if len == 0 || off < end || off + u64::from(len) > ch_len {
            return bad(format!(
                "change group from {first} is outside the file or overlaps"
            ));
        }
        end = off + u64::from(len);
        next = u64::from(first) + u64::from(n);
    }
    Ok(())
}

type Cache = Mutex<VecDeque<((usize, u32), Arc<Vec<u8>>)>>;

/// History reader. New segments and groups become visible after `refresh`; `get`
/// calls it itself when the ledger is past the known end.
pub struct HistoryReader {
    dir: PathBuf,
    segments: RwLock<Arc<Vec<Arc<Segment>>>>,
    tx_cache: Cache,
    ch_cache: Cache,
    /// Previous object versions, for format 3 changes.
    prev: Option<Arc<PrevAt>>,
    cold: RwLock<Arc<crate::cold::Cold>>,
    cold_index: RwLock<crate::coldindex::Shared>,
    cold_first: bool,
    /// When the directory was last checked for new cold files.
    cold_checked: Mutex<Option<std::time::Instant>>,
    /// Cold data is reloaded by one thread at a time.
    cold_refreshing: Mutex<()>,
}

impl std::fmt::Debug for HistoryReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryReader")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

fn cached(
    cache: &Cache,
    key: (usize, u32),
    cap: usize,
    load: impl FnOnce() -> Res<Vec<u8>>,
) -> Res<Arc<Vec<u8>>> {
    if let Some((_, v)) = cache
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(k, _)| *k == key)
    {
        return Ok(v.clone());
    }
    let v = Arc::new(load()?);
    let mut c = cache.lock().unwrap_or_else(|p| p.into_inner());
    c.push_front((key, v.clone()));
    c.truncate(cap);
    Ok(v)
}

impl HistoryReader {
    pub fn open(dir: &Path) -> Res<HistoryReader> {
        HistoryReader::recover_swaps(dir)?;
        // Indexes before segments, see refresh_cold.
        let cold_index = crate::coldindex::ColdIndexes::open(dir)?;
        Ok(HistoryReader {
            dir: dir.to_path_buf(),
            segments: RwLock::new(Arc::new(scan(dir)?)),
            tx_cache: Mutex::new(VecDeque::new()),
            ch_cache: Mutex::new(VecDeque::new()),
            prev: None,
            cold: RwLock::new(Arc::new(crate::cold::Cold::open(dir)?)),
            cold_index: RwLock::new(Arc::new(cold_index)),
            cold_first: false,
            cold_checked: Mutex::new(Some(std::time::Instant::now())),
            cold_refreshing: Mutex::new(()),
        })
    }

    /// Cold history indexes for the API (transaction by hash, account history,
    /// ledger hash).
    pub fn cold_index(&self) -> crate::coldindex::Shared {
        self.cold_index
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Cold segments before hot ones: checks the cold history against the
    /// same queries.
    pub fn with_cold_first(mut self, on: bool) -> HistoryReader {
        self.cold_first = on;
        self
    }

    fn cold(&self) -> Arc<crate::cold::Cold> {
        self.cold.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Cold segments: (first ledger, last ledger, manifest).
    pub fn cold_info(&self) -> Vec<(u32, u32, serde_json::Value)> {
        self.cold()
            .segments()
            .iter()
            .map(|s| (s.first, s.last, s.manifest.clone()))
            .collect()
    }

    /// Where to get previous object versions for format 3 changes,
    /// usually the state store.
    pub fn with_prev(mut self, prev: Arc<PrevAt>) -> HistoryReader {
        self.prev = Some(prev);
        self
    }

    /// Segments: (first ledger, last ledger, format 3 changes). For a segment
    /// with no group written yet, last is one less than first.
    pub fn segments_info(&self) -> Vec<(u32, u32, bool)> {
        self.segments()
            .iter()
            .map(|s| {
                (
                    s.start,
                    s.last().unwrap_or(s.start.saturating_sub(1)),
                    s.delta,
                )
            })
            .collect()
    }

    fn segments(&self) -> Arc<Vec<Arc<Segment>>> {
        self.segments
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn refresh(&self) -> Res<()> {
        let known: Vec<Dict> = self
            .segments()
            .iter()
            .filter_map(|s| s.dict.clone())
            .collect();
        let fresh = Arc::new(scan_with(&self.dir, &known)?);
        *self.segments.write().unwrap_or_else(|p| p.into_inner()) = fresh;
        self.refresh_cold()
    }

    /// Reloads cold segments and indexes if `every` has passed since the last
    /// check: cold history is published into the live directory without a
    /// restart, and the hot misses that trigger `refresh` never reach
    /// it.
    pub fn refresh_cold_every(&self, every: std::time::Duration) -> Res<()> {
        {
            let mut t = self.cold_checked.lock().unwrap_or_else(|p| p.into_inner());
            if t.is_some_and(|t| t.elapsed() < every) {
                return Ok(());
            }
            *t = Some(std::time::Instant::now());
        }
        self.refresh_cold()
    }

    fn refresh_cold(&self) -> Res<()> {
        // One thread reloads and the others skip; otherwise a snapshot
        // taken earlier could overwrite a newer one.
        let _busy = match self.cold_refreshing.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
        };
        // Reload only when the number of manifests changed, and then only
        // the new ones: segments and partitions already open carry over as is.
        let (mut names, mut parts) = (0, 0);
        if let Ok(d) = fs::read_dir(&self.dir) {
            for e in d.filter_map(|e| e.ok()) {
                let n = e.file_name();
                let n = n.to_string_lossy();
                if n.ends_with(".json") {
                    if n.starts_with("cold-") {
                        names += 1;
                    } else if n.starts_with("coldidx-") {
                        parts += 1;
                    }
                }
            }
        }
        // Indexes are read before segments but installed after them. A group
        // is published data first and index manifest last, so everything
        // a new index covers is already in place by the time segments are read,
        // and the API range never runs ahead of the data.
        let ix = self.cold_index();
        let fresh_ix = if parts != ix.parts() {
            Some(crate::coldindex::ColdIndexes::open_with(&self.dir, &ix)?)
        } else {
            None
        };
        let cold = self.cold();
        if fresh_ix.is_some() || names != cold.segments().len() {
            *self.cold.write().unwrap_or_else(|p| p.into_inner()) =
                Arc::new(crate::cold::Cold::open_with(&self.dir, &cold)?);
        }
        if let Some(fresh) = fresh_ix {
            *self.cold_index.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(fresh);
        }
        Ok(())
    }

    pub fn first(&self) -> Option<u32> {
        let hot = self.segments().iter().filter_map(|s| s.first()).min();
        [hot, self.cold().first()].into_iter().flatten().min()
    }

    /// Last ledger with both streams written (or a cold one).
    pub fn last(&self) -> Option<u32> {
        let hot = self.segments().iter().filter_map(|s| s.last()).max();
        [hot, self.cold().last()].into_iter().flatten().max()
    }

    /// Segment and frame number of a ledger; searches the last segment where it
    /// is written in full (after a crash the tail may be repeated in the next one).
    fn find(&self, seq: u32) -> Option<(usize, Arc<Segment>, usize)> {
        let segs = self.segments();
        for (i, s) in segs.iter().enumerate().rev() {
            if s.last().is_none_or(|l| seq > l) || s.first().is_none_or(|f| seq < f) {
                continue;
            }
            let k = s.frames.partition_point(|f| f.0 < seq);
            if s.frames.get(k).is_some_and(|f| f.0 == seq) {
                return Some((i, s.clone(), k));
            }
        }
        None
    }

    fn find_or_refresh(&self, seq: u32) -> Res<Option<(usize, Arc<Segment>, usize)>> {
        if let Some(f) = self.find(seq) {
            return Ok(Some(f));
        }
        if self.last().is_none_or(|l| seq > l) {
            self.refresh()?;
            return Ok(self.find(seq));
        }
        Ok(None)
    }

    fn frame(&self, i: usize, s: &Segment, k: usize) -> Res<Arc<Vec<u8>>> {
        let (seq, off, len) = s.frames[k];
        cached(&self.tx_cache, (i, seq), TX_CACHE, || {
            let mut z = vec![0u8; len as usize];
            s.tx.read_exact_at(&mut z, off).map_err(io)?;
            match &s.dict {
                Some(d) => zstd::bulk::Decompressor::with_dictionary(&d.bytes)
                    .and_then(|mut x| x.decompress(&z, 256 << 20))
                    .map_err(io),
                None => zstd::bulk::decompress(&z, MAX_DECODED).map_err(io),
            }
        })
    }

    fn changes(&self, i: usize, s: &Segment, seq: u32) -> Res<Vec<u8>> {
        let k = s.blocks.partition_point(|b| b.0 + b.1 <= seq);
        let &(first, n, off, len) = s
            .blocks
            .get(k)
            .filter(|b| b.0 <= seq)
            .ok_or("no changes for the ledger")?;
        let raw = cached(&self.ch_cache, (i, first), CH_CACHE, || {
            let mut z = vec![0u8; len as usize];
            s.ch.read_exact_at(&mut z, off).map_err(io)?;
            zstd::bulk::decompress(&z, MAX_DECODED).map_err(|e| corrupt(e.to_string()))
        })?;
        let count = rd32(&raw, 0)? as usize;
        if count != n as usize {
            return Err(corrupt("changes block does not match the index".into()));
        }
        let mut at = count
            .checked_mul(8)
            .and_then(|x| x.checked_add(4))
            .filter(|x| *x <= raw.len())
            .ok_or_else(|| {
                corrupt("changes block table of contents is longer than the block".into())
            })?;
        for j in 0..count {
            let (s2, l) = (rd32(&raw, 4 + j * 8)?, rd32(&raw, 8 + j * 8)? as usize);
            if s2 != first + j as u32 {
                return Err(corrupt(format!(
                    "in the block from {first} at position {j} found ledger {s2}"
                )));
            }
            let end = at
                .checked_add(l)
                .filter(|e| *e <= raw.len())
                .ok_or_else(|| corrupt("changes block truncated".into()))?;
            if s2 == seq {
                return Ok(raw[at..end].to_vec());
            }
            at = end;
        }
        Err(corrupt(format!(
            "ledger {seq} missing from its changes block"
        )))
    }

    /// Parsed transaction frame of ledger `seq`, checked to be that ledger:
    /// a whole frame of some other ledger at a wrong index address is not passed
    /// off as the requested one.
    fn txs_at(&self, i: usize, s: &Segment, k: usize, seq: u32) -> Res<Ledger> {
        let l = assemble(&self.frame(i, s, k)?, None).map_err(corrupt)?;
        let got = l.header().map_err(corrupt)?.sequence;
        if got != seq {
            return Err(corrupt(format!(
                "the address of ledger {seq} holds a frame of ledger {got}"
            )));
        }
        Ok(l)
    }

    /// Header of a ledger in cold history only, without decoding its
    /// transactions; `None` if the ledger isn't in cold history.
    pub fn cold_header(&self, seq: u32) -> Res<Option<Vec<u8>>> {
        self.cold().header(seq)
    }

    /// A ledger without state changes (header and transactions), for the API.
    pub fn get_txs(&self, seq: u32) -> Res<Option<Ledger>> {
        if self.cold_first
            && let Some(l) = self.cold().ledger(seq, false)?
        {
            return Ok(Some(l));
        }
        let Some((i, s, k)) = self.find_or_refresh(seq)? else {
            return self.cold().ledger(seq, false);
        };
        Ok(Some(self.txs_at(i, &s, k, seq)?))
    }

    /// Same, but only from already known segments, without rescanning the
    /// directory. Fresh ledgers not yet in the history are looked up among
    /// the store's pending ones, not by walking files on every request.
    pub fn get_txs_known(&self, seq: u32) -> Res<Option<Ledger>> {
        if self.cold_first
            && let Some(l) = self.cold().ledger(seq, false)?
        {
            return Ok(Some(l));
        }
        let Some((i, s, k)) = self.find(seq) else {
            return self.cold().ledger(seq, false);
        };
        Ok(Some(self.txs_at(i, &s, k, seq)?))
    }

    /// A whole ledger in `Ledger::encode` serialization.
    pub fn get(&self, seq: u32) -> Res<Option<Vec<u8>>> {
        if self.cold_first
            && let Some(l) = self.cold().ledger(seq, true)?
        {
            return Ok(Some(l.encode()));
        }
        let Some((i, s, k)) = self.find_or_refresh(seq)? else {
            return Ok(self.cold().ledger(seq, true)?.map(|l| l.encode()));
        };
        let mut l = self.txs_at(i, &s, k, seq)?;
        let ch = self.changes(i, &s, seq)?;
        if !s.delta {
            let frame = self.frame(i, &s, k)?;
            return Ok(Some(assemble(&frame, Some(&ch)).map_err(corrupt)?.encode()));
        }
        let prev = self.prev.as_ref().ok_or(
            "format 3 changes need the previous version of objects: reader has no state store",
        )?;
        let at = seq - 1;
        l.changes = crate::delta::decode(&l, seq, &ch, &|k| prev(k, at))?;
        Ok(Some(l.encode()))
    }

    /// Rewrites the changes of the segment starting at `first` into format 3:
    /// writes `*.new` alongside, then reads every ledger back and compares it
    /// byte for byte with the original. `swap_changes` replaces the files. Returns
    /// the size of the old and new changes data.
    pub fn convert_changes(&self, first: u32, group: u32, level: i32) -> Res<(u64, u64)> {
        let segs = self.segments();
        let s = segs
            .iter()
            .find(|s| s.start == first)
            .ok_or(format!("no segment starting at {first}"))?;
        if s.delta {
            return Err(format!("segment {first} is already in format 3"));
        }
        let prev = self
            .prev
            .as_ref()
            .ok_or("needs the previous version of objects")?;
        let last = s.last().ok_or("segment is empty")?;
        let ch_path = self.dir.join(format!("chg-{first:010}.xwlc"));
        let (new_path, new_idx) = (
            ch_path.with_extension("xwlc.new"),
            ch_path.with_extension("xwlc.idx.new"),
        );
        let _ = fs::remove_file(&new_path);
        let _ = fs::remove_file(&new_idx);
        let mut ch = create_new(&new_path, CH_MAGIC_DELTA)?;
        let mut idx = create_new(&new_idx, CH_IDX_MAGIC)?;
        let mut offset = CH_MAGIC.len() as u64;
        let mut pending: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut write = |pending: &mut Vec<(u32, Vec<u8>)>| -> Res<()> {
            if pending.is_empty() {
                return Ok(());
            }
            let mut raw = (pending.len() as u32).to_le_bytes().to_vec();
            for (seq, p) in pending.iter() {
                raw.extend_from_slice(&seq.to_le_bytes());
                raw.extend_from_slice(&(p.len() as u32).to_le_bytes());
            }
            for (_, p) in pending.iter() {
                raw.extend_from_slice(p);
            }
            let z = zstd::bulk::compress(&raw, level).map_err(io)?;
            ch.write_all(&z).map_err(io)?;
            let mut e = Vec::with_capacity(CH_ENTRY);
            e.extend_from_slice(&pending[0].0.to_le_bytes());
            e.extend_from_slice(&(pending.len() as u32).to_le_bytes());
            e.extend_from_slice(&offset.to_le_bytes());
            e.extend_from_slice(&(z.len() as u32).to_le_bytes());
            idx.write_all(&e).map_err(io)?;
            offset += z.len() as u64;
            pending.clear();
            Ok(())
        };
        let mut originals = Vec::new();
        for seq in first..=last {
            let body = self.get(seq)?.ok_or(format!("ledger {seq} not found"))?;
            let l = Ledger::decode(&body)?;
            let at = seq - 1;
            let (record, _) = crate::delta::encode(&l, seq, &|k| prev(k, at))?;
            pending.push((seq, record));
            originals.push(witness_core::sha512_half(&body));
            if pending.len() as u32 >= group {
                write(&mut pending)?;
            }
        }
        write(&mut pending)?;
        ch.sync_all().map_err(io)?;
        idx.sync_all().map_err(io)?;
        drop((ch, idx));
        // Verify: the new changes segment against the existing transaction frames.
        let check = HistoryReader {
            dir: self.dir.clone(),
            segments: RwLock::new(Arc::new(vec![Arc::new(Segment {
                start: s.start,
                tx_path: s.tx_path.clone(),
                tx: File::open(&s.tx_path).map_err(io)?,
                dict: s.dict.clone(),
                frames: s.frames.clone(),
                ch: File::open(&new_path).map_err(io)?,
                delta: true,
                blocks: {
                    let raw = fs::read(&new_idx).map_err(io)?;
                    raw[6..]
                        .as_chunks::<CH_ENTRY>()
                        .0
                        .iter()
                        .map(|c| (le32(c, 0), le32(c, 4), le64(c, 8), le32(c, 16)))
                        .collect()
                },
            })])),
            tx_cache: Mutex::new(VecDeque::new()),
            ch_cache: Mutex::new(VecDeque::new()),
            prev: self.prev.clone(),
            cold: RwLock::new(Arc::new(crate::cold::Cold::default())),
            cold_index: RwLock::new(Arc::new(crate::coldindex::ColdIndexes::default())),
            cold_first: false,
            cold_checked: Mutex::new(None),
            cold_refreshing: Mutex::new(()),
        };
        for (i, seq) in (first..=last).enumerate() {
            let got = check
                .get(seq)?
                .ok_or(format!("ledger {seq} missing from the new segment"))?;
            if witness_core::sha512_half(&got) != originals[i] {
                return Err(format!("ledger {seq}: differs in format 3, swap cancelled"));
            }
        }
        let old = fs::metadata(&ch_path).map_or(0, |m| m.len());
        let new = fs::metadata(&new_path).map_or(0, |m| m.len());
        Ok((old, new))
    }

    /// Replaces a segment's changes with the ones prepared by `convert_changes`,
    /// with writing and reading stopped.
    ///
    /// Two renames are not atomic, so the swap is journaled: both new
    /// halves in place → marker `chg-F.swap` with fsync → data → index →
    /// directory fsync → marker removed. If it crashes midway, `recover_swaps`
    /// finishes the swap when the history is opened: by then the new pair is
    /// written, synced and verified, and an old half never exists without the marker.
    pub fn swap_changes(dir: &Path, first: u32) -> Res<()> {
        let ch_path = dir.join(format!("chg-{first:010}.xwlc"));
        let (data, idx) = (
            ch_path.with_extension("xwlc.new"),
            ch_path.with_extension("xwlc.idx.new"),
        );
        if !data.exists() || !idx.exists() {
            return Err(format!(
                "segment {first}: the new changes pair is incomplete, swap not started"
            ));
        }
        let mark = ch_path.with_extension("swap");
        File::create(&mark).and_then(|f| f.sync_all()).map_err(io)?;
        sync_dir(dir)?;
        finish_swap(dir, &ch_path)
    }

    /// Finishes change swaps that were interrupted midway.
    pub fn recover_swaps(dir: &Path) -> Res<usize> {
        let Ok(entries) = fs::read_dir(dir) else {
            return Ok(0);
        };
        let mut done = 0;
        for e in entries {
            let p = e.map_err(io)?.path();
            if p.extension().is_some_and(|x| x == "swap") {
                finish_swap(dir, &p.with_extension("xwlc"))?;
                done += 1;
            }
        }
        Ok(done)
    }

    /// Bytes taken by segments, indexes and dictionaries.
    pub fn bytes_on_disk(&self) -> u64 {
        let len = |p: &Path| fs::metadata(p).map_or(0, |m| m.len());
        let mut total = 0;
        for s in self.segments().iter() {
            let ch = PathBuf::from(
                s.tx_path
                    .to_string_lossy()
                    .replace("txl-", "chg-")
                    .replace(".xwlt", ".xwlc"),
            );
            total += len(&s.tx_path)
                + len(&s.tx_path.with_extension("xwlt.idx"))
                + len(&ch)
                + len(&ch.with_extension("xwlc.idx"));
        }
        if let Ok(d) = fs::read_dir(self.dir.join("dicts")) {
            total += d.flatten().map(|e| len(&e.path())).sum::<u64>();
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{Change, StateChange};

    fn ledger(seq: u32) -> Ledger {
        let mut header = vec![0u8; HEADER_LEN];
        header[..4].copy_from_slice(&seq.to_be_bytes());
        Ledger {
            header,
            transactions: (0..(seq % 5))
                .map(|i| (vec![i as u8; 30 + i as usize], vec![seq as u8; 50]))
                .collect(),
            changes: (0..(seq % 3))
                .map(|i| StateChange {
                    key: [i as u8; 32],
                    change: if i == 1 {
                        Change::Deleted
                    } else {
                        Change::Modified
                    },
                    data: if i == 1 {
                        Vec::new()
                    } else {
                        vec![seq as u8; 40]
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn roundtrip_with_rotating_dictionaries() {
        let dir = tempfile::tempdir().unwrap();
        let samples: Vec<Vec<u8>> = (0..300).map(|s| tx_frame(&ledger(s))).collect();
        let d1 = Dict::store(
            dir.path(),
            zstd::dict::from_samples(&samples, 4096).unwrap(),
        )
        .unwrap();
        // First segment uses dictionary 1, with an incomplete group at the end.
        let mut w = HistoryWriter::create(dir.path(), 100, 8, 3, 19, Some(&d1), false).unwrap();
        for s in 100..130 {
            w.append(s, ledger(s).encode(), None).unwrap();
        }
        w.finish().unwrap();
        // The second uses a new dictionary.
        let d2 = Dict::store(
            dir.path(),
            zstd::dict::from_samples(&samples[..200], 2048).unwrap(),
        )
        .unwrap();
        assert_ne!(d1.id, d2.id);
        assert_eq!(Dict::current(dir.path()).unwrap().unwrap().id, d2.id);
        let mut w = HistoryWriter::create(dir.path(), 130, 8, 3, 19, Some(&d2), false).unwrap();
        for s in 130..140 {
            w.append(s, ledger(s).encode(), None).unwrap();
        }
        w.finish().unwrap();

        let r = HistoryReader::open(dir.path()).unwrap();
        assert_eq!((r.first(), r.last()), (Some(100), Some(139)));
        for s in 100..140 {
            assert_eq!(r.get(s).unwrap().unwrap(), ledger(s).encode(), "ledger {s}");
            let t = r.get_txs(s).unwrap().unwrap();
            assert_eq!(
                (t.header, t.transactions),
                (ledger(s).header, ledger(s).transactions)
            );
        }
        assert!(r.get(140).unwrap().is_none());
    }

    #[test]
    fn substituted_dictionary_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let samples: Vec<Vec<u8>> = (0..300).map(|s| tx_frame(&ledger(s))).collect();
        let d = Dict::store(
            dir.path(),
            zstd::dict::from_samples(&samples, 4096).unwrap(),
        )
        .unwrap();
        let mut w = HistoryWriter::create(dir.path(), 1, 4, 3, 19, Some(&d), false).unwrap();
        for s in 1..5 {
            w.append(s, ledger(s).encode(), None).unwrap();
        }
        w.finish().unwrap();
        let path = dict_path(dir.path(), &d.id);
        let mut bytes = fs::read(&path).unwrap();
        bytes[100] ^= 1;
        fs::write(&path, bytes).unwrap();
        let e = HistoryReader::open(dir.path()).unwrap_err();
        assert!(e.contains("does not match the hash"), "{e}");
    }

    #[test]
    fn half_written_group_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = HistoryWriter::create(dir.path(), 1, 4, 3, 19, None, false).unwrap();
        for s in 1..=4 {
            w.append(s, ledger(s).encode(), None).unwrap();
        }
        w.finish().unwrap();
        // A crash after the transaction frames, before the changes block: append
        // frames and the transaction index for ledgers 5..6 by hand, the way
        // `flush` writes them.
        let tx_path = dir.path().join("txl-0000000001.xwlt");
        let mut tx = OpenOptions::new().append(true).open(&tx_path).unwrap();
        let mut idx = OpenOptions::new()
            .append(true)
            .open(dir.path().join("txl-0000000001.xwlt.idx"))
            .unwrap();
        for s in 5..=6u32 {
            let off = fs::metadata(&tx_path).unwrap().len();
            let z = zstd::bulk::compress(&tx_frame(&ledger(s)), 3).unwrap();
            tx.write_all(&z).unwrap();
            idx.write_all(&s.to_le_bytes()).unwrap();
            idx.write_all(&off.to_le_bytes()).unwrap();
            idx.write_all(&(z.len() as u32).to_le_bytes()).unwrap();
        }
        let r = HistoryReader::open(dir.path()).unwrap();
        assert_eq!(r.last(), Some(4));
        assert!(r.get(5).unwrap().is_none());
        // The next segment starts at 5, and 5 is now read from it.
        let mut w = HistoryWriter::create(dir.path(), 5, 4, 3, 19, None, false).unwrap();
        w.append(5, ledger(5).encode(), None).unwrap();
        w.finish().unwrap();
        r.refresh().unwrap();
        assert_eq!(r.get(5).unwrap().unwrap(), ledger(5).encode());
    }

    /// A crash during a segment's first group: transaction frames and index
    /// exist, changes do not. Restarting from the same ledger replaces the
    /// leftover instead of failing with "File exists".
    #[test]
    fn cold_published_later_is_picked_up_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let r = HistoryReader::open(dir.path()).unwrap();
        assert!(r.cold().first().is_none());
        crate::cold::write(
            dir.path(),
            &crate::cold::tests::chain(500, 4),
            crate::cold::Kinds::Explicit,
        )
        .unwrap();
        // Checks happen no more often than requested: right after opening it is too early.
        r.refresh_cold_every(std::time::Duration::from_secs(3600))
            .unwrap();
        assert!(r.cold().first().is_none());
        r.refresh_cold_every(std::time::Duration::ZERO).unwrap();
        assert_eq!((r.cold().first(), r.cold().last()), (Some(500), Some(503)));
        assert!(r.get_txs(502).unwrap().is_some());
    }

    #[test]
    fn interrupted_first_group_does_not_block_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = HistoryWriter::create(dir.path(), 1, 4, 3, 19, None, false).unwrap();
        for s in 1..=4 {
            w.append(s, ledger(s).encode(), None).unwrap();
        }
        w.finish().unwrap();
        for f in ["chg-0000000001.xwlc", "chg-0000000001.xwlc.idx"] {
            let p = dir.path().join(f);
            let magic = if f.ends_with("idx") {
                CH_IDX_MAGIC
            } else {
                CH_MAGIC
            };
            fs::write(&p, magic).unwrap();
        }
        let r = HistoryReader::open(dir.path()).unwrap();
        assert_eq!(r.last(), None);
        let mut w = HistoryWriter::create(dir.path(), 1, 4, 3, 19, None, false).unwrap();
        for s in 1..=4 {
            w.append(s, ledger(s).encode(), None).unwrap();
        }
        w.finish().unwrap();
        r.refresh().unwrap();
        assert_eq!(r.last(), Some(4));
        assert_eq!(r.get(3).unwrap().unwrap(), ledger(3).encode());
    }

    /// Corruption is a bounded `corrupt_history` error, not a panic and not
    /// some other ledger's frame under the requested sequence.
    #[test]
    fn corrupt_history_is_an_error() {
        let make = || {
            let dir = tempfile::tempdir().unwrap();
            let mut w = HistoryWriter::create(dir.path(), 1, 4, 3, 19, None, false).unwrap();
            for s in 1..=4 {
                w.append(s, ledger(s).encode(), None).unwrap();
            }
            w.finish().unwrap();
            dir
        };
        // A whole zstd frame that decompresses to a single byte, in place of a changes block.
        let dir = make();
        let ch = dir.path().join("chg-0000000001.xwlc");
        let z = zstd::bulk::compress(&[7], 3).unwrap();
        let mut data = CH_MAGIC.to_vec();
        data.extend(&z);
        fs::write(&ch, &data).unwrap();
        let mut idx = CH_IDX_MAGIC.to_vec();
        idx.extend(1u32.to_le_bytes());
        idx.extend(4u32.to_le_bytes());
        idx.extend((CH_MAGIC.len() as u64).to_le_bytes());
        idx.extend((z.len() as u32).to_le_bytes());
        fs::write(ch.with_extension("xwlc.idx"), &idx).unwrap();
        let r = HistoryReader::open(dir.path()).unwrap();
        assert!(r.get(2).unwrap_err().starts_with("corrupt_history"));

        // The frame address of ledger 2 points to the whole frame of ledger 3.
        let dir = make();
        let p = dir.path().join("txl-0000000001.xwlt.idx");
        let mut idx = fs::read(&p).unwrap();
        let third = idx[6 + 2 * TX_ENTRY + 4..6 + 3 * TX_ENTRY].to_vec();
        idx[6 + TX_ENTRY + 4..6 + 2 * TX_ENTRY].copy_from_slice(&third);
        fs::write(&p, &idx).unwrap();
        assert!(
            HistoryReader::open(dir.path())
                .unwrap_err()
                .starts_with("corrupt_history")
        );

        // A transaction frame past the end of the file.
        let dir = make();
        let p = dir.path().join("txl-0000000001.xwlt");
        let len = fs::metadata(&p).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(len - 3)
            .unwrap();
        assert!(
            HistoryReader::open(dir.path())
                .unwrap_err()
                .starts_with("corrupt_history")
        );
    }

    /// A changes swap either does not start or is finished on the
    /// next open.
    #[test]
    fn swap_is_all_or_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = HistoryWriter::create(dir.path(), 1, 4, 3, 19, None, false).unwrap();
        for s in 1..=4 {
            w.append(s, ledger(s).encode(), None).unwrap();
        }
        w.finish().unwrap();
        let ch = dir.path().join("chg-0000000001.xwlc");
        // The new pair has the same bytes; the grouping does not matter, the transitions do.
        fs::copy(&ch, ch.with_extension("xwlc.new")).unwrap();
        // The new pair has no index, so the swap does not start and the old data stays.
        let before = fs::read(&ch).unwrap();
        assert!(HistoryReader::swap_changes(dir.path(), 1).is_err());
        assert_eq!(fs::read(&ch).unwrap(), before);
        assert!(!ch.with_extension("swap").exists());
        // A crash after the first rename: the marker exists, the data is
        // replaced, the index still has `.new`.
        fs::copy(
            ch.with_extension("xwlc.idx"),
            ch.with_extension("xwlc.idx.new"),
        )
        .unwrap();
        fs::write(ch.with_extension("swap"), b"").unwrap();
        fs::rename(ch.with_extension("xwlc.new"), &ch).unwrap();
        let r = HistoryReader::open(dir.path()).unwrap();
        assert!(!ch.with_extension("swap").exists());
        assert!(!ch.with_extension("xwlc.idx.new").exists());
        for s in 1..=4 {
            assert_eq!(r.get(s).unwrap().unwrap(), ledger(s).encode());
        }
    }

    /// An object with Flags, Sequence and a hash field, so the diff is shorter.
    fn object(seq: u32, tag: u8) -> Vec<u8> {
        let mut v = vec![0x11, 0, 0x61, 0x22, 0, 0, 0, 0, 0x24];
        v.extend(seq.to_be_bytes());
        v.push(0x51);
        v.extend([tag; 32]);
        v
    }

    /// Ledgers where object [1;32] changes every time and [2;32] is created.
    fn evolving(seq: u32) -> Ledger {
        let mut header = vec![0u8; HEADER_LEN];
        header[..4].copy_from_slice(&seq.to_be_bytes());
        Ledger {
            header,
            transactions: Vec::new(),
            changes: vec![
                StateChange {
                    key: [1; 32],
                    change: Change::Modified,
                    data: object(seq, 1),
                },
                StateChange {
                    key: [seq as u8; 32],
                    change: Change::Created,
                    data: object(seq, 2),
                },
            ],
        }
    }

    /// Previous versions: object [1;32] as of ledger `at`, as in `evolving(at)`.
    fn prev_versions() -> Arc<PrevAt> {
        Arc::new(|k: &[u8; 32], at: u32| -> Res<Option<Vec<u8>>> {
            Ok((*k == [1; 32] && at >= 9).then(|| object(at, 1)))
        })
    }

    #[test]
    fn delta_changes_roundtrip_and_conversion() {
        let dir = tempfile::tempdir().unwrap();
        let prev = prev_versions();
        // A format 2 segment (10..19), then a format 3 one (20..29).
        let mut w = HistoryWriter::create(dir.path(), 10, 4, 3, 19, None, false).unwrap();
        for s in 10..20 {
            w.append(s, evolving(s).encode(), None).unwrap();
        }
        w.finish().unwrap();
        let mut w = HistoryWriter::create(dir.path(), 20, 4, 3, 19, None, true).unwrap();
        assert!(
            w.append(20, evolving(20).encode(), None).is_err(),
            "format 3 needs the previous version"
        );
        for s in 20..30 {
            w.append(s, evolving(s).encode(), Some(&*prev)).unwrap();
        }
        w.finish().unwrap();

        let r = HistoryReader::open(dir.path()).unwrap();
        assert!(
            r.get(25).is_err(),
            "format 3 cannot be read without previous versions"
        );
        let r = r.with_prev(prev.clone());
        for s in 10..30 {
            assert_eq!(
                r.get(s).unwrap().unwrap(),
                evolving(s).encode(),
                "ledger {s}"
            );
        }
        assert_eq!(r.segments_info(), vec![(10, 19, false), (20, 29, true)]);

        // Rebuild the format 2 segment into format 3, with verification and swap.
        r.convert_changes(10, 4, 19).unwrap();
        HistoryReader::swap_changes(dir.path(), 10).unwrap();
        let r = HistoryReader::open(dir.path()).unwrap().with_prev(prev);
        assert_eq!(r.segments_info(), vec![(10, 19, true), (20, 29, true)]);
        for s in 10..30 {
            assert_eq!(
                r.get(s).unwrap().unwrap(),
                evolving(s).encode(),
                "after rebuild, ledger {s}"
            );
        }
    }
}
