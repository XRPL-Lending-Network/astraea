//! Cold history: ASTJ5 / JC05 segments, canonical profile (codec in the
//! `astj5` crate). For deep, closed history; the hot format (module
//! `history`) and the API stay the same.
//!
//! A segment whose first ledger is F is four files in one directory:
//! - `cold-F.astj`: an ASTJ5 archive of independent blocks of at most 1024 ledgers
//!   or 4 MiB of exact bytes (`BLOCK_RAW`); each block has a SHA-512Half of its exact bytes;
//! - `cold-F.asix`: the codec's four ASIX2 indexes: transaction and ledger by
//!   hash, account history and object history;
//! - `cold-F.kinds`: the kind of every state change (`XWCK\0\1`);
//! - `cold-F.json`: the manifest with range, profile, change kind mode,
//!   and size and SHA-512Half of every file. Written last, via a temporary
//!   file and rename: without a manifest there is no segment.
//!
//! Change kinds. The codec row (`Row`) does not carry them, and they cannot be
//! guessed from the metadata. A source with explicit kinds (the node's gRPC) uses
//! mode `explicit`: kinds are stored as a separate stream and count toward the size.
//! The XRPLA publication does not distinguish them, so it uses mode `not_recorded`:
//! such a segment serves transactions, and a request for a ledger with changes
//! gets an error rather than a guess.
//!
//! Reading goes through the codec's pool of prepared blocks (`astj5::pool`): before
//! a block enters the cache, its SHA-512Half, the transaction roots and the
//! header chain are checked. A segment's cache holds `BLOCK_BUDGET` bytes of blocks,
//! different blocks are prepared in parallel (at most `PREPARES` at once), and a
//! block wanted by concurrent requests is prepared only once. At most `COLD_OPEN`
//! segments are open; the least recently read ones are closed. A request for
//! many ledgers at once (`Cold::ledgers`) reads them block by block on up to
//! `COLD_READERS` threads.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use astraea_journal_codec::{Options, Row, indexed, pack_bounded, pool::Pool, unpack};
use serde_json::{Value, json};
use witness_core::ledger::LedgerHeader;
use witness_core::sha512_half;

use crate::ledger::{Change, Ledger, StateChange};

type Res<T> = Result<T, String>;

const KINDS_MAGIC: &[u8; 6] = b"XWCK\x00\x01";
/// Default archive block: at most this many ledgers and exact bytes.
/// The research's canonical profile uses 16 MiB. 4 MiB costs +18.7% in size
/// at the 104 million epoch and +26% on recent history, but a cold read takes
/// 24 ms instead of 118.
/// A ledger larger than the limit gets a block sized to fit it (`write_with`).
pub const BLOCK_LEDGERS: usize = 1024;
pub const BLOCK_RAW: usize = 4 << 20;

/// Archive block limit: ledgers and exact bytes.
#[derive(Debug, Clone, Copy)]
pub struct BlockLimit {
    pub ledgers: usize,
    pub raw: usize,
}

impl Default for BlockLimit {
    fn default() -> Self {
        BlockLimit {
            ledgers: BLOCK_LEDGERS,
            raw: BLOCK_RAW,
        }
    }
}
/// Maximum number of cold segments open at once. One account_tx page over
/// full history touches many segments; with too few open they are closed
/// and reopened on every request.
pub const COLD_OPEN: usize = 16;
/// Byte budget for prepared blocks in an open segment's cache (codec
/// estimate), and the number of concurrent prepares per segment. Together
/// with `COLD_OPEN` this caps the cold cache at about 1 GiB. A block takes
/// about 30 ms to prepare, and one account_tx page can need dozens of blocks
/// from a single segment, so a segment prepares as many at once as one
/// request reads in parallel.
pub const BLOCK_BUDGET: usize = 64 << 20;
pub const PREPARES: usize = COLD_READERS;
/// Threads one `Cold::ledgers` call reads with.
pub const COLD_READERS: usize = 8;
/// Maximum change kinds in a segment: checked before allocating memory.
const MAX_CHANGES: u64 = 1 << 32;

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn corrupt(what: impl std::fmt::Display) -> String {
    format!("corrupt_history: cold segment: {what}")
}

/// The canonical profile, as in the research's `jointbench encode … canonical`,
/// not `Options::default()`.
pub fn canonical() -> Options {
    Options {
        joint: true,
        adaptive: true,
        chronological: true,
        hash_order: true,
        cached_slots: true,
        recent: false,
        split_shapes: true,
        context_delta: true,
        ..Options::default()
    }
}

/// Where change kinds come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kinds {
    Explicit,
    NotRecorded,
}

impl Kinds {
    fn name(self) -> &'static str {
        match self {
            Kinds::Explicit => "explicit",
            Kinds::NotRecorded => "not_recorded",
        }
    }
}

/// Codec row from a ledger: changes as key and data (empty for a deleted object).
pub fn row_of(l: &Ledger) -> Res<Row> {
    Ok(Row {
        seq: l.header()?.sequence,
        header: l.header.clone(),
        txs: l.transactions.clone(),
        patches: l.changes.iter().map(|c| (c.key, c.data.clone())).collect(),
    })
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_varint(b: &[u8], at: &mut usize) -> Res<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*at).ok_or_else(|| corrupt("varint truncated"))?;
        *at += 1;
        v |= u64::from(x & 0x7F) << shift;
        if x & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(corrupt("varint too long"))
}

/// Kinds stream: `XWCK\0\1`, mode (1 is explicit, 0 means the source does not
/// distinguish), u32 ledger count, then zstd of (each ledger's change count as a
/// varint, then one kind byte per change, explicit mode only).
fn kinds_bytes(ledgers: &[Ledger], mode: Kinds) -> Res<Vec<u8>> {
    let mut body = Vec::new();
    for l in ledgers {
        put_varint(&mut body, l.changes.len() as u64);
    }
    for l in ledgers {
        for c in &l.changes {
            if (c.change == Change::Deleted) != c.data.is_empty() {
                return Err(format!(
                    "ledger {}: change kind {:?} does not match the data of object {}",
                    l.header()?.sequence,
                    c.change,
                    hex::encode_upper(c.key)
                ));
            }
            if mode == Kinds::Explicit {
                body.push(c.change as u8);
            }
        }
    }
    let mut out = KINDS_MAGIC.to_vec();
    out.push(u8::from(mode == Kinds::Explicit));
    out.extend((ledgers.len() as u32).to_le_bytes());
    out.extend(zstd::bulk::compress(&body, 19).map_err(io)?);
    Ok(out)
}

/// Parsed kinds stream: where each ledger starts in the stream, and the kinds.
#[derive(Debug)]
struct KindsIndex {
    mode: Kinds,
    starts: Vec<u64>,
    kinds: Vec<u8>,
}

fn parse_kinds(b: &[u8], ledgers: usize) -> Res<KindsIndex> {
    if b.get(..6) != Some(KINDS_MAGIC.as_slice()) || b.len() < 11 {
        return Err(corrupt("change kinds stream: not XWCK"));
    }
    let mode = match b[6] {
        1 => Kinds::Explicit,
        0 => Kinds::NotRecorded,
        _ => return Err(corrupt("kinds stream: mode")),
    };
    let n = u32::from_le_bytes([b[7], b[8], b[9], b[10]]) as usize;
    if n != ledgers {
        return Err(corrupt("kinds stream: ledger count"));
    }
    // Decompression limit, set before allocating: a varint per ledger and a byte per change.
    let cap = ledgers
        .checked_mul(10)
        .and_then(|x| x.checked_add(MAX_CHANGES as usize))
        .ok_or_else(|| corrupt("kinds stream: size"))?;
    let body = zstd::bulk::decompress(&b[11..], cap.min(1 << 31)).map_err(corrupt)?;
    let mut at = 0;
    let mut starts = Vec::with_capacity(ledgers + 1);
    let mut total = 0u64;
    starts.push(0);
    for _ in 0..ledgers {
        total = total
            .checked_add(get_varint(&body, &mut at)?)
            .filter(|t| *t <= MAX_CHANGES)
            .ok_or_else(|| corrupt("kinds stream: too many changes"))?;
        starts.push(total);
    }
    let kinds = body[at..].to_vec();
    let want = if mode == Kinds::Explicit {
        total as usize
    } else {
        0
    };
    if kinds.len() != want || kinds.iter().any(|k| Change::from_u8(*k).is_none()) {
        return Err(corrupt("kinds stream: length or value"));
    }
    Ok(KindsIndex {
        mode,
        starts,
        kinds,
    })
}

pub(crate) fn sync_write(path: &Path, bytes: &[u8]) -> Res<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    let mut f = File::create(&tmp).map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)?;
    fs::rename(&tmp, path).map_err(io)
}

fn names(dir: &Path, first: u32) -> [PathBuf; 4] {
    ["astj", "asix", "kinds", "json"].map(|e| dir.join(format!("cold-{first:010}.{e}")))
}

/// Exact bytes of a row in a block (as the codec counts them when cutting blocks).
fn row_raw(r: &Row) -> usize {
    20 + r.header.len()
        + r.txs
            .iter()
            .map(|(t, m)| 8 + t.len() + m.len())
            .sum::<usize>()
        + r.patches.iter().map(|(_, v)| 36 + v.len()).sum::<usize>()
}

/// Writes a segment from consecutive ledgers and publishes it with a manifest.
/// Before writing, the archive is unpacked again and compared with the rows,
/// the indexes are checked by re-encoding the decoded form, and the kinds by
/// parsing. Returns the manifest.
pub fn write(dir: &Path, ledgers: &[Ledger], mode: Kinds) -> Res<Value> {
    write_with(dir, ledgers, mode, BlockLimit::default())
}

/// `write` with a different block limit.
pub fn write_with(dir: &Path, ledgers: &[Ledger], mode: Kinds, limit: BlockLimit) -> Res<Value> {
    let first = ledgers.first().ok_or("empty range")?.header()?.sequence;
    let rows = ledgers.iter().map(row_of).collect::<Res<Vec<_>>>()?;
    for (k, r) in rows.iter().enumerate() {
        if r.seq != first + k as u32 {
            return Err(format!(
                "ledgers out of sequence: at position {k} found {}",
                r.seq
            ));
        }
    }
    let last = first + rows.len() as u32 - 1;
    // A ledger larger than the limit (some exceed 4 MiB) is not split: for such a
    // segment the limit is raised to its size; other segments are unaffected.
    let raw = rows.iter().map(row_raw).max().unwrap_or(0) + 4;
    let limit = BlockLimit {
        raw: limit.raw.max(raw),
        ..limit
    };
    let (archive, _) = pack_bounded(&rows, limit.ledgers, limit.raw, canonical())?;
    if unpack(&archive)? != rows {
        return Err("ASTJ5 archive did not restore the ledgers exactly".into());
    }
    let index = indexed::Indexes::build(&rows)?.encode();
    if indexed::Indexes::decode(&index)?.encode() != index {
        return Err("ASIX2 indexes did not re-encode exactly".into());
    }
    let kinds = kinds_bytes(ledgers, mode)?;
    let k = parse_kinds(&kinds, rows.len())?;
    if mode == Kinds::Explicit {
        let all: Vec<u8> = ledgers
            .iter()
            .flat_map(|l| l.changes.iter().map(|c| c.change as u8))
            .collect();
        if k.kinds != all {
            return Err("kinds stream did not round-trip".into());
        }
    }
    let [pa, pi, pk, pm] = names(dir, first);
    let file =
        |b: &[u8]| json!({"bytes": b.len(), "sha512half": hex::encode_upper(sha512_half(b))});
    let manifest = json!({
        "format": "astraea-cold/1",
        "payload": "ASTJ5",
        "profile": "canonical",
        "codec": "astraea-journal-codec 0.1.0 (astraea-journal-sequential-2026-10-27)",
        "first": first,
        "last": last,
        "ledgers": rows.len(),
        "transactions": rows.iter().map(|r| r.txs.len()).sum::<usize>(),
        "changes": rows.iter().map(|r| r.patches.len()).sum::<usize>(),
        "blocks": u32::from_le_bytes(archive[8..12].try_into().map_err(|_| "archive header")?),
        "max_block_ledgers": limit.ledgers,
        "max_block_raw_bytes": limit.raw,
        "change_kinds": mode.name(),
        "files": {
            "astj": file(&archive),
            "asix": file(&index),
            "kinds": file(&kinds),
        },
    });
    fs::create_dir_all(dir).map_err(io)?;
    sync_write(&pa, &archive)?;
    sync_write(&pi, &index)?;
    sync_write(&pk, &kinds)?;
    let m = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    sync_write(&pm, &m)?;
    File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
    Ok(manifest)
}

/// An open segment: the block pool and change kinds.
struct Open {
    pool: Pool,
    kinds: KindsIndex,
}

impl std::fmt::Debug for Open {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Open").finish_non_exhaustive()
    }
}

/// A published cold segment. Files are opened on the first read.
#[derive(Debug)]
pub struct ColdSegment {
    pub first: u32,
    pub last: u32,
    pub kinds: Kinds,
    pub manifest: Value,
    paths: [PathBuf; 4],
    open: Mutex<Option<Arc<Open>>>,
    budget: std::sync::atomic::AtomicUsize,
}

impl ColdSegment {
    /// Segments in a directory from their manifests, by ascending first ledger;
    /// overlapping segments are an error.
    pub fn scan(dir: &Path) -> Res<Vec<Arc<ColdSegment>>> {
        ColdSegment::scan_with(dir, &[])
    }

    /// Like `scan`, but segments from `prev` (matched by first ledger) are taken
    /// as is, without reading the manifest.
    fn scan_with(dir: &Path, prev: &[Arc<ColdSegment>]) -> Res<Vec<Arc<ColdSegment>>> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return Ok(out);
        };
        for e in entries {
            let p = e.map_err(io)?.path();
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !(name.starts_with("cold-") && name.ends_with(".json")) {
                continue;
            }
            let known = name["cold-".len()..name.len() - ".json".len()]
                .parse::<u32>()
                .ok()
                .and_then(|f| prev.iter().find(|x| x.first == f));
            if let Some(x) = known {
                out.push(x.clone());
                continue;
            }
            let m: Value = serde_json::from_slice(&fs::read(&p).map_err(io)?).map_err(corrupt)?;
            if m["format"] != "astraea-cold/1" || m["payload"] != "ASTJ5" {
                return Err(corrupt(format!("{name}: unknown format")));
            }
            let num = |k: &str| m[k].as_u64().and_then(|v| u32::try_from(v).ok());
            let (Some(first), Some(last)) = (num("first"), num("last")) else {
                return Err(corrupt(format!("{name}: range")));
            };
            let kinds = match m["change_kinds"].as_str() {
                Some("explicit") => Kinds::Explicit,
                Some("not_recorded") => Kinds::NotRecorded,
                _ => return Err(corrupt(format!("{name}: kinds mode"))),
            };
            let paths = names(dir, first);
            for (i, k) in ["astj", "asix", "kinds"].into_iter().enumerate() {
                let len = fs::metadata(&paths[i]).map_err(io)?.len();
                if Some(len) != m["files"][k]["bytes"].as_u64() {
                    return Err(corrupt(format!("{name}: wrong size of file {k}")));
                }
            }
            out.push(Arc::new(ColdSegment {
                first,
                last,
                kinds,
                manifest: m,
                paths,
                open: Mutex::new(None),
                budget: std::sync::atomic::AtomicUsize::new(BLOCK_BUDGET),
            }));
        }
        out.sort_by_key(|s| s.first);
        if out.windows(2).any(|w| w[1].first <= w[0].last) {
            return Err(corrupt("segments overlap"));
        }
        Ok(out)
    }

    /// SHA-512Half of all files, checked against the manifest. Expensive on large
    /// segments, so it runs during verification, not on every open.
    pub fn verify_files(&self) -> Res<()> {
        for (i, k) in ["astj", "asix", "kinds"].into_iter().enumerate() {
            let b = fs::read(&self.paths[i]).map_err(io)?;
            if Some(hex::encode_upper(sha512_half(&b)).as_str())
                != self.manifest["files"][k]["sha512half"].as_str()
            {
                return Err(corrupt(format!(
                    "cold-{}.{k}: hash does not match the manifest",
                    self.first
                )));
            }
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Arc<Open>>> {
        self.open.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_open(&self) -> bool {
        self.lock().is_some()
    }

    /// Closes the files and frees the block cache; reads in progress finish.
    pub fn close(&self) {
        *self.lock() = None;
    }

    /// Bytes of prepared blocks in the cache (codec estimate).
    pub fn cached_bytes(&self) -> usize {
        self.lock().as_ref().map_or(0, |o| o.pool.cached_bytes())
    }

    fn opened(&self) -> Res<Arc<Open>> {
        let mut g = self.lock();
        if let Some(o) = g.as_ref() {
            return Ok(o.clone());
        }
        let budget = self.budget.load(std::sync::atomic::Ordering::Relaxed);
        let pool = Pool::open(&self.paths[0], budget, PREPARES).map_err(corrupt)?;
        if pool.first() != Some(self.first) {
            return Err(corrupt(
                "archive does not start at the manifest's first ledger",
            ));
        }
        let ledgers = (self.last - self.first + 1) as usize;
        let kinds = parse_kinds(&fs::read(&self.paths[2]).map_err(io)?, ledgers)?;
        if kinds.mode != self.kinds {
            return Err(corrupt("kinds mode does not match the manifest"));
        }
        let o = Arc::new(Open { pool, kinds });
        *g = Some(o.clone());
        Ok(o)
    }

    /// Ledger `seq`: header and transactions, plus changes if
    /// `with_changes` (requires explicit kinds).
    pub fn ledger(&self, seq: u32, with_changes: bool) -> Res<Ledger> {
        self.check(seq, with_changes)?;
        let o = self.opened()?;
        self.read(&o, seq, with_changes)
    }

    fn check(&self, seq: u32, with_changes: bool) -> Res<()> {
        if seq < self.first || seq > self.last {
            return Err(format!(
                "ledger {seq} is outside cold segment {}",
                self.first
            ));
        }
        if with_changes && self.kinds == Kinds::NotRecorded {
            return Err(format!(
                "ledger {seq}: the cold segment's source does not distinguish created from modified objects, so changes are not served"
            ));
        }
        Ok(())
    }

    fn header(&self, o: &Open, seq: u32) -> Res<Vec<u8>> {
        let raw = o.pool.header(seq).map_err(corrupt)?;
        let got = LedgerHeader::parse(&raw).map_err(corrupt)?.sequence;
        if got != seq {
            return Err(corrupt(format!("at position {seq} found ledger {got}")));
        }
        Ok(raw)
    }

    fn read(&self, o: &Open, seq: u32, with_changes: bool) -> Res<Ledger> {
        // Patches are decoded only when changes are asked for: they outweigh
        // the transactions and API reads don't need them.
        let row = if with_changes {
            o.pool.ledger(seq)
        } else {
            o.pool.ledger_txs(seq)
        }
        .map_err(corrupt)?;
        if row.seq != seq {
            return Err(corrupt(format!(
                "at position {seq} found ledger {}",
                row.seq
            )));
        }
        let changes = if with_changes {
            let i = (seq - self.first) as usize;
            let (a, b) = (o.kinds.starts[i] as usize, o.kinds.starts[i + 1] as usize);
            if b - a != row.patches.len() {
                return Err(corrupt(format!(
                    "ledger {seq}: kind count does not match the changes"
                )));
            }
            row.patches
                .into_iter()
                .zip(&o.kinds.kinds[a..b])
                .map(|((key, data), k)| {
                    let change = Change::from_u8(*k).ok_or_else(|| corrupt("change kind"))?;
                    if (change == Change::Deleted) != data.is_empty() {
                        return Err(corrupt(format!(
                            "ledger {seq}: kind does not match the data"
                        )));
                    }
                    Ok(StateChange { key, change, data })
                })
                .collect::<Res<Vec<_>>>()?
        } else {
            Vec::new()
        };
        Ok(Ledger {
            header: row.header,
            transactions: row.txs,
            changes,
        })
    }
}

/// Cold segments of a directory, with a budget for open ones.
#[derive(Debug)]
pub struct Cold {
    segments: Vec<Arc<ColdSegment>>,
    /// Open segments, most recent last. Shared by all generations from
    /// `open_with`: readers still holding an older generation spend
    /// the same budget and close the same segments.
    recent: Arc<Mutex<VecDeque<Arc<ColdSegment>>>>,
    /// How many segments may be open at once (`COLD_OPEN`).
    open_limit: usize,
}

impl Default for Cold {
    fn default() -> Self {
        Cold {
            segments: Vec::new(),
            recent: Arc::default(),
            open_limit: COLD_OPEN,
        }
    }
}

impl Cold {
    pub fn open(dir: &Path) -> Res<Cold> {
        Cold::open_with(dir, &Cold::default())
    }

    /// Like `open`, but segments from `prev` carry over as is, with their open
    /// files, block cache and place in the open budget.
    pub fn open_with(dir: &Path, prev: &Cold) -> Res<Cold> {
        Ok(Cold {
            segments: ColdSegment::scan_with(dir, &prev.segments)?,
            recent: prev.recent.clone(),
            open_limit: prev.open_limit,
        })
    }

    /// Block cache budget per open segment, in bytes; takes effect from the
    /// next time a segment is opened.
    pub fn with_budget(self, bytes: usize) -> Cold {
        for s in &self.segments {
            s.budget.store(bytes, std::sync::atomic::Ordering::Relaxed);
            s.close();
        }
        self
    }

    pub fn segments(&self) -> &[Arc<ColdSegment>] {
        &self.segments
    }

    pub fn first(&self) -> Option<u32> {
        self.segments.first().map(|s| s.first)
    }

    pub fn last(&self) -> Option<u32> {
        self.segments.last().map(|s| s.last)
    }

    pub fn contains(&self, seq: u32) -> bool {
        self.find(seq).is_some()
    }

    fn find(&self, seq: u32) -> Option<usize> {
        let i = self
            .segments
            .partition_point(|s| s.first <= seq)
            .checked_sub(1)?;
        (seq <= self.segments[i].last).then_some(i)
    }

    /// Same segments with a different open limit (tests use a small one).
    pub fn with_open_limit(mut self, n: usize) -> Cold {
        self.open_limit = n.max(1);
        self
    }

    /// A ledger from the cold history; `None` if it is not here. Without
    /// changes only the header and transactions are decoded.
    pub fn ledger(&self, seq: u32, with_changes: bool) -> Res<Option<Ledger>> {
        let Some(i) = self.find(seq) else {
            return Ok(None);
        };
        self.segments[i].check(seq, with_changes)?;
        let (seg, o) = self.open_segment(i)?;
        seg.read(&o, seq, with_changes).map(Some)
    }

    /// Header of a cold ledger alone; `None` if it is not here.
    pub fn header(&self, seq: u32) -> Res<Option<Vec<u8>>> {
        let Some(i) = self.find(seq) else {
            return Ok(None);
        };
        self.segments[i].check(seq, false)?;
        let (seg, o) = self.open_segment(i)?;
        seg.header(&o, seq).map(Some)
    }

    /// Several ledgers without changes; those not in cold history are left
    /// out. Ledgers of one block go to one reader, so the block is prepared
    /// once, and different blocks are read on up to `COLD_READERS` threads.
    pub fn ledgers(&self, seqs: &[u32]) -> Res<HashMap<u32, Ledger>> {
        type Group = (Arc<ColdSegment>, Arc<Open>, Vec<u32>);
        let mut open: HashMap<usize, Arc<Open>> = HashMap::new();
        let mut blocks: BTreeMap<(usize, usize), Vec<u32>> = BTreeMap::new();
        for &seq in seqs {
            let Some(i) = self.find(seq) else { continue };
            self.segments[i].check(seq, false)?;
            let o = match open.get(&i) {
                Some(o) => o,
                None => {
                    let (_, o) = self.open_segment(i)?;
                    open.entry(i).or_insert(o)
                }
            };
            let b = o.pool.block_id(seq).map_err(corrupt)?;
            blocks.entry((i, b)).or_default().push(seq);
        }
        let groups: Vec<Group> = blocks
            .into_iter()
            .map(|((i, _), seqs)| (self.segments[i].clone(), open[&i].clone(), seqs))
            .collect();
        let read = |(seg, o, seqs): &Group| -> Res<Vec<(u32, Ledger)>> {
            seqs.iter()
                .map(|&seq| Ok((seq, seg.read(o, seq, false)?)))
                .collect()
        };
        let mut out = HashMap::with_capacity(seqs.len());
        if groups.len() <= 1 {
            for g in &groups {
                out.extend(read(g)?);
            }
            return Ok(out);
        }
        let next = std::sync::atomic::AtomicUsize::new(0);
        let parts = std::thread::scope(|sc| {
            let workers: Vec<_> = (0..COLD_READERS.min(groups.len()))
                .map(|_| {
                    sc.spawn(|| -> Res<Vec<(u32, Ledger)>> {
                        let mut got = Vec::new();
                        loop {
                            let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(g) = groups.get(k) else {
                                return Ok(got);
                            };
                            got.extend(read(g)?);
                        }
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| {
                    w.join()
                        .unwrap_or_else(|_| Err("cold reader panicked".into()))
                })
                .collect::<Vec<_>>()
        });
        for p in parts {
            out.extend(p?);
        }
        Ok(out)
    }

    fn open_segment(&self, i: usize) -> Res<(&Arc<ColdSegment>, Arc<Open>)> {
        let seg = &self.segments[i];
        // Open budget: a slot is freed and the segment is opened under the
        // shared lock, before reading, so there are never more than `COLD_OPEN` open.
        // The read itself happens outside the lock; reads already running on a closed
        // segment finish with their own instance.
        let o = {
            let mut r = self.recent.lock().unwrap_or_else(|p| p.into_inner());
            r.retain(|s| !Arc::ptr_eq(s, seg));
            while r.len() >= self.open_limit {
                match r.pop_front() {
                    Some(s) => s.close(),
                    None => break,
                }
            }
            let o = seg.opened()?;
            r.push_back(seg.clone());
            o
        };
        Ok((seg, o))
    }

    /// How many segments are open right now. Counted under the same lock that
    /// guards closing and opening segments; otherwise the count could see
    /// a closing segment and a freshly opened one at the same time.
    pub fn open_count(&self) -> usize {
        let _r = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        self.segments.iter().filter(|s| s.is_open()).count()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A chain of ledgers without transactions, with changes of all three kinds.
    pub(crate) fn chain(first: u32, n: u32) -> Vec<Ledger> {
        let mut out: Vec<Ledger> = Vec::new();
        let mut parent = [0u8; 32];
        for k in 0..n {
            // Header: sequence (BE), coins, parent; the transaction root is the
            // empty tree.
            let mut header = vec![0u8; 118];
            header[..4].copy_from_slice(&(first + k).to_be_bytes());
            header[12..44].copy_from_slice(&parent);
            parent = LedgerHeader::parse(&header).unwrap().hash();
            let changes = vec![
                StateChange {
                    key: [k as u8; 32],
                    change: Change::Created,
                    data: vec![0x11, 0x00, 0x61, k as u8],
                },
                StateChange {
                    key: [0xAA; 32],
                    change: Change::Modified,
                    data: vec![0x11, 0x00, 0x61, 7],
                },
                StateChange {
                    key: [0xBB; 32],
                    change: Change::Deleted,
                    data: vec![],
                },
            ];
            out.push(Ledger {
                header,
                transactions: vec![],
                changes,
            });
        }
        out
    }

    #[test]
    fn segment_round_trips_with_explicit_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let ls = chain(100, 40);
        let m = write(dir.path(), &ls, Kinds::Explicit).unwrap();
        assert_eq!(m["last"], 139);
        let cold = Cold::open(dir.path()).unwrap();
        cold.segments()[0].verify_files().unwrap();
        for l in &ls {
            let seq = l.header().unwrap().sequence;
            assert_eq!(cold.ledger(seq, true).unwrap().unwrap(), *l);
            let t = cold.ledger(seq, false).unwrap().unwrap();
            assert!(t.changes.is_empty() && t.header == l.header);
        }
        assert!(cold.ledger(99, false).unwrap().is_none());
        assert!(cold.ledger(140, false).unwrap().is_none());
    }

    #[test]
    fn ledger_larger_than_block_limit_gets_its_own_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut ls = chain(200, 6);
        ls[3].changes[0].data = vec![0x11; 3000];
        let small = BlockLimit {
            ledgers: 1024,
            raw: 1024,
        };
        let m = write_with(dir.path(), &ls, Kinds::Explicit, small).unwrap();
        assert!(m["max_block_raw_bytes"].as_u64().unwrap() > 3000);
        let cold = Cold::open(dir.path()).unwrap();
        for l in &ls {
            let seq = l.header().unwrap().sequence;
            assert_eq!(cold.ledger(seq, true).unwrap().unwrap(), *l);
        }
    }

    #[test]
    fn ledgers_read_in_parallel_match_single_reads() {
        let dir = tempfile::tempdir().unwrap();
        let small = BlockLimit {
            ledgers: 3,
            raw: 1 << 20,
        };
        for f in [100u32, 120, 140] {
            write_with(dir.path(), &chain(f, 12), Kinds::Explicit, small).unwrap();
        }
        let cold = Cold::open(dir.path()).unwrap().with_open_limit(2);
        let seqs: Vec<u32> = vec![150, 149, 141, 130, 125, 111, 104, 103, 99, 115];
        let got = cold.ledgers(&seqs).unwrap();
        assert_eq!(got.len(), 8);
        assert!(!got.contains_key(&99) && !got.contains_key(&115));
        for (seq, l) in &got {
            assert_eq!(*l, cold.ledger(*seq, false).unwrap().unwrap());
            assert!(l.changes.is_empty());
        }
        assert!(cold.open_count() <= 2);
        assert!(cold.ledgers(&[]).unwrap().is_empty());
    }

    #[test]
    fn reopen_keeps_open_segments_and_their_budget() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &chain(20, 5), Kinds::Explicit).unwrap();
        let cold = Cold::open(dir.path()).unwrap();
        cold.ledger(21, true).unwrap().unwrap();
        write(dir.path(), &chain(10, 5), Kinds::Explicit).unwrap();
        let next = Cold::open_with(dir.path(), &cold).unwrap();
        assert_eq!((next.first(), next.last()), (Some(10), Some(24)));
        assert!(Arc::ptr_eq(&next.segments()[1], &cold.segments()[0]));
        assert_eq!(next.open_count(), 1);
        next.ledger(11, true).unwrap().unwrap();
        assert_eq!(next.open_count(), 2);
    }

    #[test]
    fn not_recorded_kinds_refuse_changes_and_bad_kinds_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ls = chain(5, 3);
        write(dir.path(), &ls, Kinds::NotRecorded).unwrap();
        let cold = Cold::open(dir.path()).unwrap();
        assert!(cold.ledger(6, false).unwrap().is_some());
        assert!(cold.ledger(6, true).is_err());
        let mut bad = chain(50, 1);
        bad[0].changes[0].change = Change::Deleted;
        assert!(write(dir.path(), &bad, Kinds::Explicit).is_err());
    }

    #[test]
    fn budget_closes_old_segments_and_tampering_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        for f in [10u32, 20, 30] {
            write(dir.path(), &chain(f, 5), Kinds::Explicit).unwrap();
        }
        let cold = Cold::open(dir.path()).unwrap().with_open_limit(2);
        for s in [10u32, 20, 30, 12] {
            cold.ledger(s, true).unwrap().unwrap();
        }
        assert_eq!(cold.open_count(), 2);
        // Concurrently: the number of open segments never exceeds the budget.
        let cold = Arc::new(cold);
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hs: Vec<_> = (0..6u32)
            .map(|t| {
                let (cold, seen) = (cold.clone(), seen.clone());
                std::thread::spawn(move || {
                    for k in 0..60u32 {
                        let seq = [10u32, 20, 30][((k + t) % 3) as usize] + k % 5;
                        cold.ledger(seq, true).unwrap().unwrap();
                        seen.fetch_max(cold.open_count(), std::sync::atomic::Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert!(seen.load(std::sync::atomic::Ordering::Relaxed) <= 2);
        let p = dir.path().join("cold-0000000020.kinds");
        let mut b = fs::read(&p).unwrap();
        let n = b.len();
        b[n - 1] ^= 1;
        fs::write(&p, b).unwrap();
        let cold = Cold::open(dir.path()).unwrap();
        assert!(cold.segments()[1].verify_files().is_err());
        assert!(cold.ledger(21, true).is_err());
    }
}
