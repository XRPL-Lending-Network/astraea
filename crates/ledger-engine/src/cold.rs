//! Cold history: ASTJ5 / JC05 segments, canonical profile (codec in the
//! `astj5` crate). For deep, closed history; the hot format (module
//! `history`) and the API stay the same.
//!
//! A segment whose first ledger is F is four files in one directory:
//! - `cold-F.astj`: an ASTJ5 archive of independent blocks of at most 1024 ledgers
//!   or 4 MiB of exact bytes (`BLOCK_RAW`); each block has a SHA-512Half of its exact bytes;
//! - `cold-F.asix`: only in segments written before 0.3, the codec's four
//!   ASIX2 indexes (transaction and ledger by hash, account history, object
//!   history). Nothing reads them: lookups go through the partition indexes
//!   (`coldindex`). `ColdSegment::drop_index` removes them;
//! - `cold-F.kinds`: the kind of every state change (`XWCK\0\1`);
//! - `cold-F.seal`: optional, digests of every block's stored bytes taken
//!   after the block passed the full check (`XWCS\0\1`, one per block, or
//!   `XWCS\0\2`, a list per block: a JC06 block has its head and each part),
//!   see below;
//! - `cold-F.json`: the manifest with range, profile, change kind mode,
//!   and size and SHA-512Half of every file. Written last, via a temporary
//!   file and rename: without a manifest there is no segment.
//!
//! State patches are stored only where the metadata doesn't give them
//! (`coldpatch`). A segment written that way has format `astraea-cold/2`, so a
//! server that doesn't know the format refuses it; `astraea-cold/1` segments
//! hold every patch and stay readable. Each ledger says which it is, so a segment
//! rewritten while it is being read is read correctly from either archive.
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
//! header chain are checked. The check costs as much as preparing the block,
//! so it runs once, when the segment is written (or by `write_seal` for older
//! segments), and the seal keeps the result: a block whose stored bytes match
//! its digest is prepared without repeating it. A block that doesn't match, or
//! a segment without a seal, is checked in full on every load. The seal is not
//! in the manifest; a damaged one only costs speed. A segment's cache holds up to
//! `BLOCK_BUDGET` bytes of blocks, different blocks are prepared in parallel (at
//! most `PREPARES` at once), and a block wanted by concurrent requests is
//! prepared only once. The cache as a whole holds `COLD_BUDGET` bytes: past
//! that, and past `COLD_OPEN` open segments, the least recently read segments
//! are closed. A request for
//! many ledgers at once (`Cold::ledgers`) reads them block by block on up to
//! `COLD_READERS` threads.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use astraea_journal_codec::{Options, Row, pack_bounded, pool::Pool, unpack};
use serde_json::{Value, json};
use witness_core::ledger::LedgerHeader;
use witness_core::sha512_half;

use crate::coldpatch;
use crate::ledger::{Change, Ledger, StateChange};

type Res<T> = Result<T, String>;

const KINDS_MAGIC: &[u8; 6] = b"XWCK\x00\x01";
const SEAL_MAGIC: &[u8; 6] = b"XWCS\x00\x01";
const SEAL_LISTS: &[u8; 6] = b"XWCS\x00\x02";
/// The manifest format segments are written in, and the older one with every patch.
const FORMAT: &str = "astraea-cold/2";
const FORMAT_ALL_PATCHES: &str = "astraea-cold/1";
/// Default archive block: at most this many ledgers and exact bytes.
/// The research's canonical profile uses 16 MiB. 4 MiB costs +18.7% in size
/// at the 104 million epoch and +26% on recent history, but a cold read takes
/// 24 ms instead of 118.
/// A ledger larger than the limit gets a block sized to fit it (`write_with`).
pub const BLOCK_LEDGERS: usize = 1024;
pub const BLOCK_RAW: usize = 4 << 20;
/// Blocks are written as JC06: cut into parts of whole ledgers and at most
/// this many exact bytes, each decoded on its own. Reading one transaction
/// then costs one part instead of the whole block.
pub const PART_RAW: usize = 1 << 20;

/// Archive block limit: ledgers and exact bytes, and the part size (0 writes
/// JC05 blocks, decoded whole).
#[derive(Debug, Clone, Copy)]
pub struct BlockLimit {
    pub ledgers: usize,
    pub raw: usize,
    pub part: usize,
}

impl Default for BlockLimit {
    fn default() -> Self {
        BlockLimit {
            ledgers: BLOCK_LEDGERS,
            raw: BLOCK_RAW,
            part: PART_RAW,
        }
    }
}
/// Maximum number of cold segments open at once. One account_tx page over
/// full history touches many segments; with too few open they are closed
/// and reopened on every request. An open segment without cached blocks
/// costs little.
pub const COLD_OPEN: usize = 64;
/// Byte budget for the prepared blocks of all open segments (codec estimate).
/// Shared rather than split per segment: a busy account's page can need a
/// few dozen blocks of about 7 MB from one segment, while most open segments
/// hold one or two.
pub const COLD_BUDGET: usize = 1 << 30;
/// Most of the cold cache one segment may hold, and the number of concurrent
/// prepares per segment. A block takes about 10 ms to prepare, and one
/// account_tx page can need dozens of blocks from a single segment, so a
/// segment prepares as many at once as one request reads in parallel.
pub const BLOCK_BUDGET: usize = 256 << 20;
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

/// Seal file: `XWCS\0\1` and one digest per block when every block has one,
/// otherwise `XWCS\0\2` and, per block, a u32 count and its digests.
fn seal_bytes(seal: &[Vec<[u8; 32]>]) -> Vec<u8> {
    let lists = seal.iter().any(|d| d.len() != 1);
    let mut out = if lists { SEAL_LISTS } else { SEAL_MAGIC }.to_vec();
    out.extend((seal.len() as u32).to_le_bytes());
    for d in seal {
        if lists {
            out.extend((d.len() as u32).to_le_bytes());
        }
        for x in d {
            out.extend(x);
        }
    }
    out
}

fn parse_seal(b: &[u8]) -> Option<Vec<Vec<[u8; 32]>>> {
    let u32_at = |b: &[u8]| Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?) as usize);
    if let Some(rest) = b.strip_prefix(SEAL_MAGIC) {
        let n = u32_at(rest)?;
        let body = &rest[4..];
        if body.len() != n.checked_mul(32)? {
            return None;
        }
        return Some(body.as_chunks::<32>().0.iter().map(|d| vec![*d]).collect());
    }
    let rest = b.strip_prefix(SEAL_LISTS)?;
    let n = u32_at(rest)?;
    let mut at = 4;
    let mut out = Vec::with_capacity(n.min(rest.len() / 36));
    for _ in 0..n {
        let k = u32_at(rest.get(at..)?)?;
        at += 4;
        let body = rest.get(at..at.checked_add(k.checked_mul(32)?)?)?;
        out.push(body.as_chunks::<32>().0.to_vec());
        at += body.len();
    }
    (at == rest.len()).then_some(out)
}

/// The data files a manifest lists, by their position in `names`: the
/// archive and the kinds, and the ASIX2 indexes of an older segment.
fn listed(m: &Value) -> Vec<(usize, &'static str)> {
    let mut v = vec![(0, "astj"), (2, "kinds")];
    if m["files"].get("asix").is_some() {
        v.push((1, "asix"));
    }
    v
}

fn names(dir: &Path, first: u32) -> [PathBuf; 4] {
    ["astj", "asix", "kinds", "json"].map(|e| dir.join(format!("cold-{first:010}.{e}")))
}

/// Removes a file, and its target if it is a link (published segments are
/// links into the loader's directory). A missing file is not an error.
fn remove_with_link(p: &Path) -> Res<()> {
    if let Ok(real) = fs::canonicalize(p)
        && real != p
    {
        fs::remove_file(&real).map_err(io)?;
    }
    match fs::remove_file(p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(e)),
        _ => Ok(()),
    }
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
    let mut rows = ledgers.iter().map(row_of).collect::<Res<Vec<_>>>()?;
    for (k, r) in rows.iter().enumerate() {
        if r.seq != first + k as u32 {
            return Err(format!(
                "ledgers out of sequence: at position {k} found {}",
                r.seq
            ));
        }
    }
    let last = first + rows.len() as u32 - 1;
    let changes: usize = rows.iter().map(|r| r.patches.len()).sum();
    for r in &mut rows {
        r.patches = coldpatch::compact(r);
    }
    // A ledger larger than the limit (some exceed 4 MiB) is not split: for such a
    // segment the limit is raised to its size; other segments are unaffected.
    let raw = rows.iter().map(row_raw).max().unwrap_or(0) + 4;
    let limit = BlockLimit {
        raw: limit.raw.max(raw),
        ..limit
    };
    let opt = Options {
        part_raw: limit.part,
        ..canonical()
    };
    let (archive, _) = pack_bounded(&rows, limit.ledgers, limit.raw, opt)?;
    if unpack(&archive)? != rows {
        return Err("ASTJ5 archive did not restore the ledgers exactly".into());
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
    let [pa, _, pk, pm] = names(dir, first);
    let file =
        |b: &[u8]| json!({"bytes": b.len(), "sha512half": hex::encode_upper(sha512_half(b))});
    let manifest = json!({
        "format": FORMAT,
        "payload": if limit.part > 0 { "ASTJ6" } else { "ASTJ5" },
        "profile": "canonical",
        "codec": "astraea-journal-codec 0.1.0 (astraea-journal-sequential-2026-10-27)",
        "first": first,
        "last": last,
        "ledgers": rows.len(),
        "transactions": rows.iter().map(|r| r.txs.len()).sum::<usize>(),
        "changes": changes,
        "blocks": u32::from_le_bytes(archive[8..12].try_into().map_err(|_| "archive header")?),
        "max_block_ledgers": limit.ledgers,
        "max_block_raw_bytes": limit.raw,
        "max_part_raw_bytes": limit.part,
        "change_kinds": mode.name(),
        "files": {
            "astj": file(&archive),
            "kinds": file(&kinds),
        },
    });
    fs::create_dir_all(dir).map_err(io)?;
    sync_write(&pa, &archive)?;
    sync_write(&pk, &kinds)?;
    // The full check of every block, once; readers then trust the seal.
    let seal = Pool::open(&pa, 0, 1)
        .and_then(|p| p.seal(COLD_READERS))
        .map_err(corrupt)?;
    sync_write(&pa.with_extension("seal"), &seal_bytes(&seal))?;
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
            if ![FORMAT, FORMAT_ALL_PATCHES]
                .map(Value::from)
                .contains(&m["format"])
                || !["ASTJ5", "ASTJ6"].map(Value::from).contains(&m["payload"])
            {
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
            for (i, k) in listed(&m) {
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
        for (i, k) in listed(&self.manifest) {
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

    fn seal_path(&self) -> PathBuf {
        self.paths[0].with_extension("seal")
    }

    /// Whether the segment has a seal file.
    pub fn sealed(&self) -> bool {
        self.seal_path().exists()
    }

    /// Checks every block in full and writes the seal next to the archive
    /// file. If the archive is a link, the seal goes next to its target and
    /// gets a link here. Takes effect from the next time the segment is opened.
    pub fn write_seal(&self, threads: usize) -> Res<PathBuf> {
        let seal = Pool::open(&self.paths[0], 0, 1)
            .and_then(|p| p.seal(threads))
            .map_err(corrupt)?;
        let real = fs::canonicalize(&self.paths[0])
            .map_err(io)?
            .with_extension("seal");
        sync_write(&real, &seal_bytes(&seal))?;
        let here = self.seal_path();
        if real != here && fs::symlink_metadata(&here).is_err() {
            std::os::unix::fs::symlink(&real, &here).map_err(io)?;
        }
        Ok(real)
    }

    /// Whether the segment's blocks are JC06 (cut into parts).
    pub fn in_parts(&self) -> bool {
        self.manifest["payload"] == "ASTJ6"
    }

    /// Whether the segment stores only the patches the metadata doesn't give.
    pub fn patches_derived(&self) -> bool {
        self.manifest["format"] == FORMAT
    }

    /// Ledger `seq` as written: transactions and every patch.
    fn whole_row(&self, o: &Open, seq: u32) -> Res<Row> {
        let mut row = o.pool.ledger(seq).map_err(corrupt)?;
        row.patches = coldpatch::restore(&row.txs, row.seq, &row.patches).map_err(corrupt)?;
        Ok(row)
    }

    /// Writes the segment again in the current format, with JC06 blocks of at most
    /// `part` exact bytes per part, next to the archive (the target of a link). The ledgers,
    /// indexes and change kinds come out the same, which is checked; the
    /// archive, seal and manifest are then replaced, each by rename. A reader
    /// that has the segment open keeps the old archive; one that opens it
    /// between the renames finds a seal that doesn't match and checks blocks
    /// in full. Returns the new manifest.
    pub fn recode(&self, part: usize) -> Res<Value> {
        let o = self.opened()?;
        let mut ledgers = Vec::with_capacity((self.last - self.first + 1) as usize);
        for seq in self.first..=self.last {
            ledgers.push(if self.kinds == Kinds::Explicit {
                self.read(&o, seq, true)?
            } else {
                // Kinds are not recorded: written the same way as the loader does.
                let row = self.whole_row(&o, seq)?;
                Ledger {
                    header: row.header,
                    transactions: row.txs,
                    changes: row
                        .patches
                        .into_iter()
                        .map(|(key, data)| StateChange {
                            key,
                            change: if data.is_empty() {
                                Change::Deleted
                            } else {
                                Change::Modified
                            },
                            data,
                        })
                        .collect(),
                }
            });
        }
        drop(o);
        let real = fs::canonicalize(&self.paths[0]).map_err(io)?;
        let dir = real.parent().ok_or("archive without a directory")?;
        let staging = dir.join(format!(".recode-{:010}", self.first));
        let _ = fs::remove_dir_all(&staging);
        let limit = BlockLimit {
            ledgers: self.manifest["max_block_ledgers"]
                .as_u64()
                .map_or(BLOCK_LEDGERS, |n| n as usize),
            raw: self.manifest["max_block_raw_bytes"]
                .as_u64()
                .map_or(BLOCK_RAW, |n| n as usize),
            part,
        };
        let m = write_with(&staging, &ledgers, self.kinds, limit)?;
        drop(ledgers);
        let [na, _, nk, nm] = names(&staging, self.first);
        if fs::read(&nk).map_err(io)? != fs::read(&self.paths[2]).map_err(io)? {
            let _ = fs::remove_dir_all(&staging);
            return Err(corrupt(format!(
                "{}: recoding changed it",
                self.paths[2].display()
            )));
        }
        let target = |p: &Path| -> Res<PathBuf> { fs::canonicalize(p).map_err(io) };
        fs::rename(&na, &real).map_err(io)?;
        let seal = real.with_extension("seal");
        fs::rename(na.with_extension("seal"), &seal).map_err(io)?;
        if seal != self.seal_path() && fs::symlink_metadata(self.seal_path()).is_err() {
            std::os::unix::fs::symlink(&seal, self.seal_path()).map_err(io)?;
        }
        fs::rename(&nm, target(&self.paths[3])?).map_err(io)?;
        File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
        fs::remove_dir_all(&staging).map_err(io)?;
        // The new manifest no longer lists the ASIX2 indexes.
        remove_with_link(&self.paths[1])?;
        self.close();
        Ok(m)
    }

    /// Removes the ASIX2 indexes of a segment written before 0.3: the
    /// manifest is replaced first (via a temporary file and rename), then the
    /// file, so a crash in between leaves only an unlisted file behind.
    /// Returns the bytes freed; 0 if the segment has none.
    pub fn drop_index(&self) -> Res<u64> {
        if self.manifest["files"].get("asix").is_none() {
            return Ok(0);
        }
        let bytes = self.manifest["files"]["asix"]["bytes"]
            .as_u64()
            .unwrap_or(0);
        let mut m = self.manifest.clone();
        if let Some(files) = m["files"].as_object_mut() {
            files.remove("asix");
        }
        let real = fs::canonicalize(&self.paths[3]).map_err(io)?;
        let tmp = real.with_extension("json.tmp");
        sync_write(
            &tmp,
            &serde_json::to_vec_pretty(&m).map_err(|e| e.to_string())?,
        )?;
        fs::rename(&tmp, &real).map_err(io)?;
        if let Some(dir) = real.parent() {
            File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
        }
        remove_with_link(&self.paths[1])?;
        Ok(bytes)
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
        let mut pool = Pool::open(&self.paths[0], budget, PREPARES).map_err(corrupt)?;
        // Without a usable seal every block is checked in full, as before.
        if let Some(seal) = fs::read(self.seal_path()).ok().and_then(|b| parse_seal(&b)) {
            let _ = pool.set_seal(seal);
        }
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

    /// Header of ledger `seq` and its transactions with the given
    /// TransactionIndex values, without changes.
    fn read_txs(&self, o: &Open, seq: u32, indexes: &[u32]) -> Res<Ledger> {
        let mut header = None;
        let mut transactions = Vec::with_capacity(indexes.len());
        for &index in indexes {
            if let Some(at) = o.pool.tx_with_index(seq, index).map_err(corrupt)? {
                header.get_or_insert(at.header);
                transactions.push((at.tx, at.meta));
            }
        }
        let header = match header {
            Some(h) => h,
            None => o.pool.header(seq).map_err(corrupt)?,
        };
        let got = LedgerHeader::parse(&header).map_err(corrupt)?.sequence;
        if got != seq {
            return Err(corrupt(format!("at position {seq} found ledger {got}")));
        }
        Ok(Ledger {
            header,
            transactions,
            changes: Vec::new(),
        })
    }

    fn read(&self, o: &Open, seq: u32, with_changes: bool) -> Res<Ledger> {
        // Patches are decoded only when changes are asked for: they outweigh
        // the transactions and API reads don't need them.
        let row = if with_changes {
            self.whole_row(o, seq)?
        } else {
            o.pool.ledger_txs(seq).map_err(corrupt)?
        };
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
    /// Bytes of prepared blocks all open segments may hold (`COLD_BUDGET`).
    cache_budget: usize,
}

impl Default for Cold {
    fn default() -> Self {
        Cold {
            segments: Vec::new(),
            recent: Arc::default(),
            open_limit: COLD_OPEN,
            cache_budget: COLD_BUDGET,
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
            cache_budget: prev.cache_budget,
        })
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

    /// Same segments with a different budget for the whole block cache.
    pub fn with_cache_budget(mut self, bytes: usize) -> Cold {
        self.cache_budget = bytes;
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
        self.grouped(seqs, &|seg, o, seq| seg.read(o, seq, false))
    }

    /// Ledgers holding only the transactions asked for, by ledger and
    /// TransactionIndex, and their headers; an index the ledger doesn't have is
    /// left out. In a JC06 block only the part holding a ledger is decoded.
    pub fn transactions(&self, wants: &[(u32, u32)]) -> Res<HashMap<u32, Ledger>> {
        let mut by_seq: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for &(seq, index) in wants {
            by_seq.entry(seq).or_default().push(index);
        }
        let seqs: Vec<u32> = by_seq.keys().copied().collect();
        self.grouped(&seqs, &|seg, o, seq| seg.read_txs(o, seq, &by_seq[&seq]))
    }

    /// Reads `seqs` with `read`, block by block on up to `COLD_READERS` threads.
    fn grouped(
        &self,
        seqs: &[u32],
        read: &(dyn Fn(&ColdSegment, &Open, u32) -> Res<Ledger> + Sync),
    ) -> Res<HashMap<u32, Ledger>> {
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
                .map(|&seq| Ok((seq, read(seg, o, seq)?)))
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
        // segment finish with their own instance. Then the byte budget: while the
        // cache as a whole is over it, the least recently read segments other than
        // this one are closed.
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
            let mut total = r.iter().map(|s| s.cached_bytes()).sum::<usize>();
            while total > self.cache_budget && r.len() > 1 {
                let Some(s) = r.pop_front() else { break };
                total -= s.cached_bytes().min(total);
                s.close();
            }
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
    fn segments_without_asix_and_older_ones_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let ls = chain(100, 20);
        let m = write(dir.path(), &ls, Kinds::Explicit).unwrap();
        assert!(m["files"].get("asix").is_none());
        let [_, asix, _, man] = names(dir.path(), 100);
        assert!(!asix.exists());
        // A segment from before 0.3: its manifest lists ASIX2 indexes.
        let index = b"ASIX2 indexes from before 0.3".to_vec();
        fs::write(&asix, &index).unwrap();
        let mut old = m.clone();
        old["files"]["asix"] =
            json!({"bytes": index.len(), "sha512half": hex::encode_upper(sha512_half(&index))});
        fs::write(&man, serde_json::to_vec(&old).unwrap()).unwrap();
        let cold = Cold::open(dir.path()).unwrap();
        cold.segments()[0].verify_files().unwrap();
        // Published through a link, as the loader does.
        let live = tempfile::tempdir().unwrap();
        for e in ["astj", "asix", "kinds", "json"] {
            let n = format!("cold-0000000100.{e}");
            std::os::unix::fs::symlink(dir.path().join(&n), live.path().join(&n)).unwrap();
        }
        let cold = Cold::open(live.path()).unwrap();
        assert_eq!(cold.segments()[0].drop_index().unwrap(), index.len() as u64);
        assert!(!asix.exists() && !live.path().join("cold-0000000100.asix").exists());
        let cold = Cold::open(live.path()).unwrap();
        assert_eq!(cold.segments()[0].drop_index().unwrap(), 0);
        cold.segments()[0].verify_files().unwrap();
        assert_eq!(cold.ledger(110, true).unwrap().unwrap(), ls[10]);
    }

    #[test]
    fn ledger_larger_than_block_limit_gets_its_own_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut ls = chain(200, 6);
        ls[3].changes[0].data = vec![0x11; 3000];
        let small = BlockLimit {
            ledgers: 1024,
            raw: 1024,
            ..BlockLimit::default()
        };
        let m = write_with(dir.path(), &ls, Kinds::Explicit, small).unwrap();
        assert!(m["max_block_raw_bytes"].as_u64().unwrap() > 3000);
        let cold = Cold::open(dir.path()).unwrap();
        for l in &ls {
            let seq = l.header().unwrap().sequence;
            assert_eq!(cold.ledger(seq, true).unwrap().unwrap(), *l);
        }
    }

    /// A chain of ledgers with transactions (in hash order, as ledgers store
    /// them) and a matching transaction root, and the changes of `chain`.
    pub(crate) fn chain_with_txs(first: u32, n: u32) -> Vec<Ledger> {
        let mut out = chain(first, n);
        let mut parent = [0u8; 32];
        for (k, l) in out.iter_mut().enumerate() {
            let mut txs: Vec<(Vec<u8>, Vec<u8>)> = (0..(k as u32 % 4 + 1))
                .map(|i| {
                    let mut tx = vec![0x12, 0x00, 0x00, 0x24];
                    tx.extend((k as u32 * 10 + i).to_be_bytes());
                    // TransactionIndex, empty AffectedNodes, TransactionResult.
                    let mut meta = vec![0x20, 0x1C];
                    meta.extend(i.to_be_bytes());
                    meta.extend([0xF8, 0xF1, 0x03, 0x10, 0x00]);
                    (tx, meta)
                })
                .collect();
            txs.sort_by_key(|(t, _)| witness_core::shamap::tx_id(t));
            let leaves: Vec<_> = txs
                .iter()
                .map(|(t, m)| {
                    let id = witness_core::shamap::tx_id(t);
                    (id, witness_core::shamap::tx_leaf_hash(t, m, &id))
                })
                .collect();
            l.header[12..44].copy_from_slice(&parent);
            l.header[44..76].copy_from_slice(&witness_core::shamap::root(&leaves));
            parent = LedgerHeader::parse(&l.header).unwrap().hash();
            l.transactions = txs;
        }
        out
    }

    #[test]
    fn transactions_are_read_alone_by_transaction_index() {
        for part in [0, 200] {
            let dir = tempfile::tempdir().unwrap();
            let ls = chain_with_txs(700, 20);
            let limit = BlockLimit {
                ledgers: 8,
                raw: 1 << 20,
                part,
            };
            let m = write_with(dir.path(), &ls, Kinds::Explicit, limit).unwrap();
            assert_eq!(m["payload"], if part > 0 { "ASTJ6" } else { "ASTJ5" });
            let cold = Cold::open(dir.path()).unwrap();
            for l in &ls {
                let seq = l.header().unwrap().sequence;
                assert_eq!(cold.ledger(seq, true).unwrap().unwrap(), *l);
            }
            let wants = [(703, 1), (703, 0), (715, 2), (719, 0), (705, 9), (690, 0)];
            let got = cold.transactions(&wants).unwrap();
            assert!(!got.contains_key(&690));
            assert_eq!(got.len(), 4);
            assert_eq!(got[&703].transactions.len(), 2);
            assert!(got[&705].transactions.is_empty());
            for (seq, l) in &got {
                let full = &ls[(seq - 700) as usize];
                assert_eq!(l.header, full.header);
                assert!(l.changes.is_empty());
                for t in &l.transactions {
                    assert!(full.transactions.contains(t));
                }
            }
            assert_eq!(got[&715].transactions[0].1[2..6], 2u32.to_be_bytes());
        }
    }

    /// A chain whose transactions modify one account each, with exactly the
    /// patch their metadata gives, plus the changes of `chain`, sorted by key.
    fn chain_with_derived_patches(first: u32, n: u32) -> Vec<Ledger> {
        let mut out = chain(first, n);
        let mut parent = [0u8; 32];
        for (k, l) in out.iter_mut().enumerate() {
            let seq = l.header().unwrap().sequence;
            let mut tx = vec![0x12, 0x00, 0x00, 0x24];
            tx.extend((k as u32).to_be_bytes());
            let id = witness_core::shamap::tx_id(&tx);
            let key = [0xC0 + k as u8; 32];
            let sequence = [0x24, 0, 0, 0, k as u8];
            let mut meta = vec![0x20, 0x1C, 0, 0, 0, 0, 0xF8, 0xE5, 0x11, 0x00, 0x61, 0x56];
            meta.extend(key);
            meta.push(0xE7);
            meta.extend(sequence);
            meta.extend([0xE1, 0xE1, 0xF1, 0x03, 0x10, 0x00]);
            let mut data = vec![0x11, 0x00, 0x61];
            data.extend(sequence);
            l.changes.push(StateChange {
                key,
                change: Change::Modified,
                data,
            });
            l.changes.sort_by_key(|c| c.key);
            let leaf = witness_core::shamap::tx_leaf_hash(&tx, &meta, &id);
            l.header[12..44].copy_from_slice(&parent);
            l.header[44..76].copy_from_slice(&witness_core::shamap::root(&[(id, leaf)]));
            parent = LedgerHeader::parse(&l.header).unwrap().hash();
            l.transactions = vec![(tx, meta)];
            assert_eq!(seq, first + k as u32);
        }
        out
    }

    #[test]
    fn patches_the_metadata_gives_are_not_stored() {
        let dir = tempfile::tempdir().unwrap();
        let ls = chain_with_derived_patches(900, 12);
        let m = write(dir.path(), &ls, Kinds::Explicit).unwrap();
        assert_eq!(m["format"], FORMAT);
        assert_eq!(m["changes"], 12 * 4);
        let cold = Cold::open(dir.path()).unwrap();
        for l in &ls {
            let seq = l.header().unwrap().sequence;
            assert_eq!(cold.ledger(seq, true).unwrap().unwrap(), *l);
        }
        let seg = &cold.segments()[0];
        assert!(seg.patches_derived());
        let pool = Pool::open(&seg.paths[0], 0, 1).unwrap();
        // The marker and the three changes of `chain`.
        assert_eq!(pool.ledger(905).unwrap().patches.len(), 4);
    }

    #[test]
    fn older_segments_with_every_patch_are_read_and_recoded() {
        for kinds in [Kinds::Explicit, Kinds::NotRecorded] {
            let dir = tempfile::tempdir().unwrap();
            let ls = chain_with_txs(950, 12);
            let mut m = write(dir.path(), &ls, kinds).unwrap();
            // A manifest in the older format; each row says how it is stored.
            m["format"] = FORMAT_ALL_PATCHES.into();
            let json = names(dir.path(), 950)[3].clone();
            fs::write(&json, serde_json::to_vec(&m).unwrap()).unwrap();
            let cold = Cold::open(dir.path()).unwrap();
            let seg = &cold.segments()[0];
            assert!(seg.in_parts() && !seg.patches_derived());
            if kinds == Kinds::Explicit {
                assert_eq!(cold.ledger(955, true).unwrap().unwrap(), ls[5]);
            }
            seg.recode(PART_RAW).unwrap();
            let cold = Cold::open(dir.path()).unwrap();
            assert!(cold.segments()[0].patches_derived());
            if kinds == Kinds::Explicit {
                assert_eq!(cold.ledger(955, true).unwrap().unwrap(), ls[5]);
            }
        }
    }

    #[test]
    fn unknown_formats_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = write(dir.path(), &chain(970, 4), Kinds::Explicit).unwrap();
        m["format"] = "astraea-cold/3".into();
        let json = names(dir.path(), 970)[3].clone();
        fs::write(&json, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(
            ColdSegment::scan(dir.path())
                .unwrap_err()
                .contains("unknown format")
        );
    }

    #[test]
    fn segments_are_recoded_in_parts() {
        for kinds in [Kinds::Explicit, Kinds::NotRecorded] {
            let dir = tempfile::tempdir().unwrap();
            let ls = chain_with_txs(800, 30);
            let limit = BlockLimit {
                ledgers: 8,
                raw: 1 << 20,
                part: 0,
            };
            write_with(dir.path(), &ls, kinds, limit).unwrap();
            let cold = Cold::open(dir.path()).unwrap();
            let seg = &cold.segments()[0];
            assert!(!seg.in_parts());
            let before = cold.ledger(810, false).unwrap().unwrap();
            let m = seg.recode(300).unwrap();
            assert_eq!(m["payload"], "ASTJ6");
            assert!(
                fs::read_dir(dir.path()).unwrap().all(|e| !e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.'))
            );
            // The segment already open reads the new archive once reopened.
            assert_eq!(cold.ledger(810, false).unwrap().unwrap(), before);
            let again = Cold::open(dir.path()).unwrap();
            assert!(again.segments()[0].in_parts());
            again.segments()[0].verify_files().unwrap();
            for l in &ls {
                let seq = l.header().unwrap().sequence;
                let got = again
                    .ledger(seq, kinds == Kinds::Explicit)
                    .unwrap()
                    .unwrap();
                if kinds == Kinds::Explicit {
                    assert_eq!(got, *l);
                } else {
                    assert_eq!(
                        (&got.header, &got.transactions),
                        (&l.header, &l.transactions)
                    );
                }
            }
            assert_eq!(
                again.transactions(&[(805, 1)]).unwrap()[&805]
                    .transactions
                    .len(),
                1
            );
        }
    }

    #[test]
    fn ledgers_read_in_parallel_match_single_reads() {
        let dir = tempfile::tempdir().unwrap();
        let small = BlockLimit {
            ledgers: 3,
            raw: 1 << 20,
            ..BlockLimit::default()
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
    fn segments_are_sealed_and_read_without_a_usable_seal() {
        let dir = tempfile::tempdir().unwrap();
        let ls = chain(300, 9);
        let small = BlockLimit {
            ledgers: 4,
            raw: 1 << 20,
            ..BlockLimit::default()
        };
        write_with(dir.path(), &ls, Kinds::Explicit, small).unwrap();
        let seal = dir.path().join("cold-0000000300.seal");
        assert_eq!(parse_seal(&fs::read(&seal).unwrap()).unwrap().len(), 3);
        let lists = vec![vec![[1; 32]], vec![[2; 32], [3; 32]], vec![]];
        assert_eq!(parse_seal(&seal_bytes(&lists)), Some(lists.clone()));
        let one = vec![vec![[4; 32]]; 2];
        assert_eq!(seal_bytes(&one)[..6], *SEAL_MAGIC);
        assert_eq!(parse_seal(&seal_bytes(&one)), Some(one));
        let mut cut = seal_bytes(&lists);
        cut.pop();
        assert!(parse_seal(&cut).is_none());
        let read_all = |dir: &Path| {
            let cold = Cold::open(dir).unwrap();
            for l in &ls {
                let seq = l.header().unwrap().sequence;
                assert_eq!(cold.ledger(seq, true).unwrap().unwrap(), *l);
            }
        };
        read_all(dir.path());
        fs::write(&seal, b"XWCS\x00\x01junk").unwrap();
        read_all(dir.path());
        fs::remove_file(&seal).unwrap();
        read_all(dir.path());
        // An older segment published through links gets its seal next to the
        // archive and a link beside the published one.
        let live = tempfile::tempdir().unwrap();
        for e in ["astj", "kinds", "json"] {
            let n = format!("cold-0000000300.{e}");
            std::os::unix::fs::symlink(dir.path().join(&n), live.path().join(&n)).unwrap();
        }
        let cold = Cold::open(live.path()).unwrap();
        assert!(!cold.segments()[0].sealed());
        cold.segments()[0].write_seal(2).unwrap();
        assert!(seal.exists() && cold.segments()[0].sealed());
        assert!(
            fs::symlink_metadata(live.path().join("cold-0000000300.seal"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        read_all(live.path());
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
    fn cache_budget_is_shared_by_open_segments() {
        let dir = tempfile::tempdir().unwrap();
        for f in [10u32, 20, 30] {
            write(dir.path(), &chain(f, 5), Kinds::Explicit).unwrap();
        }
        // A roomy budget keeps every segment and its blocks.
        let cold = Cold::open(dir.path()).unwrap();
        for s in [10u32, 20, 30] {
            cold.ledger(s, false).unwrap().unwrap();
        }
        assert_eq!(cold.open_count(), 3);
        assert!(cold.segments().iter().all(|s| s.cached_bytes() > 0));
        // A tiny one: opening the next segment closes the older ones, whatever
        // the open limit, and reads still work.
        let cold = Cold::open(dir.path()).unwrap().with_cache_budget(1);
        for s in [10u32, 20, 30, 11] {
            assert!(cold.ledger(s, false).unwrap().is_some());
            assert_eq!(cold.open_count(), 1);
        }
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
