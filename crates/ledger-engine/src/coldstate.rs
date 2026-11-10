//! Version index over cold history: for every object key, the ledgers whose
//! state patches changed it, so that the object as of an old ledger can be read
//! from the cold segments without a database.
//!
//! The object as of ledger N is the patch of the last ledger at or before N that
//! changed its key; an empty patch means the object was deleted there. A ledger
//! number is enough to find its cold segment (`Cold::find`), so the index keeps
//! no pointers into segments, only ledger numbers.
//!
//! Layout of an index directory, written by `build`:
//! - `bucket-XX.xver` for each first key byte `XX`: `MAGIC`, then blocks of
//!   zstd-compressed entries sorted by key, then a directory of the blocks, then a
//!   footer. An entry is the key (32 bytes), the number of ledgers (varint) and the
//!   ledgers as ascending deltas (varints, the first absolute). The directory holds,
//!   per block, its first key (32 bytes), offset (u64), stored length (u32),
//!   decoded length (u32) and the sha256 of its stored bytes (32 bytes); the footer
//!   holds the block count (u32), the directory offset (u64), the sha256 of the
//!   directory (32 bytes) and `MAGIC`. All integers are little-endian.
//! - `base.bin`: the objects of the base state at ledger `first - 1`, which the
//!   cold patches do not carry: `MAGIC`, the base ledger (u32), the first and last
//!   indexed cold ledger (u32 each), the count (u32), then
//!   per object the key, the length (u32) and the bytes, in key order.
//! - `manifest.json`, written last: format, `first` and `last` cold ledger, base
//!   ledger, and the sha256 of every file. Without it the index does not open, so
//!   a build that stopped half way is never read.
//!
//! Damage is refused, never answered: opening checks every bucket's directory
//! against the sha256 in its footer, `base.bin` against the manifest, and the
//! manifest's ledger range against the copy in `base.bin`; every
//! block read checks the block against its sha256 in the directory. `verify`
//! checks every file against the manifest in full, for use before an index is
//! attached.
//!
//! The served range is from the base ledger to `last`. Building it is a single pass
//! over the cold patches; pairs of key and ledger are held per bucket in memory and
//! written to temporary files past `spill_after` pairs, then each bucket is sorted
//! on its own, so memory stays bounded and the result does not depend on the
//! threshold.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::cold::{Cold, sync_write};
use crate::varint;

type Hash = [u8; 32];
type Res<T> = Result<T, String>;

/// Magic and format version of every index file.
pub const MAGIC: &[u8; 6] = b"XVER\x00\x01";
/// Format version recorded in the manifest.
pub const FORMAT: u64 = 1;
const BUCKETS: usize = 256;
const BLOCK: usize = 64 << 10;
const MANIFEST: &str = "manifest.json";
const BASE: &str = "base.bin";
const FOOTER: usize = 4 + 8 + 32 + MAGIC.len();

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn corrupt(what: impl std::fmt::Display) -> String {
    format!("corrupt_history: version index: {what}")
}

fn bucket_name(b: usize) -> String {
    format!("bucket-{b:02x}.xver")
}

/// What to build an index of.
#[derive(Debug)]
pub struct Build<'a> {
    pub cold: &'a Cold,
    /// First and last cold ledger to index.
    pub first: u32,
    pub last: u32,
    /// The whole state at ledger `first - 1`: objects the cold patches don't carry.
    pub base: Vec<(Hash, Vec<u8>)>,
    /// Pairs held in memory before they go to temporary files.
    pub spill_after: usize,
}

/// A file being written: hashed as it goes, moved into place when finished.
struct Out {
    w: BufWriter<File>,
    sha: Sha256,
    len: u64,
    tmp: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl Out {
    fn create(path: &Path) -> Res<Out> {
        let tmp = path.with_extension("tmp");
        Ok(Out {
            w: BufWriter::new(File::create(&tmp).map_err(io)?),
            sha: Sha256::new(),
            len: 0,
            tmp,
            path: path.to_path_buf(),
        })
    }
    fn put(&mut self, b: &[u8]) -> Res<()> {
        self.sha.update(b);
        self.len += b.len() as u64;
        self.w.write_all(b).map_err(io)
    }
    fn finish(self) -> Res<String> {
        let f = self.w.into_inner().map_err(|e| e.to_string())?;
        f.sync_all().map_err(io)?;
        fs::rename(&self.tmp, &self.path).map_err(io)?;
        Ok(hex::encode(self.sha.finalize()))
    }
}

/// Writes one bucket from its pairs, sorted and without duplicates. Returns
/// keys, versions and the file's sha256.
fn write_bucket(path: &Path, pairs: &[(Hash, u32)]) -> Res<(u64, u64, String)> {
    let mut out = Out::create(path)?;
    out.put(MAGIC)?;
    let mut dir: Vec<BlockRef> = Vec::new();
    let mut block = Vec::with_capacity(BLOCK * 2);
    let mut block_first: Option<Hash> = None;
    let mut keys = 0u64;
    let mut flush = |out: &mut Out, block: &mut Vec<u8>, first: &mut Option<Hash>| -> Res<()> {
        let Some(k) = first.take() else {
            return Ok(());
        };
        let z = zstd::bulk::compress(block, 3).map_err(io)?;
        dir.push(BlockRef {
            first: k,
            off: out.len,
            len: z.len() as u32,
            raw: block.len() as u32,
            sha: Sha256::digest(&z).into(),
        });
        out.put(&z)?;
        block.clear();
        Ok(())
    };
    let mut i = 0;
    while i < pairs.len() {
        let key = pairs[i].0;
        let mut j = i;
        while j < pairs.len() && pairs[j].0 == key {
            j += 1;
        }
        if block_first.is_none() {
            block_first = Some(key);
        }
        block.extend_from_slice(&key);
        varint::put(&mut block, (j - i) as u64);
        let mut prev = 0u32;
        for p in &pairs[i..j] {
            varint::put(&mut block, u64::from(p.1 - prev));
            prev = p.1;
        }
        keys += 1;
        if block.len() >= BLOCK {
            flush(&mut out, &mut block, &mut block_first)?;
        }
        i = j;
    }
    flush(&mut out, &mut block, &mut block_first)?;
    let dir_at = out.len;
    let mut table = Vec::with_capacity(dir.len() * DIR_ENTRY);
    for b in &dir {
        table.extend_from_slice(&b.first);
        table.extend_from_slice(&b.off.to_le_bytes());
        table.extend_from_slice(&b.len.to_le_bytes());
        table.extend_from_slice(&b.raw.to_le_bytes());
        table.extend_from_slice(&b.sha);
    }
    out.put(&table)?;
    out.put(&(dir.len() as u32).to_le_bytes())?;
    out.put(&dir_at.to_le_bytes())?;
    out.put(&Sha256::digest(&table))?;
    out.put(MAGIC)?;
    Ok((keys, pairs.len() as u64, out.finish()?))
}

/// Builds the index of `b` into `dir` and returns its manifest.
pub fn build(dir: &Path, b: &Build<'_>) -> Res<Value> {
    if b.first == 0 || b.first > b.last {
        return Err(format!("bad range {}..={}", b.first, b.last));
    }
    if !b.cold.contains(b.first) || !b.cold.contains(b.last) {
        return Err(format!(
            "{}..={} is not in the cold history",
            b.first, b.last
        ));
    }
    let base_seq = b.first - 1;
    fs::create_dir_all(dir).map_err(io)?;
    let tmp = dir.join("spill");
    fs::create_dir_all(&tmp).map_err(io)?;
    let spill_after = b.spill_after.max(1);
    let mut held: Vec<Vec<(Hash, u32)>> = vec![Vec::new(); BUCKETS];
    let mut count = 0usize;
    let mut spills: Vec<Option<BufWriter<File>>> = (0..BUCKETS).map(|_| None).collect();
    let spill =
        |held: &mut Vec<Vec<(Hash, u32)>>, spills: &mut Vec<Option<BufWriter<File>>>| -> Res<()> {
            for (n, pairs) in held.iter_mut().enumerate() {
                if pairs.is_empty() {
                    continue;
                }
                if spills[n].is_none() {
                    let f = File::create(tmp.join(format!("{n:02x}"))).map_err(io)?;
                    spills[n] = Some(BufWriter::new(f));
                }
                let w = spills[n].as_mut().ok_or("spill file")?;
                for (k, s) in pairs.drain(..) {
                    w.write_all(&k).map_err(io)?;
                    w.write_all(&s.to_le_bytes()).map_err(io)?;
                }
            }
            Ok(())
        };
    let mut push = |k: Hash,
                    s: u32,
                    held: &mut Vec<Vec<(Hash, u32)>>,
                    spills: &mut Vec<Option<BufWriter<File>>>|
     -> Res<()> {
        held[usize::from(k[0])].push((k, s));
        count += 1;
        if count >= spill_after {
            spill(held, spills)?;
            count = 0;
        }
        Ok(())
    };
    for (k, _) in &b.base {
        push(*k, base_seq, &mut held, &mut spills)?;
    }
    for seq in b.first..=b.last {
        let (_, patches) = b
            .cold
            .patches(seq)?
            .ok_or(format!("ledger {seq} is not in the cold history"))?;
        for (k, _) in patches {
            push(k, seq, &mut held, &mut spills)?;
        }
    }
    for w in spills.iter_mut().flatten() {
        w.flush().map_err(io)?;
    }
    drop(spills);
    let mut buckets = Vec::with_capacity(BUCKETS);
    for (n, mine) in held.iter_mut().enumerate() {
        let mut pairs = Vec::new();
        let sp = tmp.join(format!("{n:02x}"));
        if sp.exists() {
            let mut r = BufReader::new(File::open(&sp).map_err(io)?);
            let mut rec = [0u8; 36];
            loop {
                match r.read_exact(&mut rec) {
                    Ok(()) => {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&rec[..32]);
                        let s = u32::from_le_bytes([rec[32], rec[33], rec[34], rec[35]]);
                        pairs.push((k, s));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(io(e)),
                }
            }
            fs::remove_file(&sp).map_err(io)?;
        }
        pairs.append(mine);
        pairs.sort_unstable();
        pairs.dedup();
        let name = bucket_name(n);
        let (keys, versions, sha) = write_bucket(&dir.join(&name), &pairs)?;
        buckets.push(json!({"file": name, "keys": keys, "versions": versions, "sha256": sha}));
    }
    fs::remove_dir(&tmp).map_err(io)?;
    let mut base = b.base.clone();
    base.sort_unstable_by_key(|a| a.0);
    base.dedup_by(|a, b| a.0 == b.0);
    let mut out = Out::create(&dir.join(BASE))?;
    out.put(MAGIC)?;
    out.put(&base_seq.to_le_bytes())?;
    // The range is repeated here so that the hashed file, not only the
    // manifest, decides which ledgers the index answers for.
    out.put(&b.first.to_le_bytes())?;
    out.put(&b.last.to_le_bytes())?;
    out.put(&(base.len() as u32).to_le_bytes())?;
    for (k, d) in &base {
        out.put(k)?;
        out.put(&(d.len() as u32).to_le_bytes())?;
        out.put(d)?;
    }
    let base_sha = out.finish()?;
    let manifest = json!({
        "format": FORMAT,
        "first": b.first,
        "last": b.last,
        "base": base_seq,
        "base_objects": base.len(),
        "base_sha256": base_sha,
        "buckets": buckets,
    });
    let text = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    sync_write(&dir.join(MANIFEST), &text)?;
    Ok(manifest)
}

/// Where a block lies in its bucket file and what its stored bytes hash to.
#[derive(Debug, Clone)]
struct BlockRef {
    first: Hash,
    off: u64,
    len: u32,
    raw: u32,
    sha: Hash,
}

const DIR_ENTRY: usize = 32 + 8 + 4 + 4 + 32;

/// One bucket file opened for reading: its block directory in memory.
#[derive(Debug)]
struct Bucket {
    file: File,
    dir: Vec<BlockRef>,
}

impl Bucket {
    fn open(path: &Path) -> Res<Bucket> {
        let file = File::open(path).map_err(io)?;
        let len = file.metadata().map_err(io)?.len();
        let mut head = [0u8; MAGIC.len()];
        file.read_exact_at(&mut head, 0).map_err(io)?;
        let mut foot = [0u8; FOOTER];
        if len < (MAGIC.len() + FOOTER) as u64 {
            return Err(corrupt("bucket too short"));
        }
        file.read_exact_at(&mut foot, len - FOOTER as u64)
            .map_err(io)?;
        if &head != MAGIC || &foot[44..] != MAGIC {
            return Err(corrupt("bucket magic"));
        }
        let n = u32::from_le_bytes(foot[..4].try_into().map_err(|_| corrupt("footer"))?) as usize;
        let at = u64::from_le_bytes(foot[4..12].try_into().map_err(|_| corrupt("footer"))?);
        let size = n
            .checked_mul(DIR_ENTRY)
            .filter(|s| at.checked_add(*s as u64) == Some(len - FOOTER as u64))
            .ok_or_else(|| corrupt("directory size"))?;
        let mut table = vec![0u8; size];
        file.read_exact_at(&mut table, at).map_err(io)?;
        if Sha256::digest(&table).as_slice() != &foot[12..44] {
            return Err(corrupt("directory does not match its sha256"));
        }
        let dir = table
            .as_chunks::<DIR_ENTRY>()
            .0
            .iter()
            .map(|c| {
                let mut first = [0u8; 32];
                first.copy_from_slice(&c[..32]);
                let mut sha = [0u8; 32];
                sha.copy_from_slice(&c[48..80]);
                BlockRef {
                    first,
                    off: u64::from_le_bytes(c[32..40].try_into().unwrap_or_default()),
                    len: u32::from_le_bytes(c[40..44].try_into().unwrap_or_default()),
                    raw: u32::from_le_bytes(c[44..48].try_into().unwrap_or_default()),
                    sha,
                }
            })
            .collect();
        Ok(Bucket { file, dir })
    }

    /// Ledgers that changed `key`, ascending; empty if it was never changed.
    fn ledgers(&self, key: &Hash) -> Res<Vec<u32>> {
        let Some(b) = self.dir.partition_point(|d| d.first <= *key).checked_sub(1) else {
            return Ok(vec![]);
        };
        let r = &self.dir[b];
        let mut z = vec![0u8; r.len as usize];
        self.file.read_exact_at(&mut z, r.off).map_err(io)?;
        if Sha256::digest(&z).as_slice() != r.sha {
            return Err(corrupt(format!(
                "block at offset {} does not match its sha256",
                r.off
            )));
        }
        let block = zstd::bulk::decompress(&z, r.raw as usize).map_err(io)?;
        let mut at = 0;
        while at < block.len() {
            let k: Hash = block
                .get(at..at + 32)
                .ok_or_else(|| corrupt("entry key"))?
                .try_into()
                .map_err(|_| corrupt("entry key"))?;
            at += 32;
            let n = varint::get(&block, &mut at).map_err(corrupt)? as usize;
            if k == *key {
                let mut out = Vec::with_capacity(n);
                let mut prev = 0u64;
                for _ in 0..n {
                    prev += varint::get(&block, &mut at).map_err(corrupt)?;
                    out.push(u32::try_from(prev).map_err(|_| corrupt("ledger"))?);
                }
                return Ok(out);
            }
            if k > *key {
                return Ok(vec![]);
            }
            for _ in 0..n {
                varint::get(&block, &mut at).map_err(corrupt)?;
            }
        }
        Ok(vec![])
    }
}

/// An index opened for reading.
#[derive(Debug)]
pub struct VersionIndex {
    first: u32,
    last: u32,
    base_seq: u32,
    base: BTreeMap<Hash, Vec<u8>>,
    buckets: Vec<Bucket>,
}

impl VersionIndex {
    /// Opens the index in `dir`; refuses one without a manifest or with files
    /// that don't match it.
    pub fn open(dir: &Path) -> Res<VersionIndex> {
        let m: Value =
            serde_json::from_slice(&fs::read(dir.join(MANIFEST)).map_err(io)?).map_err(corrupt)?;
        if m["format"].as_u64() != Some(FORMAT) {
            return Err(corrupt(format!("format {}", m["format"])));
        }
        let num = |f: &str| -> Res<u32> {
            m[f].as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| corrupt(format!("manifest field {f}")))
        };
        let (first, last, base_seq) = (num("first")?, num("last")?, num("base")?);
        let list = m["buckets"].as_array().ok_or_else(|| corrupt("buckets"))?;
        if list.len() != BUCKETS {
            return Err(corrupt("bucket count"));
        }
        let mut buckets = Vec::with_capacity(BUCKETS);
        for (n, b) in list.iter().enumerate() {
            if b["file"].as_str() != Some(bucket_name(n).as_str()) {
                return Err(corrupt(format!("bucket {n} file name")));
            }
            buckets.push(Bucket::open(&dir.join(bucket_name(n)))?);
        }
        let raw = fs::read(dir.join(BASE)).map_err(io)?;
        if m["base_sha256"].as_str() != Some(hex::encode(Sha256::digest(&raw)).as_str()) {
            return Err(corrupt("base.bin does not match the manifest"));
        }
        if raw.get(..MAGIC.len()) != Some(&MAGIC[..]) {
            return Err(corrupt("base magic"));
        }
        let mut at = MAGIC.len();
        let mut take = |n: usize| -> Res<&[u8]> {
            let s = raw
                .get(at..at + n)
                .ok_or_else(|| corrupt("base truncated"))?;
            at += n;
            Ok(s)
        };
        let mut word = || -> Res<u32> {
            Ok(u32::from_le_bytes(
                take(4)?.try_into().map_err(|_| corrupt("base"))?,
            ))
        };
        let (seq, f, l) = (word()?, word()?, word()?);
        if (seq, f, l) != (base_seq, first, last)
            || first != base_seq.wrapping_add(1)
            || last < first
        {
            return Err(corrupt(
                "ledger range in base.bin does not match the manifest",
            ));
        }
        let count = u32::from_le_bytes(take(4)?.try_into().map_err(|_| corrupt("base"))?);
        let mut base = BTreeMap::new();
        for _ in 0..count {
            let k: Hash = take(32)?.try_into().map_err(|_| corrupt("base key"))?;
            let len = u32::from_le_bytes(take(4)?.try_into().map_err(|_| corrupt("base"))?);
            base.insert(k, take(len as usize)?.to_vec());
        }
        Ok(VersionIndex {
            first,
            last,
            base_seq,
            base,
            buckets,
        })
    }

    /// Ledgers the index can answer for: the base ledger through the last
    /// indexed cold ledger.
    pub fn range(&self) -> (u32, u32) {
        (self.base_seq, self.last)
    }

    /// First cold ledger in the index.
    pub fn first(&self) -> u32 {
        self.first
    }

    /// Ledgers that changed `key`, ascending, including the base ledger if the
    /// object was in the base state.
    pub fn ledgers(&self, key: &Hash) -> Res<Vec<u32>> {
        self.buckets[usize::from(key[0])].ledgers(key)
    }

    /// The last version of `key` at or before ledger `at`: the ledger and the
    /// object, empty if it was deleted there; `None` if it did not exist yet.
    /// Ledgers outside `range` are refused.
    pub fn version_at(&self, cold: &Cold, key: &Hash, at: u32) -> Res<Option<(u32, Vec<u8>)>> {
        if at < self.base_seq || at > self.last {
            return Err(format!(
                "no state for ledger {at}: outside the version index {}..={}",
                self.base_seq, self.last
            ));
        }
        let ledgers = self.ledgers(key)?;
        let Some(seq) = (match ledgers.partition_point(|&s| s <= at) {
            0 => None,
            n => Some(ledgers[n - 1]),
        }) else {
            return Ok(None);
        };
        if seq == self.base_seq {
            return match self.base.get(key) {
                Some(d) => Ok(Some((seq, d.clone()))),
                None => Err(corrupt("base ledger listed for a key not in the base")),
            };
        }
        let (_, patches) = cold
            .patches(seq)?
            .ok_or(format!("ledger {seq} is not in the cold history"))?;
        let (_, data) = patches
            .into_iter()
            .find(|(k, _)| k == key)
            .ok_or_else(|| corrupt(format!("ledger {seq} has no change of a key listed for it")))?;
        Ok(Some((seq, data)))
    }
}

/// Checks every file of the index in `dir` against the sha256 in its manifest,
/// reading each file in full. Meant to run once before an index is attached;
/// `open` and every read check their own parts on top of this.
pub fn verify(dir: &Path) -> Res<()> {
    let m: Value =
        serde_json::from_slice(&fs::read(dir.join(MANIFEST)).map_err(io)?).map_err(corrupt)?;
    let list = m["buckets"].as_array().ok_or_else(|| corrupt("buckets"))?;
    if list.len() != BUCKETS {
        return Err(corrupt("bucket count"));
    }
    let mut files: Vec<(String, &str)> = Vec::with_capacity(BUCKETS + 1);
    for (n, b) in list.iter().enumerate() {
        let sha = b["sha256"]
            .as_str()
            .ok_or_else(|| corrupt(format!("bucket {n} sha256")))?;
        files.push((bucket_name(n), sha));
    }
    let base = m["base_sha256"]
        .as_str()
        .ok_or_else(|| corrupt("base_sha256"))?;
    files.push((BASE.to_string(), base));
    for (name, want) in files {
        let mut f = File::open(dir.join(&name)).map_err(io)?;
        let mut h = Sha256::new();
        std::io::copy(&mut f, &mut h).map_err(io)?;
        if hex::encode(h.finalize()) != want {
            return Err(corrupt(format!("{name} does not match the manifest")));
        }
    }
    Ok(())
}

/// The command-line entry: builds from a cold directory into `out` with the
/// given base state. Same result as `build`.
pub fn build_from_dirs(
    cold_dir: &Path,
    out: &Path,
    first: u32,
    last: u32,
    base: Vec<(Hash, Vec<u8>)>,
    spill_after: usize,
) -> Res<Value> {
    let cold = Cold::open(cold_dir)?;
    build(
        out,
        &Build {
            cold: &cold,
            first,
            last,
            base,
            spill_after,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cold::{Kinds, write};
    use crate::ledger::{Change, Ledger, StateChange};
    use witness_core::ledger::LedgerHeader;

    struct Rng(u64);
    impl Rng {
        fn step(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn key(n: u8) -> Hash {
        // Spread over buckets and share buckets: first byte cycles over 7 values.
        let mut k = [n; 32];
        k[0] = n % 7 * 37;
        k
    }

    /// A base state at `first - 1`, `n` ledgers of creations, changes and
    /// deletions (a key can come back after deletion), and the state after each
    /// ledger, as the truth to compare with.
    #[allow(clippy::type_complexity)]
    fn history(
        first: u32,
        n: u32,
    ) -> (
        Vec<(Hash, Vec<u8>)>,
        Vec<Ledger>,
        Vec<BTreeMap<Hash, Vec<u8>>>,
    ) {
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let mut state: BTreeMap<Hash, Vec<u8>> = BTreeMap::new();
        for i in 0..10u8 {
            state.insert(key(i), vec![0x11, 0x00, 0x61, i, 0]);
        }
        let base: Vec<_> = state.iter().map(|(k, v)| (*k, v.clone())).collect();
        let mut truth = vec![state.clone()];
        let mut ledgers = Vec::new();
        let mut parent = [0u8; 32];
        for s in 0..n {
            let mut header = vec![0u8; 118];
            header[..4].copy_from_slice(&(first + s).to_be_bytes());
            header[12..44].copy_from_slice(&parent);
            parent = LedgerHeader::parse(&header).unwrap().hash();
            let mut touched = std::collections::BTreeSet::new();
            let mut changes = Vec::new();
            for _ in 0..1 + rng.step() % 6 {
                let k = key((rng.step() % 40) as u8);
                if !touched.insert(k) {
                    continue;
                }
                let exists = state.contains_key(&k);
                if exists && rng.step().is_multiple_of(4) {
                    state.remove(&k);
                    changes.push(StateChange {
                        key: k,
                        change: Change::Deleted,
                        data: vec![],
                    });
                } else {
                    let d = vec![
                        0x11,
                        0x00,
                        0x61,
                        k[1],
                        (s % 251) as u8,
                        (rng.step() % 256) as u8,
                    ];
                    state.insert(k, d.clone());
                    let change = if exists {
                        Change::Modified
                    } else {
                        Change::Created
                    };
                    changes.push(StateChange {
                        key: k,
                        change,
                        data: d,
                    });
                }
            }
            ledgers.push(Ledger {
                header,
                transactions: vec![],
                changes,
            });
            truth.push(state.clone());
        }
        (base, ledgers, truth)
    }

    fn sha_of(dir: &Path) -> String {
        let mut h = Sha256::new();
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        for n in names {
            h.update(n.to_string_lossy().as_bytes());
            h.update(fs::read(dir.join(&n)).unwrap());
        }
        hex::encode(h.finalize())
    }

    const FIRST: u32 = 1001;
    const N: u32 = 300;

    #[allow(clippy::type_complexity)]
    fn setup() -> (
        tempfile::TempDir,
        Cold,
        Vec<(Hash, Vec<u8>)>,
        Vec<BTreeMap<Hash, Vec<u8>>>,
    ) {
        let cold_dir = tempfile::tempdir().unwrap();
        let (base, ledgers, truth) = history(FIRST, N);
        write(cold_dir.path(), &ledgers, Kinds::Explicit).unwrap();
        let cold = Cold::open(cold_dir.path()).unwrap();
        (cold_dir, cold, base, truth)
    }

    fn build_into(dir: &Path, cold: &Cold, base: &[(Hash, Vec<u8>)], spill_after: usize) -> Value {
        build(
            dir,
            &Build {
                cold,
                first: FIRST,
                last: FIRST + N - 1,
                base: base.to_vec(),
                spill_after,
            },
        )
        .unwrap()
    }

    #[test]
    fn read_matches_patch_replay() {
        let (_c, cold, base, truth) = setup();
        let out = tempfile::tempdir().unwrap();
        build_into(out.path(), &cold, &base, 1 << 20);
        let idx = VersionIndex::open(out.path()).unwrap();
        assert_eq!(idx.range(), (FIRST - 1, FIRST + N - 1));
        for (i, state) in truth.iter().enumerate() {
            let at = FIRST - 1 + i as u32;
            for n in 0..40u8 {
                let k = key(n);
                let got = idx
                    .version_at(&cold, &k, at)
                    .unwrap()
                    .and_then(|(_, d)| (!d.is_empty()).then_some(d));
                assert_eq!(got.as_ref(), state.get(&k), "key {n} at ledger {at}");
            }
        }
        // Outside the range: refused, not answered.
        assert!(idx.version_at(&cold, &key(1), FIRST - 2).is_err());
        assert!(idx.version_at(&cold, &key(1), FIRST + N).is_err());
    }

    #[test]
    fn build_twice_same_sha256() {
        let (_c, cold, base, _) = setup();
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ma = build_into(a.path(), &cold, &base, 1 << 20);
        let mb = build_into(b.path(), &cold, &base, 1 << 20);
        assert_eq!(ma, mb);
        assert_eq!(sha_of(a.path()), sha_of(b.path()));
    }

    #[test]
    fn spill_threshold_same_sha256() {
        let (_c, cold, base, _) = setup();
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        build_into(a.path(), &cold, &base, 1 << 20);
        // Spills to temporary files every 5 pairs.
        build_into(b.path(), &cold, &base, 5);
        assert_eq!(sha_of(a.path()), sha_of(b.path()));
        assert!(!b.path().join("spill").exists());
    }

    #[test]
    fn cli_entry_same_sha256() {
        let (cold_dir, cold, base, _) = setup();
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        build_into(a.path(), &cold, &base, 1 << 20);
        build_from_dirs(
            cold_dir.path(),
            b.path(),
            FIRST,
            FIRST + N - 1,
            base.clone(),
            1 << 20,
        )
        .unwrap();
        assert_eq!(sha_of(a.path()), sha_of(b.path()));
    }

    #[test]
    fn a_damaged_or_unfinished_index_does_not_open() {
        let (_c, cold, base, _) = setup();
        let out = tempfile::tempdir().unwrap();
        build_into(out.path(), &cold, &base, 1 << 20);
        let path = out.path().join(bucket_name(0));
        let mut b = fs::read(&path).unwrap();
        let n = b.len();
        b[n - 1] ^= 1;
        fs::write(&path, &b).unwrap();
        assert!(VersionIndex::open(out.path()).is_err());
        fs::remove_file(out.path().join(MANIFEST)).unwrap();
        assert!(VersionIndex::open(out.path()).is_err());
    }

    /// The bucket whose first block has the most bytes, and that block's span.
    fn biggest_block(dir: &Path) -> (usize, u64, u32) {
        (0..BUCKETS)
            .filter_map(|n| {
                let b = Bucket::open(&dir.join(bucket_name(n))).unwrap();
                b.dir.first().map(|d| (n, d.off, d.len))
            })
            .max_by_key(|x| x.2)
            .unwrap()
    }

    #[test]
    fn a_byte_flipped_inside_a_block_is_refused_on_read() {
        let (_c, cold, base, _) = setup();
        let out = tempfile::tempdir().unwrap();
        build_into(out.path(), &cold, &base, 1 << 20);
        verify(out.path()).unwrap();
        let (n, off, len) = biggest_block(out.path());
        let path = out.path().join(bucket_name(n));
        let mut b = fs::read(&path).unwrap();
        b[(off + u64::from(len) / 2) as usize] ^= 0x40;
        fs::write(&path, &b).unwrap();
        // The directory is intact, so the index opens; every read of that
        // block fails instead of answering, and verify names the file.
        let idx = VersionIndex::open(out.path()).unwrap();
        let first = Bucket::open(&path).unwrap().dir[0].first;
        let end = Bucket::open(&path).unwrap().dir.get(1).map(|d| d.first);
        assert!(idx.ledgers(&first).unwrap_err().contains("sha256"));
        let mut refused = 0;
        for n2 in 0..40u8 {
            let k = key(n2);
            if usize::from(k[0]) == n && k >= first && end.is_none_or(|e| k < e) {
                let e = idx.version_at(&cold, &k, FIRST + N - 1).unwrap_err();
                assert!(e.contains("sha256"), "{e}");
                refused += 1;
            }
        }
        assert!(refused > 0);
        assert!(verify(out.path()).unwrap_err().contains(&bucket_name(n)));
    }

    #[test]
    fn a_changed_range_in_the_manifest_does_not_open() {
        let (_c, cold, base, _) = setup();
        let out = tempfile::tempdir().unwrap();
        build_into(out.path(), &cold, &base, 1 << 20);
        let mp = out.path().join(MANIFEST);
        let good = fs::read_to_string(&mp).unwrap();
        VersionIndex::open(out.path()).unwrap();
        // One range field changed by 9: still valid JSON, and the file hashes
        // in the manifest still match, so only the range check sees it.
        for (field, at) in [
            ("last", FIRST + N - 1),
            ("first", FIRST),
            ("base", FIRST - 1),
        ] {
            let mut m: Value = serde_json::from_str(&good).unwrap();
            assert_eq!(m[field], json!(at), "{field}");
            m[field] = json!(at + 9);
            fs::write(&mp, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
            let e = VersionIndex::open(out.path()).unwrap_err();
            assert!(e.contains("does not match the manifest"), "{field}: {e}");
        }
        fs::write(&mp, &good).unwrap();
        VersionIndex::open(out.path()).unwrap();
    }

    #[test]
    fn a_byte_flipped_in_the_directory_or_base_does_not_open() {
        let (_c, cold, base, _) = setup();
        let out = tempfile::tempdir().unwrap();
        build_into(out.path(), &cold, &base, 1 << 20);
        let (n, _, _) = biggest_block(out.path());
        let path = out.path().join(bucket_name(n));
        let good = fs::read(&path).unwrap();
        // The directory starts right after the last block; byte 40 is inside
        // the stored length of the first entry.
        let b0 = Bucket::open(&path).unwrap();
        let last = b0.dir.last().unwrap();
        let dir_at = (last.off + u64::from(last.len)) as usize;
        let mut b = good.clone();
        b[dir_at + 40] ^= 1;
        fs::write(&path, &b).unwrap();
        assert!(VersionIndex::open(out.path()).is_err());
        fs::write(&path, &good).unwrap();
        VersionIndex::open(out.path()).unwrap();

        let bp = out.path().join(BASE);
        let mut raw = fs::read(&bp).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 1;
        fs::write(&bp, &raw).unwrap();
        assert!(
            VersionIndex::open(out.path())
                .unwrap_err()
                .contains("base.bin")
        );
        assert!(verify(out.path()).unwrap_err().contains("base.bin"));
    }
}
