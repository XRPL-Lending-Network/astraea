//! Block storage for ledgers: random access to any ledger without
//! decompressing the whole archive.
//!
//! Compressing each ledger separately is expensive: zstd loses the repetition
//! between neighbouring ledgers (measured on the validation archive: 32% larger
//! than a whole segment). Compressing a whole segment loses random access.
//! The compromise is a block of `block_ledgers` consecutive ledgers, optionally
//! with a zstd dictionary: reading a ledger means decompressing one block.
//!
//! Segment file `blk-<first>.xwlb`: magic `XWLB\0\1`, then blocks:
//! `u32 compressed length | compressed`. A decompressed block: `u32 n`, n pairs
//! `(u32 sequence, u32 length)`, then the records back to back.
//!
//! Index `blk-<first>.xwlb.idx`: magic `XWLI\0\1`, then for each block
//! `u32 first sequence | u32 n | u64 offset | u32 compressed length`. The index
//! is kept in memory: for a million ledgers in blocks of 16 it is under 2 MB.
//!
//! The reader keeps the last few decompressed blocks: the history of an
//! active account touches consecutive ledgers, and decompressing a block
//! (32 ledgers, a few megabytes) costs more than searching within it.
//!
//! The dictionary, if any, is `dict.zdict` in the same directory. Blocks cannot
//! be read without it, so it is written before the first block.
//!
//! A block goes into the index only after the block itself is on disk (fsync),
//! so a segment tail torn by a crash has no index entry and is never read.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

const MAGIC: &[u8; 6] = b"XWLB\x00\x01";
const IDX_MAGIC: &[u8; 6] = b"XWLI\x00\x01";
const IDX_ENTRY: usize = 4 + 4 + 8 + 4;
/// How many decompressed blocks the reader keeps.
const CACHE_BLOCKS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockRef {
    first: u32,
    count: u32,
    offset: u64,
    len: u32,
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

/// Writer: collects ledgers into a block and flushes the block when it is full.
#[derive(Debug)]
pub struct BlockWriter {
    file: File,
    index: File,
    offset: u64,
    level: i32,
    dict: Option<Vec<u8>>,
    block_ledgers: u32,
    pending: Vec<(u32, Vec<u8>)>,
}

impl BlockWriter {
    /// A new segment starting at ledger `first`.
    pub fn create(
        dir: &Path,
        first: u32,
        block_ledgers: u32,
        level: i32,
        dict: Option<Vec<u8>>,
    ) -> Result<BlockWriter, String> {
        fs::create_dir_all(dir).map_err(io)?;
        if let Some(d) = &dict {
            fs::write(dir.join("dict.zdict"), d).map_err(io)?;
        }
        let path = dir.join(format!("blk-{first:010}.xwlb"));
        let idx_path = path.with_extension("xwlb.idx");
        // A segment with the same start but not a single block in the index is
        // left over from a crash right after creation, so it can be replaced.
        if let Ok(m) = fs::metadata(&idx_path)
            && m.len() < (IDX_MAGIC.len() + IDX_ENTRY) as u64
        {
            fs::remove_file(&path).map_err(io)?;
            fs::remove_file(&idx_path).map_err(io)?;
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(io)?;
        file.write_all(MAGIC).map_err(io)?;
        let mut index = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(idx_path)
            .map_err(io)?;
        index.write_all(IDX_MAGIC).map_err(io)?;
        Ok(BlockWriter {
            file,
            index,
            offset: MAGIC.len() as u64,
            level,
            dict,
            block_ledgers: block_ledgers.max(1),
            pending: Vec::new(),
        })
    }

    pub fn append(&mut self, sequence: u32, ledger: Vec<u8>) -> Result<(), String> {
        if let Some((last, _)) = self.pending.last()
            && sequence != last + 1
        {
            return Err(format!("ledgers out of sequence: {last} → {sequence}"));
        }
        self.pending.push((sequence, ledger));
        if self.pending.len() as u32 >= self.block_ledgers {
            self.flush()?;
        }
        Ok(())
    }

    /// Flushes an incomplete block, at the end of a run or before closing.
    pub fn flush(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let n = self.pending.len() as u32;
        let total: usize = self.pending.iter().map(|(_, l)| l.len() + 8).sum();
        let mut raw = Vec::with_capacity(4 + total);
        raw.extend_from_slice(&n.to_le_bytes());
        for (seq, l) in &self.pending {
            raw.extend_from_slice(&seq.to_le_bytes());
            raw.extend_from_slice(&(l.len() as u32).to_le_bytes());
        }
        for (_, l) in &self.pending {
            raw.extend_from_slice(l);
        }
        let zst = match &self.dict {
            Some(d) => zstd::bulk::Compressor::with_dictionary(self.level, d)
                .and_then(|mut c| c.compress(&raw))
                .map_err(io)?,
            None => zstd::bulk::compress(&raw, self.level).map_err(io)?,
        };
        self.file
            .write_all(&(zst.len() as u32).to_le_bytes())
            .map_err(io)?;
        self.file.write_all(&zst).map_err(io)?;
        self.file.sync_data().map_err(io)?;
        let entry = BlockRef {
            first: self.pending[0].0,
            count: n,
            offset: self.offset + 4,
            len: zst.len() as u32,
        };
        let mut e = Vec::with_capacity(IDX_ENTRY);
        e.extend_from_slice(&entry.first.to_le_bytes());
        e.extend_from_slice(&entry.count.to_le_bytes());
        e.extend_from_slice(&entry.offset.to_le_bytes());
        e.extend_from_slice(&entry.len.to_le_bytes());
        self.index.write_all(&e).map_err(io)?;
        self.index.sync_data().map_err(io)?;
        self.offset += 4 + zst.len() as u64;
        self.pending.clear();
        Ok(())
    }

    /// How many ledgers are waiting in the incomplete block.
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Flushes the remainder and syncs data to disk.
    pub fn finish(mut self) -> Result<(), String> {
        self.flush()?;
        self.file.sync_all().map_err(io)?;
        self.index.sync_all().map_err(io)
    }
}

/// A block segment: the file and its index in memory.
#[derive(Debug)]
struct Segment {
    path: PathBuf,
    file: File,
    blocks: Vec<BlockRef>,
}

/// Reads by ledger sequence.
///
/// The reader knows the segments as of the last directory scan; new
/// blocks appended by the loader become visible after `refresh`. `get`
/// calls it itself when the ledger is past the known end.
#[derive(Debug)]
pub struct BlockReader {
    dir: PathBuf,
    segments: RwLock<Arc<Vec<Arc<Segment>>>>,
    dict: Option<Vec<u8>>,
    /// Decompressed blocks keyed by first ledger, most recent first.
    cache: Mutex<VecDeque<(u32, Arc<Vec<u8>>)>>,
}

fn scan(dir: &Path) -> Result<Vec<Arc<Segment>>, String> {
    let mut segments = Vec::new();
    for e in fs::read_dir(dir).map_err(io)? {
        let path = e.map_err(io)?.path();
        if path.extension().is_none_or(|x| x != "xwlb") {
            continue;
        }
        let mut idx = Vec::new();
        File::open(path.with_extension("xwlb.idx"))
            .and_then(|mut f| f.read_to_end(&mut idx))
            .map_err(io)?;
        if !idx.starts_with(IDX_MAGIC) {
            return Err(format!("{}: not a block index", path.display()));
        }
        let blocks = idx[IDX_MAGIC.len()..]
            .as_chunks::<IDX_ENTRY>()
            .0
            .iter()
            .map(|c| BlockRef {
                first: u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                count: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                offset: u64::from_le_bytes([c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]]),
                len: u32::from_le_bytes([c[16], c[17], c[18], c[19]]),
            })
            .collect::<Vec<_>>();
        let mut file = File::open(&path).map_err(io)?;
        let mut magic = [0u8; 6];
        file.read_exact(&mut magic).map_err(io)?;
        if &magic != MAGIC {
            return Err(format!("{}: not a block segment", path.display()));
        }
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        segments.push(Arc::new(Segment { path, file, blocks }));
    }
    segments.sort_by_key(|s| s.blocks.first().map_or(u32::MAX, |r| r.first));
    Ok(segments)
}

impl BlockReader {
    pub fn open(dir: &Path) -> Result<BlockReader, String> {
        let dict = match fs::read(dir.join("dict.zdict")) {
            Ok(d) => Some(d),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        Ok(BlockReader {
            dir: dir.to_path_buf(),
            segments: RwLock::new(Arc::new(scan(dir)?)),
            dict,
            cache: Mutex::new(VecDeque::new()),
        })
    }

    fn segments(&self) -> Arc<Vec<Arc<Segment>>> {
        self.segments
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Rescans the directory for new blocks and segments.
    pub fn refresh(&self) -> Result<(), String> {
        let fresh = Arc::new(scan(&self.dir)?);
        *self.segments.write().unwrap_or_else(|p| p.into_inner()) = fresh;
        Ok(())
    }

    /// First ledger in the blocks.
    pub fn first(&self) -> Option<u32> {
        self.segments()
            .iter()
            .filter_map(|s| s.blocks.first().map(|r| r.first))
            .min()
    }

    /// Last ledger in the blocks.
    pub fn last(&self) -> Option<u32> {
        self.segments()
            .iter()
            .filter_map(|s| s.blocks.last().map(|r| r.first + r.count - 1))
            .max()
    }

    fn find(&self, sequence: u32) -> Option<(Arc<Segment>, BlockRef)> {
        for s in self.segments().iter() {
            let i = s.blocks.partition_point(|b| b.first + b.count <= sequence);
            if let Some(b) = s.blocks.get(i)
                && b.first <= sequence
            {
                return Some((s.clone(), *b));
            }
        }
        None
    }

    /// Serialized ledger by sequence; `None` if there is no such ledger.
    pub fn get(&self, sequence: u32) -> Result<Option<Vec<u8>>, String> {
        let found = match self.find(sequence) {
            Some(f) => Some(f),
            None if self.last().is_none_or(|l| sequence > l) => {
                self.refresh()?;
                self.find(sequence)
            }
            None => None,
        };
        let Some((segment, b)) = found else {
            return Ok(None);
        };
        let raw = self.block(&segment.file, b)?;
        let n = u32::from_le_bytes(raw[..4].try_into().map_err(|_| "block")?) as usize;
        let mut at = 4 + n * 8;
        for i in 0..n {
            let h = &raw[4 + i * 8..12 + i * 8];
            let seq = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
            let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
            if seq == sequence {
                return raw
                    .get(at..at + len)
                    .map(|s| Some(s.to_vec()))
                    .ok_or_else(|| "block truncated".into());
            }
            at += len;
        }
        Err(format!("ledger {sequence} missing from its block"))
    }

    /// A decompressed block, from the cache or from disk.
    fn block(&self, file: &File, b: BlockRef) -> Result<Arc<Vec<u8>>, String> {
        let cached = |c: &VecDeque<(u32, Arc<Vec<u8>>)>| {
            c.iter()
                .find(|(f, _)| *f == b.first)
                .map(|(_, r)| r.clone())
        };
        if let Some(r) = cached(&self.cache.lock().unwrap_or_else(|p| p.into_inner())) {
            return Ok(r);
        }
        let mut zst = vec![0u8; b.len as usize];
        file.read_exact_at(&mut zst, b.offset).map_err(io)?;
        let raw = Arc::new(match &self.dict {
            Some(d) => zstd::bulk::Decompressor::with_dictionary(d)
                .and_then(|mut z| z.decompress(&zst, 512 << 20))
                .map_err(io)?,
            None => zstd::stream::decode_all(&zst[..]).map_err(io)?,
        });
        let mut c = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cached(&c).is_none() {
            c.push_front((b.first, raw.clone()));
            c.truncate(CACHE_BLOCKS);
        }
        Ok(raw)
    }

    /// Bytes taken by segments, indexes and the dictionary.
    pub fn bytes_on_disk(&self, dir: &Path) -> u64 {
        let mut total = fs::metadata(dir.join("dict.zdict")).map_or(0, |m| m.len());
        for s in self.segments().iter() {
            total += fs::metadata(&s.path).map_or(0, |m| m.len());
            total += fs::metadata(s.path.with_extension("xwlb.idx")).map_or(0, |m| m.len());
        }
        total
    }
}

/// A zstd dictionary trained on sample ledgers.
pub fn train_dictionary(samples: &[Vec<u8>], size: usize) -> Result<Vec<u8>, String> {
    zstd::dict::from_samples(samples, size).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(seq: u32) -> Vec<u8> {
        let mut v = format!("ledger {seq} ").into_bytes();
        v.extend(std::iter::repeat_n((seq % 251) as u8, (seq % 300) as usize));
        v
    }

    fn roundtrip(block: u32, dict: bool) {
        let dir = tempfile::tempdir().unwrap();
        let d = dict.then(|| {
            let samples: Vec<_> = (0..200).map(ledger).collect();
            train_dictionary(&samples, 4096).unwrap()
        });
        let mut w = BlockWriter::create(dir.path(), 1000, block, 3, d).unwrap();
        for s in 1000..1100 {
            w.append(s, ledger(s)).unwrap();
        }
        w.finish().unwrap();
        let r = BlockReader::open(dir.path()).unwrap();
        for s in 1000..1100 {
            assert_eq!(
                r.get(s).unwrap().unwrap(),
                ledger(s),
                "block {block} dictionary {dict} ledger {s}"
            );
        }
        assert!(r.get(999).unwrap().is_none());
        assert!(r.get(1100).unwrap().is_none());
        assert_eq!((r.first(), r.last()), (Some(1000), Some(1099)));
    }

    #[test]
    fn random_access_roundtrips() {
        for block in [1, 7, 16, 100, 1000] {
            roundtrip(block, false);
        }
        roundtrip(16, true);
    }

    #[test]
    fn empty_leftover_segment_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        drop(BlockWriter::create(dir.path(), 5, 4, 3, None).unwrap());
        let mut w = BlockWriter::create(dir.path(), 5, 4, 3, None).unwrap();
        w.append(5, vec![5]).unwrap();
        w.finish().unwrap();
        assert!(BlockWriter::create(dir.path(), 5, 4, 3, None).is_err());
        assert_eq!(BlockReader::open(dir.path()).unwrap().last(), Some(5));
    }

    #[test]
    fn gaps_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = BlockWriter::create(dir.path(), 1, 16, 3, None).unwrap();
        w.append(1, vec![1]).unwrap();
        assert!(w.append(3, vec![3]).is_err());
    }
}
