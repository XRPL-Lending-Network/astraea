//! Ledger log: the first storage version of the Ledger Engine.
//!
//! The open segment is `current.xwle`, an append-only file: the magic
//! `XWLE\0\1`, then records `u32 length | u32 sequence | ledger`. Every
//! ledger is flushed to disk immediately, since they arrive every few seconds.
//! A torn tail left by a crash is cut off.
//!
//! Every `segment_ledgers` ledgers the log is compressed into
//! `segments/led-<first>-<last>.xwle.zst` and started afresh. The compressed
//! file is written first, then the log is removed.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 6] = b"XWLE\x00\x01";

#[derive(Debug)]
pub struct LedgerLog {
    dir: PathBuf,
    segment_ledgers: u32,
    zstd_level: i32,
    file: File,
    /// Sequence of the first and last ledger in the open log.
    first: Option<u32>,
    last: Option<u32>,
    /// Last ledger in the sealed segments.
    sealed_last: Option<u32>,
    /// Hash of the last written ledger, so that after a restart the first
    /// new ledger is checked against the chain like all the others.
    last_hash: Option<[u8; 32]>,
}

/// Ledger hash from a serialized log record (the header is the leading bytes).
fn record_hash(body: &[u8]) -> Option<[u8; 32]> {
    witness_core::ledger::LedgerHeader::parse(body.get(..witness_core::ledger::HEADER_LEN)?)
        .ok()
        .map(|h| h.hash())
}

/// Hash of the last ledger in the most recent sealed segment.
fn sealed_last_hash(segments: &Path, last: Option<u32>) -> Result<Option<[u8; 32]>, String> {
    let Some(last) = last else {
        return Ok(None);
    };
    let suffix = format!("-{last:010}.xwle.zst");
    for e in fs::read_dir(segments).map_err(|e| e.to_string())? {
        let path = e.map_err(|e| e.to_string())?.path();
        if path.to_string_lossy().ends_with(&suffix) {
            let raw = zstd::decode_all(&fs::read(&path).map_err(|e| e.to_string())?[..])
                .map_err(|e| e.to_string())?;
            let (records, _) = parse_records(&raw)?;
            return Ok(records.last().and_then(|(_, b)| record_hash(b)));
        }
    }
    Ok(None)
}

/// The whole log in a directory, decompressed, in order: sealed segments,
/// then the open log. Records from each come from `parse_records`.
pub fn read_journal(dir: &Path) -> Result<Vec<Vec<u8>>, String> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir.join("segments"))
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.to_string_lossy().ends_with(".xwle.zst"))
        .collect();
    files.sort();
    let mut raws = Vec::new();
    for f in files {
        let zst = fs::read(&f).map_err(|e| e.to_string())?;
        raws.push(zstd::decode_all(&zst[..]).map_err(|e| e.to_string())?);
    }
    match fs::read(dir.join("current.xwle")) {
        Ok(raw) => raws.push(raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(raws)
}

/// Log records (sequence and serialized ledger), and where the last
/// complete record ended.
pub type Records<'a> = (Vec<(u32, &'a [u8])>, usize);

pub fn parse_records(raw: &[u8]) -> Result<Records<'_>, String> {
    if !raw.starts_with(MAGIC) {
        return Err("not a ledger log".into());
    }
    let mut out = Vec::new();
    let mut at = MAGIC.len();
    while let Some(hdr) = raw.get(at..at + 8) {
        let len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let seq = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let Some(body) = raw.get(at + 8..at + 8 + len) else {
            break;
        };
        out.push((seq, body));
        at += 8 + len;
    }
    Ok((out, at))
}

/// Last ledger in the sealed segments, from the file names.
fn sealed_last(segments: &Path) -> std::io::Result<Option<u32>> {
    let mut best = None;
    for e in fs::read_dir(segments)? {
        let name = e?.file_name().to_string_lossy().into_owned();
        if let Some(last) = name
            .strip_prefix("led-")
            .and_then(|n| n.strip_suffix(".xwle.zst"))
            .and_then(|n| n.split('-').nth(1))
            .and_then(|n| n.parse::<u32>().ok())
        {
            best = best.max(Some(last));
        }
    }
    Ok(best)
}

impl LedgerLog {
    pub fn open(dir: &Path, segment_ledgers: u32, zstd_level: i32) -> Result<LedgerLog, String> {
        let io = |e: std::io::Error| e.to_string();
        fs::create_dir_all(dir.join("segments")).map_err(io)?;
        let path = dir.join("current.xwle");
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(io)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw).map_err(io)?;
        let (first, last, journal_hash) = if raw.is_empty() {
            file.write_all(MAGIC).map_err(io)?;
            file.sync_data().map_err(io)?;
            (None, None, None)
        } else {
            let (records, end) = parse_records(&raw)?;
            if end < raw.len() {
                file.set_len(end as u64).map_err(io)?;
                file.seek(SeekFrom::End(0)).map_err(io)?;
                file.sync_data().map_err(io)?;
            }
            (
                records.first().map(|r| r.0),
                records.last().map(|r| r.0),
                records.last().and_then(|(_, b)| record_hash(b)),
            )
        };
        let sealed = sealed_last(&dir.join("segments")).map_err(io)?;
        let last_hash = match journal_hash {
            Some(h) => Some(h),
            None => sealed_last_hash(&dir.join("segments"), sealed)?,
        };
        Ok(LedgerLog {
            last_hash,
            sealed_last: sealed,
            dir: dir.to_owned(),
            segment_ledgers,
            zstd_level,
            file,
            first,
            last,
        })
    }

    /// Last written ledger; we resume from it after a restart.
    pub fn last(&self) -> Option<u32> {
        self.last.or(self.sealed_last)
    }

    /// Hash of the last written ledger.
    pub fn last_hash(&self) -> Option<[u8; 32]> {
        self.last_hash
    }

    /// Appends a ledger and seals the segment when it is time. Returns the path
    /// of the sealed segment.
    pub fn append(&mut self, sequence: u32, ledger: &[u8]) -> Result<Option<PathBuf>, String> {
        let io = |e: std::io::Error| e.to_string();
        let mut rec = Vec::with_capacity(ledger.len() + 8);
        rec.extend_from_slice(&(ledger.len() as u32).to_le_bytes());
        rec.extend_from_slice(&sequence.to_le_bytes());
        rec.extend_from_slice(ledger);
        self.file.write_all(&rec).map_err(io)?;
        self.file.sync_data().map_err(io)?;
        self.first.get_or_insert(sequence);
        self.last = Some(sequence);
        self.last_hash = record_hash(ledger);
        if (sequence + 1).is_multiple_of(self.segment_ledgers) {
            return self.seal().map(Some);
        }
        Ok(None)
    }

    fn seal(&mut self) -> Result<PathBuf, String> {
        let io = |e: std::io::Error| e.to_string();
        let (Some(first), Some(last)) = (self.first, self.last) else {
            return Err("an empty log cannot be sealed".into());
        };
        let journal = self.dir.join("current.xwle");
        let raw = fs::read(&journal).map_err(io)?;
        let zst = zstd::bulk::compress(&raw, self.zstd_level).map_err(io)?;
        let path = self
            .dir
            .join("segments")
            .join(format!("led-{first:010}-{last:010}.xwle.zst"));
        witness_core::util::write_atomic(&path, &zst).map_err(io)?;
        // The compressed segment is on disk, so the log is no longer needed.
        fs::remove_file(&journal).map_err(io)?;
        self.file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&journal)
            .map_err(io)?;
        self.file.write_all(MAGIC).map_err(io)?;
        self.file.sync_data().map_err(io)?;
        self.sealed_last = Some(last);
        self.first = None;
        self.last = None;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_survive_restart_and_segments_rotate() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = LedgerLog::open(dir.path(), 4, 3).unwrap();
            assert_eq!(log.last(), None);
            for s in 101..=106 {
                let sealed = log.append(s, &[s as u8; 50]).unwrap();
                // 103 is the last one in segment 100..103.
                assert_eq!(sealed.is_some(), s == 103);
            }
        }
        let mut log = LedgerLog::open(dir.path(), 4, 3).unwrap();
        assert_eq!(log.last(), Some(106));
        // Test records are not 118-byte headers, so there is no hash.
        assert_eq!(log.last_hash(), None);
        log.append(107, &[7; 50]).unwrap();
        let seg = dir
            .path()
            .join("segments/led-0000000104-0000000107.xwle.zst");
        assert!(seg.exists());
        let raw = zstd::decode_all(&fs::read(&seg).unwrap()[..]).unwrap();
        let (records, _) = parse_records(&raw).unwrap();
        assert_eq!(
            records.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![104, 105, 106, 107]
        );
    }

    #[test]
    fn torn_tail_is_cut() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = LedgerLog::open(dir.path(), 1024, 3).unwrap();
            log.append(5, &[1; 20]).unwrap();
        }
        let path = dir.path().join("current.xwle");
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[100, 0, 0, 0, 6, 0, 0, 0, 1, 2]).unwrap();
        let log = LedgerLog::open(dir.path(), 1024, 3).unwrap();
        assert_eq!(log.last(), Some(5));
    }

    #[test]
    fn last_hash_survives_restart_and_seal() {
        use witness_core::ledger::{HEADER_LEN, LedgerHeader};
        let dir = tempfile::tempdir().unwrap();
        let ledger = |seq: u32| {
            let mut h = vec![0u8; HEADER_LEN];
            h[..4].copy_from_slice(&seq.to_be_bytes());
            h
        };
        let expected = LedgerHeader::parse(&ledger(7)).unwrap().hash();
        {
            let mut log = LedgerLog::open(dir.path(), 4, 3).unwrap();
            log.append(6, &ledger(6)).unwrap();
            log.append(7, &ledger(7)).unwrap(); // 7 seals segment 4..7
        }
        let log = LedgerLog::open(dir.path(), 4, 3).unwrap();
        assert_eq!(log.last(), Some(7));
        assert_eq!(log.last_hash(), Some(expected));
    }
}
