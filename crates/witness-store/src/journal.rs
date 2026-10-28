//! Journal of the current segment: an append-only file.
//!
//! Records accumulate in a buffer and are flushed to disk on `sync`; the
//! archiver calls it once a second. A process crash loses at most what has
//! accumulated since the last flush.
//!
//! An existing journal is read in full when opened. If the tail is cut off in
//! the middle of a record (the process was killed mid-write), the tail is
//! truncated and the complete records before it are kept.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::record::{MAX_DATA_LEN, Record};
use crate::{Error, Result};

/// Format signature at the start of a journal and of a compressed segment.
pub const MAGIC: &[u8; 6] = b"XWVJ\x00\x01";

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    pending: Vec<u8>,
    bytes: u64,
}

/// What was found in the journal when it was opened.
#[derive(Debug, Default)]
pub struct Recovered {
    pub records: Vec<Record>,
    /// How many bytes of torn tail were cut off.
    pub torn_bytes: u64,
}

impl Journal {
    /// Opens the journal or creates a new one. Returns the complete records from
    /// an existing journal.
    pub fn open(path: &Path) -> Result<(Journal, Recovered)> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;

        let mut recovered = Recovered::default();
        if raw.is_empty() {
            file.write_all(MAGIC)?;
            file.sync_data()?;
            let bytes = MAGIC.len() as u64;
            return Ok((
                Journal {
                    path: path.to_owned(),
                    file,
                    pending: Vec::new(),
                    bytes,
                },
                recovered,
            ));
        }
        if !raw.starts_with(MAGIC) {
            return Err(Error::Format(format!(
                "{}: not an xrpl-witness journal",
                path.display()
            )));
        }

        let mut at = MAGIC.len();
        loop {
            match Record::decode(&raw[at..]) {
                Ok(Some((rec, used))) => {
                    recovered.records.push(rec);
                    at += used;
                }
                Ok(None) => break,
                Err(e) => {
                    return Err(Error::Format(format!(
                        "{}: record at offset {at}: {e}",
                        path.display()
                    )));
                }
            }
        }
        if at < raw.len() {
            recovered.torn_bytes = (raw.len() - at) as u64;
            file.set_len(at as u64)?;
            file.seek(SeekFrom::End(0))?;
            file.sync_data()?;
        }
        Ok((
            Journal {
                path: path.to_owned(),
                file,
                pending: Vec::new(),
                bytes: at as u64,
            },
            recovered,
        ))
    }

    pub fn append(&mut self, rec: &Record) -> Result<()> {
        if rec.data.len() > MAX_DATA_LEN {
            return Err(Error::Format(format!(
                "original of {} bytes exceeds the limit of {MAX_DATA_LEN}",
                rec.data.len()
            )));
        }
        rec.encode_into(&mut self.pending);
        Ok(())
    }

    /// Flushes buffered records to disk and waits for the device to confirm.
    pub fn sync(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.file.write_all(&self.pending)?;
        self.file.sync_data()?;
        self.bytes += self.pending.len() as u64;
        self.pending.clear();
        Ok(())
    }

    /// Journal size on disk plus whatever has not been flushed yet.
    pub fn len(&self) -> u64 {
        self.bytes + self.pending.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() <= MAGIC.len() as u64
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(i: u32) -> Record {
        Record {
            received_ms: u64::from(i),
            ledger_index: 100 + i,
            data: vec![i as u8; 233],
        }
    }

    #[test]
    fn records_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("current.xwvj");
        {
            let (mut j, rec0) = Journal::open(&path).unwrap();
            assert!(rec0.records.is_empty());
            for i in 0..5 {
                j.append(&rec(i)).unwrap();
            }
            j.sync().unwrap();
        }
        let (_, got) = Journal::open(&path).unwrap();
        assert_eq!(got.records, (0..5).map(rec).collect::<Vec<_>>());
        assert_eq!(got.torn_bytes, 0);
    }

    #[test]
    fn unsynced_records_are_lost_but_journal_stays_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("current.xwvj");
        {
            let (mut j, _) = Journal::open(&path).unwrap();
            j.append(&rec(1)).unwrap();
            j.sync().unwrap();
            j.append(&rec(2)).unwrap(); // not flushed: "crash" before sync
        }
        let (_, got) = Journal::open(&path).unwrap();
        assert_eq!(got.records, vec![rec(1)]);
    }

    #[test]
    fn torn_tail_is_cut_and_writing_continues() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("current.xwvj");
        {
            let (mut j, _) = Journal::open(&path).unwrap();
            j.append(&rec(1)).unwrap();
            j.sync().unwrap();
        }
        // Simulate a write cut off halfway.
        let mut half = Vec::new();
        rec(2).encode_into(&mut half);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&half[..half.len() / 2])
            .unwrap();

        let (mut j, got) = Journal::open(&path).unwrap();
        assert_eq!(got.records, vec![rec(1)]);
        assert!(got.torn_bytes > 0);
        j.append(&rec(3)).unwrap();
        j.sync().unwrap();
        let (_, got) = Journal::open(&path).unwrap();
        assert_eq!(got.records, vec![rec(1), rec(3)]);
    }

    #[test]
    fn foreign_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("current.xwvj");
        std::fs::write(&path, b"hello").unwrap();
        assert!(Journal::open(&path).is_err());
    }
}
