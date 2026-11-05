//! Writing the archive in segments.
//!
//! A segment nominally covers `segment_ledgers` consecutive ledgers.
//! Validations for one ledger arrive over several seconds and some are late,
//! so a segment is not closed exactly at the range boundary but once a
//! validation arrives `grace_ledgers` past it. Anything later than that goes
//! into the next segment; every record carries its own ledger index, so
//! readers are not affected.
//!
//! Data directory layout:
//!
//! ```text
//! current.xwvj        journal of the open segment
//! current.json        what this segment is: nominal start, open time
//! segments/           closed segments: *.xwv.zst and seals *.seal.json
//! ```
//!
//! The closing order is chosen so that a crash at any moment loses nothing:
//! the compressed segment and the seal are written first (via temporary files
//! and rename), and only then is the journal deleted. If the process dies
//! between these steps, the seal already exists at startup, so the journal is
//! treated as a duplicate and deleted.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use witness_core::sha512_half;

use crate::journal::{Journal, MAGIC};
use crate::record::Record;
use crate::seal::{FORMAT, Seal, missing_ranges};
use crate::{Error, Result};

/// How many recent records to keep for the median: about 25 seconds of the
/// mainnet stream. A shorter window gets knocked over by a burst: on
/// 2026-10-23 at 14:20 UTC peers relayed a batch of devnet validations, and
/// the median over 129 records (a second and a half of the stream) jumped to
/// devnet numbers for three seconds. Knocking over a median of 2048 takes
/// more than a thousand foreign records in a row.
const RECENT: usize = 2048;

/// How many records are needed before the median is trusted and a segment is
/// opened. On live mainnet this is less than a second of the stream.
const WARMUP: usize = 64;

/// How far a ledger index may be from the median for the record to count as
/// belonging to our network.
///
/// This is needed because validations from other networks leak into the
/// mainnet stream through peer relaying: a measurement on one of our
/// archivers on 2026-10-23 showed about 13% of the stream, with ledgers
/// around 6.3 million (devnet) and 21.7 million (testnet). Their `network_id`
/// field in the stream is the same as mainnet's, so they can only be told
/// apart by ledger index. Such records are stored (they are signed data
/// too), but they take no part in segment slicing or completeness
/// accounting.
const OUTLIER_WINDOW: u32 = 256;

#[derive(Debug, Clone)]
pub struct SegmentConfig {
    pub dir: PathBuf,
    pub source: String,
    pub segment_ledgers: u32,
    pub grace_ledgers: u32,
    pub zstd_level: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenMeta {
    nominal_first: u32,
    opened_ms: u64,
    /// The ledger from which the archive starts being responsible for
    /// completeness, if it has not started yet: the first segment, or the
    /// first one after re-slicing. This is the network's current ledger at
    /// open time, not the oldest record: lagging validators send validations
    /// a hundred ledgers back, and using those would make the archive report
    /// as missing everything from before it started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coverage_from: Option<u32>,
}

/// Result of closing a segment, for the archiver's event log.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub seal: Seal,
    pub path: PathBuf,
    /// Size of the compressed file, for the log; not part of the seal.
    pub zst_bytes: u64,
}

/// The numbering lineage the archive is responsible for keeping complete: the
/// last ledger and when it was reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lineage {
    last: u32,
    at_ms: u64,
}

/// The network does not advance faster than this: a ledger closes every 3 to 4
/// seconds, and we take twice the margin.
const MIN_LEDGER_MS: u64 = 1_500;

impl Lineage {
    /// The reference ledger could have grown to `reference` in the elapsed
    /// time, so this is a continuation of the same lineage, not a jump to
    /// foreign numbering. Archiver downtime counts as a continuation: over
    /// hours the network moves thousands of ledgers ahead, and the gap is
    /// recorded honestly in the seal.
    fn continued_by(&self, reference: u32, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.at_ms) / MIN_LEDGER_MS;
        let reach = u64::from(self.last) + u64::from(OUTLIER_WINDOW) + elapsed;
        reference.saturating_add(OUTLIER_WINDOW) >= self.last && u64::from(reference) <= reach
    }
}

/// How many parked lineages to remember.
const PARKED: usize = 4;

#[derive(Debug)]
pub struct SegmentWriter {
    cfg: SegmentConfig,
    journal: Journal,
    open: Option<OpenMeta>,
    seen: Vec<u32>,
    records: u64,
    /// Records far from the network's current ledger; see `OUTLIER_WINDOW`.
    out_of_window: u64,
    first: u32,
    last: u32,
    /// Ledger indexes of recent records; their median determines which ledger
    /// is the network's current one.
    recent: VecDeque<u32>,
    /// Records received before the median became reliable.
    warmup: Vec<Record>,
    /// Hash of the previous seal; there is one hash chain for the whole archive.
    prev_hash: Option<String>,
    /// The numbering lineage we are currently responsible for. `None` means we
    /// have not started yet.
    lineage: Option<Lineage>,
    /// Parked lineages: if the reference jumped to foreign numbering and came
    /// back, responsibility resumes where it was parked instead of reporting
    /// everything between the two numberings as missing.
    parked: Vec<Lineage>,
    /// How many bytes of torn tail were cut off at startup.
    pub torn_bytes_at_start: u64,
}

impl SegmentWriter {
    pub fn open(cfg: SegmentConfig) -> Result<SegmentWriter> {
        if cfg.segment_ledgers == 0 {
            return Err(Error::Format("segment_ledgers cannot be zero".into()));
        }
        fs::create_dir_all(cfg.dir.join("segments"))?;
        let latest = latest_seal(&cfg.dir.join("segments"))?;
        let lineage = latest
            .as_ref()
            .filter(|s| s.coverage_last > 0)
            .map(|s| Lineage {
                last: s.coverage_last,
                at_ms: s.sealed_ms,
            });
        let prev_hash = latest.map(|s| s.seal_hash);

        let meta_path = cfg.dir.join("current.json");
        let journal_path = cfg.dir.join("current.xwvj");
        let mut open: Option<OpenMeta> = match fs::read(&meta_path) {
            Ok(b) => Some(serde_json::from_slice(&b)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };

        // The journal was already sealed but not yet deleted: it is a duplicate.
        if let Some(m) = &open
            && seal_path(&cfg.dir, m.nominal_first, m.opened_ms).exists()
        {
            fs::remove_file(&journal_path).ok();
            fs::remove_file(&meta_path).ok();
            open = None;
        }

        let (journal, recovered) = Journal::open(&journal_path)?;
        let mut w = SegmentWriter {
            cfg,
            journal,
            open: None,
            seen: Vec::new(),
            records: 0,
            out_of_window: 0,
            first: u32::MAX,
            last: 0,
            recent: VecDeque::with_capacity(RECENT + 1),
            warmup: Vec::new(),
            prev_hash,
            lineage,
            parked: Vec::new(),
            torn_bytes_at_start: recovered.torn_bytes,
        };
        match open {
            Some(m) => {
                // Whether records belong to the network is judged by the
                // segment's own range, not by the current reference: the
                // journal may have accumulated for up to an hour, and records
                // from its start are more than a window away from the current
                // ledger. On 2026-10-23 a restart reported 8 ledgers as
                // missing this way, even though they were in the journal.
                let lo = m.nominal_first.saturating_sub(OUTLIER_WINDOW);
                let hi = m
                    .nominal_first
                    .saturating_add(w.cfg.segment_ledgers)
                    .saturating_add(w.cfg.grace_ledgers)
                    .saturating_add(OUTLIER_WINDOW);
                for r in &recovered.records {
                    w.remember(r.ledger_index);
                    w.note_in(r.ledger_index, (lo..=hi).contains(&r.ledger_index));
                }
                w.open = Some(m);
            }
            None if !recovered.records.is_empty() => {
                return Err(Error::Format(
                    "journal has records but no segment description: needs manual inspection"
                        .into(),
                ));
            }
            None => {}
        }
        Ok(w)
    }

    fn remember(&mut self, ledger: u32) {
        self.recent.push_back(ledger);
        if self.recent.len() > RECENT {
            self.recent.pop_front();
        }
    }

    /// The network's current ledger: the median of recent records' ledger
    /// indexes. Foreign networks are a minority in the stream, so the median
    /// ignores them.
    fn reference(&self) -> Option<u32> {
        if self.recent.is_empty() {
            return None;
        }
        let mut v: Vec<u32> = self.recent.iter().copied().collect();
        let mid = v.len() / 2;
        Some(*v.select_nth_unstable(mid).1)
    }

    fn note(&mut self, ledger: u32, reference: u32) {
        self.note_in(ledger, ledger.abs_diff(reference) <= OUTLIER_WINDOW);
    }

    fn note_in(&mut self, ledger: u32, in_window: bool) {
        self.records += 1;
        if !in_window {
            self.out_of_window += 1;
            return;
        }
        self.seen.push(ledger);
        self.first = self.first.min(ledger);
        self.last = self.last.max(ledger);
    }

    fn nominal_start(&self, ledger: u32) -> u32 {
        ledger - ledger % self.cfg.segment_ledgers
    }

    /// Picks the responsibility lineage for a new segment: continue the current
    /// one, return to a parked one, or start over.
    fn choose_lineage(&mut self, reference: u32, now: u64) {
        if self.lineage.is_some_and(|l| l.continued_by(reference, now)) {
            return;
        }
        if let Some(l) = self.lineage.take() {
            self.parked.push(l);
            if self.parked.len() > PARKED {
                self.parked.remove(0);
            }
        }
        if let Some(i) = self
            .parked
            .iter()
            .rposition(|l| l.continued_by(reference, now))
        {
            self.lineage = Some(self.parked.remove(i));
        }
    }

    fn open_segment(&mut self, reference: u32) -> Result<()> {
        let now = witness_core::util::now_ms();
        self.choose_lineage(reference, now);
        let m = OpenMeta {
            nominal_first: self.nominal_start(reference),
            opened_ms: now,
            coverage_from: self.lineage.is_none().then_some(reference),
        };
        witness_core::util::write_atomic(
            &self.cfg.dir.join("current.json"),
            &serde_json::to_vec(&m)?,
        )?;
        self.open = Some(m);
        Ok(())
    }

    fn write(&mut self, rec: &Record, reference: u32) -> Result<()> {
        self.journal.append(rec)?;
        self.note(rec.ledger_index, reference);
        Ok(())
    }

    /// Adds a record. If it is time to close the current segment, closes it and
    /// returns its seal.
    ///
    /// After a start with an empty journal, the first `WARMUP` records are
    /// buffered in memory while the median cannot be trusted yet: opening a
    /// segment on a stray validation from a foreign network would slice the
    /// archive in the wrong place. If that happens anyway, the segment
    /// re-slices itself (see the `stale` condition below), and completeness
    /// responsibility does not mix up lineages (see `Lineage`).
    pub fn append(&mut self, rec: &Record) -> Result<Option<Sealed>> {
        self.remember(rec.ledger_index);
        let Some(reference) = self.reference() else {
            return Ok(None);
        };

        if self.open.is_none() {
            if self.recent.len() < WARMUP {
                self.warmup.push(rec.clone());
                return Ok(None);
            }
            self.open_segment(reference)?;
            for early in std::mem::take(&mut self.warmup) {
                self.write(&early, reference)?;
            }
            self.write(rec, reference)?;
            return Ok(None);
        }

        let mut sealed = None;
        if let Some(m) = &self.open {
            let boundary = m
                .nominal_first
                .saturating_add(self.cfg.segment_ledgers)
                .saturating_add(self.cfg.grace_ledgers);
            // The second condition is self-healing. If the segment was opened
            // in the wrong place (the archiver started during a burst of
            // foreign-network validations and the median was wrong), or the
            // network was restarted with different numbers, the current
            // ledger ends up far below the open range. The segment is then
            // closed as is and reopened from the network; otherwise slicing
            // would be stuck forever.
            let stale = reference.saturating_add(OUTLIER_WINDOW) < m.nominal_first;
            if reference >= boundary || stale {
                sealed = self.seal_current()?;
                self.open_segment(reference)?;
            }
        }
        self.write(rec, reference)?;
        Ok(sealed)
    }

    /// Flushes the journal to disk.
    pub fn sync(&mut self) -> Result<()> {
        self.journal.sync()
    }

    /// Nominal start of the open segment and the number of records in it.
    pub fn current(&self) -> Option<(u32, u64)> {
        self.open.as_ref().map(|m| (m.nominal_first, self.records))
    }

    /// The network's current ledger, from the median of recent records.
    pub fn network_ledger(&self) -> Option<u32> {
        self.reference()
    }

    /// The record is far from the current ledger: a foreign network or very late.
    pub fn is_out_of_window(&self, ledger: u32) -> bool {
        self.reference()
            .is_some_and(|r| ledger.abs_diff(r) > OUTLIER_WINDOW)
    }

    /// Size of the open segment's journal, including what has not been flushed.
    pub fn journal_bytes(&self) -> u64 {
        self.journal.len()
    }

    /// The highest ledger index among records in the open segment.
    pub fn last_ledger(&self) -> Option<u32> {
        (self.records > 0).then_some(self.last)
    }

    fn seal_current(&mut self) -> Result<Option<Sealed>> {
        let Some(m) = self.open.clone() else {
            return Ok(None);
        };
        self.journal.sync()?;
        if self.journal.is_empty() {
            return Ok(None);
        }

        let raw = fs::read(self.journal.path())?;
        let zst = zstd::bulk::compress(&raw, self.cfg.zstd_level)?;
        let seg_path = segment_path(&self.cfg.dir, m.nominal_first, m.opened_ms);
        witness_core::util::write_atomic(&seg_path, &zst)?;

        let nominal_last = m.nominal_first.saturating_add(self.cfg.segment_ledgers - 1);
        let in_window = !self.seen.is_empty();
        let (first, last) = if in_window {
            (self.first, self.last)
        } else {
            (0, 0)
        };
        // Coverage spans are contiguous: each one starts right after the
        // previous. A segment with no ledgers from our network is responsible
        // for nothing (an empty span), and the next one continues from the
        // same place.
        let prev_last = self.lineage.map(|l| l.last);
        let (coverage_first, coverage_last) = if in_window {
            // A new lineage is responsible from the first ledger that actually
            // landed in the segment, but not earlier than the reference at
            // open time: below the reference are lagging validators, above it
            // is whatever the median, while switching to this numbering,
            // still assigned to the previous segment.
            let from = match m.coverage_from {
                Some(c) => c.max(first),
                None => prev_last.map_or(first, |p| p.saturating_add(1)),
            };
            (from, last)
        } else {
            let p = prev_last.unwrap_or(0);
            (p.saturating_add(1), p)
        };
        let seal = Seal {
            format: FORMAT.into(),
            source: self.cfg.source.clone(),
            nominal_first: m.nominal_first,
            nominal_last,
            first_ledger: first,
            last_ledger: last,
            records: self.records,
            out_of_window: self.out_of_window,
            coverage_first,
            coverage_last,
            missing_ledgers: missing_ranges(coverage_first, coverage_last, &self.seen),
            opened_ms: m.opened_ms,
            sealed_ms: witness_core::util::now_ms(),
            raw_bytes: raw.len() as u64,
            raw_hash: hex::encode_upper(sha512_half(&raw)),
            prev_seal_hash: self.prev_hash.clone(),
            seal_hash: String::new(),
        }
        .finalize();
        witness_core::util::write_atomic(
            &seal_path(&self.cfg.dir, m.nominal_first, m.opened_ms),
            &serde_json::to_vec_pretty(&seal)?,
        )?;

        // Only now, with the segment and the seal on disk, is the journal no longer needed.
        fs::remove_file(self.cfg.dir.join("current.json"))?;
        fs::remove_file(self.journal.path())?;
        let (journal, _) = Journal::open(&self.cfg.dir.join("current.xwvj"))?;
        self.journal = journal;
        self.open = None;
        self.seen.clear();
        self.records = 0;
        self.out_of_window = 0;
        self.first = u32::MAX;
        self.last = 0;
        self.prev_hash = Some(seal.seal_hash.clone());
        if in_window {
            self.lineage = Some(Lineage {
                last: seal.coverage_last,
                at_ms: seal.sealed_ms,
            });
        }
        Ok(Some(Sealed {
            seal,
            path: seg_path,
            zst_bytes: zst.len() as u64,
        }))
    }
}

fn segment_path(dir: &Path, nominal_first: u32, opened_ms: u64) -> PathBuf {
    dir.join("segments")
        .join(format!("seg-{nominal_first:010}-{opened_ms}.xwv.zst"))
}

fn seal_path(dir: &Path, nominal_first: u32, opened_ms: u64) -> PathBuf {
    dir.join("segments")
        .join(format!("seg-{nominal_first:010}-{opened_ms}.seal.json"))
}

/// The most recently sealed seal in the segments directory.
pub fn latest_seal(segments: &Path) -> Result<Option<Seal>> {
    let mut best: Option<Seal> = None;
    for entry in fs::read_dir(segments)? {
        let path = entry?.path();
        if !path.to_string_lossy().ends_with(".seal.json") {
            continue;
        }
        let seal: Seal = serde_json::from_slice(&fs::read(&path)?)?;
        if !seal.is_intact() {
            return Err(Error::Format(format!(
                "{}: seal is damaged",
                path.display()
            )));
        }
        if best.as_ref().is_none_or(|b| seal.sealed_ms > b.sealed_ms) {
            best = Some(seal);
        }
    }
    Ok(best)
}

/// Decompressed content of a closed segment: what the seal commits to.
pub fn read_segment_raw(path: &Path) -> Result<Vec<u8>> {
    Ok(zstd::stream::decode_all(&fs::read(path)?[..])?)
}

/// The segment matches its seal: the seal is intact and the content is the same.
pub fn verify_segment(path: &Path, seal: &Seal) -> Result<bool> {
    let raw = read_segment_raw(path)?;
    Ok(seal.is_intact()
        && raw.len() as u64 == seal.raw_bytes
        && hex::encode_upper(sha512_half(&raw)) == seal.raw_hash)
}

/// Reads a closed segment in full.
pub fn read_segment(path: &Path) -> Result<Vec<Record>> {
    let raw = read_segment_raw(path)?;
    if !raw.starts_with(MAGIC) {
        return Err(Error::Format(format!(
            "{}: not an xrpl-witness segment",
            path.display()
        )));
    }
    let mut out = Vec::new();
    let mut at = MAGIC.len();
    while let Some((rec, used)) = Record::decode(&raw[at..]).map_err(Error::Format)? {
        out.push(rec);
        at += used;
    }
    if at != raw.len() {
        return Err(Error::Format(format!(
            "{}: trailing data cannot be parsed",
            path.display()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live mainnet has about 85 validations per ledger.
    const PER_LEDGER: u8 = 85;

    fn cfg(dir: &Path) -> SegmentConfig {
        SegmentConfig {
            dir: dir.to_owned(),
            source: "test".into(),
            segment_ledgers: 100,
            grace_ledgers: 5,
            zstd_level: 3,
        }
    }

    fn rec(ledger: u32, n: u8) -> Record {
        Record {
            received_ms: u64::from(ledger) * 1000 + u64::from(n),
            ledger_index: ledger,
            data: vec![n; 233],
        }
    }

    /// Feeds consecutive ledgers, `PER_LEDGER` validations each; collects the seals.
    fn feed(w: &mut SegmentWriter, ledgers: impl Iterator<Item = u32>) -> Vec<Sealed> {
        let mut out = Vec::new();
        for l in ledgers {
            for n in 0..PER_LEDGER {
                if let Some(s) = w.append(&rec(l, n)).unwrap() {
                    out.push(s);
                }
            }
        }
        out
    }

    fn check_chain(seals: &[Sealed]) {
        for pair in seals.windows(2) {
            let (a, b) = (&pair[0].seal, &pair[1].seal);
            assert_eq!(b.prev_seal_hash.as_deref(), Some(a.seal_hash.as_str()));
            // Coverage spans meet with no gaps or overlaps.
            assert_eq!(b.coverage_first, a.coverage_last + 1);
        }
        for s in seals {
            assert!(s.seal.is_intact());
            let back = read_segment(&s.path).unwrap();
            assert_eq!(back.len() as u64, s.seal.records);
            assert!(verify_segment(&s.path, &s.seal).unwrap());
        }
    }

    #[test]
    fn segments_seal_with_a_hash_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let seals = feed(&mut w, 1000..1400);
        assert!(seals.len() >= 3, "seals: {}", seals.len());
        assert_eq!(seals[0].seal.prev_seal_hash, None);
        check_chain(&seals);
        for s in &seals {
            assert!(
                s.seal.missing_ledgers.is_empty(),
                "{:?}",
                s.seal.missing_ledgers
            );
            assert_eq!(s.seal.out_of_window, 0);
        }
        // No record is lost: everything is either in seals or in the open segment.
        let sealed: u64 = seals.iter().map(|s| s.seal.records).sum();
        let open = w.current().map(|c| c.1).unwrap_or(0);
        assert_eq!(sealed + open, 400 * u64::from(PER_LEDGER));
    }

    #[test]
    fn missing_ledgers_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let seals = feed(&mut w, (1000..1250).filter(|l| !(1040..=1042).contains(l)));
        assert_eq!(seals[0].seal.missing_ledgers, vec![[1040, 1042]]);
    }

    #[test]
    fn restart_continues_the_open_segment_and_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let first = {
            let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
            let seals = feed(&mut w, 1000..1160);
            w.sync().unwrap();
            seals
        };
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        assert!(w.current().is_some(), "the open segment should continue");
        let second = feed(&mut w, 1160..1400);
        let all: Vec<Sealed> = first.into_iter().chain(second).collect();
        check_chain(&all);
        for s in &all {
            assert!(
                s.seal.missing_ledgers.is_empty(),
                "{:?}",
                s.seal.missing_ledgers
            );
        }
    }

    #[test]
    fn foreign_network_validations_do_not_derail_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let mut seals = Vec::new();
        let mut foreign = 0u64;
        for l in 1000..1400u32 {
            for n in 0..PER_LEDGER {
                // Like the live stream: ~13% foreign networks, plus rare garbage from the future.
                let ledger = match n {
                    0..=5 => 6_348_163 + l,
                    6..=10 => 21_757_096 + l,
                    11 if l % 50 == 0 => 4_000_000_000,
                    _ => l,
                };
                if ledger != l {
                    foreign += 1;
                }
                if let Some(s) = w.append(&rec(ledger, n)).unwrap() {
                    seals.push(s);
                }
            }
        }
        assert!(seals.len() >= 3);
        check_chain(&seals);
        for s in &seals {
            let s = &s.seal;
            // Slicing follows mainnet; foreign numbers did not throw it off.
            assert!(
                (1000..1400).contains(&s.nominal_first),
                "{}",
                s.nominal_first
            );
            assert!(s.last_ledger < 1400 && s.first_ledger >= 1000);
            assert!(s.missing_ledgers.is_empty(), "{:?}", s.missing_ledgers);
            assert!(s.out_of_window > 0);
        }
        let counted: u64 = seals.iter().map(|s| s.seal.out_of_window).sum();
        assert!(counted <= foreign && counted > 0);
    }

    #[test]
    fn archive_recovers_if_it_started_on_foreign_validations() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        // Worst start: the first few hundred records are all from a foreign network.
        for n in 0..200u32 {
            w.append(&rec(6_348_163 + n / 85, 0)).unwrap();
        }
        let seals = feed(&mut w, 1000..1400);
        assert!(seals.len() >= 3, "seals: {}", seals.len());
        // The first seal may be odd; after that slicing follows mainnet.
        for s in &seals[1..] {
            assert!(
                (1000..1400).contains(&s.seal.nominal_first),
                "{}",
                s.seal.nominal_first
            );
            // Mainnet responsibility started afresh instead of continuing from
            // foreign numbers: no false gaps and no span "from zero".
            assert!(s.seal.coverage_first >= 1000, "{}", s.seal.coverage_first);
            assert!(
                s.seal.missing_ledgers.is_empty(),
                "{:?}",
                s.seal.missing_ledgers
            );
        }
        // Hashes are linked through the whole chain, including the odd first seal.
        assert_eq!(
            seals[1].seal.prev_seal_hash.as_deref(),
            Some(seals[0].seal.seal_hash.as_str())
        );
        check_chain(&seals[1..]);
    }

    #[test]
    fn lagging_validators_do_not_fake_gaps_before_the_start() {
        // Live mainnet, 2026-10-23: some validators lag and send validations
        // dozens of ledgers back. Because of this, the first seal on one of our
        // archivers reported 83 ledgers as missing that the archiver could
        // never have seen.
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let mut seals = Vec::new();
        for l in 1000..1400u32 {
            for n in 0..PER_LEDGER {
                let ledger = if n < 3 { l - 90 } else { l };
                if let Some(s) = w.append(&rec(ledger, n)).unwrap() {
                    seals.push(s);
                }
            }
        }
        assert!(seals.len() >= 3);
        check_chain(&seals);
        assert_eq!(seals[0].seal.coverage_first, 1000);
        // Lagging records are kept and show up in the first/last ledgers.
        assert!(seals[0].seal.first_ledger < 1000);
        for s in &seals {
            assert!(
                s.seal.missing_ledgers.is_empty(),
                "{:?}",
                s.seal.missing_ledgers
            );
        }
    }

    #[test]
    fn restart_after_a_seal_reports_the_downtime() {
        let dir = tempfile::tempdir().unwrap();
        let first = {
            let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
            let seals = feed(&mut w, 1000..1110);
            w.sync().unwrap();
            seals
        };
        // Downtime: nobody recorded ledgers 1110..1120.
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let second = feed(&mut w, 1120..1400);
        let all: Vec<Sealed> = first.into_iter().chain(second).collect();
        check_chain(&all);
        let missing: Vec<[u32; 2]> = all
            .iter()
            .flat_map(|s| s.seal.missing_ledgers.clone())
            .collect();
        assert_eq!(missing, vec![[1110, 1119]]);
    }

    #[test]
    fn leftover_journal_after_crash_mid_seal_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (journal_copy, meta_copy) = {
            let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
            let mut copies = None;
            'outer: for l in 1000..1300 {
                // Snapshot the journal once per ledger: what matters for the check
                // is the description of the sealed segment, not how fresh the
                // journal is.
                w.sync().unwrap();
                let j = fs::read(dir.path().join("current.xwvj")).ok();
                let m = fs::read(dir.path().join("current.json")).ok();
                for n in 0..PER_LEDGER {
                    if w.append(&rec(l, n)).unwrap().is_some() {
                        copies = j.clone().zip(m.clone());
                        break 'outer;
                    }
                }
            }
            copies.unwrap()
        };
        // Crash after writing the seal but before deleting the journal: the
        // journal and the description of the already sealed segment are back
        // on disk.
        fs::write(dir.path().join("current.xwvj"), &journal_copy).unwrap();
        fs::write(dir.path().join("current.json"), &meta_copy).unwrap();

        let w = SegmentWriter::open(cfg(dir.path())).unwrap();
        assert_eq!(w.current(), None, "the sealed journal should be discarded");
        assert!(latest_seal(&dir.path().join("segments")).unwrap().is_some());
    }

    #[test]
    fn recompression_keeps_the_seal_and_tampering_breaks_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let seals = feed(&mut w, 1000..1250);
        let s = &seals[0];

        // Recompressing at another level: different file, same seal.
        let raw = read_segment_raw(&s.path).unwrap();
        let before = fs::read(&s.path).unwrap();
        let again = zstd::bulk::compress(&raw, 19).unwrap();
        assert_ne!(before, again);
        fs::write(&s.path, &again).unwrap();
        assert!(verify_segment(&s.path, &s.seal).unwrap());

        // Changing a single content byte fails the seal check.
        let mut forged = raw.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        fs::write(&s.path, zstd::bulk::compress(&forged, 9).unwrap()).unwrap();
        assert!(!verify_segment(&s.path, &s.seal).unwrap());
    }

    // On the live network mainnet numbers are HIGHER than devnet and testnet
    // numbers, and the tests below reproduce exactly that relationship.
    const MAIN: u32 = 107_000_000;
    const DEVNET: u32 = 6_350_000;

    fn total_missing(seals: &[Sealed]) -> u64 {
        seals
            .iter()
            .flat_map(|s| s.seal.missing_ledgers.iter())
            .map(|[a, b]| u64::from(b - a) + 1)
            .sum()
    }

    /// Consecutive mainnet ledgers, with a batch of `burst` devnet validations at ledger `at`.
    fn feed_with_burst(w: &mut SegmentWriter, at: u32, burst: u32) -> Vec<Sealed> {
        let mut out = Vec::new();
        for l in MAIN..MAIN + 400 {
            if l == MAIN + at {
                for i in 0..burst {
                    if let Some(s) = w.append(&rec(DEVNET + i / 85, 0)).unwrap() {
                        out.push(s);
                    }
                }
            }
            for n in 0..PER_LEDGER {
                if let Some(s) = w.append(&rec(l, n)).unwrap() {
                    out.push(s);
                }
            }
        }
        out
    }

    #[test]
    fn burst_of_foreign_validations_does_not_move_the_reference() {
        // 800 records in a row: six times the old median window.
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let seals = feed_with_burst(&mut w, 150, 800);
        check_chain(&seals);
        for s in &seals {
            assert!(s.seal.nominal_first >= MAIN, "{}", s.seal.nominal_first);
        }
        assert_eq!(total_missing(&seals), 0);
    }

    #[test]
    fn hijack_and_return_does_not_fake_a_gap() {
        // A batch that does knock over the median. This happened on
        // 2026-10-23: a seal reported a hundred million ledgers between the
        // numberings as missing.
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let seals = feed_with_burst(&mut w, 150, 6000);
        assert!(
            seals.iter().any(|s| s.seal.nominal_first < MAIN),
            "the scenario should knock over the median"
        );
        for pair in seals.windows(2) {
            assert_eq!(
                pair[1].seal.prev_seal_hash.as_deref(),
                Some(pair[0].seal.seal_hash.as_str())
            );
        }
        // Gaps are only what really did not reach the mainnet lineage while the
        // reference was off, not everything between the numberings.
        let main: Vec<Sealed> = seals
            .into_iter()
            .filter(|s| s.seal.nominal_first >= MAIN)
            .collect();
        assert!(total_missing(&main) < 100, "{}", total_missing(&main));
        for s in &main {
            assert!(s.seal.coverage_first >= MAIN, "{}", s.seal.coverage_first);
        }
    }

    #[test]
    fn start_on_a_lower_numbered_foreign_network() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SegmentWriter::open(cfg(dir.path())).unwrap();
        let mut seals = Vec::new();
        for i in 0..3000u32 {
            if let Some(s) = w.append(&rec(DEVNET + i / 85, 0)).unwrap() {
                seals.push(s);
            }
        }
        seals.extend(feed(&mut w, MAIN..MAIN + 400));
        let main: Vec<Sealed> = seals
            .into_iter()
            .filter(|s| s.seal.nominal_first >= MAIN)
            .collect();
        assert!(main.len() >= 2);
        // Mainnet responsibility started from mainnet instead of continuing from
        // devnet numbers.
        assert!(
            main[0].seal.coverage_first >= MAIN,
            "{}",
            main[0].seal.coverage_first
        );
        assert_eq!(total_missing(&main), 0);
    }

    #[test]
    fn restart_late_in_a_long_segment_keeps_its_early_ledgers() {
        // 1024-ledger segments, restart 500 ledgers after opening: further from
        // its start than the membership window.
        let dir = tempfile::tempdir().unwrap();
        let long = SegmentConfig {
            segment_ledgers: 1024,
            grace_ledgers: 32,
            ..cfg(dir.path())
        };
        {
            let mut w = SegmentWriter::open(long.clone()).unwrap();
            assert!(feed(&mut w, 2048..2600).is_empty());
            w.sync().unwrap();
        }
        let mut w = SegmentWriter::open(long).unwrap();
        let seals = feed(&mut w, 2600..3300);
        assert_eq!(seals.len(), 1);
        assert_eq!(seals[0].seal.coverage_first, 2048);
        assert!(
            seals[0].seal.missing_ledgers.is_empty(),
            "{:?}",
            seals[0].seal.missing_ledgers
        );
    }
}
