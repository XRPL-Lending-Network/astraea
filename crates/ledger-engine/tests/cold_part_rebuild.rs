//! Rebuilding the parts of cold blocks after they were evicted, on a real
//! mainnet ledger (107 855 813, 511 transactions).
//!
//! The sample ledger is copied into a short chain (the same transactions,
//! consecutive sequences, each header naming the previous one as parent), its
//! state changes are the ones its metadata gives, and `cold::write` stores the
//! chain as a segment of JC06 blocks with the default limits. A pool with a
//! budget of one byte keeps only the block read last, so reading the chain
//! again in order prepares every block again and compiles every part again:
//! the reads after the first are the rebuilds a busy server does under
//! concurrent cold reads.
//!
//! `bench_rebuild` (ignored; run with `--release -- --ignored bench_rebuild`)
//! times those rebuilds and adds one run to the JSON file named by
//! `BENCH307_OUT`: `commit` (from `BENCH307_COMMIT`), `date`, `host`, `runs`,
//! `runs_ns`, `median_ns` and `answers_sha256` (SHA-256 of every row read in
//! one pass). A run whose answers, commit or host differ from the file's is
//! refused and the file is left as it was.

// Test code: a panic on unexpected data is exactly a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use astraea_journal_codec::Row;
use astraea_journal_codec::pool::Pool;
use ledger_engine::cold::{self, Kinds};
use ledger_engine::coldpatch;
use ledger_engine::ledger::{Change, Ledger, StateChange};
use sha2::{Digest, Sha256};
use witness_core::ledger::{HEADER_LEN, LedgerHeader};

const SAMPLE: &[u8] = include_bytes!("../../witness-core/tests/fixtures/ledger-107855813.xwtl.zst");
/// Ledgers in the test chain and in the benchmark's.
const TEST_LEDGERS: usize = 16;
const BENCH_LEDGERS: usize = 48;
/// Timed passes over the chain in one benchmark run.
const BENCH_PASSES: usize = 5;
const SEAL_ERROR: &str = "part does not match its seal";
/// Transactions with their metadata.
type Txs = Vec<(Vec<u8>, Vec<u8>)>;

fn take<'a>(b: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, rest) = b.split_at(n);
    *b = rest;
    head
}

fn u32le(b: &mut &[u8]) -> usize {
    u32::from_le_bytes(take(b, 4).try_into().unwrap()) as usize
}

/// Header and transactions of the sample (format in `witness-core`'s
/// `tx_inclusion` test): magic, header, ledger hash and transaction root from
/// Clio, the count, then for each transaction its Clio hash, tx and metadata.
fn sample() -> (Vec<u8>, Txs) {
    let raw = zstd::decode_all(SAMPLE).unwrap();
    let mut b = &raw[..];
    assert_eq!(take(&mut b, 6), b"XWTL\x00\x01");
    let header = take(&mut b, HEADER_LEN).to_vec();
    take(&mut b, 64);
    let n = u32le(&mut b);
    let txs = (0..n)
        .map(|_| {
            take(&mut b, 32);
            let len = u32le(&mut b);
            let tx = take(&mut b, len).to_vec();
            let len = u32le(&mut b);
            (tx, take(&mut b, len).to_vec())
        })
        .collect();
    assert!(b.is_empty());
    (header, txs)
}

/// `n` consecutive ledgers with the sample's transactions, chained by parent
/// hash, with the state changes the metadata gives (the stored form's
/// "derived" marker with threaded directories and nothing else).
fn chain(n: usize) -> Vec<Ledger> {
    let (mut header, txs) = sample();
    let first = LedgerHeader::parse(&header).unwrap().sequence;
    let mut out = Vec::with_capacity(n);
    for k in 0..n {
        let seq = first + k as u32;
        header[..4].copy_from_slice(&seq.to_be_bytes());
        if let Some(prev) = out.last() {
            let prev: &Ledger = prev;
            header[12..44].copy_from_slice(&prev.header().unwrap().hash());
        }
        let patches = coldpatch::restore(&txs, seq, &[([0; 32], vec![0xFC, 1])]).unwrap();
        let changes = patches
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
            .collect();
        let l = Ledger {
            header: header.clone(),
            transactions: txs.clone(),
            changes,
        };
        l.verify().unwrap();
        out.push(l);
    }
    out
}

/// One block of the archive: first ledger, ledger count, offset and length
/// of its stored bytes (the front directory: magic, u32 count, then 56 bytes
/// per block).
struct Block {
    first: u32,
    count: usize,
    offset: usize,
    length: usize,
}

fn blocks(archive: &[u8]) -> Vec<Block> {
    let n = u32::from_le_bytes(archive[8..12].try_into().unwrap()) as usize;
    (0..n)
        .map(|i| {
            let e = &archive[12 + 56 * i..12 + 56 * (i + 1)];
            Block {
                first: u32::from_le_bytes(e[..4].try_into().unwrap()),
                count: u32::from_le_bytes(e[4..8].try_into().unwrap()) as usize,
                offset: u64::from_le_bytes(e[8..16].try_into().unwrap()) as usize,
                length: u64::from_le_bytes(e[16..24].try_into().unwrap()) as usize,
            }
        })
        .collect()
}

/// Parts of a JC06 block (payload mode 2, then the u32 part count after the
/// two u64 sizes of the shared section).
fn parts(archive: &[u8], b: &Block) -> usize {
    let p = &archive[b.offset..b.offset + b.length];
    assert_eq!(p[0], 2, "blocks are JC06");
    u32::from_le_bytes(p[17..21].try_into().unwrap()) as usize
}

/// A segment of `n` chained ledgers in a directory that is kept if the test
/// fails. Returns the directory, the archive path and the rows as stored.
fn segment(n: usize) -> (PathBuf, PathBuf, Vec<Row>) {
    let dir = tempfile::tempdir().unwrap().keep();
    eprintln!("segment directory: {}", dir.display());
    let ledgers = chain(n);
    let m = cold::write(&dir, &ledgers, Kinds::Explicit).unwrap();
    let first = m["first"].as_u64().unwrap();
    let path = dir.join(format!("cold-{first:010}.astj"));
    let rows = ledgers
        .iter()
        .map(|l| {
            let mut r = cold::row_of(l).unwrap();
            r.patches = coldpatch::compact(&r);
            r
        })
        .collect();
    (dir, path, rows)
}

fn row_bytes(r: &Row, out: &mut Vec<u8>) {
    out.extend(r.seq.to_le_bytes());
    out.extend((r.header.len() as u32).to_le_bytes());
    out.extend(&r.header);
    out.extend((r.txs.len() as u32).to_le_bytes());
    for (t, m) in &r.txs {
        out.extend((t.len() as u32).to_le_bytes());
        out.extend(t);
        out.extend((m.len() as u32).to_le_bytes());
        out.extend(m);
    }
    out.extend((r.patches.len() as u32).to_le_bytes());
    for (k, v) in &r.patches {
        out.extend(k);
        out.extend((v.len() as u32).to_le_bytes());
        out.extend(v);
    }
}

/// A pool over `path` with the seal taken from the archive itself and a
/// budget that keeps only the block read last.
fn sealed_pool(path: &Path) -> Pool {
    let seal = Pool::open(path, 0, 1).unwrap().seal(2).unwrap();
    let mut pool = Pool::open(path, 1, 1).unwrap();
    pool.set_seal(seal).unwrap();
    pool
}

/// Every ledger of the chain in order: the bytes of each row.
fn pass(pool: &Pool, rows: &[Row]) -> Vec<Vec<u8>> {
    rows.iter()
        .map(|r| {
            let got = pool.ledger(r.seq).unwrap();
            let mut b = vec![];
            row_bytes(&got, &mut b);
            b
        })
        .collect()
}

#[test]
fn repeat_rebuild_same_bytes() {
    let (dir, path, rows) = segment(TEST_LEDGERS);
    let archive = std::fs::read(&path).unwrap();
    let bs = blocks(&archive);
    assert!(bs.len() >= 2, "the chain spans several blocks");
    assert!(
        bs.iter().any(|b| parts(&archive, b) >= 2),
        "some block has several parts"
    );
    let want: Vec<Vec<u8>> = rows
        .iter()
        .map(|r| {
            let mut b = vec![];
            row_bytes(r, &mut b);
            b
        })
        .collect();
    let pool = sealed_pool(&path);
    let first = pass(&pool, &rows);
    assert_eq!(first, want, "first build gives the stored rows");
    // Each pass prepares every block again: only the block read last stays.
    for round in 0..2 {
        assert_eq!(pass(&pool, &rows), first, "rebuild {round}");
    }
    // Out of order too: back to front, so the neighbour is never cached.
    for r in rows.iter().rev() {
        let mut b = vec![];
        row_bytes(&pool.ledger(r.seq).unwrap(), &mut b);
        assert_eq!(b, want[(r.seq - rows[0].seq) as usize]);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tampered_part_rejected() {
    let (dir, path, rows) = segment(TEST_LEDGERS);
    let mut archive = std::fs::read(&path).unwrap();
    let bs = blocks(&archive);
    let b = bs
        .iter()
        .find(|b| parts(&archive, b) >= 2)
        .expect("a block with several parts");
    let seal = Pool::open(&path, 0, 1).unwrap().seal(2).unwrap();
    // The last byte of the block is in its last part.
    archive[b.offset + b.length - 1] ^= 1;
    std::fs::write(&path, &archive).unwrap();
    let mut pool = Pool::open(&path, 1, 1).unwrap();
    pool.set_seal(seal.clone()).unwrap();
    let last = b.first + b.count as u32 - 1;
    let mut bad = 0;
    for seq in b.first..=last {
        match pool.ledger(seq) {
            Ok(r) => assert_eq!(r, rows[(seq - rows[0].seq) as usize]),
            Err(e) => {
                assert!(e.contains(SEAL_ERROR), "{e}");
                bad += 1;
            }
        }
    }
    assert!(bad >= 1 && bad < b.count, "only the last part fails");
    // Again after another block evicted this one, and a second time in a row.
    let other = bs.iter().find(|o| o.first != b.first).unwrap();
    pool.ledger(other.first).unwrap();
    for _ in 0..2 {
        let e = pool.ledger(last).unwrap_err();
        assert!(e.contains(SEAL_ERROR), "{e}");
    }
    // A fresh pool rejects it on first use.
    let mut fresh = Pool::open(&path, 1, 1).unwrap();
    fresh.set_seal(seal).unwrap();
    let e = fresh.ledger(last).unwrap_err();
    assert!(e.contains(SEAL_ERROR), "{e}");
    std::fs::remove_dir_all(dir).unwrap();
}

fn median(v: &[u64]) -> u64 {
    let mut s = v.to_vec();
    s.sort_unstable();
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2
    }
}

/// UTC date and time of now, `YYYY-MM-DDTHH:MM:SSZ`.
fn now_utc() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (days, rem) = ((t / 86_400) as i64, t % 86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

fn host() -> String {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    format!(
        "{} ({})",
        read("/proc/sys/kernel/hostname"),
        read("/proc/sys/kernel/osrelease")
    )
}

#[test]
#[ignore = "benchmark: run with --release -- --ignored bench_rebuild"]
fn bench_rebuild() {
    let out = PathBuf::from(std::env::var("BENCH307_OUT").expect("BENCH307_OUT"));
    let commit = std::env::var("BENCH307_COMMIT").expect("BENCH307_COMMIT");
    let note = std::env::var("BENCH307_NOTE").unwrap_or_default();
    let (dir, path, rows) = segment(BENCH_LEDGERS);
    let archive = std::fs::read(&path).unwrap();
    let bs = blocks(&archive);
    let n_parts: usize = bs.iter().map(|b| parts(&archive, b)).sum();
    let pool = sealed_pool(&path);
    // The first pass checks every part against the seal; it is not timed.
    let first = pass(&pool, &rows);
    let mut answers = Sha256::new();
    for b in &first {
        answers.update(b);
    }
    let answers = hex::encode(answers.finalize());
    let start = Instant::now();
    for _ in 0..BENCH_PASSES {
        assert_eq!(pass(&pool, &rows), first);
    }
    let ns = start.elapsed().as_nanos() as u64;
    std::fs::remove_dir_all(dir).unwrap();

    let host = host();
    let mut doc = match std::fs::read(&out) {
        Ok(b) => serde_json::from_slice::<serde_json::Value>(&b).unwrap(),
        Err(_) => serde_json::json!({
            "commit": commit,
            "date": now_utc(),
            "host": host,
            "answers_sha256": answers,
            "runs_ns": [],
            "run_dates": [],
        }),
    };
    for (k, v) in [
        ("commit", &commit),
        ("host", &host),
        ("answers_sha256", &answers),
    ] {
        assert_eq!(
            doc[k].as_str(),
            Some(v.as_str()),
            "{k} differs from {}; the file is left as it was",
            out.display()
        );
    }
    doc["runs_ns"].as_array_mut().unwrap().push(ns.into());
    doc["run_dates"]
        .as_array_mut()
        .unwrap()
        .push(now_utc().into());
    let runs: Vec<u64> = doc["runs_ns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    doc["runs"] = runs.len().into();
    doc["median_ns"] = median(&runs).into();
    doc["what"] = format!(
        "time of {BENCH_PASSES} passes reading every ledger of a {BENCH_LEDGERS}-ledger chain \
         of ledger 107855813 ({} blocks, {n_parts} parts) through a pool that keeps one block, \
         so every pass prepares every block and compiles every part again; the first pass \
         (seal check) is not timed",
        bs.len()
    )
    .into();
    if !note.is_empty() {
        doc["note"] = note.into();
    }
    let tmp = out.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    std::fs::rename(&tmp, &out).unwrap();
    eprintln!("run {}: {ns} ns, answers {answers}", runs.len());
}
