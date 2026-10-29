//! astraea-partbench: JC06 blocks (cut into parts read on their own) against
//! the ASTJ5 blocks of a live cold segment.
//!
//! `encode` writes the segment's ledgers again with the given part sizes and
//! prints the archive sizes; `read` times one transaction read from a block
//! that is not cached, every 16th ledger, the way account_tx reads it. Run
//! `read` in a process of its own: one holding a whole segment in memory reads
//! slower. The seal is kept next to the archive between runs.

use std::path::{Path, PathBuf};
use std::time::Instant;

use astraea_journal_codec::{Options, Row, pack_bounded, pool::Pool};
use clap::{Parser, Subcommand};
use ledger_engine::cold::{BLOCK_LEDGERS, BLOCK_RAW, canonical};

type Res<T> = Result<T, String>;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode segment `first` of `cold` with each part size into `out`.
    Encode {
        cold: PathBuf,
        first: u32,
        out: PathBuf,
        #[arg(required = true)]
        parts: Vec<usize>,
    },
    /// Cold reads of one transaction from `archive`, `rounds` times over.
    Read {
        archive: PathBuf,
        #[arg(long, default_value_t = 1)]
        rounds: usize,
    },
}

fn encode(cold: &Path, first: u32, out: &Path, parts: &[usize]) -> Res<()> {
    let src = cold.join(format!("cold-{first:010}.astj"));
    let size = std::fs::metadata(&src).map_err(|e| e.to_string())?.len() as f64;
    let pool = Pool::open(&src, 2 << 30, 8)?;
    let mut rows: Vec<Row> = vec![];
    while let Ok(r) = pool.ledger(first + rows.len() as u32) {
        rows.push(r);
    }
    drop(pool);
    println!(
        "segment {first}: {} ledgers, ASTJ5 {:.1} MB",
        rows.len(),
        size / 1e6
    );
    for &part_raw in parts {
        let t = Instant::now();
        let opt = Options {
            part_raw,
            ..canonical()
        };
        let (archive, stats) = pack_bounded(&rows, BLOCK_LEDGERS, BLOCK_RAW, opt)?;
        let sum =
            |f: fn(&astraea_journal_codec::Stats) -> usize| stats.iter().map(f).sum::<usize>();
        let path = out.join(format!("cold-{first:010}-{part_raw}.astj"));
        std::fs::write(&path, &archive).map_err(|e| e.to_string())?;
        println!(
            "  parts up to {:>4} KiB: {:.1} MB ({:+.1}%), {} parts in {} blocks, shared sections {:.0}% of the decoded bytes, encoded in {:.0} s",
            part_raw >> 10,
            archive.len() as f64 / 1e6,
            (archive.len() as f64 / size - 1.0) * 100.0,
            sum(|s| s.parts),
            stats.len(),
            sum(|s| s.shared_bytes) as f64 * 100.0 / sum(|s| s.inner_bytes).max(1) as f64,
            t.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

fn read(archive: &Path, rounds: usize) -> Res<()> {
    let cache = archive.with_extension("seal-cache");
    let seal: Vec<Vec<[u8; 32]>> = match std::fs::read(&cache) {
        Ok(b) => serde_json::from_slice::<Vec<Vec<String>>>(&b)
            .map_err(|e| e.to_string())?
            .iter()
            .map(|d| {
                d.iter()
                    .map(|x| {
                        hex::decode(x)
                            .ok()
                            .and_then(|v| v.try_into().ok())
                            .ok_or("seal cache")
                    })
                    .collect::<Result<_, _>>()
            })
            .collect::<Result<_, _>>()?,
        Err(_) => {
            let s = Pool::open(archive, 0, 1)?.seal(8)?;
            let j: Vec<Vec<String>> = s
                .iter()
                .map(|d| d.iter().map(hex::encode).collect())
                .collect();
            std::fs::write(&cache, serde_json::to_vec(&j).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            s
        }
    };
    // A cache of one byte keeps only the last block, and the next ledger read
    // is in another one.
    let mut pool = Pool::open(archive, 1, 1)?;
    pool.set_seal(seal)?;
    let first = pool.first().ok_or("empty archive")?;
    let mut seqs = vec![];
    while pool.header(first + seqs.len() as u32 * 16).is_ok() {
        seqs.push(first + seqs.len() as u32 * 16);
    }
    let t = Instant::now();
    let mut found = 0;
    for _ in 0..rounds {
        for &seq in &seqs {
            found += usize::from(pool.tx_with_index(seq, 0)?.is_some());
        }
    }
    let n = seqs.len() * rounds;
    println!(
        "{}: {:.2} ms per transaction, {found} of {n} found",
        archive.display(),
        t.elapsed().as_secs_f64() * 1e3 / n.max(1) as f64
    );
    Ok(())
}

fn main() -> Res<()> {
    match Args::parse().command {
        Command::Encode {
            cold,
            first,
            out,
            parts,
        } => encode(&cold, first, &out, &parts),
        Command::Read { archive, rounds } => read(&archive, rounds),
    }
}
