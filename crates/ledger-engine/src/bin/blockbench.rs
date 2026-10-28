//! astraea-blockbench: benchmarks the block store on a history corpus.
//!
//! The corpus is an XWHL container (see corpus/README.md): consecutive ledgers,
//! header and transactions with metadata. For each variant (block size,
//! dictionary) it writes the store and measures: size on disk with all indexes and the
//! dictionary, write time, random ledger read latency; then it
//! restores all ledgers and compares them byte for byte with the source, checking
//! each one's transaction tree.
//!
//! The corpus is read as a stream and not held in memory.

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Parser;
use ledger_engine::blocks::{BlockReader, BlockWriter, train_dictionary};
use ledger_engine::ledger::Ledger;

#[derive(Debug, Parser)]
#[command(about = "Astraea: block store benchmark on a history corpus")]
struct Args {
    /// Corpus .xwhl.zst.
    corpus: PathBuf,
    /// Working directory for the variants.
    #[arg(long)]
    work: PathBuf,
    /// Block sizes, comma-separated.
    #[arg(long, value_delimiter = ',', default_value = "1,8,32,128")]
    blocks: Vec<u32>,
    #[arg(long, default_value_t = 9)]
    level: i32,
    /// How many leading ledgers to use for dictionary training.
    #[arg(long, default_value_t = 1024)]
    train: usize,
    #[arg(long, default_value_t = 112_640)]
    dict_size: usize,
    /// How many random reads to measure.
    #[arg(long, default_value_t = 5000)]
    reads: usize,
}

/// Stream of corpus ledgers: sequence and Ledger serialization (without state
/// changes, which the corpus does not have).
fn corpus(path: &Path) -> Result<impl Iterator<Item = Result<(u32, Vec<u8>), String>>, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut r = BufReader::new(zstd::Decoder::new(f).map_err(|e| e.to_string())?);
    let mut magic = [0u8; 6];
    r.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if &magic != b"XWHL\x00\x01" {
        return Err("not an XWHL corpus".into());
    }
    let u32le = |r: &mut dyn Read| -> std::io::Result<u32> {
        let mut b = [0u8; 4];
        r.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    };
    Ok(std::iter::from_fn(move || {
        let seq = match u32le(&mut r) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e.to_string())),
        };
        let mut one = || -> std::io::Result<(u32, Vec<u8>)> {
            let hl = u32le(&mut r)? as usize;
            let mut header = vec![0u8; hl];
            r.read_exact(&mut header)?;
            let n = u32le(&mut r)?;
            let mut transactions = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let l = u32le(&mut r)? as usize;
                let mut tx = vec![0u8; l];
                r.read_exact(&mut tx)?;
                let l = u32le(&mut r)? as usize;
                let mut meta = vec![0u8; l];
                r.read_exact(&mut meta)?;
                transactions.push((tx, meta));
            }
            let l = Ledger {
                header,
                transactions,
                changes: Vec::new(),
            };
            Ok((seq, l.encode()))
        };
        Some(one().map_err(|e| e.to_string()))
    }))
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.work).map_err(|e| e.to_string())?;

    // Dictionary training on the first ledgers, and the raw corpus size.
    let mut samples = Vec::new();
    let (mut raw_bytes, mut ledgers, mut first) = (0u64, 0u32, None);
    for item in corpus(&args.corpus)? {
        let (seq, l) = item?;
        first.get_or_insert(seq);
        raw_bytes += l.len() as u64;
        ledgers += 1;
        if samples.len() < args.train {
            samples.push(l);
        }
    }
    let first = first.ok_or("empty corpus")?;
    let t = Instant::now();
    let dict = train_dictionary(&samples, args.dict_size)?;
    drop(samples);
    println!(
        "corpus: {ledgers} ledgers from {first}, {raw_bytes} bytes; dictionary {} bytes in {:.1} s",
        dict.len(),
        t.elapsed().as_secs_f64()
    );
    println!(
        "| block | dictionary | on disk, bytes | bytes/ledger | compression | write, s | read p50/p95/p99, ms | restored |"
    );
    println!("|---:|---|---:|---:|---:|---:|---|---|");

    for &block in &args.blocks {
        for use_dict in [false, true] {
            let dir = args.work.join(format!(
                "b{block}-{}",
                if use_dict { "dict" } else { "plain" }
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let t = Instant::now();
            let mut w = BlockWriter::create(
                &dir,
                first,
                block,
                args.level,
                use_dict.then(|| dict.clone()),
            )?;
            for item in corpus(&args.corpus)? {
                let (seq, l) = item?;
                w.append(seq, l)?;
            }
            w.finish()?;
            let write_s = t.elapsed().as_secs_f64();

            let r = BlockReader::open(&dir)?;
            let disk = r.bytes_on_disk(&dir);
            // Random reads use a deterministic sequence.
            let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
            let mut lat = Vec::with_capacity(args.reads);
            for _ in 0..args.reads {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let seq = first + (x % u64::from(ledgers)) as u32;
                let t = Instant::now();
                r.get(seq)?.ok_or("ledger not found")?;
                lat.push(t.elapsed().as_secs_f64() * 1000.0);
            }
            lat.sort_by(f64::total_cmp);

            // Restore the whole corpus byte for byte, checking the tree.
            let mut ok = 0u32;
            for item in corpus(&args.corpus)? {
                let (seq, l) = item?;
                let back = r.get(seq)?.ok_or("ledger not found")?;
                if back != l {
                    return Err(format!("ledger {seq}: bytes do not match"));
                }
                Ledger::decode(&back)?.verify()?;
                ok += 1;
            }
            println!(
                "| {block} | {} | {disk} | {:.0} | {:.2} | {write_s:.0} | {:.2} / {:.2} / {:.2} | {ok} of {ledgers} |",
                if use_dict { "yes" } else { "no" },
                disk as f64 / f64::from(ledgers),
                raw_bytes as f64 / disk as f64,
                percentile(&lat, 0.5),
                percentile(&lat, 0.95),
                percentile(&lat, 0.99),
            );
            std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
