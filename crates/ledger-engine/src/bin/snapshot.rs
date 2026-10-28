//! astraea-snapshot: a snapshot of the full ledger state from xrpld.
//!
//! The ledger loader writes changes; to answer questions about state it needs
//! a starting point, the full state at one ledger. The snapshot is downloaded
//! in parallel by key ranges (`GetLedgerData` with markers), the same way
//! Clio.
//!
//! The whole state is verified: a state tree is built from all objects,
//! and its root must match the header's `AccountHash`. If it does not
//! match, the snapshot is unusable.
//!
//! File: a zstd stream `XWLS\0\1`, the ledger header (118 bytes), then objects
//! in increasing key order: key (32), u32 length, object. Next to it is a `.json` with
//! the verification result.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use ledger_engine::source::Source;
use tracing::{error, info};
use witness_core::ledger::LedgerHeader;
use witness_core::shamap::{root, state_leaf_hash};

#[derive(Debug, Parser)]
#[command(version, about = "Astraea: ledger state snapshot from xrpld")]
struct Args {
    #[arg(long, env = "ASTRAEA_GRPC")]
    grpc: String,
    /// Ledger; defaults to the latest validated one.
    #[arg(long)]
    ledger: Option<u32>,
    /// Snapshot file (.xwls.zst).
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = "astraea")]
    user: String,
    /// How many key ranges to download in parallel.
    #[arg(long, default_value_t = 16)]
    parallel: u8,
    #[arg(long, default_value_t = 9)]
    zstd_level: i32,
}

/// The key minus one: the marker means "strictly greater", so to start a
/// range at key `k` we pass `k − 1`.
fn decrement(mut k: [u8; 32]) -> [u8; 32] {
    for b in k.iter_mut().rev() {
        if *b == 0 {
            *b = 0xFF;
        } else {
            *b -= 1;
            break;
        }
    }
    k
}

/// Range bounds by the first key byte: `[start, end)`; the first has no
/// start, the last has no end.
fn ranges(n: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
    let n = u16::from(n.clamp(1, 128));
    let bound = |i: u16| -> Vec<u8> {
        let mut k = [0u8; 32];
        k[0] = (i * 256 / n) as u8;
        k.to_vec()
    };
    (0..n)
        .map(|i| {
            let start = if i == 0 {
                Vec::new()
            } else {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bound(i));
                decrement(k).to_vec()
            };
            let end = if i + 1 == n { Vec::new() } else { bound(i + 1) };
            (start, end)
        })
        .collect()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    let args = Args::parse();
    if let Err(e) = run(args).await {
        error!("stopped with error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    let t0 = Instant::now();
    let mut source = Source::connect(&args.grpc, &args.user).await?;
    source.require_unlimited().await?;
    let sequence = match args.ledger {
        Some(s) => s,
        None => source.validated().await?,
    };
    let header_raw = source.header(sequence).await?;
    let header = LedgerHeader::parse(&header_raw).map_err(|e| e.to_string())?;
    info!("snapshot of ledger {sequence}, {} ranges", args.parallel);

    // Each range goes to a temporary file; only leaf hashes are kept in memory.
    let tmp_dir = args.out.with_extension("parts");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    let mut tasks = Vec::new();
    for (i, (start, end)) in ranges(args.parallel).into_iter().enumerate() {
        let mut src = source.clone();
        let part = tmp_dir.join(format!("{i:03}"));
        tasks.push(tokio::spawn(async move {
            let mut w = BufWriter::new(File::create(&part).map_err(|e| e.to_string())?);
            let mut leaves = Vec::new();
            let mut marker = start;
            loop {
                let (objs, next) = src.state_page(sequence, &marker, &end).await?;
                for (key, data) in objs {
                    leaves.push((key, state_leaf_hash(&data, &key)));
                    w.write_all(&key).map_err(|e| e.to_string())?;
                    w.write_all(&(data.len() as u32).to_le_bytes())
                        .map_err(|e| e.to_string())?;
                    w.write_all(&data).map_err(|e| e.to_string())?;
                }
                if next.is_empty() {
                    break;
                }
                marker = next;
            }
            w.flush().map_err(|e| e.to_string())?;
            Ok::<_, String>((part, leaves))
        }));
    }
    let mut parts = Vec::new();
    let mut leaves = Vec::new();
    for t in tasks {
        let (part, l) = t.await.map_err(|e| e.to_string())??;
        parts.push(part);
        leaves.extend(l);
    }
    let objects = leaves.len();
    let computed = root(&leaves);
    drop(leaves);
    let matches = computed == header.account_hash;
    info!(
        "{objects} objects, downloaded in {:.0} s; state root {}",
        t0.elapsed().as_secs_f64(),
        if matches {
            "matches AccountHash"
        } else {
            "does NOT match"
        }
    );

    // Assemble the file: the parts are already in increasing key order.
    let out = File::create(&args.out).map_err(|e| e.to_string())?;
    let mut z = zstd::Encoder::new(out, args.zstd_level).map_err(|e| e.to_string())?;
    z.write_all(b"XWLS\x00\x01").map_err(|e| e.to_string())?;
    z.write_all(&header_raw).map_err(|e| e.to_string())?;
    let mut raw_bytes = 0u64;
    for p in &parts {
        let mut buf = Vec::new();
        File::open(p)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|e| e.to_string())?;
        raw_bytes += buf.len() as u64;
        z.write_all(&buf).map_err(|e| e.to_string())?;
    }
    z.finish().map_err(|e| e.to_string())?;
    std::fs::remove_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    let zst_bytes = std::fs::metadata(&args.out)
        .map_err(|e| e.to_string())?
        .len();
    let summary = format!(
        "{{\"ledger\":{sequence},\"ledger_hash\":\"{}\",\"account_hash\":\"{}\",\"objects\":{objects},\"raw_bytes\":{raw_bytes},\"zst_bytes\":{zst_bytes},\"state_root_matches\":{matches},\"seconds\":{:.1}}}\n",
        hex::encode_upper(header.hash()),
        hex::encode_upper(header.account_hash),
        t0.elapsed().as_secs_f64()
    );
    std::fs::write(args.out.with_extension("json"), &summary).map_err(|e| e.to_string())?;
    print!("{summary}");
    if !matches {
        return Err("state root does not match the header, snapshot is unusable".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_cover_the_keyspace_without_gaps() {
        let r = ranges(16);
        assert_eq!(r.len(), 16);
        assert!(r[0].0.is_empty() && r[15].1.is_empty());
        for w in r.windows(2) {
            // The start of the next range is one less than the end of the previous one:
            // "strictly greater" and "strictly less" meet without gaps.
            let mut end: [u8; 32] = w[0].1.as_slice().try_into().unwrap();
            end = decrement(end);
            assert_eq!(w[1].0, end.to_vec());
        }
        assert_eq!(decrement([0; 32]), [0xFF; 32]);
    }
}
