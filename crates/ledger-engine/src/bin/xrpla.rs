//! astraea-xrpla: full history from the XRPLA publication, verified on our
//! side.
//!
//! - `catalog`: the current signed catalog. Ed25519 signature with the pinned
//!   publisher key, SHA-256 from the pointer; summary of ranges.
//! - `fetch --from A --to B --out file`: only the needed segments, via range
//!   requests. The directory is checked against the catalog, the segment against
//!   the directory, pages and segment against digests of the canonical bytes,
//!   each ledger against its transaction root and parent chain, range edges
//!   against hashes from the catalog. Output is an `XWCP` corpus: ledgers in
//!   `Ledger` serialization together with object changes.
//!
//! Default key and URL come from `config/publications.toml` in the XRPLA project
//! (publication `xrpla-mainnet`).

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use witness_core::ledger::LedgerHeader;

use ledger_engine::xrpla::{Directory, Segment, sha256};

const URL: &str = "https://xrpla-data.firstledger.net/mainnet";
const KEY: &str = "1b4adf5cccad231179f5eaad2ede3f1927908d9cee0966f0b559a617264e6ce6";
/// Corpus: magic, then ledgers (u32 length, `Ledger::encode`).
pub const CORPUS_MAGIC: &[u8; 6] = b"XWCP\x00\x01";

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = URL)]
    url: String,
    /// Publisher's Ed25519 public key, hex.
    #[arg(long, default_value = KEY)]
    key: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Catalog,
    Fetch {
        #[arg(long)]
        from: u32,
        #[arg(long)]
        to: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare the corpus against an independent source, our loader's blocks
    /// (format 1, with full objects): transactions, metadata and object changes,
    /// byte for byte.
    Compare {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        blocks: PathBuf,
    },
}

type Res<T> = Result<T, String>;

fn compare(corpus: &std::path::Path, blocks: &std::path::Path) -> Res<()> {
    let b = std::fs::read(corpus).map_err(e)?;
    let rest = b
        .strip_prefix(CORPUS_MAGIC.as_slice())
        .ok_or("not an XWCP corpus")?;
    let reader = ledger_engine::blocks::BlockReader::open(blocks)?;
    let (mut at, mut n, mut changes) = (0, 0, 0);
    while at < rest.len() {
        let len = u32::from_le_bytes(rest[at..at + 4].try_into().map_err(e)?) as usize;
        let ours = ledger_engine::ledger::Ledger::decode(&rest[at + 4..at + 4 + len])?;
        at += 4 + len;
        let seq = ours.header()?.sequence;
        let theirs = ledger_engine::ledger::Ledger::decode(
            &reader
                .get(seq)?
                .ok_or(format!("ledger {seq} not found in blocks"))?,
        )?;
        if ours.header != theirs.header || ours.transactions != theirs.transactions {
            return Err(format!("{seq}: transactions or header differ"));
        }
        let mut a: Vec<_> = ours.changes.iter().map(|c| (c.key, &c.data)).collect();
        let mut t: Vec<_> = theirs.changes.iter().map(|c| (c.key, &c.data)).collect();
        a.sort();
        t.sort();
        if a != t {
            return Err(format!(
                "{seq}: object changes differ ({} vs {})",
                a.len(),
                t.len()
            ));
        }
        n += 1;
        changes += a.len();
    }
    println!("matches loader blocks: {n} ledgers, {changes} object changes byte for byte");
    Ok(())
}

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

struct Http {
    agent: ureq::Agent,
    base: String,
}

impl Http {
    /// One object or byte range. Dropped connections, timeouts, 5xx answers
    /// and short ranges are retried with a growing pause: the publication
    /// server sometimes cuts long transfers, and one cut segment shouldn't
    /// cost the whole chunk. Contents are checked by digest afterwards anyway.
    fn get(&self, path: &str, range: Option<(u64, u64)>) -> Res<Vec<u8>> {
        const PAUSES: [u64; 5] = [5, 15, 30, 60, 120];
        let mut attempt = 0;
        loop {
            match self.get_once(path, range) {
                Ok(b) => return Ok(b),
                Err((err, retry)) if retry && attempt < PAUSES.len() => {
                    eprintln!("{err}; retrying in {} s", PAUSES[attempt]);
                    std::thread::sleep(std::time::Duration::from_secs(PAUSES[attempt]));
                    attempt += 1;
                }
                Err((err, _)) => return Err(err),
            }
        }
    }

    /// One attempt; the flag says whether the failure is worth retrying.
    fn get_once(&self, path: &str, range: Option<(u64, u64)>) -> Result<Vec<u8>, (String, bool)> {
        let url = format!("{}/{path}", self.base);
        let mut req = self.agent.get(&url);
        if let Some((a, b)) = range {
            req = req.header("Range", &format!("bytes={a}-{}", b - 1));
        }
        let mut resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::StatusCode(code)) => {
                return Err((format!("{url}: HTTP {code}"), code >= 500));
            }
            Err(x) => return Err((format!("{url}: {x}"), true)),
        };
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(1 << 30)
            .read_to_vec()
            .map_err(|x| (format!("{url}: {x}"), true))?;
        if let Some((a, b)) = range
            && (status != 206 || body.len() as u64 != b - a)
        {
            return Err((format!("{url}: range request not honored ({status})"), true));
        }
        Ok(body)
    }
}

fn hex32(v: &Value) -> Res<[u8; 32]> {
    hex::decode(v.as_str().ok_or("not a string")?)
        .map_err(e)?
        .try_into()
        .map_err(|_| "not 32 bytes".to_string())
}

/// Catalog, verified by signature and by the pointer's SHA-256.
fn catalog(h: &Http, key: &str) -> Res<Value> {
    let ptr: Value = serde_json::from_slice(&h.get("catalog/current.json", None)?).map_err(e)?;
    let object = ptr["object"].as_str().ok_or("pointer without object")?;
    let body = h.get(object, None)?;
    if sha256(&body) != hex32(&ptr["sha256"])? {
        return Err("catalog does not match the pointer hash".into());
    }
    let sig = h.get(&format!("{object}.sig"), None)?;
    let vk = VerifyingKey::from_bytes(
        &hex::decode(key)
            .map_err(e)?
            .try_into()
            .map_err(|_| "key is not 32 bytes")?,
    )
    .map_err(e)?;
    vk.verify(&body, &Signature::from_slice(&sig).map_err(e)?)
        .map_err(|_| "catalog signature does not match the publisher key")?;
    let c: Value = serde_json::from_slice(&body).map_err(e)?;
    if c["format"] != "xrpla-catalog-v1" || c["codec"]["format"] != "xrph-v2" {
        return Err("unsupported catalog or codec format".into());
    }
    Ok(c)
}

fn ranges(c: &Value) -> Vec<&Value> {
    let mut v: Vec<&Value> = c["ranges"].as_array().into_iter().flatten().collect();
    v.extend(c["tail"]["ranges"].as_array().into_iter().flatten());
    v
}

fn main() -> Res<()> {
    let a = Args::parse();
    let h = Http {
        agent: ureq::Agent::config_builder()
            // A segment is up to 512 MB and parallel downloads share the link:
            // 10 minutes per request was not enough.
            .timeout_global(Some(std::time::Duration::from_secs(1800)))
            .user_agent(concat!("astraea-xrpla/", env!("CARGO_PKG_VERSION")))
            .build()
            .into(),
        base: a.url.trim_end_matches('/').to_string(),
    };
    if let Command::Compare { corpus, blocks } = &a.command {
        return compare(corpus, blocks);
    }
    let c = catalog(&h, &a.key)?;
    match a.command {
        Command::Compare { .. } => unreachable!("handled above"),
        Command::Catalog => {
            let rs = ranges(&c);
            let bytes: u64 = rs.iter().filter_map(|r| r["size"].as_u64()).sum();
            let txs: u64 = rs.iter().filter_map(|r| r["transactions"].as_u64()).sum();
            println!(
                "catalog {} from {}: signature OK; {} ranges, ledgers {}…{}, {:.3} TB, {txs} transactions",
                c["generation"],
                c["published_at"],
                rs.len(),
                rs.first().map_or(Value::Null, |r| r["first"].clone()),
                rs.last().map_or(Value::Null, |r| r["last"].clone()),
                bytes as f64 / 1e12
            );
        }
        Command::Fetch { from, to, out } => {
            if to < from {
                return Err(format!("empty range {from}…{to}"));
            }
            let mut f = std::fs::File::create(&out).map_err(e)?;
            f.write_all(CORPUS_MAGIC).map_err(e)?;
            let (mut written, mut fetched) = (0u64, 0u64);
            let mut prev: Option<(u32, [u8; 32])> = None;
            for r in ranges(&c) {
                let (rf, rl) = (
                    r["first"].as_u64().unwrap_or(0) as u32,
                    r["last"].as_u64().unwrap_or(0) as u32,
                );
                if rl < from || rf > to {
                    continue;
                }
                let object = r["object"].as_str().ok_or("range without object")?;
                let head = h.get(object, Some((0, Directory::HEAD as u64)))?;
                let size = Directory::size_from_head(&head)?;
                let dir = Directory::parse(
                    &h.get(object, Some((0, size as u64)))?,
                    &hex32(&r["directory_sha256"])?,
                )?;
                if dir.first != rf
                    || dir.last != rl
                    || dir.parent_hash != hex32(&r["parent_hash"])?
                    || dir.last_hash != hex32(&r["last_hash"])?
                {
                    return Err(format!("{object}: directory does not match the catalog"));
                }
                for &(sf, sn, at, len, sha) in &dir.rows {
                    if sf + sn - 1 < from || sf > to {
                        continue;
                    }
                    let data = h.get(object, Some((at, at + len)))?;
                    fetched += len;
                    let mut seg = Segment::open(&data, &sha)?;
                    for l in seg.ledgers()? {
                        let hd = l.verify()?;
                        let hash = LedgerHeader::parse(&l.header).map_err(e)?.hash();
                        let seq = hd.sequence;
                        // Chain: against the previous ledger of the selection and against
                        // the range edges from the catalog.
                        if let Some((ps, ph)) = prev
                            && ps + 1 == seq
                            && hd.parent_hash != ph
                        {
                            return Err(format!("chain breaks at {seq}"));
                        }
                        if seq == dir.first && hd.parent_hash != dir.parent_hash {
                            return Err(format!("{seq}: parent does not match the catalog"));
                        }
                        if seq == dir.last && hash != dir.last_hash {
                            return Err(format!("{seq}: hash does not match the catalog"));
                        }
                        prev = Some((seq, hash));
                        if (from..=to).contains(&seq) {
                            // The selection must be contiguous from `from`: a gap or duplicate
                            // in the catalog must not turn into a short corpus.
                            let want = from + written as u32;
                            if seq != want {
                                return Err(format!(
                                    "ledger {seq} instead of {want}: selection is not contiguous"
                                ));
                            }
                            let b = l.encode();
                            f.write_all(&(b.len() as u32).to_le_bytes()).map_err(e)?;
                            f.write_all(&b).map_err(e)?;
                            written += 1;
                        }
                    }
                }
            }
            if written != u64::from(to - from) + 1 {
                return Err(format!(
                    "catalog has {written} ledgers of {} ({from}…{to})",
                    u64::from(to - from) + 1
                ));
            }
            f.sync_all().map_err(e)?;
            println!(
                "catalog {}: {written} ledgers ({from}…{to}) to {}, downloaded {:.1} MB; pages, segments, transaction roots and chain verified",
                c["generation"],
                out.display(),
                fetched as f64 / 1e6
            );
        }
    }
    Ok(())
}
