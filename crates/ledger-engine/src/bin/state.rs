//! astraea-state: ledger state over time, a snapshot plus changes.
//!
//! - `load`: load a snapshot (`astraea-snapshot`) into an empty store;
//! - `apply`: apply ledger changes from the `astraea-ingest` journal,
//!   strictly in order, starting from the ledger after the last applied one;
//! - `verify`: compute the root of the whole state at a ledger and compare it
//!   with the `AccountHash` in its header. A match means the snapshot and all
//!   changes were applied exactly, down to the last object;
//! - `blocks`: check the history in blocks against the state. Every ledger after
//!   the snapshot is in blocks or in pending, the transaction tree matches, and
//!   the header is the same one that was applied to the state;
//! - `ledgers`: sequence, hash and transaction count of each ledger in blocks,
//!   as JSON lines, for comparison with Clio;
//! - `get`: object by key at a ledger;
//! - `tx`, `account-tx`: transaction by hash and account history from the indexes;
//! - `bench`: index query latencies on a random sample, and index
//!   sizes.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use ledger_engine::history::{self, HistoryReader, HistoryWriter, PrevAt};
use ledger_engine::index::{AccountId, entries};
use ledger_engine::ledger::Ledger;
use ledger_engine::log::{parse_records, read_journal};
use ledger_engine::state::{StateStore, TxPosition};
use ledger_engine::xrpl_json;
use witness_core::keys::decode_base58;
use witness_core::ledger::{HEADER_LEN, LedgerHeader};
use witness_core::shamap::{root, state_leaf_hash, tx_id};

#[derive(Debug, Parser)]
#[command(about = "Astraea: ledger state over time")]
struct Cli {
    /// State store directory.
    #[arg(long, env = "ASTRAEA_STATE_DIR")]
    db: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load a state snapshot.
    Load { snapshot: PathBuf },
    /// Apply changes from the loader journal.
    Apply { ledgers: PathBuf },
    /// Check the state root at a ledger against its header.
    Verify {
        #[arg(long)]
        at: Option<u32>,
    },
    /// Move history from old-format blocks to format 2 (the history
    /// module) and check every ledger byte for byte.
    HistoryMigrate {
        /// Directory of old-format blocks.
        #[arg(long)]
        blocks: PathBuf,
        /// New history directory, must be empty.
        #[arg(long)]
        to: PathBuf,
        /// Number of leading ledgers to train the dictionary on.
        #[arg(long, default_value_t = 512)]
        train: u32,
        #[arg(long, default_value_t = 32_768)]
        segment_ledgers: u32,
    },
    /// Prepare format 3 changes for closed format 2 history segments
    /// (`*.new` alongside), checking every ledger; `history-swap` does the replacement.
    /// Previous versions come from `--db` (a copy of the store if the loader is running).
    HistoryConvert { history: PathBuf },
    /// Replace changes with the ones prepared by `history-convert`, with the
    /// loader stopped.
    HistorySwap { history: PathBuf },
    /// Export full history ledgers, with state changes (format 3
    /// needs previous versions from `--db`), to an XWCP corpus, checking transaction
    /// roots and the header chain.
    HistoryExport {
        history: PathBuf,
        #[arg(long)]
        from: u32,
        #[arg(long)]
        to: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// ASTJ5 cold history from an XWCP corpus: segments of `--segment-ledgers`
    /// into the `--to` directory; after publishing, every ledger is read back and
    /// compared byte for byte. `--kinds not-recorded` is for a source without change
    /// kinds (the XRPLA publication).
    HistoryCold {
        corpus: PathBuf,
        #[arg(long)]
        to: PathBuf,
        #[arg(long, default_value = "explicit")]
        kinds: String,
        #[arg(long, default_value_t = 32_768)]
        segment_ledgers: u32,
        /// Archive block limit: ledgers and MiB of exact bytes.
        #[arg(long, default_value_t = 1024)]
        block_ledgers: usize,
        #[arg(long, default_value_t = 4)]
        block_mib: usize,
    },
    /// API indexes over the directory's cold segments (transaction by hash,
    /// account history, ledger hash): partition over `--first..--last`, by
    /// default the whole cold range.
    HistoryColdIndex {
        dir: PathBuf,
        #[arg(long)]
        first: Option<u32>,
        #[arg(long)]
        last: Option<u32>,
    },
    /// Seal cold segments written before seals existed: check every block in
    /// full once and record it, so readers don't repeat the check. Segments
    /// that already have a seal are skipped unless `--force`.
    HistoryColdSeal {
        dir: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long, default_value_t = 8)]
        threads: usize,
    },
    /// Remove the ASIX2 indexes of cold segments written before 0.3: nothing
    /// reads them. The server must already run 0.3 or later, which doesn't
    /// expect them.
    HistoryColdDropIndex { dir: PathBuf },
    /// Write cold segments again as JC06 (blocks cut into parts read on their
    /// own), in place and with the server running. Segments already in parts
    /// are skipped.
    HistoryColdRecode {
        dir: PathBuf,
        #[arg(long)]
        first: Option<u32>,
        #[arg(long)]
        last: Option<u32>,
        /// Segments recoded at once, one thread each.
        #[arg(long, default_value_t = 4)]
        threads: usize,
        #[arg(long, default_value_t = ledger_engine::cold::PART_RAW)]
        part: usize,
    },
    /// Check cold history indexes against the fjall indexes (`--db`) on the shared
    /// range: account history pages in both directions with marker, and transaction
    /// lookup by hash on a sample.
    ColdIndexCheck {
        dir: PathBuf,
        #[arg(long, default_value_t = 2000)]
        samples: usize,
    },
    /// Cold history adjoins hot history: the last cold ledger is the
    /// parent of the first hot one.
    HistoryAnchor {
        #[arg(long)]
        cold: PathBuf,
        #[arg(long)]
        history: PathBuf,
    },
    /// Build the state tree at the latest ledger: after that the root
    /// is checked against AccountHash on every ledger.
    TreeBuild {
        /// Delete the existing tree and build it again.
        #[arg(long)]
        rebuild: bool,
    },
    /// Check the loader blocks against the state.
    Blocks { dir: PathBuf },
    /// Ledgers from blocks as JSON lines: sequence, hash, transactions, changes.
    Ledgers {
        dir: PathBuf,
        #[arg(long)]
        from: Option<u32>,
        #[arg(long)]
        to: Option<u32>,
    },
    /// Transaction by hash: ledger, position, transaction and metadata in hex.
    Tx { hash: String, blocks: PathBuf },
    /// Account history, newest transactions first by default.
    AccountTx {
        account: String,
        #[arg(long, default_value_t = 0)]
        min: u32,
        #[arg(long, default_value_t = u32::MAX)]
        max: u32,
        #[arg(long)]
        forward: bool,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Where to continue from: "ledger:position" from the previous response.
        #[arg(long)]
        marker: Option<String>,
        /// Blocks directory: if given, each transaction also gets its hash.
        #[arg(long)]
        blocks: Option<PathBuf>,
    },
    /// Transactions and changed objects from blocks in xrpld JSON, one per line,
    /// for checking the codec against Clio.
    Json {
        blocks: PathBuf,
        #[arg(long)]
        from: u32,
        #[arg(long)]
        to: u32,
    },
    /// Index query latencies on a random sample, index sizes.
    Bench {
        blocks: PathBuf,
        #[arg(long, default_value_t = 2000)]
        samples: usize,
    },
    /// Object by key (hex) at a ledger.
    Get {
        key: String,
        #[arg(long)]
        at: Option<u32>,
    },
}

type Object = Result<([u8; 32], Vec<u8>), String>;

/// Snapshot header and a stream of its objects.
fn snapshot(path: &Path) -> Result<(Vec<u8>, impl Iterator<Item = Object>), String> {
    let f = File::open(path).map_err(|e| e.to_string())?;
    let mut r = BufReader::new(zstd::Decoder::new(f).map_err(|e| e.to_string())?);
    let mut head = vec![0u8; 6 + HEADER_LEN];
    r.read_exact(&mut head).map_err(|e| e.to_string())?;
    if &head[..6] != b"XWLS\x00\x01" {
        return Err("not an XWLS snapshot".into());
    }
    let header = head[6..].to_vec();
    let iter = std::iter::from_fn(move || {
        let mut key = [0u8; 32];
        match r.read_exact(&mut key) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e.to_string())),
        }
        let mut len = [0u8; 4];
        let mut data = Vec::new();
        let res = r.read_exact(&mut len).and_then(|()| {
            data = vec![0u8; u32::from_le_bytes(len) as usize];
            r.read_exact(&mut data)
        });
        Some(res.map(|()| (key, data)).map_err(|e| e.to_string()))
    });
    Ok((header, iter))
}

/// Previous object versions from the store, for format 3 changes.
fn prev_from(store: &Arc<StateStore>) -> Arc<PrevAt> {
    let store = store.clone();
    Arc::new(move |k: &[u8; 32], at: u32| store.get(k, at))
}

fn hash32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "hash is not 32 bytes".into())
}

fn account_id(s: &str) -> Result<AccountId, String> {
    match decode_base58(s) {
        Some((0, a)) => a.try_into().map_err(|_| "address is not 20 bytes".into()),
        _ => Err(format!("{s}: not an account address")),
    }
}

fn percentiles(mut v: Vec<f64>) -> String {
    v.sort_by(f64::total_cmp);
    let p = |q: f64| v[((v.len() as f64 - 1.0) * q).round() as usize];
    format!("{:.2} / {:.2} / {:.2}", p(0.5), p(0.95), p(0.99))
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// Query latencies on random transactions from blocks.
fn bench(store: &StateStore, blocks: &HistoryReader, samples: usize) -> Result<(), String> {
    // Blocks can run ahead of the store (it is a copy while loading goes on):
    // sample only from what is indexed.
    let first = blocks.first().ok_or("no blocks")?;
    let last = blocks
        .last()
        .ok_or("no blocks")?
        .min(store.indexed()?.ok_or("no indexes")?);
    let span = u64::from(last - first + 1);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut picks = Vec::with_capacity(samples);
    while picks.len() < samples {
        let seq = first + (rnd() % span) as u32;
        let l = Ledger::decode(
            &blocks
                .get(seq)?
                .ok_or(format!("ledger {seq} not found in blocks"))?,
        )?;
        if l.transactions.is_empty() {
            continue;
        }
        let e = entries(&l)?;
        let t = &e[(rnd() % e.len() as u64) as usize];
        let account = t.accounts[(rnd() % t.accounts.len() as u64) as usize];
        let object = l
            .changes
            .get((rnd() % l.changes.len().max(1) as u64) as usize)
            .map(|c| c.key);
        picks.push((seq, l.header()?.hash(), t.id, account, object));
    }

    let (mut tx, mut lh, mut page, mut bodies, mut obj) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut page_len = 0usize;
    for (seq, hash, id, account, object) in &picks {
        let t = Instant::now();
        let (s, pos) = store.tx_location(id)?.ok_or("transaction not in index")?;
        let l = Ledger::decode(
            &blocks
                .get(s)?
                .ok_or(format!("ledger {s} from the tx index not found in blocks"))?,
        )?;
        if l.transactions.get(pos as usize).is_none() || s != *seq {
            return Err("index points to the wrong place".into());
        }
        tx.push(ms(t));

        let t = Instant::now();
        if store.ledger_by_hash(hash)? != Some(*seq) {
            return Err("wrong ledger by hash".into());
        }
        lh.push(ms(t));

        let t = Instant::now();
        let p = store.account_tx(account, 0, u32::MAX, false, 200, None)?;
        page.push(ms(t));
        page_len += p.transactions.len();

        // The page together with the transactions themselves: each ledger of the page
        // is decompressed once.
        let t = Instant::now();
        let mut cache: HashMap<u32, Ledger> = HashMap::new();
        for a in &p.transactions {
            if let std::collections::hash_map::Entry::Vacant(v) = cache.entry(a.at.ledger) {
                let body = blocks.get(a.at.ledger)?.ok_or(format!(
                    "ledger {} from account history not found in blocks",
                    a.at.ledger
                ))?;
                v.insert(Ledger::decode(&body)?);
            }
        }
        bodies.push(ms(t));

        if let Some(k) = object {
            let t = Instant::now();
            store.get(k, *seq)?;
            obj.push(ms(t));
        }
    }
    println!(
        "sample of {samples} transactions from ledgers {first}..{last}; latency p50 / p95 / p99, ms:"
    );
    println!("- tx by hash (index, block, decode): {}", percentiles(tx));
    println!("- ledger by hash: {}", percentiles(lh));
    println!(
        "- account_tx, page of up to 200 (index only): {}; {:.0} transactions on average",
        percentiles(page),
        page_len as f64 / samples as f64
    );
    println!(
        "- same page with transactions from blocks: {}",
        percentiles(bodies)
    );
    println!("- object by key at a ledger: {}", percentiles(obj));
    for (name, disk, len) in store.index_sizes() {
        println!("index {name}: {len} entries, {disk} bytes on disk");
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    // Only one process can open the store: while the loader is running,
    // only `ledgers` is available, since blocks are enough for it.
    let open = || StateStore::open(&cli.db);
    let t = Instant::now();
    match cli.command {
        Command::Load { snapshot: path } => {
            let store = open()?;
            let (header, objects) = snapshot(&path)?;
            let h = LedgerHeader::parse(&header).map_err(|e| e.to_string())?;
            let n = store.load_snapshot(h.sequence, &header, objects)?;
            println!(
                "snapshot of ledger {} loaded: {n} objects in {:.0} s",
                h.sequence,
                t.elapsed().as_secs_f64()
            );
        }
        Command::Apply { ledgers } => {
            let store = open()?;
            let mut last = store.last()?.ok_or("load a state snapshot first")?;
            let (mut applied, mut changes) = (0u32, 0u64);
            for raw in read_journal(&ledgers)? {
                let (records, _) = parse_records(&raw)?;
                for (seq, body) in records {
                    if seq <= last {
                        continue;
                    }
                    if seq != last + 1 {
                        return Err(format!("gap in journal: {seq} follows {last}"));
                    }
                    let l = Ledger::decode(body)?;
                    store.apply(seq, &l.header, &l.changes)?;
                    changes += l.changes.len() as u64;
                    applied += 1;
                    last = seq;
                }
            }
            store.persist()?;
            println!(
                "applied {applied} ledgers, {changes} changes, last {last}, in {:.0} s",
                t.elapsed().as_secs_f64()
            );
        }
        Command::Verify { at } => {
            let store = open()?;
            let at = match at {
                Some(a) => a,
                None => store.last()?.ok_or("store is empty")?,
            };
            let header = store
                .header(at)?
                .ok_or(format!("no header for ledger {at}"))?;
            let h = LedgerHeader::parse(&header).map_err(|e| e.to_string())?;
            let mut leaves = Vec::new();
            for item in store.objects_at(at) {
                let (key, data) = item?;
                leaves.push((key, state_leaf_hash(&data, &key)));
            }
            let n = leaves.len();
            let ok = root(&leaves) == h.account_hash;
            println!(
                "ledger {at}: {n} objects, state root {} AccountHash, in {:.0} s",
                if ok { "matches" } else { "does NOT match" },
                t.elapsed().as_secs_f64()
            );
            if !ok {
                std::process::exit(1);
            }
        }
        Command::HistoryMigrate {
            blocks,
            to,
            train,
            segment_ledgers,
        } => {
            let old = ledger_engine::blocks::BlockReader::open(&blocks)?;
            let (first, last) = (
                old.first().ok_or("no blocks")?,
                old.last().ok_or("no blocks")?,
            );
            if HistoryReader::open(&to)?.last().is_some() {
                return Err(format!("{}: history already exists there", to.display()));
            }
            let body = |seq: u32| {
                old.get(seq)?
                    .ok_or(format!("ledger {seq} not found in blocks"))
            };
            let mut samples = Vec::new();
            for seq in first..first.saturating_add(train).min(last + 1) {
                samples.push(history::tx_frame(&Ledger::decode(&body(seq)?)?));
            }
            let dict = history::Dict::store(
                &to,
                zstd::dict::from_samples(&samples, 112 << 10).map_err(|e| e.to_string())?,
            )?;
            drop(samples);
            println!(
                "dictionary {} trained on {train} ledgers",
                hex::encode_upper(dict.id)
            );
            let mut w = HistoryWriter::create(&to, first, 128, 9, 19, Some(&dict), false)?;
            let mut in_segment = 0u32;
            for seq in first..=last {
                w.append(seq, body(seq)?, None)?;
                in_segment += 1;
                if in_segment >= segment_ledgers && w.buffered() == 0 {
                    w.finish()?;
                    w = HistoryWriter::create(&to, seq + 1, 128, 9, 19, Some(&dict), false)?;
                    in_segment = 0;
                }
            }
            w.finish()?;
            let written = t.elapsed().as_secs_f64();
            let new = HistoryReader::open(&to)?;
            for seq in first..=last {
                if new.get(seq)?.as_deref() != Some(&body(seq)?[..]) {
                    return Err(format!("ledger {seq}: wrong in the new format"));
                }
            }
            let old_bytes = ledger_engine::metrics::dir_bytes(&blocks);
            let new_bytes = new.bytes_on_disk();
            let n = f64::from(last - first + 1);
            println!(
                "ledgers {first}..{last}: written in {written:.0} s, all checked byte for byte in {:.0} s; before {old_bytes} bytes ({:.1} KB/ledger), after {new_bytes} ({:.1} KB/ledger)",
                t.elapsed().as_secs_f64() - written,
                old_bytes as f64 / n / 1000.0,
                new_bytes as f64 / n / 1000.0
            );
        }
        Command::HistoryConvert { history } => {
            let store = Arc::new(open()?);
            let reader = HistoryReader::open(&history)?.with_prev(prev_from(&store));
            let infos = reader.segments_info();
            let newest = infos.iter().map(|i| i.0).max();
            let (mut old_total, mut new_total, mut n) = (0u64, 0u64, 0u32);
            for (first, last, delta) in infos {
                // The newest segment is the one the loader is writing to.
                if delta || Some(first) == newest || last < first {
                    continue;
                }
                let (old, new) = reader.convert_changes(first, 128, 19)?;
                println!(
                    "segment {first}..{last}: changes {old} → {new} bytes, all ledgers checked byte for byte",
                );
                old_total += old;
                new_total += new;
                n += last - first + 1;
            }
            println!(
                "prepared {n} ledgers: changes {:.1} → {:.1} KB/ledger, in {:.0} s",
                old_total as f64 / f64::from(n.max(1)) / 1000.0,
                new_total as f64 / f64::from(n.max(1)) / 1000.0,
                t.elapsed().as_secs_f64()
            );
        }
        Command::HistorySwap { history } => {
            let mut n = 0;
            for e in std::fs::read_dir(&history).map_err(|e| e.to_string())? {
                let name = e
                    .map_err(|e| e.to_string())?
                    .file_name()
                    .to_string_lossy()
                    .into_owned();
                if let Some(first) = name
                    .strip_prefix("chg-")
                    .and_then(|r| r.strip_suffix(".xwlc.new"))
                    .and_then(|f| f.parse::<u32>().ok())
                {
                    HistoryReader::swap_changes(&history, first)?;
                    n += 1;
                }
            }
            println!("segments replaced: {n}");
        }
        Command::HistoryExport {
            history,
            from,
            to,
            out,
        } => {
            use std::io::Write as _;
            let store = Arc::new(open()?);
            let reader = HistoryReader::open(&history)?.with_prev(prev_from(&store));
            let mut w = std::io::BufWriter::new(File::create(&out).map_err(|e| e.to_string())?);
            w.write_all(b"XWCP\x00\x01").map_err(|e| e.to_string())?;
            let mut parent: Option<[u8; 32]> = None;
            let (mut txs, mut changes, mut bytes) = (0usize, 0usize, 0usize);
            for seq in from..=to {
                let raw = reader
                    .get(seq)?
                    .ok_or(format!("ledger {seq} not found in history"))?;
                let l = Ledger::decode(&raw)?;
                if l.encode() != raw {
                    return Err(format!("ledger {seq}: serialization does not round-trip"));
                }
                let h = l.verify()?;
                if h.sequence != seq || parent.is_some_and(|p| p != h.parent_hash) {
                    return Err(format!("ledger {seq}: chain break"));
                }
                parent = Some(h.hash());
                txs += l.transactions.len();
                changes += l.changes.len();
                bytes += raw.len();
                w.write_all(&(raw.len() as u32).to_le_bytes())
                    .map_err(|e| e.to_string())?;
                w.write_all(&raw).map_err(|e| e.to_string())?;
            }
            w.flush().map_err(|e| e.to_string())?;
            w.into_inner()
                .map_err(|e| e.to_string())?
                .sync_all()
                .map_err(|e| e.to_string())?;
            println!(
                "ledgers {from}..{to}: {txs} transactions, {changes} changes, {bytes} bytes; transaction roots and chain verified, in {:.0} s",
                t.elapsed().as_secs_f64()
            );
        }
        Command::HistoryCold {
            corpus,
            to,
            kinds,
            segment_ledgers,
            block_ledgers,
            block_mib,
        } => {
            use ledger_engine::cold::{self, Cold, Kinds};
            let mode = match kinds.as_str() {
                "explicit" => Kinds::Explicit,
                "not-recorded" => Kinds::NotRecorded,
                _ => return Err("--kinds: explicit or not-recorded".into()),
            };
            let mut r = BufReader::new(File::open(&corpus).map_err(|e| e.to_string())?);
            let mut magic = [0u8; 6];
            r.read_exact(&mut magic).map_err(|e| e.to_string())?;
            if &magic != b"XWCP\x00\x01" {
                return Err("not an XWCP corpus".into());
            }
            let next = |r: &mut BufReader<File>| -> Result<Option<Ledger>, String> {
                let mut len = [0u8; 4];
                match r.read_exact(&mut len) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(e) => return Err(e.to_string()),
                }
                let n = u32::from_le_bytes(len) as usize;
                if n > 512 << 20 {
                    return Err("ledger in corpus is larger than 512 MiB".into());
                }
                let mut b = vec![0u8; n];
                r.read_exact(&mut b).map_err(|e| e.to_string())?;
                Ledger::decode(&b).map(Some)
            };
            let mut totals = [0u64; 5];
            loop {
                let mut chunk = Vec::new();
                while chunk.len() < segment_ledgers as usize {
                    match next(&mut r)? {
                        Some(l) => chunk.push(l),
                        None => break,
                    }
                }
                if chunk.is_empty() {
                    break;
                }
                let t0 = Instant::now();
                let limit = cold::BlockLimit {
                    ledgers: block_ledgers,
                    raw: block_mib << 20,
                    ..Default::default()
                };
                let m = cold::write_with(&to, &chunk, mode, limit)?;
                let written = t0.elapsed().as_secs_f64();
                let check = Cold::open(&to)?;
                let first = chunk[0].header()?.sequence;
                let seg = check
                    .segments()
                    .iter()
                    .find(|s| s.first == first)
                    .ok_or("segment not published")?
                    .clone();
                seg.verify_files()?;
                for l in &chunk {
                    let seq = l.header()?.sequence;
                    let t = seg.ledger(seq, false)?;
                    if t.header != l.header || t.transactions != l.transactions {
                        return Err(format!(
                            "ledger {seq}: wrong transactions from cold history"
                        ));
                    }
                    match mode {
                        Kinds::Explicit => {
                            if seg.ledger(seq, true)?.encode() != l.encode() {
                                return Err(format!("ledger {seq}: wrong from cold history"));
                            }
                        }
                        Kinds::NotRecorded => {
                            if seg.ledger(seq, true).is_ok() {
                                return Err(format!(
                                    "ledger {seq}: changes returned without kinds"
                                ));
                            }
                        }
                    }
                }
                let checked = t0.elapsed().as_secs_f64() - written;
                let f = |k: &str| m["files"][k]["bytes"].as_u64().unwrap_or(0);
                let tx = m["transactions"].as_u64().unwrap_or(0).max(1);
                let per = |b: u64| b as f64 / tx as f64;
                println!(
                    "segment {}..{}: {} transactions, {} changes, {} blocks; ASTJ5 {:.2} B/tx, ASIX2 {:.2}, kinds {:.3}, overall {:.2} B/tx; write {written:.0} s, check {checked:.0} s",
                    m["first"],
                    m["last"],
                    m["transactions"],
                    m["changes"],
                    m["blocks"],
                    per(f("astj")),
                    per(f("asix")),
                    per(f("kinds")),
                    per(f("astj") + f("asix") + f("kinds")),
                );
                for (i, v) in [f("astj"), f("asix"), f("kinds"), tx, chunk.len() as u64]
                    .into_iter()
                    .enumerate()
                {
                    totals[i] += v;
                }
            }
            let per = |b: u64| b as f64 / totals[3].max(1) as f64;
            println!(
                "total {} ledgers, {} transactions: ASTJ5 {:.2} B/tx, ASIX2 {:.2}, kinds {:.3}, overall {:.2} B/tx (excluding manifests), in {:.0} s",
                totals[4],
                totals[3],
                per(totals[0]),
                per(totals[1]),
                per(totals[2]),
                per(totals[0] + totals[1] + totals[2]),
                t.elapsed().as_secs_f64()
            );
        }
        Command::HistoryColdIndex { dir, first, last } => {
            let cold = ledger_engine::cold::Cold::open(&dir)?;
            let first = first.or(cold.first()).ok_or("no cold segments")?;
            let last = last.or(cold.last()).ok_or("no cold segments")?;
            let m = ledger_engine::coldindex::build(&dir, &cold, first, last)?;
            let tx = m["transactions"].as_u64().unwrap_or(0).max(1) as f64;
            let b = |k: &str| m["files"][k]["bytes"].as_u64().unwrap_or(0) as f64;
            println!(
                "cold history indexes {first}..{last}: {} transactions, {} accounts; XTXH {:.2} B/tx, XACC {:.2}, ledger hashes {:.3}; every transaction found, account history verified, in {:.0} s",
                m["transactions"],
                m["accounts"],
                b("xtxh") / tx,
                b("xacc") / tx,
                b("lgr") / tx,
                t.elapsed().as_secs_f64()
            );
        }
        Command::HistoryColdSeal {
            dir,
            force,
            threads,
        } => {
            let cold = ledger_engine::cold::Cold::open(&dir)?;
            let (mut sealed, mut skipped) = (0, 0);
            for seg in cold.segments() {
                if seg.sealed() && !force {
                    skipped += 1;
                    continue;
                }
                seg.write_seal(threads)?;
                sealed += 1;
            }
            println!(
                "sealed {sealed} cold segments, {skipped} already sealed, in {:.0} s",
                t.elapsed().as_secs_f64()
            );
        }
        Command::HistoryColdDropIndex { dir } => {
            let cold = ledger_engine::cold::Cold::open(&dir)?;
            let (mut n, mut bytes) = (0, 0u64);
            for seg in cold.segments() {
                let b = seg.drop_index()?;
                n += usize::from(b > 0);
                bytes += b;
            }
            println!(
                "removed ASIX2 indexes of {n} cold segments, {:.1} GB, in {:.0} s",
                bytes as f64 / 1e9,
                t.elapsed().as_secs_f64()
            );
        }
        Command::HistoryColdRecode {
            dir,
            first,
            last,
            threads,
            part,
        } => {
            let cold = ledger_engine::cold::Cold::open(&dir)?.with_open_limit(threads.max(1) * 2);
            let todo: Vec<_> = cold
                .segments()
                .iter()
                .filter(|s| {
                    !s.in_parts()
                        && first.is_none_or(|f| s.last >= f)
                        && last.is_none_or(|l| s.first <= l)
                })
                .cloned()
                .collect();
            let next = std::sync::atomic::AtomicUsize::new(0);
            let done = std::sync::atomic::AtomicUsize::new(0);
            let (before, after) = (
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
            );
            let results: Vec<Result<(), String>> = std::thread::scope(|sc| {
                let workers: Vec<_> = (0..threads.clamp(1, todo.len().max(1)))
                    .map(|_| {
                        sc.spawn(|| -> Result<(), String> {
                            use std::sync::atomic::Ordering::Relaxed;
                            loop {
                                let Some(seg) = todo.get(next.fetch_add(1, Relaxed)) else {
                                    return Ok(());
                                };
                                let old =
                                    seg.manifest["files"]["astj"]["bytes"].as_u64().unwrap_or(0);
                                let m = seg
                                    .recode(part)
                                    .map_err(|e| format!("segment {}: {e}", seg.first))?;
                                before.fetch_add(old, Relaxed);
                                after.fetch_add(
                                    m["files"]["astj"]["bytes"].as_u64().unwrap_or(0),
                                    Relaxed,
                                );
                                let n = done.fetch_add(1, Relaxed) + 1;
                                eprintln!(
                                    "recoded segment {} ({n} of {}), {:.0} s",
                                    seg.first,
                                    todo.len(),
                                    t.elapsed().as_secs_f64()
                                );
                            }
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|w| {
                        w.join()
                            .unwrap_or_else(|_| Err("recode worker panicked".into()))
                    })
                    .collect()
            });
            for r in results {
                r?;
            }
            let (b, a) = (
                before.load(std::sync::atomic::Ordering::Relaxed),
                after.load(std::sync::atomic::Ordering::Relaxed),
            );
            println!(
                "recoded {} cold segments in {:.0} s: archives {:.1} GB -> {:.1} GB",
                done.load(std::sync::atomic::Ordering::Relaxed),
                t.elapsed().as_secs_f64(),
                b as f64 / 1e9,
                a as f64 / 1e9
            );
        }
        Command::ColdIndexCheck { dir, samples } => {
            let store = open()?;
            let cold = ledger_engine::cold::Cold::open(&dir)?;
            let ix = ledger_engine::coldindex::ColdIndexes::open(&dir)?;
            let (first, last) = (
                cold.first().ok_or("no cold segments")?,
                cold.last().ok_or("no cold segments")?,
            );
            let mut rng = 0x9E37_79B9_7F4A_7C15u64;
            let mut next = |n: u32| {
                rng = rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((rng >> 33) % u64::from(n.max(1))) as u32
            };
            let mut accounts = std::collections::BTreeSet::new();
            let (mut txs, mut pages) = (0usize, 0usize);
            for _ in 0..samples {
                let seq = first + next(last - first + 1);
                let l = cold.ledger(seq, false)?.ok_or("no ledger")?;
                let es = entries(&l)?;
                if es.is_empty() {
                    continue;
                }
                let e = &es[next(es.len() as u32) as usize];
                let want = store
                    .tx_location(&e.id)?
                    .ok_or("transaction not in fjall")?;
                if !ix.tx_candidates(&e.id)?.contains(&want) {
                    return Err(format!(
                        "transaction {}: not found by the cold index",
                        hex::encode_upper(e.id)
                    ));
                }
                txs += 1;
                accounts.extend(e.accounts.iter().copied());
            }
            let pos = |l: u32, i: u32| TxPosition {
                ledger: l,
                index: i,
            };
            for acc in &accounts {
                for forward in [false, true] {
                    let mut start: Option<TxPosition> = None;
                    for _ in 0..5 {
                        let hot = store.account_tx(acc, first, last, forward, 200, start)?;
                        let (lo, hi) = match (forward, start) {
                            (true, Some(s)) => (s, pos(last, u32::MAX)),
                            (false, Some(s)) => (pos(first, 0), s),
                            (_, None) => (pos(first, 0), pos(last, u32::MAX)),
                        };
                        let got = ix.account_tx(acc, lo, hi, forward, 200)?;
                        let want: Vec<TxPosition> = hot.transactions.iter().map(|t| t.at).collect();
                        if got != want {
                            return Err(format!(
                                "account {}: {} page does not match ({} vs {})",
                                hex::encode_upper(acc),
                                if forward { "forward" } else { "backward" },
                                got.len(),
                                want.len()
                            ));
                        }
                        pages += 1;
                        let Some(m) = hot.marker else { break };
                        start = Some(m);
                    }
                }
            }
            println!(
                "cold indexes {first}..{last} vs fjall: {txs} transactions by hash, {} accounts, {pages} account_tx pages match, in {:.0} s",
                accounts.len(),
                t.elapsed().as_secs_f64()
            );
        }
        Command::HistoryAnchor { cold, history } => {
            let c = ledger_engine::cold::Cold::open(&cold)?;
            let last = c.last().ok_or("no cold segments")?;
            let tail = c
                .ledger(last, false)?
                .ok_or("no last cold ledger")?
                .header()?;
            let hot = HistoryReader::open(&history)?;
            let next = hot
                .get_txs(last + 1)?
                .ok_or(format!("hot history has no ledger {}", last + 1))?
                .header()?;
            if next.parent_hash != tail.hash() {
                return Err(format!(
                    "cold {last} ({}) is not the parent of hot {} ({})",
                    hex::encode_upper(tail.hash()),
                    last + 1,
                    hex::encode_upper(next.parent_hash)
                ));
            }
            println!(
                "cold history {}..{last} adjoins hot history: hash of {last} = parent of {}",
                c.first().unwrap_or(last),
                last + 1
            );
        }
        Command::TreeBuild { rebuild } => {
            let mut store = open()?;
            if rebuild {
                store.drop_tree()?;
                store = open()?;
            }
            let (seq, n) = store.build_tree()?;
            println!(
                "state tree at ledger {seq}: {n} leaves, root matches AccountHash, in {:.0} s",
                t.elapsed().as_secs_f64()
            );
        }
        Command::Blocks { dir } => {
            let store = Arc::new(open()?);
            let base = store.base()?.ok_or("store is empty")?;
            let last = store.last()?.ok_or("store is empty")?;
            let blocks = HistoryReader::open(&dir)?.with_prev(prev_from(&store));
            let pending: std::collections::HashMap<u32, Vec<u8>> =
                store.pending()?.into_iter().collect();
            let (mut in_blocks, mut waiting) = (0u32, 0u32);
            for seq in base + 1..=last {
                let body = match blocks.get(seq)? {
                    Some(b) => {
                        in_blocks += 1;
                        b
                    }
                    None => {
                        waiting += 1;
                        pending
                            .get(&seq)
                            .cloned()
                            .ok_or(format!("ledger {seq} is neither in blocks nor in pending"))?
                    }
                };
                let l = Ledger::decode(&body)?;
                l.verify()?;
                if Some(&l.header) != store.header(seq)?.as_ref() {
                    return Err(format!(
                        "ledger {seq}: header in block differs from the one in state"
                    ));
                }
            }
            println!(
                "ledgers {}..{last}: {in_blocks} in blocks, {waiting} pending, all verified, in {:.0} s",
                base + 1,
                t.elapsed().as_secs_f64()
            );
        }
        Command::Ledgers { dir, from, to } => {
            let blocks = HistoryReader::open(&dir)?;
            let from = match from {
                Some(f) => f,
                None => blocks.first().ok_or("no blocks")?,
            };
            let to = match to {
                Some(t) => t,
                None => blocks.last().ok_or("no blocks")?,
            };
            // Header and transactions are enough: state changes are not read and
            // the store is not needed (the loader holds it).
            for seq in from..=to {
                let l = blocks
                    .get_txs(seq)?
                    .ok_or(format!("ledger {seq} not found in history"))?;
                println!(
                    "{{\"seq\":{seq},\"hash\":\"{}\",\"transactions\":{}}}",
                    hex::encode_upper(l.header()?.hash()),
                    l.transactions.len()
                );
            }
        }
        Command::Tx { hash, blocks } => {
            let store = open()?;
            let (seq, pos) = store
                .tx_location(&hash32(&hash)?)?
                .ok_or("transaction not in index")?;
            let body = HistoryReader::open(&blocks)?
                .get_txs(seq)?
                .map(|l| l.encode())
                .or(store
                    .pending()?
                    .into_iter()
                    .find(|(s, _)| *s == seq)
                    .map(|(_, b)| b))
                .ok_or("ledger is neither in blocks nor in pending")?;
            let l = Ledger::decode(&body)?;
            let (tx, meta) = l
                .transactions
                .get(pos as usize)
                .ok_or("no such position in the ledger")?;
            println!(
                "{{\"ledger_index\":{seq},\"tx\":\"{}\",\"meta\":\"{}\"}}",
                hex::encode_upper(tx),
                hex::encode_upper(meta)
            );
        }
        Command::AccountTx {
            account,
            min,
            max,
            forward,
            limit,
            marker,
            blocks,
        } => {
            let store = open()?;
            let marker = match marker {
                Some(m) => {
                    let (l, i) = m.split_once(':').ok_or("marker is \"ledger:position\"")?;
                    Some(TxPosition {
                        ledger: l.parse().map_err(|_| "marker: ledger")?,
                        index: i.parse().map_err(|_| "marker: position")?,
                    })
                }
                None => None,
            };
            let a = account_id(&account)?;
            let page = store.account_tx(&a, min, max, forward, limit, marker)?;
            let reader = blocks.map(|b| HistoryReader::open(&b)).transpose()?;
            let mut cache: HashMap<u32, Ledger> = HashMap::new();
            for t in &page.transactions {
                let hash = match &reader {
                    Some(r) => {
                        if let std::collections::hash_map::Entry::Vacant(v) =
                            cache.entry(t.at.ledger)
                        {
                            v.insert(
                                r.get_txs(t.at.ledger)?
                                    .ok_or("ledger not found in history")?,
                            );
                        }
                        let (tx, _) = &cache[&t.at.ledger].transactions[t.pos as usize];
                        format!(",\"hash\":\"{}\"", hex::encode_upper(tx_id(tx)))
                    }
                    None => String::new(),
                };
                println!(
                    "{{\"ledger\":{},\"seq\":{}{hash}}}",
                    t.at.ledger, t.at.index
                );
            }
            if let Some(m) = page.marker {
                println!(
                    "{{\"marker\":{{\"ledger\":{},\"seq\":{}}}}}",
                    m.ledger, m.index
                );
            }
        }
        Command::Json { blocks, from, to } => {
            // Format 3 objects are stored as a diff against the previous version, so the store
            // is needed (a copy if the loader is running).
            let mut reader = HistoryReader::open(&blocks)?;
            if let Ok(store) = open() {
                reader = reader.with_prev(prev_from(&Arc::new(store)));
            }
            for seq in from..=to {
                let body = reader
                    .get(seq)?
                    .ok_or(format!("ledger {seq} not found in blocks"))?;
                let l = Ledger::decode(&body)?;
                for (tx, meta) in &l.transactions {
                    let line = serde_json::json!({
                        "kind": "tx",
                        "ledger": seq,
                        "tx": xrpl_json::transaction(tx)?,
                        "meta": xrpl_json::metadata(meta)?,
                    });
                    println!("{line}");
                }
                for c in &l.changes {
                    if c.data.is_empty() {
                        continue;
                    }
                    let line = serde_json::json!({
                        "kind": "object",
                        "ledger": seq,
                        "node": xrpl_json::ledger_entry(&c.key, &c.data)?,
                    });
                    println!("{line}");
                }
            }
        }
        Command::Bench { blocks, samples } => {
            let store = open()?;
            let store = Arc::new(store);
            bench(
                &store,
                &HistoryReader::open(&blocks)?.with_prev(prev_from(&store)),
                samples,
            )?;
        }
        Command::Get { key, at } => {
            let store = open()?;
            let k: [u8; 32] = hex::decode(&key)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "key is not 32 bytes")?;
            let at = match at {
                Some(a) => a,
                None => store.last()?.ok_or("store is empty")?,
            };
            match store.get(&k, at)? {
                Some(v) => println!("{}", hex::encode_upper(v)),
                None => println!("no object at ledger {at}"),
            }
        }
    }
    Ok(())
}
