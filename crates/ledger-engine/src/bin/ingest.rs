//! astraea-ingest: loads validated ledgers into the Ledger Engine.
//!
//! Follows the network tip: once a second it asks xrpld for the latest
//! validated ledger and loads everything up to it in order. After a
//! restart it continues from the ledger after the last applied one.
//!
//! Every ledger is checked before it is written:
//! - the transaction tree matches the root in the header;
//! - the sequence is the next one in order, and the parent hash in the header is
//!   the hash of the previously applied ledger. The chain cannot break and a gap
//!   cannot slip through silently.
//!
//! Data goes to two places (in the `--data-dir` directory):
//! - `state`: state over time (fjall). Object changes, header, indexes, the
//!   state tree and the ledger itself in the block's pending set, all in one
//!   atomic batch, synced to disk immediately. The tree root after the changes
//!   must match the header's `AccountHash`, otherwise the ledger is rejected;
//! - `history`: history (the `history` module). Transactions as one frame per
//!   ledger with a dictionary, state changes in blocks; a group is written with
//!   fsync, after which its ledgers are removed from pending.
//!
//! A Clio-compatible API is served on `--api-addr` (modules `api`, `server`),
//! in the same process, because only one process can open the store.
//!
//! Metrics are on `--metrics-addr` (the `metrics` module): node tip and
//! last applied ledger, its network close time, sizes on disk.
//!
//! Loaded does not mean confirmed. A ledger is confirmed by a quorum of UNL
//! validators, using the nodes' validation stream (`--validations-ws`) and the
//! publisher lists from the `witness-unl` archive (`--unl-dir`), checked against
//! pinned keys (the `confirm` module). Once a ledger is confirmed, all ledgers
//! before it are too, since the parent hash chain is already verified. The API
//! serves only confirmed data.
//!
//! Loading can only start from a state snapshot (`astraea-state load`): without
//! one there is nothing to build the state from. A ledger cannot be skipped: if the
//! node no longer has it, the loader waits and retries, and the lag shows in the tip.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use ledger_engine::api::Engine;
use ledger_engine::confirm::{self, Confirmer};
use ledger_engine::forward::Forwarder;
use ledger_engine::history::{Dict, HistoryReader, HistoryWriter};
use ledger_engine::ledger::Ledger;
use ledger_engine::log::{parse_records, read_journal};
use ledger_engine::metrics::{self, Metrics, Shared, dir_bytes, lock};
use ledger_engine::server;
use ledger_engine::source::Source;
use ledger_engine::state::StateStore;
use tracing::{error, info, warn};
use witness_core::evidence::ValidationEvidence;
use witness_core::ledger::LedgerHeader;

/// zstd level for state change blocks: they are rarely read, space matters more.
const CHANGES_LEVEL: i32 = 19;

#[derive(Debug, Parser)]
#[command(version, about = "Astraea: loads validated ledgers from xrpld")]
struct Args {
    /// xrpld gRPC, e.g. http://<node-host>:50051.
    #[arg(long, env = "ASTRAEA_GRPC")]
    grpc: String,
    /// Data directory: holds `state` and `history`.
    #[arg(long, env = "ASTRAEA_DATA_DIR")]
    data_dir: PathBuf,
    /// Client name for xrpld (secure_gateway, no rate limit).
    #[arg(long, default_value = "astraea")]
    user: String,
    /// First load ledgers from the journal of the previous loader version.
    #[arg(long)]
    import_log: Option<PathBuf>,
    /// Ledgers per state change block (these are read only during
    /// rebuilds); transactions are one frame per ledger.
    #[arg(long, default_value_t = 128)]
    changes_group: u32,
    /// Ledgers per history segment.
    #[arg(long, default_value_t = 32_768)]
    segment_ledgers: u32,
    /// zstd level for transaction frames; changes use level 19.
    #[arg(long, default_value_t = 9)]
    zstd_level: i32,
    /// Prometheus metrics address, e.g. <metrics-host>:9104. No metrics without it.
    #[arg(long, env = "ASTRAEA_METRICS_ADDR")]
    metrics_addr: Option<SocketAddr>,
    /// Addresses of the Clio-compatible API (JSON-RPC and WebSocket),
    /// comma-separated, e.g. 127.0.0.1:51300. No API without them.
    #[arg(long, env = "ASTRAEA_API_ADDR", value_delimiter = ',')]
    api_addr: Vec<SocketAddr>,
    /// Node JSON-RPC endpoints for methods Clio forwards to a node (fee,
    /// server_state, ledger_current, server_definitions), comma-separated,
    /// e.g. http://<node-host>:51234. Without them these methods return unknownCmd.
    #[arg(long, value_delimiter = ',')]
    forward_rpc: Vec<String>,
    /// Per-node timeout when forwarding, in seconds.
    #[arg(long, default_value_t = 5)]
    forward_timeout: u64,
    /// Request limits per client (`guard`), like Clio's dos_guard: weighted
    /// requests per sweep. Off if none of the three limits is given.
    #[arg(long)]
    max_requests: Option<u64>,
    /// Response bytes per client per sweep.
    #[arg(long)]
    max_response_bytes: Option<u64>,
    /// Connections per client open at once.
    #[arg(long)]
    max_connections: Option<u32>,
    /// Length of the interval the request and byte budgets cover, in seconds.
    #[arg(long, default_value_t = 1)]
    sweep_secs: u64,
    /// Addresses or networks (CIDR) that are never limited, comma-separated.
    #[arg(long, value_delimiter = ',')]
    limit_whitelist: Vec<ledger_engine::guard::Net>,
    /// Proxies whose CF-Connecting-IP, Forwarded or X-Forwarded-For name the
    /// client, comma-separated (for a tunnel on the same host: 127.0.0.1).
    #[arg(long, value_delimiter = ',')]
    trusted_proxies: Vec<ledger_engine::guard::Net>,
    /// Network NetworkID for ctid: 0 is mainnet.
    #[arg(long, default_value_t = 0)]
    network_id: u32,
    /// Node WebSocket endpoints for the validation stream, comma-separated: ledgers
    /// are confirmed by a UNL quorum from them, independent of the ledger source.
    #[arg(long, value_delimiter = ',', required = true)]
    validations_ws: Vec<String>,
    /// UNL list archive of the witness-unl collector.
    #[arg(long)]
    unl_dir: PathBuf,
    /// Trusted UNL list publisher keys (hex). Defaults to
    /// vl.ripple.com and unl.xrplf.org, as in [validator_list_keys] on our nodes.
    #[arg(long, value_delimiter = ',', default_values_t = [
        "ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734".to_string(),
        "ED42AEC58B701EEBB77356FFFEC26F83C1F0407263530F068C7C73D392C7E06FD1".to_string(),
    ])]
    publishers: Vec<String>,
}

/// Writes a ledger and records it in the metrics.
fn commit(sink: &mut Sink, ledger: &Ledger, metrics: &Shared) -> Result<(), String> {
    let t = Instant::now();
    sink.commit(ledger)?;
    let close_time = ledger.header()?.close_time;
    let mut m = lock(metrics);
    m.commit_seconds += t.elapsed().as_secs_f64();
    m.ledgers += 1;
    m.transactions += ledger.transactions.len() as u64;
    m.changes += ledger.changes.len() as u64;
    m.last_ledger = sink.last;
    m.last_close_time = close_time;
    m.last_commit_ms = witness_core::util::now_ms();
    m.pending_ledgers = sink.writer.buffered() as u64;
    Ok(())
}

/// The ledger with the EnableAmendment of NonFungibleTokensV1_1 on mainnet
/// (2022-10-31): no NFT transaction can be older.
const MAINNET_FIRST_NFT_LEDGER: u32 = 75_443_457;
/// Ledgers per NFT backfill batch, and the cold block cache of its reader.
const NFT_BACKFILL_CHUNK: u32 = 1024;
const NFT_BACKFILL_THREADS: usize = 8;
const NFT_BACKFILL_CACHE: usize = 256 << 20;

fn backfill_nfts(state: &Arc<StateStore>, history: &Path, start: u32) -> Result<(), String> {
    let reader = HistoryReader::open(history)?
        .with_prev(Arc::new(prev_of(state)))
        .with_cold_cache(NFT_BACKFILL_CACHE)?;
    // Not below the first ledger the history holds.
    let first = reader
        .cold_info()
        .first()
        .map(|c| c.0)
        .into_iter()
        .chain(reader.first())
        .min()
        .unwrap_or(start);
    // Ledgers of one cold block go to one reader thread, and a batch of
    // recent ledgers fits in a block or two, so the batch is read in pieces
    // on several threads.
    let read = |seqs: &[u32]| -> Result<Vec<Ledger>, String> {
        let piece = seqs.len().div_ceil(NFT_BACKFILL_THREADS).max(1);
        let parts = std::thread::scope(|s| {
            let hs: Vec<_> = seqs
                .chunks(piece)
                .map(|c| s.spawn(|| reader.ledgers_txs(c)))
                .collect();
            hs.into_iter()
                .map(|h| {
                    h.join()
                        .map_err(|_| "NFT backfill reader panicked".to_string())?
                })
                .collect::<Result<Vec<_>, String>>()
        })?;
        let got = parts.into_iter().flatten();
        seqs.iter()
            .zip(got)
            .map(|(s, l)| match l {
                Some(l) => Ok(l),
                // A ledger pending when the reader opened may have been
                // written to history files since, and left pending.
                None => match state.pending_ledger(*s)? {
                    Some(b) => Ledger::decode(&b),
                    None => reader
                        .get_txs(*s)?
                        .ok_or(format!("ledger {s} is not in history")),
                },
            })
            .collect()
    };
    let t = Instant::now();
    let last_log = Mutex::new(Instant::now());
    let progress = |at: u32, to: u32| {
        let mut l = last_log.lock().unwrap_or_else(|p| p.into_inner());
        if l.elapsed() >= Duration::from_secs(300) {
            info!("NFT index: at ledger {at} of {to}");
            *l = Instant::now();
        }
    };
    // History that doesn't reach the first NFTs can't say who holds a token
    // that hasn't moved since: such a store starts from the tokens in its state.
    if first > start {
        state.seed_nfts()?;
    }
    if let Some((from, to)) =
        state.backfill_nfts(start.max(first), NFT_BACKFILL_CHUNK, &read, &progress)?
    {
        info!(
            "NFT index filled for ledgers {from}..{to} in {:.0} s",
            t.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

/// Previous object versions for format 3 changes, from the state
/// store: the version as of ledger `at`.
fn prev_of(
    state: &Arc<StateStore>,
) -> impl Fn(&[u8; 32], u32) -> Result<Option<Vec<u8>>, String> + Send + Sync + use<> {
    let state = state.clone();
    move |k, at| state.get(k, at)
}

/// Confirms the newest loaded ledger that reached a quorum: all ledgers before
/// it are confirmed by the parent hash chain.
fn try_confirm(sink: &Sink, confirmer: &Confirmer, metrics: &Shared) -> Result<(), String> {
    let confirmed = sink.state.confirmed()?.unwrap_or(0);
    let lowest = confirmed.max(sink.state.base()?.unwrap_or(0)) + 1;
    let mut seq = sink.last;
    // Look no deeper than 256 ledgers: older validations are not always still
    // in the buffer, and confirming a newer ledger confirms those too.
    while seq >= lowest && sink.last - seq < 256 {
        let header = sink
            .state
            .header(seq)?
            .ok_or(format!("no header for {seq}"))?;
        let hash = LedgerHeader::parse(&header)
            .map_err(|e| e.to_string())?
            .hash();
        let verdict = confirmer.check(seq, &hash);
        if verdict.confirmed {
            sink.state.set_confirmed(seq)?;
            {
                let mut m = lock(metrics);
                m.quorum_signers = verdict.signers;
                m.quorum_needed = verdict.quorum;
                m.unl_size = verdict.unl_size;
            }
            // Anchor evidence once every 256 ledgers: with it and the header chain
            // we can prove ledgers whose validations are no longer in memory.
            if sink
                .state
                .last_evidence()?
                .is_none_or(|e| seq / 256 > e / 256)
            {
                let vals: Vec<ValidationEvidence> = confirmer
                    .validations_for(seq, &hash)
                    .into_iter()
                    .map(|(raw, at)| ValidationEvidence {
                        data: hex::encode_upper(raw),
                        received_ms: at,
                    })
                    .collect();
                sink.state.put_evidence(seq, &vals)?;
                lock(metrics).evidence_ledger = seq;
            }
            lock(metrics).confirmed_ledger = seq;
            return Ok(());
        }
        seq -= 1;
    }
    Ok(())
}

fn update_validation_stats(confirmer: &Confirmer, metrics: &Shared) {
    let (connected, validations, rejected, manifests) = confirmer.stats();
    let lists = confirmer
        .latest_lists()
        .into_iter()
        .map(|(p, sequence, validators, exp)| metrics::UnlList {
            publisher: hex::encode_upper(&p).chars().take(16).collect(),
            sequence,
            validators,
            expiration: exp.map_or(0, metrics::unix_of_ripple),
        })
        .collect();
    let mut m = lock(metrics);
    m.unl_lists = lists;
    m.validations_connected = connected;
    m.validations = validations;
    m.validations_rejected = rejected;
    m.manifests = manifests;
}

/// The served range, the first ledgers with state and with tree history,
/// cold history from the segment manifests, and bytes on disk by part.
fn coverage(engine: &Engine) -> metrics::Coverage {
    let mut c = metrics::Coverage::default();
    if let Ok((lo, hi)) = engine.range() {
        (c.first_ledger, c.last_ledger) = (lo, hi);
    }
    c.state_first_ledger = engine.state.base().ok().flatten().unwrap_or(0);
    c.tree_history_first_ledger = engine.state.levels_from().ok().flatten().unwrap_or(0);
    let mut seg = 0u64;
    let files = |m: &serde_json::Value| -> u64 {
        m["files"]
            .as_object()
            .map_or(0, |f| f.values().filter_map(|v| v["bytes"].as_u64()).sum())
    };
    for (_, _, m) in engine.blocks.cold_info() {
        c.cold_segments += 1;
        c.cold_transactions += m["transactions"].as_u64().unwrap_or(0);
        seg += files(&m);
    }
    c.bytes.insert("cold_segments", seg);
    c.bytes
        .insert("cold_indexes", engine.blocks.cold_index().bytes());
    for (name, disk, _) in engine.state.index_sizes() {
        c.bytes.insert(
            match name {
                "levels" => "tree_history",
                "tx" => "index_tx",
                "ledger_hash" => "index_ledger_hash",
                "nft_owner" => "index_nft_owner",
                "nft_uri" => "index_nft_uri",
                "nft_issuer" => "index_nft_issuer",
                "nft_tx" => "index_nft_tx",
                _ => "index_account_tx",
            },
            disk,
        );
    }
    c
}

fn update_sizes(dir: &Path, metrics: &Shared) {
    let (blocks, state) = (
        dir_bytes(&dir.join("history")),
        dir_bytes(&dir.join("state")),
    );
    let mut m = lock(metrics);
    m.blocks_bytes = blocks;
    m.state_bytes = state;
}

/// Where a verified ledger is written: state and blocks.
#[derive(Debug)]
struct Sink {
    state: Arc<StateStore>,
    history: PathBuf,
    writer: HistoryWriter,
    args: (u32, u32, i32),
    in_segment: u32,
    last: u32,
    prev_hash: [u8; 32],
}

impl Sink {
    fn open(
        dir: &Path,
        block_ledgers: u32,
        segment_ledgers: u32,
        level: i32,
    ) -> Result<Sink, String> {
        let state = Arc::new(StateStore::open(&dir.join("state"))?);
        let last = state.last()?.ok_or(
            "state is empty: load a snapshot first with astraea-state --db <data-dir>/state load",
        )?;
        let header = state
            .header(last)?
            .ok_or(format!("no header for ledger {last}"))?;
        let prev_hash = LedgerHeader::parse(&header)
            .map_err(|e| e.to_string())?
            .hash();
        if let Some(n) = state.ensure_mpt_index()? {
            info!("MPT holder index built: {n} versions");
        }
        let nft_from = state.start_nft_index()?;
        if state.nft_coverage()?.is_none() {
            info!(
                "NFT index: from ledger {nft_from} as ledgers arrive; earlier ones in the background"
            );
        }
        // The state root is checked on every ledger, so the tree is required.
        if state.tree_ledger()? != Some(last) {
            return Err(format!(
                "state tree is not at ledger {last}: run astraea-state --db <data-dir>/state tree-build first"
            ));
        }

        // Pending ledgers whose block was written before a crash are no longer needed;
        // the rest must be contiguous from the end of blocks to the end of state.
        let history = dir.join("history");
        if !history.exists() && dir.join("blocks").exists() {
            return Err(
                "history is in the old format (blocks): run astraea-state history-migrate first"
                    .into(),
            );
        }
        std::fs::create_dir_all(&history).map_err(|e| e.to_string())?;
        let mut pending = state.pending()?;
        let reader = HistoryReader::open(&history)?;
        let blocks_last = reader.last();
        if let Some(b) = blocks_last {
            state.drop_pending(b)?;
            pending.retain(|(seq, _)| *seq > b);
        }
        let first = match (blocks_last, pending.first()) {
            (Some(b), _) => b + 1,
            (None, Some((p, _))) => *p,
            (None, None) => last + 1,
        };
        let contiguous = pending
            .iter()
            .enumerate()
            .all(|(i, (seq, _))| *seq == first + i as u32);
        if !contiguous || first + pending.len() as u32 != last + 1 {
            return Err(format!(
                "blocks and state diverged: blocks up to {blocks_last:?}, {} pending, state up to {last}",
                pending.len()
            ));
        }

        // Indexes were added after the state: build them from the ledgers already
        // written, from blocks and from pending.
        let from = state.indexed()?.map_or(first, |i| i + 1);
        if from <= last {
            let t = Instant::now();
            for seq in from..=last {
                let body = match reader.get(seq)? {
                    Some(b) => b,
                    None => pending
                        .iter()
                        .find(|(p, _)| *p == seq)
                        .map(|(_, b)| b.clone())
                        .ok_or(format!("ledger {seq} is neither in blocks nor in pending"))?,
                };
                state.index_ledger(seq, &Ledger::decode(&body)?)?;
            }
            state.persist()?;
            info!(
                "indexes built: ledgers {from}..{last} in {:.0} s",
                t.elapsed().as_secs_f64()
            );
        }
        drop(reader);

        let dict = Dict::current(&history)?;
        let mut writer = HistoryWriter::create(
            &history,
            first,
            block_ledgers,
            level,
            CHANGES_LEVEL,
            dict.as_ref(),
            true,
        )?;
        let in_segment = pending.len() as u32;
        for (seq, body) in pending {
            writer.append(seq, body, Some(&prev_of(&state)))?;
            if writer.buffered() == 0 {
                state.drop_pending(seq)?;
            }
        }
        Ok(Sink {
            state,
            history,
            writer,
            args: (block_ledgers, segment_ledgers, level),
            in_segment,
            last,
            prev_hash,
        })
    }

    fn next(&self) -> u32 {
        self.last + 1
    }

    /// Checks a ledger and writes it. Accepts only the next one in
    /// order that continues the hash chain.
    fn commit(&mut self, ledger: &Ledger) -> Result<(), String> {
        let header = ledger.verify()?;
        let seq = header.sequence;
        if seq != self.next() {
            return Err(format!("expected {}, got {seq}", self.next()));
        }
        if header.parent_hash != self.prev_hash {
            return Err(format!(
                "chain broken at {seq}: parent hash does not match the previous ledger"
            ));
        }
        let body = ledger.encode();
        self.state.apply_ledger(seq, ledger, &body)?;
        self.state.persist()?;
        self.writer.append(seq, body, Some(&prev_of(&self.state)))?;
        if self.writer.buffered() == 0 {
            self.state.drop_pending(seq)?;
        }
        self.in_segment += 1;
        let (block_ledgers, segment_ledgers, level) = self.args;
        if self.in_segment >= segment_ledgers && self.writer.buffered() == 0 {
            let dict = Dict::current(&self.history)?;
            let fresh = HistoryWriter::create(
                &self.history,
                seq + 1,
                block_ledgers,
                level,
                CHANGES_LEVEL,
                dict.as_ref(),
                true,
            )?;
            std::mem::replace(&mut self.writer, fresh).finish()?;
            self.in_segment = 0;
            info!("block segment closed at {seq}");
        }
        self.last = seq;
        self.prev_hash = header.hash();
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,fjall=warn,lsm_tree=warn".into()),
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
    let mut sink = Sink::open(
        &args.data_dir,
        args.changes_group,
        args.segment_ledgers,
        args.zstd_level,
    )?;
    let metrics: Shared = Arc::new(Mutex::new(Metrics {
        last_ledger: sink.last,
        pending_ledgers: sink.writer.buffered() as u64,
        ..Metrics::default()
    }));
    update_sizes(&args.data_dir, &metrics);
    if let Some(addr) = args.metrics_addr {
        tokio::spawn(metrics::serve(addr, metrics.clone()));
    }
    let publishers = args
        .publishers
        .iter()
        .map(|h| hex::decode(h).map_err(|e| format!("publisher key {h}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let confirmer = Confirmer::new(publishers, args.unl_dir.clone());
    // The nodes' validations and manifests, passed on to API subscribers.
    let (node_streams, _) = tokio::sync::broadcast::channel(4096);
    for url in &args.validations_ws {
        tokio::spawn(confirm::listen(
            url.clone(),
            confirmer.clone(),
            Some(node_streams.clone()),
        ));
    }
    lock(&metrics).confirmed_ledger = sink.state.confirmed()?.unwrap_or(0);
    lock(&metrics).evidence_ledger = sink.state.last_evidence()?.unwrap_or(0);
    if !args.api_addr.is_empty() {
        let engine = Engine {
            state: sink.state.clone(),
            blocks: HistoryReader::open(&args.data_dir.join("history"))?
                .with_prev(Arc::new(prev_of(&sink.state))),
            network_id: args.network_id,
            started: Instant::now(),
            confirmer: Some(confirmer.clone()),
            quorum: Default::default(),
        };
        let forwarder = (!args.forward_rpc.is_empty()).then(|| {
            Arc::new(Forwarder::new(
                args.forward_rpc.clone(),
                Duration::from_secs(args.forward_timeout),
            ))
        });
        // So that the first client's server_info already has the node's fields.
        if let Some(f) = &forwarder {
            f.node_server_info();
        }
        let engine = Arc::new(engine);
        // What history and state the server holds, and how much disk each part takes.
        let (cov, m2) = (engine.clone(), metrics.clone());
        std::thread::spawn(move || {
            loop {
                let mut c = coverage(&cov);
                let mut m = lock(&m2);
                c.bytes.insert("state", m.state_bytes);
                c.bytes.insert("hot_history", m.blocks_bytes);
                m.coverage = c;
                drop(m);
                std::thread::sleep(Duration::from_secs(60));
            }
        });
        // New cold files are picked up in the background, more often than the
        // check in `range()`, so requests do not wait for the directory re-read.
        let bg = engine.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(15));
                if let Err(e) = bg.blocks.refresh_cold_every(Duration::from_secs(15)) {
                    warn!("cold history not re-read: {e}");
                }
            }
        });
        let guard = ledger_engine::guard::GuardConfig {
            max_requests: args.max_requests,
            max_bytes: args.max_response_bytes,
            max_connections: args.max_connections,
            sweep: Duration::from_secs(args.sweep_secs.max(1)),
            whitelist: args.limit_whitelist.clone(),
            trusted_proxies: args.trusted_proxies.clone(),
        };
        if guard.enabled() {
            info!(
                "client limits: {:?} requests, {:?} bytes per {} s, {:?} connections",
                guard.max_requests,
                guard.max_bytes,
                guard.sweep.as_secs(),
                guard.max_connections
            );
        }
        tokio::spawn(server::serve(
            args.api_addr.clone(),
            engine,
            forwarder,
            metrics.clone(),
            guard,
            Some(node_streams.clone()),
        ));
    }
    // Tree history below the ledger it started at, rebuilt in the background
    // from the object versions; until it is done, proof_entry starts there.
    {
        let state = sink.state.clone();
        let scratch = args.data_dir.join("levels-backfill");
        std::thread::spawn(move || {
            let t = Instant::now();
            match state.backfill_levels(&scratch, 8, |m| info!("tree history: {m}")) {
                Ok(Some((from, to))) => info!(
                    "tree history rebuilt for ledgers {from}..{to} in {:.0} s",
                    t.elapsed().as_secs_f64()
                ),
                Ok(None) => {}
                Err(e) => warn!("tree history not rebuilt: {e}"),
            }
        });
    }
    // The NFT index below the ledger it started at, filled in the background
    // with its own cold reader; until it is done the NFT history methods
    // answer notReady. On a failure it tries again later from where it stopped.
    {
        let state = sink.state.clone();
        let history = args.data_dir.join("history");
        let start = if args.network_id == 0 {
            MAINNET_FIRST_NFT_LEDGER
        } else {
            0
        };
        std::thread::spawn(move || {
            loop {
                match backfill_nfts(&state, &history, start) {
                    Ok(()) => break,
                    Err(e) => warn!("NFT index not filled yet: {e}; trying again in 10 minutes"),
                }
                std::thread::sleep(Duration::from_secs(600));
            }
        });
    }
    if let Some(dir) = &args.import_log {
        let from = sink.next();
        for raw in read_journal(dir)? {
            let (records, _) = parse_records(&raw)?;
            for (seq, body) in records {
                if seq >= sink.next() {
                    commit(&mut sink, &Ledger::decode(body)?, &metrics)?;
                }
            }
        }
        info!(
            "from journal {}: ledgers {from}..{}",
            dir.display(),
            sink.last
        );
    }
    let mut source = Source::connect(&args.grpc, &args.user).await?;
    source.require_unlimited().await?;
    info!(
        "tip {}, starting from {}",
        source.validated().await?,
        sink.next()
    );

    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    let mut stats_at = Instant::now();
    let mut written = 0u64;
    // A stop is taken while waiting on the node or between retries, never in
    // the middle of writing a ledger.
    'run: loop {
        let tip = tokio::select! {
            r = source.validated() => r,
            _ = &mut shutdown => break,
        };
        let tip = match tip {
            Ok(t) => {
                let mut m = lock(&metrics);
                m.connected = true;
                m.tip_ledger = t;
                t
            }
            Err(e) => {
                {
                    let mut m = lock(&metrics);
                    m.connected = false;
                    m.source_errors += 1;
                }
                warn!("tip: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        while sink.next() <= tip {
            let next = sink.next();
            let fetched = tokio::select! {
                r = source.ledger(next) => r,
                _ = &mut shutdown => break 'run,
            };
            let ledger = match fetched {
                Ok(l) => l,
                Err(e) => {
                    let missing = e.contains("NotFound") || e.contains("not found");
                    {
                        let mut m = lock(&metrics);
                        m.source_errors += 1;
                        m.missing_retries += u64::from(missing);
                    }
                    warn!("ledger {next}: {e}; retrying");
                    let pause = Duration::from_secs(if missing { 30 } else { 2 });
                    tokio::select! {
                        _ = tokio::time::sleep(pause) => {}
                        _ = &mut shutdown => break 'run,
                    }
                    continue;
                }
            };
            commit(&mut sink, &ledger, &metrics)?;
            try_confirm(&sink, &confirmer, &metrics)?;
            written += 1;
        }
        // Validations can arrive after the ledger, so try even without new writes.
        try_confirm(&sink, &confirmer, &metrics)?;
        update_validation_stats(&confirmer, &metrics);
        if stats_at.elapsed() > Duration::from_secs(60) {
            info!("written in the last minute: {written}, last {}", sink.last);
            written = 0;
            stats_at = Instant::now();
            update_sizes(&args.data_dir, &metrics);
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = &mut shutdown => break,
        }
    }
    info!("stopped, last applied {}", sink.last);
    Ok(())
}
