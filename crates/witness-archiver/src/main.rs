//! Archiver of signed XRPL validations.
//!
//! Subscribes to the node's validation stream through its local admin port
//! and writes the originals (raw signed validations) into archive segments.
//! It exposes nothing to the outside.
//!
//! Resilience:
//! - the journal is flushed to disk once a second, so a crash loses at most
//!   that much;
//! - on disconnect it reconnects with a growing pause of up to 5 s: the node
//!   is local, an attempt costs nothing, and every extra second of waiting
//!   is validations that cannot be recovered. After a successful connection
//!   the pause starts from one second again;
//! - if the connection is up but no validations arrive for longer than
//!   `--stall-secs`, that also counts as a disconnect: the node may have hung
//!   while leaving the socket open;
//! - every disconnect and recovery is written to `gaps.jsonl` as one line,
//!   with the last and first ledger around it, so gaps are visible instead
//!   of guessed. Failed reconnect attempts only go to the process log.
//!   Shutdown is logged too, so downtime during a restart can be explained
//!   from the journal.
//!
//! Metrics are served on `--metrics-addr`, see the `metrics` module.
//! Validator manifests: see the `manifests` module.

mod manifests;
mod metrics;
mod nunl;

use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::time::{Instant, interval, sleep};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};
use witness_core::util::now_ms;
use witness_store::segment::latest_seal;
use witness_store::{Record, SegmentConfig, SegmentWriter};

use crate::manifests::{Book, Outcome};
use crate::metrics::{Metrics, Shared, lock};

#[derive(Debug, Parser)]
#[command(version, about = "Archiver of signed XRPL validations")]
struct Args {
    /// The node's admin WebSocket. Local address only: the archiver must not
    /// reach the node over the network.
    #[arg(long, env = "WITNESS_URL", default_value = "ws://127.0.0.1:6006")]
    url: String,
    /// Archive directory.
    #[arg(long, env = "WITNESS_DATA_DIR")]
    data_dir: PathBuf,
    /// Source name in seals: which of our machines received the validations.
    #[arg(long, env = "WITNESS_SOURCE")]
    source: String,
    /// Nominal segment size in ledgers; 1024 is about an hour.
    #[arg(long, default_value_t = 1024)]
    segment_ledgers: u32,
    /// Margin for late validations before a segment is closed.
    #[arg(long, default_value_t = 32)]
    grace_ledgers: u32,
    /// zstd level used when closing a segment. Going above 9 makes no sense:
    /// validations are mostly signatures and keys, i.e. noise, and level 19 on
    /// live data gains about one percent at 30 times the time. Compression
    /// also runs on the same thread that reads the subscription.
    #[arg(long, default_value_t = 9)]
    zstd_level: i32,
    /// How many seconds of silence on a live connection count as a disconnect.
    #[arg(long, default_value_t = 60)]
    stall_secs: u64,
    /// Where to serve metrics, for example an address inside the monitoring
    /// tunnel. If unset, there are no metrics.
    #[arg(long, env = "WITNESS_METRICS_ADDR")]
    metrics_addr: Option<SocketAddr>,
    /// Directory of the UNL list collector on the same machine, used to report
    /// in metrics when it last saw each publisher.
    #[arg(long, env = "WITNESS_UNL_DIR")]
    unl_dir: Option<PathBuf>,
}

/// Supporting evidence the archiver requests from the node over the same
/// connection: validator manifests and the Negative UNL.
struct Side {
    book: Book,
    nunl: nunl::Watch,
}

/// How a single connection session ended.
enum SessionEnd {
    Shutdown,
    /// Connection lost. `was_connected` tells whether this session got connected
    /// at all: a failed reconnect attempt is not a new disconnect.
    Lost {
        reason: String,
        was_connected: bool,
    },
}

fn lost(reason: impl Into<String>, was_connected: bool) -> SessionEnd {
    SessionEnd::Lost {
        reason: reason.into(),
        was_connected,
    }
}

const MAX_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Stats {
    received: u64,
    bad: u64,
    window: u64,
    sealed: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time() // journald adds the timestamp
        // Colors only in a terminal: in journald the color codes are just garbage.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    let args = Args::parse();
    if let Err(e) = run(args).await {
        error!("stopped with error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    if !args.url.starts_with("ws://127.0.0.1:") && !args.url.starts_with("ws://[::1]:") {
        warn!(
            "address {} is not local: the archiver is meant to connect to its own node",
            args.url
        );
    }
    let mut writer = SegmentWriter::open(SegmentConfig {
        dir: args.data_dir.clone(),
        source: args.source.clone(),
        segment_ledgers: args.segment_ledgers,
        grace_ledgers: args.grace_ledgers,
        zstd_level: args.zstd_level,
    })?;
    if writer.torn_bytes_at_start > 0 {
        warn!(
            "cut off a torn journal tail at startup: {} bytes",
            writer.torn_bytes_at_start
        );
    }
    if let Some((first, n)) = writer.current() {
        info!("continuing the open segment from ledger {first}, {n} records in it");
    }
    let gaps = args.data_dir.join("gaps.jsonl");
    let metrics = start_metrics(&args, &writer)?;
    let mut side = Side {
        book: Book::open(&args.data_dir)?,
        nunl: nunl::Watch::open(&args.data_dir)?,
    };
    let mut stats = Stats::default();
    let mut backoff = Duration::from_secs(1);
    let mut shutdown = Box::pin(shutdown_signal());

    loop {
        let end = session(
            &args,
            &mut writer,
            &mut side,
            &mut stats,
            &metrics,
            &gaps,
            &mut shutdown,
        )
        .await;
        lock(&metrics).connected = false;
        match end {
            SessionEnd::Shutdown => break,
            SessionEnd::Lost {
                reason,
                was_connected,
            } => {
                writer.sync()?;
                if was_connected {
                    lock(&metrics).disconnects += 1;
                    backoff = Duration::from_secs(1);
                    log_gap(
                        &gaps,
                        json!({
                            "event": "disconnected",
                            "at_ms": now_ms(),
                            "last_ledger": writer.last_ledger(),
                            "reason": reason,
                        }),
                    );
                }
                warn!(
                    "connection lost: {reason}; retrying in {} s",
                    backoff.as_secs()
                );
            }
        }
        tokio::select! {
            _ = sleep(backoff) => {}
            _ = &mut shutdown => break,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }

    writer.sync()?;
    log_gap(
        &gaps,
        json!({"event": "stopped", "at_ms": now_ms(), "last_ledger": writer.last_ledger()}),
    );
    info!(
        "stopped; received {}, rejected {}, segments sealed {}",
        stats.received, stats.bad, stats.sealed
    );
    Ok(())
}

/// Initial metrics state, from what is already on disk, plus the server.
fn start_metrics(
    args: &Args,
    writer: &SegmentWriter,
) -> Result<Shared, Box<dyn std::error::Error>> {
    let segments = args.data_dir.join("segments");
    let mut archive_bytes = 0;
    for entry in std::fs::read_dir(&segments)? {
        let path = entry?.path();
        if path.to_string_lossy().ends_with(".xwv.zst") {
            archive_bytes += std::fs::metadata(&path)?.len();
        }
    }
    let last = latest_seal(&segments)?;
    let metrics: Shared = Arc::new(Mutex::new(Metrics {
        source: args.source.clone(),
        unl_dir: args.unl_dir.clone(),
        archive_bytes,
        journal_bytes: writer.journal_bytes(),
        last_seal_ms: last.as_ref().map_or(0, |s| s.sealed_ms),
        last_seal_missing: last
            .as_ref()
            .map_or(0, |s| missing_count(&s.missing_ledgers)),
        ..Metrics::default()
    }));
    if let Some(addr) = args.metrics_addr {
        tokio::spawn(metrics::serve(addr, metrics.clone()));
    }
    Ok(metrics)
}

fn missing_count(ranges: &[[u32; 2]]) -> u64 {
    ranges
        .iter()
        .map(|[a, b]| u64::from(b.saturating_sub(*a)) + 1)
        .sum()
}

async fn session(
    args: &Args,
    writer: &mut SegmentWriter,
    side: &mut Side,
    stats: &mut Stats,
    metrics: &Shared,
    gaps: &Path,
    shutdown: &mut std::pin::Pin<Box<impl std::future::Future<Output = ()>>>,
) -> SessionEnd {
    let Side { book, nunl } = side;
    let (mut ws, _) = tokio::select! {
        r = connect_async(args.url.as_str()) => match r {
            Ok(x) => x,
            Err(e) => return lost(format!("connect: {e}"), false),
        },
        _ = &mut *shutdown => return SessionEnd::Shutdown,
    };
    let subscribe = json!({"id": 1, "command": "subscribe", "streams": ["validations"]});
    if let Err(e) = ws.send(Message::text(subscribe.to_string())).await {
        return lost(format!("subscribe: {e}"), true);
    }
    info!("connected to {}, validation subscription sent", args.url);
    lock(metrics).connected = true;
    log_gap(
        gaps,
        json!({"event": "connected", "at_ms": now_ms(), "last_ledger": writer.last_ledger()}),
    );

    let mut tick = interval(Duration::from_secs(1));
    let mut report = interval(Duration::from_secs(60));
    report.tick().await;
    let stall = Duration::from_secs(args.stall_secs);
    let mut last_validation = Instant::now();
    let mut first_after_connect = true;

    loop {
        tokio::select! {
            msg = ws.next() => {
                let text = match msg {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Close(c))) => return lost(format!("node closed the connection: {c:?}"), true),
                    Some(Ok(_)) => continue, // ping/pong/binary: the library answers pings itself
                    Some(Err(e)) => return lost(format!("read: {e}"), true),
                    None => return lost("stream ended", true),
                };
                let v: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(e) => {
                        stats.bad += 1;
                        lock(metrics).rejected += 1;
                        warn!("message is not json: {e}");
                        continue;
                    }
                };
                if Book::is_ours(&v) {
                    match book.absorb(&v, now_ms()) {
                        Ok(Outcome::Stored { master_key, seq }) => {
                            lock(metrics).manifests_stored = book.stored_total;
                            info!("manifest stored: {master_key}, seq {seq}");
                        }
                        Ok(_) => {}
                        Err(e) => error!("writing manifest: {e}"),
                    }
                    continue;
                }
                if nunl::Watch::is_ours(&v) {
                    match nunl.absorb(&v, now_ms()) {
                        Ok((flag, Ok(0))) => info!("Negative UNL at flag ledger {flag}: empty"),
                        Ok((flag, Ok(n))) => info!("Negative UNL at flag ledger {flag}: object of {n} bytes"),
                        Ok((flag, Err(e))) => warn!("Negative UNL at flag ledger {flag}: node answered {e}"),
                        Err(e) => error!("writing Negative UNL: {e}"),
                    }
                    continue;
                }
                match parse_validation_value(&v) {
                    Ok(Some(Parsed { rec, key })) => {
                        if first_after_connect {
                            first_after_connect = false;
                            log_gap(gaps, json!({"event": "first_validation", "at_ms": now_ms(), "ledger": rec.ledger_index}));
                        }
                        last_validation = Instant::now();
                        let appended = writer.append(&rec);
                        // The metrics lock is held only inside this block: the
                        // socket send comes next, and the lock must not be held
                        // across an await. None means the write failed and the
                        // validation is not counted.
                        let ask = {
                            let mut m = lock(metrics);
                            if let Some(net) = writer.network_ledger() {
                                m.network_ledger = net;
                            }
                            match appended {
                                Ok(sealed) => {
                                    if let Some(sealed) = sealed {
                                        stats.sealed += 1;
                                        let s = &sealed.seal;
                                        let missing = missing_count(&s.missing_ledgers);
                                        m.sealed += 1;
                                        m.last_seal_ms = s.sealed_ms;
                                        m.last_seal_missing = missing;
                                        m.missing_ledgers += missing;
                                        m.archive_bytes += sealed.zst_bytes;
                                        info!(
                                            "segment sealed: {}..{} records {} gaps {} compressed {} -> {} bytes",
                                            s.coverage_first, s.coverage_last, s.records,
                                            s.missing_ledgers.len(), s.raw_bytes, sealed.zst_bytes
                                        );
                                    }
                                    m.validations += 1;
                                    m.last_validation_ms = rec.received_ms;
                                    m.journal_bytes = writer.journal_bytes();
                                    if writer.is_out_of_window(rec.ledger_index) {
                                        m.out_of_window += 1;
                                        Some(None)
                                    } else if let Some(key) = &key {
                                        m.saw_validator(key, rec.ledger_index);
                                        // Only ask for manifests on our own network:
                                        // the node does not know foreign validators anyway.
                                        Some(book.request_for(key, rec.received_ms))
                                    } else {
                                        Some(None)
                                    }
                                }
                                Err(e) => {
                                    // A write error is no reason to drop the connection,
                                    // but it must not go unreported either.
                                    error!("writing to archive: {e}");
                                    stats.bad += 1;
                                    m.rejected += 1;
                                    None
                                }
                            }
                        };
                        let Some(ask) = ask else { continue };
                        if let Some(req) = ask
                            && let Err(e) = ws.send(Message::text(req)).await
                        {
                            return lost(format!("manifest request: {e}"), true);
                        }
                        // Only after warmup: until a segment is open the reference is not reliable yet.
                        if let Some(req) = writer.current().and(writer.network_ledger()).and_then(|n| nunl.request_for(n))
                            && let Err(e) = ws.send(Message::text(req)).await
                        {
                            return lost(format!("Negative UNL request: {e}"), true);
                        }
                        stats.received += 1;
                        stats.window += 1;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        stats.bad += 1;
                        lock(metrics).rejected += 1;
                        warn!("could not parse message: {e}");
                    }
                }
            }
            _ = tick.tick() => {
                if let Err(e) = writer.sync() {
                    error!("journal flush: {e}");
                }
                if let Err(e) = ws.flush().await {
                    return lost(format!("send: {e}"), true);
                }
                if last_validation.elapsed() > stall {
                    return lost(format!("no validations for {} s on a live connection", stall.as_secs()), true);
                }
            }
            _ = report.tick() => {
                let cur = writer.current().map(|(f, n)| format!("segment from {f}, {n} records")).unwrap_or_default();
                info!("{} validations in the last minute; total {}, rejected {}; {cur}", stats.window, stats.received, stats.bad);
                stats.window = 0;
            }
            _ = &mut *shutdown => {
                ws.close(None).await.ok();
                return SessionEnd::Shutdown;
            }
        }
    }
}

/// A validation from the stream: the archive record and the signer's key, for
/// counting validators. The key may be missing; the record is just as good.
struct Parsed {
    rec: Record,
    key: Option<String>,
}

/// Extracts the original validation and the ledger index from a stream message.
/// `Ok(None)` means the message is not a validation (for example, the
/// subscription response).
#[cfg(test)]
fn parse_validation(text: &str) -> Result<Option<Parsed>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("json: {e}"))?;
    parse_validation_value(&v)
}

fn parse_validation_value(v: &Value) -> Result<Option<Parsed>, String> {
    if v.get("type").and_then(Value::as_str) != Some("validationReceived") {
        return Ok(None);
    }
    let data_hex = v
        .get("data")
        .and_then(Value::as_str)
        .ok_or("no data field")?;
    let data = hex::decode(data_hex).map_err(|e| format!("data is not hex: {e}"))?;
    let ledger_index = match v.get("ledger_index") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
    .and_then(|n| u32::try_from(n).ok())
    .ok_or("missing or invalid ledger_index")?;
    let key = v
        .get("validation_public_key")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(Some(Parsed {
        rec: Record {
            received_ms: now_ms(),
            ledger_index,
            data,
        },
        key,
    }))
}

fn log_gap(path: &Path, event: Value) {
    let line = format!("{event}\n");
    let res = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(line.as_bytes()).and_then(|()| f.sync_data()));
    if let Err(e) = res {
        error!("gap log {}: {e}", path.display());
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(_) => {
                tokio::signal::ctrl_c().await.ok();
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
    info!("received shutdown signal");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_shaped_message() {
        let msg = r#"{"type":"validationReceived","data":"2280000001","ledger_index":107834197,"ledger_hash":"EC","validation_public_key":"n9K"}"#;
        let p = parse_validation(msg).unwrap().unwrap();
        assert_eq!(p.rec.ledger_index, 107_834_197);
        assert_eq!(p.rec.data, vec![0x22, 0x80, 0x00, 0x00, 0x01]);
        assert_eq!(p.key.as_deref(), Some("n9K"));
    }

    #[test]
    fn string_ledger_index_is_accepted() {
        let msg = r#"{"type":"validationReceived","data":"22","ledger_index":"42"}"#;
        assert_eq!(parse_validation(msg).unwrap().unwrap().rec.ledger_index, 42);
    }

    #[test]
    fn other_messages_are_skipped() {
        assert!(
            parse_validation(r#"{"type":"response","result":{}}"#)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn missing_ranges_are_counted_inclusive() {
        assert_eq!(missing_count(&[[10, 10], [20, 24]]), 6);
        assert_eq!(missing_count(&[]), 0);
    }

    #[test]
    fn broken_validation_is_an_error() {
        assert!(
            parse_validation(r#"{"type":"validationReceived","data":"zz","ledger_index":1}"#)
                .is_err()
        );
        assert!(parse_validation(r#"{"type":"validationReceived","ledger_index":1}"#).is_err());
    }
}
