//! Loader metrics in Prometheus format, for any Prometheus-compatible scraper.
//!
//! The HTTP side is minimal, like the archiver's: one path `/metrics`, no
//! keep-alive, the whole response at once. If the address is not up yet (the
//! tunnel starts later), the metrics server keeps retrying while loading goes on.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

/// Seconds from the XRPL epoch (2000-01-01) to the Unix epoch.
const RIPPLE_EPOCH: u64 = 946_684_800;

#[derive(Debug, Default)]
pub struct Metrics {
    /// The last tip request to the node succeeded.
    pub connected: bool,
    /// Last validated ledger according to the node.
    pub tip_ledger: u32,
    /// Last applied ledger.
    pub last_ledger: u32,
    /// Close time of the last applied ledger, seconds since the XRPL epoch.
    pub last_close_time: u32,
    pub last_commit_ms: u64,
    pub ledgers: u64,
    pub transactions: u64,
    pub changes: u64,
    /// Total seconds spent writing ledgers.
    pub commit_seconds: f64,
    pub source_errors: u64,
    /// Retries because the node does not have the needed ledger.
    pub missing_retries: u64,
    pub pending_ledgers: u64,
    pub blocks_bytes: u64,
    pub state_bytes: u64,
    /// Last ledger confirmed by a validator quorum.
    pub confirmed_ledger: u32,
    pub validations_connected: bool,
    pub validations: u64,
    pub validations_rejected: u64,
    pub manifests: u64,
    /// Last ledger with stored anchor evidence.
    pub evidence_ledger: u32,
}

pub type Shared = Arc<Mutex<Metrics>>;

/// A poisoned mutex is no reason to crash: these are counters, not invariants.
pub fn lock(m: &Shared) -> MutexGuard<'_, Metrics> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Metrics {
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP astraea_ingest_info Loader version.\n\
             # TYPE astraea_ingest_info gauge\n\
             astraea_ingest_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION"),
        );
        let mut put = |name: &str, kind: &str, help: &str, value: String| {
            let _ = writeln!(out, "# HELP astraea_ingest_{name} {help}");
            let _ = writeln!(out, "# TYPE astraea_ingest_{name} {kind}");
            let _ = writeln!(out, "astraea_ingest_{name} {value}");
        };
        put(
            "connected",
            "gauge",
            "The last tip request to the node succeeded.",
            u8::from(self.connected).to_string(),
        );
        put(
            "tip_ledger",
            "gauge",
            "Last validated ledger according to the node.",
            self.tip_ledger.to_string(),
        );
        put(
            "last_ledger",
            "gauge",
            "Last applied ledger.",
            self.last_ledger.to_string(),
        );
        let close = if self.last_close_time == 0 {
            0
        } else {
            u64::from(self.last_close_time) + RIPPLE_EPOCH
        };
        put(
            "last_ledger_close_timestamp_seconds",
            "gauge",
            "When the network closed the last applied ledger, Unix time.",
            close.to_string(),
        );
        put(
            "last_commit_timestamp_seconds",
            "gauge",
            "When the last ledger was written, Unix time.",
            format!("{:.3}", self.last_commit_ms as f64 / 1000.0),
        );
        put(
            "ledgers_total",
            "counter",
            "Ledgers written since start.",
            self.ledgers.to_string(),
        );
        put(
            "transactions_total",
            "counter",
            "Transactions in written ledgers.",
            self.transactions.to_string(),
        );
        put(
            "state_changes_total",
            "counter",
            "State changes in written ledgers.",
            self.changes.to_string(),
        );
        put(
            "commit_seconds_total",
            "counter",
            "Time spent writing ledgers: verification, state, blocks.",
            format!("{:.6}", self.commit_seconds),
        );
        put(
            "source_errors_total",
            "counter",
            "Failed requests to the node.",
            self.source_errors.to_string(),
        );
        put(
            "missing_retries_total",
            "counter",
            "Retries because the node does not have the needed ledger.",
            self.missing_retries.to_string(),
        );
        put(
            "pending_ledgers",
            "gauge",
            "Ledgers waiting for their block.",
            self.pending_ledgers.to_string(),
        );
        put(
            "blocks_bytes",
            "gauge",
            "Size of the block history on disk.",
            self.blocks_bytes.to_string(),
        );
        put(
            "confirmed_ledger",
            "gauge",
            "Last ledger confirmed by a quorum of UNL validators.",
            self.confirmed_ledger.to_string(),
        );
        put(
            "validations_connected",
            "gauge",
            "The node's validation stream is connected.",
            u8::from(self.validations_connected).to_string(),
        );
        put(
            "validations_total",
            "counter",
            "Validations received with a valid signature.",
            self.validations.to_string(),
        );
        put(
            "validations_rejected_total",
            "counter",
            "Validations rejected: unparsable or bad signature.",
            self.validations_rejected.to_string(),
        );
        put(
            "evidence_ledger",
            "gauge",
            "Last ledger with stored anchor evidence (quorum validations).",
            self.evidence_ledger.to_string(),
        );
        put(
            "manifests_total",
            "counter",
            "Manifests received from the node.",
            self.manifests.to_string(),
        );
        put(
            "state_bytes",
            "gauge",
            "Size of the state store on disk.",
            self.state_bytes.to_string(),
        );
        out
    }
}

/// Total size of all files in a directory, including subdirectories.
pub fn dir_bytes(dir: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_bytes(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

pub async fn serve(addr: SocketAddr, metrics: Shared) {
    loop {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!("metrics: cannot listen on {addr}: {e}; retrying in 10 s");
                sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        info!("metrics on http://{addr}/metrics");
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let _ = timeout(Duration::from_secs(5), answer(stream, &metrics)).await;
                }
                Err(e) => {
                    warn!("metrics: accept: {e}");
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

async fn answer(mut stream: TcpStream, metrics: &Shared) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    let (status, body) = if head.starts_with("GET /metrics ") || head.starts_with("GET /metrics?") {
        ("200 OK", lock(metrics).render())
    } else {
        ("404 Not Found", String::from("only /metrics\n"))
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_valid_exposition() {
        let m = Metrics {
            last_ledger: 107_875_645,
            last_close_time: 1_000,
            last_commit_ms: 1_500,
            ..Metrics::default()
        };
        let text = m.render();
        assert!(text.contains("\nastraea_ingest_last_ledger 107875645\n"));
        assert!(text.contains("\nastraea_ingest_last_ledger_close_timestamp_seconds 946685800\n"));
        assert!(text.contains("\nastraea_ingest_last_commit_timestamp_seconds 1.500\n"));
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (_, v) = line.rsplit_once(' ').unwrap();
            assert!(v.parse::<f64>().is_ok(), "{line}");
        }
    }

    #[test]
    fn dir_bytes_counts_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), [0u8; 10]).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b"), [0u8; 5]).unwrap();
        assert_eq!(dir_bytes(dir.path()), 15);
    }
}
