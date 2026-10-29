//! Loader metrics in Prometheus format, for any Prometheus-compatible scraper.
//!
//! The HTTP side is minimal, like the archiver's: one path `/metrics`, no
//! keep-alive, the whole response at once. If the address is not up yet (the
//! tunnel starts later), the metrics server keeps retrying while loading goes on.

use std::collections::BTreeMap;
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
    pub api: Api,
}

/// Upper bounds of the API latency buckets, seconds.
pub const LATENCY_BUCKETS: [f64; 9] = [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 2.5];

/// Requests to the Clio-compatible API. Methods and statuses come from a
/// bounded set (the server folds unknown ones into `other`), so the series
/// stay few.
#[derive(Debug, Default)]
pub struct Api {
    /// Requests by (transport, method, status), status being `success` or the
    /// error name.
    pub requests: BTreeMap<(&'static str, String, String), u64>,
    /// Latency by method: requests per bucket (not cumulative), count, sum.
    pub latency: BTreeMap<String, ([u64; LATENCY_BUCKETS.len()], u64, f64)>,
    /// Open WebSocket sessions.
    pub ws_sessions: u64,
    pub ws_sessions_total: u64,
}

impl Api {
    pub fn record(&mut self, transport: &'static str, method: &str, status: &str, seconds: f64) {
        *self
            .requests
            .entry((transport, method.to_owned(), status.to_owned()))
            .or_default() += 1;
        let (buckets, count, sum) = self.latency.entry(method.to_owned()).or_default();
        if let Some(i) = LATENCY_BUCKETS.iter().position(|&b| seconds <= b) {
            buckets[i] += 1;
        }
        *count += 1;
        *sum += seconds;
    }

    fn render(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# HELP astraea_api_requests_total API requests by transport, method and status.\n\
             # TYPE astraea_api_requests_total counter"
        );
        for ((transport, method, status), n) in &self.requests {
            let _ = writeln!(
                out,
                "astraea_api_requests_total{{transport=\"{transport}\",method=\"{method}\",status=\"{status}\"}} {n}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP astraea_api_request_duration_seconds Time to answer an API request.\n\
             # TYPE astraea_api_request_duration_seconds histogram"
        );
        for (method, (buckets, count, sum)) in &self.latency {
            let mut below = 0;
            for (b, n) in LATENCY_BUCKETS.iter().zip(buckets) {
                below += n;
                let _ = writeln!(
                    out,
                    "astraea_api_request_duration_seconds_bucket{{method=\"{method}\",le=\"{b}\"}} {below}"
                );
            }
            let _ = writeln!(
                out,
                "astraea_api_request_duration_seconds_bucket{{method=\"{method}\",le=\"+Inf\"}} {count}\n\
                 astraea_api_request_duration_seconds_sum{{method=\"{method}\"}} {sum:.6}\n\
                 astraea_api_request_duration_seconds_count{{method=\"{method}\"}} {count}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP astraea_api_ws_sessions Open WebSocket sessions.\n\
             # TYPE astraea_api_ws_sessions gauge\n\
             astraea_api_ws_sessions {}\n\
             # HELP astraea_api_ws_sessions_total WebSocket sessions opened since start.\n\
             # TYPE astraea_api_ws_sessions_total counter\n\
             astraea_api_ws_sessions_total {}",
            self.ws_sessions, self.ws_sessions_total
        );
    }
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
        self.api.render(&mut out);
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
    fn api_requests_render_as_a_histogram() {
        let mut m = Metrics::default();
        m.api.record("ws", "account_tx", "success", 0.003);
        m.api.record("http", "account_tx", "actNotFound", 0.2);
        m.api.record("ws", "account_tx", "success", 9.0);
        m.api.ws_sessions = 2;
        let text = m.render();
        for line in [
            "astraea_api_requests_total{transport=\"ws\",method=\"account_tx\",status=\"success\"} 2",
            "astraea_api_requests_total{transport=\"http\",method=\"account_tx\",status=\"actNotFound\"} 1",
            "astraea_api_request_duration_seconds_bucket{method=\"account_tx\",le=\"0.0025\"} 0",
            "astraea_api_request_duration_seconds_bucket{method=\"account_tx\",le=\"0.005\"} 1",
            "astraea_api_request_duration_seconds_bucket{method=\"account_tx\",le=\"2.5\"} 2",
            "astraea_api_request_duration_seconds_bucket{method=\"account_tx\",le=\"+Inf\"} 3",
            "astraea_api_request_duration_seconds_count{method=\"account_tx\"} 3",
            "astraea_api_ws_sessions 2",
        ] {
            assert!(text.contains(&format!("\n{line}\n")), "{line}");
        }
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
