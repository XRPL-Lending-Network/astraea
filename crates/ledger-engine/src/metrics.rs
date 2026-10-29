//! Loader metrics in Prometheus format, for any Prometheus-compatible scraper.
//!
//! Beyond what a history server usually reports (requests, latency, load
//! progress), these say how far the data can be trusted: how many validators
//! signed the last confirmed ledger and how many were needed, which UNL lists
//! are in effect and when they expire, how proofs were built, and what part of
//! history is served, with state, and with tree history for state proofs.
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
    /// The quorum decision for the last confirmed ledger: validators that
    /// signed it, how many were needed, and the size of the UNL.
    pub quorum_signers: usize,
    pub quorum_needed: usize,
    pub unl_size: usize,
    /// Each configured publisher's latest list.
    pub unl_lists: Vec<UnlList>,
    pub coverage: Coverage,
    pub api: Api,
}

/// A publisher's latest UNL list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnlList {
    /// The publisher's master key, the first 16 hex digits.
    pub publisher: String,
    pub sequence: u64,
    pub validators: usize,
    /// Unix time; 0 if the list has none.
    pub expiration: u64,
}

/// What the server holds, refreshed every minute.
#[derive(Debug, Default)]
pub struct Coverage {
    /// Ledgers the API serves.
    pub first_ledger: u32,
    pub last_ledger: u32,
    /// First ledger with state (the snapshot), and first with tree history,
    /// which `proof_entry` needs.
    pub state_first_ledger: u32,
    pub tree_history_first_ledger: u32,
    pub cold_segments: u64,
    pub cold_transactions: u64,
    /// Bytes on disk by part.
    pub bytes: BTreeMap<&'static str, u64>,
}

/// Converts XRPL-epoch seconds to Unix time; 0 stays 0.
pub fn unix_of_ripple(t: u32) -> u64 {
    if t == 0 {
        0
    } else {
        u64::from(t) + RIPPLE_EPOCH
    }
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
    /// Requests answered by the node, by method.
    pub forwarded: BTreeMap<String, u64>,
    /// Response bytes by method.
    pub response_bytes: BTreeMap<String, u64>,
    /// Proof bundles built, by (method, how the target was confirmed).
    pub proofs: BTreeMap<(String, String), u64>,
    pub proof_cache_hits: u64,
    /// Requests being served now, regular and proofs.
    pub inflight: u64,
    pub inflight_proofs: u64,
    /// Sessions subscribed to each stream, and accounts subscribed in all.
    pub subscribers: BTreeMap<&'static str, u64>,
    pub subscribed_accounts: u64,
    /// Sessions disconnected for not reading their messages.
    pub ws_dropped: u64,
}

impl Api {
    pub fn record(
        &mut self,
        transport: &'static str,
        method: &str,
        status: &str,
        seconds: f64,
        bytes: usize,
        forwarded: bool,
    ) {
        *self
            .requests
            .entry((transport, method.to_owned(), status.to_owned()))
            .or_default() += 1;
        *self.response_bytes.entry(method.to_owned()).or_default() += bytes as u64;
        if forwarded {
            *self.forwarded.entry(method.to_owned()).or_default() += 1;
        }
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
        family(
            out,
            "astraea_api_forwarded_total",
            "counter",
            "Requests answered by the node rather than from our own data, by method.",
            self.forwarded
                .iter()
                .map(|(m, n)| (format!("method=\"{m}\""), n.to_string())),
        );
        family(
            out,
            "astraea_api_response_bytes_total",
            "counter",
            "Bytes of API responses, by method.",
            self.response_bytes
                .iter()
                .map(|(m, n)| (format!("method=\"{m}\""), n.to_string())),
        );
        family(
            out,
            "astraea_proof_bundles_total",
            "counter",
            "Evidence bundles built, by method and how the target ledger was confirmed (quorum, hash-chain, skip-list).",
            self.proofs.iter().map(|((m, by), n)| {
                (
                    format!("method=\"{m}\",confirmed_by=\"{by}\""),
                    n.to_string(),
                )
            }),
        );
        family(
            out,
            "astraea_proof_cache_hits_total",
            "counter",
            "Evidence bundles served from the cache of bundles that never change.",
            [(String::new(), self.proof_cache_hits.to_string())],
        );
        family(
            out,
            "astraea_api_inflight",
            "gauge",
            "Requests being served now, by pool: regular requests and proof bundles.",
            [
                ("pool=\"api\"".to_owned(), self.inflight.to_string()),
                (
                    "pool=\"proof\"".to_owned(),
                    self.inflight_proofs.to_string(),
                ),
            ],
        );
        family(
            out,
            "astraea_api_subscribers",
            "gauge",
            "WebSocket sessions subscribed to each stream.",
            self.subscribers
                .iter()
                .map(|(s, n)| (format!("stream=\"{s}\""), n.to_string())),
        );
        family(
            out,
            "astraea_api_subscribed_accounts",
            "gauge",
            "Accounts subscribed to, over all sessions.",
            [(String::new(), self.subscribed_accounts.to_string())],
        );
        family(
            out,
            "astraea_api_ws_dropped_total",
            "counter",
            "WebSocket sessions disconnected for not reading their messages.",
            [(String::new(), self.ws_dropped.to_string())],
        );
    }
}

/// One metric family: HELP, TYPE, and a sample per label set (empty labels
/// for a single sample).
fn family(
    out: &mut String,
    name: &str,
    kind: &str,
    help: &str,
    samples: impl IntoIterator<Item = (String, String)>,
) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    for (labels, value) in samples {
        if labels.is_empty() {
            let _ = writeln!(out, "{name} {value}");
        } else {
            let _ = writeln!(out, "{name}{{{labels}}} {value}");
        }
    }
}

/// The standard process metrics, from `/proc/self`; nothing where there is no
/// `/proc`.
fn process(out: &mut String) {
    // Clock ticks per second: 100 on every Linux the server runs on.
    const TICKS: f64 = 100.0;
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return;
    };
    // Fields after the command name, which is in parentheses and may hold spaces.
    let Some(rest) = stat.rfind(')').map(|i| &stat[i + 2..]) else {
        return;
    };
    let f: Vec<&str> = rest.split_whitespace().collect();
    let num = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    // Indexes from field 3 (state): utime 14, stime 15, threads 20, starttime 22.
    let cpu = (num(11) + num(12)) / TICKS;
    let boot = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("btime ")?.trim().parse::<f64>().ok())
        })
        .unwrap_or(0.0);
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("VmRSS:")?
                    .trim()
                    .trim_end_matches(" kB")
                    .parse::<u64>()
                    .ok()
            })
        })
        .unwrap_or(0)
        * 1024;
    let fds = std::fs::read_dir("/proc/self/fd").map_or(0, |d| d.count());
    let one = |v: String| [(String::new(), v)];
    family(
        out,
        "process_cpu_seconds_total",
        "counter",
        "User and system CPU time.",
        one(format!("{cpu:.2}")),
    );
    family(
        out,
        "process_resident_memory_bytes",
        "gauge",
        "Resident memory.",
        one(rss.to_string()),
    );
    family(
        out,
        "process_open_fds",
        "gauge",
        "Open file descriptors.",
        one(fds.to_string()),
    );
    family(
        out,
        "process_threads",
        "gauge",
        "Threads.",
        one(format!("{}", num(17))),
    );
    family(
        out,
        "process_start_time_seconds",
        "gauge",
        "Start time, Unix time.",
        one(format!("{:.0}", boot + num(19) / TICKS)),
    );
}

impl Coverage {
    fn render(&self, out: &mut String) {
        let one = |v: String| [(String::new(), v)];
        family(
            out,
            "astraea_history_first_ledger",
            "gauge",
            "First ledger the API serves.",
            one(self.first_ledger.to_string()),
        );
        family(
            out,
            "astraea_history_last_ledger",
            "gauge",
            "Last ledger the API serves.",
            one(self.last_ledger.to_string()),
        );
        family(
            out,
            "astraea_state_first_ledger",
            "gauge",
            "First ledger with state (the snapshot): state methods start here.",
            one(self.state_first_ledger.to_string()),
        );
        family(
            out,
            "astraea_tree_history_first_ledger",
            "gauge",
            "First ledger with tree history: proof_entry starts here.",
            one(self.tree_history_first_ledger.to_string()),
        );
        family(
            out,
            "astraea_cold_segments",
            "gauge",
            "Cold history segments.",
            one(self.cold_segments.to_string()),
        );
        family(
            out,
            "astraea_cold_transactions",
            "gauge",
            "Transactions in cold history.",
            one(self.cold_transactions.to_string()),
        );
        family(
            out,
            "astraea_storage_bytes",
            "gauge",
            "Bytes on disk by part: the state store (its indexes and tree history are in it, and also shown on their own), hot history, cold segments, cold indexes.",
            self.bytes
                .iter()
                .map(|(p, n)| (format!("part=\"{p}\""), n.to_string())),
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
        let one = |v: usize| [(String::new(), v.to_string())];
        family(
            &mut out,
            "astraea_quorum_signers",
            "gauge",
            "UNL validators that signed the last confirmed ledger.",
            one(self.quorum_signers),
        );
        family(
            &mut out,
            "astraea_quorum_needed",
            "gauge",
            "Signatures the quorum rule needed for the last confirmed ledger.",
            one(self.quorum_needed),
        );
        family(
            &mut out,
            "astraea_unl_size",
            "gauge",
            "Validators in the UNL the last confirmation was decided with.",
            one(self.unl_size),
        );
        let lists = |f: fn(&UnlList) -> String| {
            self.unl_lists
                .iter()
                .map(move |l| (format!("publisher=\"{}\"", l.publisher), f(l)))
        };
        family(
            &mut out,
            "astraea_unl_list_sequence",
            "gauge",
            "Sequence of the publisher's latest UNL list.",
            lists(|l| l.sequence.to_string()),
        );
        family(
            &mut out,
            "astraea_unl_list_validators",
            "gauge",
            "Validators in the publisher's latest UNL list.",
            lists(|l| l.validators.to_string()),
        );
        family(
            &mut out,
            "astraea_unl_list_expiration_timestamp_seconds",
            "gauge",
            "When the publisher's latest UNL list expires, Unix time.",
            lists(|l| l.expiration.to_string()),
        );
        self.coverage.render(&mut out);
        self.api.render(&mut out);
        process(&mut out);
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
        m.api
            .record("ws", "account_tx", "success", 0.003, 1000, false);
        m.api
            .record("http", "account_tx", "actNotFound", 0.2, 200, false);
        m.api
            .record("ws", "account_tx", "success", 9.0, 1000, false);
        m.api.record("http", "fee", "success", 0.01, 300, true);
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
            "astraea_api_response_bytes_total{method=\"account_tx\"} 2200",
            "astraea_api_forwarded_total{method=\"fee\"} 1",
        ] {
            assert!(text.contains(&format!("\n{line}\n")), "{line}");
        }
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (_, v) = line.rsplit_once(' ').unwrap();
            assert!(v.parse::<f64>().is_ok(), "{line}");
        }
    }

    #[test]
    fn trust_and_coverage_render() {
        let mut m = Metrics {
            quorum_signers: 33,
            quorum_needed: 28,
            unl_size: 35,
            unl_lists: vec![UnlList {
                publisher: "ED2677ABFFD1B33A".into(),
                sequence: 2026,
                validators: 35,
                expiration: unix_of_ripple(1_000),
            }],
            ..Metrics::default()
        };
        m.coverage.first_ledger = 86_339_141;
        m.coverage.bytes.insert("cold", 466_000_000_000);
        m.api
            .proofs
            .insert(("proof_tx".into(), "skip-list".into()), 4);
        m.api.subscribers.insert("ledger", 2);
        let text = m.render();
        for line in [
            "astraea_quorum_signers 33",
            "astraea_quorum_needed 28",
            "astraea_unl_list_expiration_timestamp_seconds{publisher=\"ED2677ABFFD1B33A\"} 946685800",
            "astraea_history_first_ledger 86339141",
            "astraea_storage_bytes{part=\"cold\"} 466000000000",
            "astraea_proof_bundles_total{method=\"proof_tx\",confirmed_by=\"skip-list\"} 4",
            "astraea_api_subscribers{stream=\"ledger\"} 2",
            "astraea_api_inflight{pool=\"proof\"} 0",
        ] {
            assert!(text.contains(&format!("\n{line}\n")), "{line}");
        }
        // Every family is declared once, and every sample parses.
        let mut seen = std::collections::BTreeSet::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                assert!(
                    seen.insert(rest.split(' ').next().unwrap().to_owned()),
                    "{line}"
                );
            } else if !line.starts_with('#') {
                let (_, v) = line.rsplit_once(' ').unwrap();
                assert!(v.parse::<f64>().is_ok(), "{line}");
            }
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
