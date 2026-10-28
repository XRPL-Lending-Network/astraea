//! Archiver metrics in Prometheus format, for any Prometheus-compatible scraper.
//!
//! Served on an address inside the monitoring tunnel. The HTTP here is
//! minimal: one path, `/metrics`, no keep-alive, the whole response at once.
//! A heavy web server is not needed for one scrape every 15 seconds.
//!
//! Metrics matter, but the archive matters more: if the address is not up
//! yet (the tunnel starts after the archiver) or is taken, the metrics server
//! keeps retrying while recording continues.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

/// A validator counts as active if its last validation is no more than this
/// many ledgers behind the current one (about 30 seconds).
const ACTIVE_LEDGERS: u32 = 8;

/// Keys silent for longer are forgotten: the validator pool keeps changing.
const FORGET_LEDGERS: u32 = 256;

#[derive(Debug, Default)]
pub struct Metrics {
    pub source: String,
    pub connected: bool,
    pub validations: u64,
    pub out_of_window: u64,
    pub rejected: u64,
    pub disconnects: u64,
    pub last_validation_ms: u64,
    /// The network's current ledger, from the stream median.
    pub network_ledger: u32,
    pub sealed: u64,
    pub last_seal_ms: u64,
    pub last_seal_missing: u64,
    /// Missing ledgers across all seals since the process started.
    pub missing_ledgers: u64,
    pub archive_bytes: u64,
    pub journal_bytes: u64,
    pub manifests_stored: u64,
    /// Directory of the UNL list collector, if it runs on this machine.
    pub unl_dir: Option<PathBuf>,
    /// Validator key -> last ledger it sent a validation for.
    pub(crate) validators: HashMap<String, u32>,
}

pub type Shared = Arc<Mutex<Metrics>>;

/// A poisoned mutex is no reason to crash here: metrics are counters, not
/// invariants, and they can still be served after a panic elsewhere.
pub fn lock(m: &Shared) -> MutexGuard<'_, Metrics> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Metrics {
    pub fn saw_validator(&mut self, key: &str, ledger: u32) {
        let e = self.validators.entry(key.to_owned()).or_insert(ledger);
        *e = (*e).max(ledger);
    }

    /// How many distinct validators sent validations over the last few ledgers.
    pub fn active_validators(&self) -> usize {
        self.validators
            .values()
            .filter(|l| l.saturating_add(ACTIVE_LEDGERS) >= self.network_ledger)
            .count()
    }

    pub fn forget_silent(&mut self) {
        let now = self.network_ledger;
        self.validators
            .retain(|_, l| l.saturating_add(FORGET_LEDGERS) >= now);
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        // The info value is always 1; the meaning is in the labels.
        let _ = writeln!(
            out,
            "# HELP xrpl_witness_info Archiver version and the source name used in seals.\n\
             # TYPE xrpl_witness_info gauge\n\
             xrpl_witness_info{{version=\"{}\",source=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION"),
            self.source.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let mut put = |name: &str, kind: &str, help: &str, value: String| {
            let _ = writeln!(out, "# HELP xrpl_witness_{name} {help}");
            let _ = writeln!(out, "# TYPE xrpl_witness_{name} {kind}");
            let _ = writeln!(out, "xrpl_witness_{name} {value}");
        };
        let secs = |ms: u64| format!("{:.3}", ms as f64 / 1000.0);
        put(
            "connected",
            "gauge",
            "The subscription to the node's validation stream is active.",
            u8::from(self.connected).to_string(),
        );
        put(
            "validations_total",
            "counter",
            "Validations written to the archive.",
            self.validations.to_string(),
        );
        put(
            "validations_out_of_window_total",
            "counter",
            "Of those, far from the current ledger: other networks and very late ones.",
            self.out_of_window.to_string(),
        );
        put(
            "rejected_total",
            "counter",
            "Messages that could not be parsed or written.",
            self.rejected.to_string(),
        );
        put(
            "disconnects_total",
            "counter",
            "Disconnects from the node.",
            self.disconnects.to_string(),
        );
        put(
            "last_validation_timestamp_seconds",
            "gauge",
            "When the last validation was written, Unix time.",
            secs(self.last_validation_ms),
        );
        put(
            "network_ledger",
            "gauge",
            "The network's current ledger, from the stream median.",
            self.network_ledger.to_string(),
        );
        put(
            "validators",
            "gauge",
            "Distinct validators over the last 8 ledgers.",
            self.active_validators().to_string(),
        );
        put(
            "segments_sealed_total",
            "counter",
            "Segments sealed since startup.",
            self.sealed.to_string(),
        );
        put(
            "last_seal_timestamp_seconds",
            "gauge",
            "When the last segment was sealed, Unix time.",
            secs(self.last_seal_ms),
        );
        put(
            "last_seal_missing_ledgers",
            "gauge",
            "Missing ledgers in the last seal.",
            self.last_seal_missing.to_string(),
        );
        put(
            "missing_ledgers_total",
            "counter",
            "Missing ledgers across all seals since startup.",
            self.missing_ledgers.to_string(),
        );
        put(
            "archive_bytes",
            "gauge",
            "Size of closed segments on disk.",
            self.archive_bytes.to_string(),
        );
        put(
            "journal_bytes",
            "gauge",
            "Size of the open segment's journal.",
            self.journal_bytes.to_string(),
        );
        put(
            "manifests_stored_total",
            "counter",
            "New validator manifests stored since startup.",
            self.manifests_stored.to_string(),
        );
        if let Some(dir) = &self.unl_dir {
            let _ = writeln!(
                out,
                "# HELP xrpl_witness_unl_last_success_timestamp_seconds Last successful poll of a UNL list publisher.\n\
                 # TYPE xrpl_witness_unl_last_success_timestamp_seconds gauge"
            );
            for (site, ms) in unl_last_success(&dir.join("observations.jsonl")) {
                let _ = writeln!(
                    out,
                    "xrpl_witness_unl_last_success_timestamp_seconds{{site=\"{}\"}} {}",
                    site.replace('\\', "\\\\").replace('"', "\\\""),
                    secs(ms)
                );
            }
        }
        out
    }
}

/// Last successful poll of each publisher, from the tail of the collector's log.
/// With polls every 10 minutes for two publishers, a 32 KB tail covers more
/// than a day.
fn unl_last_success(path: &Path) -> Vec<(String, u64)> {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL: u64 = 32 * 1024;
    let mut buf = String::new();
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if f.seek(SeekFrom::Start(len.saturating_sub(TAIL))).is_err()
        || f.read_to_string(&mut buf).is_err()
    {
        return Vec::new();
    }
    let mut best: HashMap<String, u64> = HashMap::new();
    for line in buf.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue; // the first line of the tail may be cut off
        };
        let ok = v.get("status").and_then(|s| s.as_u64()) == Some(200) && v.get("error").is_none();
        if let (true, Some(site), Some(at)) = (
            ok,
            v.get("site").and_then(|s| s.as_str()),
            v.get("at_ms").and_then(|a| a.as_u64()),
        ) {
            let e = best.entry(site.to_owned()).or_insert(at);
            *e = (*e).max(at);
        }
    }
    let mut out: Vec<_> = best.into_iter().collect();
    out.sort();
    out
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
                // Time limit: a slow client must not hold up the only
                // handler.
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
        let mut m = lock(metrics);
        m.forget_silent();
        ("200 OK", m.render())
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
    fn active_validators_follow_the_network() {
        let mut m = Metrics {
            network_ledger: 1000,
            ..Metrics::default()
        };
        m.saw_validator("A", 1000);
        m.saw_validator("B", 995);
        m.saw_validator("C", 900); // silent for a long time
        m.saw_validator("B", 999);
        assert_eq!(m.active_validators(), 2);
        m.network_ledger = 1500;
        m.forget_silent();
        assert_eq!(m.active_validators(), 0);
        assert!(m.validators.is_empty());
    }

    #[test]
    fn unl_freshness_comes_from_the_collector_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("observations.jsonl");
        std::fs::write(
            &log,
            "{\"at_ms\":1000,\"site\":\"a\",\"status\":200}\n\
             {\"at_ms\":2000,\"site\":\"a\",\"error\":\"timeout\"}\n\
             {\"at_ms\":1500,\"site\":\"b\",\"status\":200}\n",
        )
        .unwrap();
        assert_eq!(
            unl_last_success(&log),
            vec![("a".into(), 1000), ("b".into(), 1500)]
        );
        let m = Metrics {
            unl_dir: Some(dir.path().to_owned()),
            ..Metrics::default()
        };
        assert!(
            m.render()
                .contains("xrpl_witness_unl_last_success_timestamp_seconds{site=\"b\"} 1.500\n")
        );
    }

    #[test]
    fn render_is_valid_exposition() {
        let m = Metrics {
            source: "node-\"a\"".into(),
            validations: 7,
            last_validation_ms: 1_500,
            ..Metrics::default()
        };
        let text = m.render();
        assert!(text.contains("xrpl_witness_info{version=\""));
        assert!(text.contains("source=\"node-\\\"a\\\"\"} 1\n"));
        assert!(text.contains("\nxrpl_witness_validations_total 7\n"));
        assert!(text.contains("\nxrpl_witness_last_validation_timestamp_seconds 1.500\n"));
        // Every value line is name, space, number; no empty values.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (_, v) = line.rsplit_once(' ').unwrap();
            assert!(v.parse::<f64>().is_ok(), "{line}");
        }
    }
}
