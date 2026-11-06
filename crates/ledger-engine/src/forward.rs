//! Forwarding to a node: methods that Clio does not serve itself but passes
//! to xrpld (node state, fees, the current ledger, field definitions).
//! Nodes are tried round-robin, each with its own timeout; the node's
//! response is returned as is and marked `forwarded`, as in Clio. Identical
//! requests within `CACHE_FOR` get the same response; this is how Clio absorbs
//! bursts of fee polling. One request gets `TOTAL_LIMIT` over all nodes, and a
//! node that just failed is tried last, so that one dead node doesn't cost half
//! of the requests a timeout.
//!
//! `submit` and `simulate` go to a node only when the operator turned them on,
//! never carry signing material, and `submit` is never cached or retried once
//! it may have reached a node (`send_transaction`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::api::RpcError;

/// Methods that go to the node.
pub const FORWARDED: [&str; 4] = [
    "server_state",
    "fee",
    "ledger_current",
    "server_definitions",
];
/// Methods that Clio always serves itself, even for the current ledger.
const CLIO_ONLY: [&str; 6] = [
    "mpt_holders",
    "nft_history",
    "nft_info",
    "nfts_by_issuer",
    "ledger_index",
    "version",
];

/// Public read methods that go to the node when asked about the current or
/// closed ledger. Nothing else ever does; otherwise `ledger_index: "current"`
/// would pass anything to the node, from `submit` to the admin `stop` and `log_level`.
const CURRENT_ON_NODE: [&str; 20] = [
    "account_channels",
    "account_currencies",
    "account_info",
    "account_lines",
    "account_nfts",
    "account_objects",
    "account_offers",
    "amm_info",
    "book_changes",
    "book_offers",
    "deposit_authorized",
    "gateway_balances",
    "ledger",
    "ledger_data",
    "ledger_entry",
    "nft_buy_offers",
    "nft_sell_offers",
    "noripple_check",
    "ripple_path_find",
    "vault_info",
];

/// Whether a request goes to the node, following Clio's rule: node methods; a
/// public read method asking about the current or closed ledger (Astraea keeps
/// only validated ones); the transaction queue in `account_info` and `ledger`.
pub fn forwarded(method: &str, params: &Map<String, Value>) -> bool {
    if FORWARDED.contains(&method) {
        return true;
    }
    if CLIO_ONLY.contains(&method) || !CURRENT_ON_NODE.contains(&method) {
        return false;
    }
    if matches!(
        params.get("ledger_index").and_then(Value::as_str),
        Some("current" | "closed")
    ) {
        return true;
    }
    matches!(method, "account_info" | "ledger") && params.get("queue") == Some(&Value::Bool(true))
}

/// Methods that send a transaction to a node or try one out.
pub fn submission(method: &str) -> bool {
    matches!(method, "submit" | "simulate")
}

fn invalid(message: &str) -> RpcError {
    RpcError {
        error: "invalidParams",
        code: 31,
        message: message.into(),
    }
}

/// The parameters of `submit` or `simulate` that may reach the node. A request
/// that would have the node sign is refused: a secret must not travel through
/// this server, and a node that trusts us might act on it.
pub fn submission_params(
    method: &str,
    params: &Map<String, Value>,
) -> Result<Map<String, Value>, RpcError> {
    for k in ["secret", "seed", "seed_hex", "passphrase", "key_type"] {
        if params.contains_key(k) {
            return Err(invalid("signingNotSupported"));
        }
    }
    let keep: &[&str] = if method == "submit" {
        if !params.get("tx_blob").is_some_and(Value::is_string) {
            return Err(invalid("submit takes a signed tx_blob."));
        }
        &["tx_blob", "fail_hard", "api_version"]
    } else {
        &["tx_blob", "tx_json", "binary", "api_version"]
    };
    Ok(params
        .iter()
        .filter(|(k, _)| keep.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect())
}

/// Node fields in `server_info`, as in Clio: the fee multiplier (clients such
/// as xrpl.js compute fees from it; hundreds under escalation) and the xrpld version.
/// `node` is the `result` of the node's `server_info` response.
pub fn node_info(result: &mut Map<String, Value>, node: &Map<String, Value>) {
    let (Some(Value::Object(info)), Some(n)) = (
        result.get_mut("info"),
        node.get("info").and_then(Value::as_object),
    ) else {
        return;
    };
    if let Some(v) = n.get("load_factor").filter(|v| v.is_number()) {
        info.insert("load_factor".into(), v.clone());
    }
    if let Some(v) = n.get("build_version").filter(|v| v.is_string()) {
        info.insert("rippled_version".into(), v.clone());
    }
}

/// How long a node response stays cached: `forwarding.cache_timeout` in Clio.
const CACHE_FOR: Duration = Duration::from_millis(250);
/// Maximum number of cached responses; the key is the method and params.
const CACHE_MAX: usize = 64;
/// How long to answer `failedToForward` immediately after all nodes failed:
/// a hung node must not hold request slots and slow down server_info.
const DOWN_FOR: Duration = Duration::from_secs(5);

/// How long one forwarded request may take over all nodes. Clients commonly give
/// up after 10 seconds, and the answer is no use to them after that.
const TOTAL_LIMIT: Duration = Duration::from_secs(8);
/// How long a request may spend connecting. Past this nothing was sent, so
/// another node can safely be asked.
const CONNECT_LIMIT: Duration = Duration::from_secs(2);

/// How old the node's server_info may be and still be merged into ours while
/// a refresh runs; older than this (the node stopped answering), it is dropped.
const INFO_KEEP: Duration = Duration::from_secs(10);

/// Why a node gave no answer.
#[derive(Debug)]
struct AskError {
    /// The request can't have reached the node.
    nothing_sent: bool,
    text: String,
}

impl AskError {
    fn after_send(text: impl Into<String>) -> AskError {
        AskError {
            nothing_sent: false,
            text: text.into(),
        }
    }
}

/// Whether a failed request can't have reached the node. Anything else, a reset
/// connection or a timeout while waiting, may have delivered it.
fn nothing_sent(e: &ureq::Error) -> bool {
    use ureq::Timeout;
    match e {
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => true,
        ureq::Error::Timeout(Timeout::Resolve | Timeout::Connect) => true,
        ureq::Error::Io(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
        _ => false,
    }
}

/// Method and params → when the node response was received, and the response.
type Cache = HashMap<String, (Instant, Map<String, Value>)>;

#[derive(Debug)]
pub struct Forwarder {
    /// Node JSON-RPC endpoints, e.g. `http://<node>:51234`.
    sources: Vec<String>,
    agent: ureq::Agent,
    /// Timeout for each node.
    timeout: Duration,
    /// When each node last failed, in the order of `sources`.
    failed_at: Mutex<Vec<Option<Instant>>>,
    next: AtomicUsize,
    cache: Mutex<Cache>,
    /// When all nodes last failed to respond.
    down: Mutex<Option<Instant>>,
    /// The node's last server_info and when it came, for `node_server_info`.
    info: Mutex<Option<(Instant, Map<String, Value>)>>,
    info_refreshing: AtomicBool,
}

impl Forwarder {
    pub fn new(sources: Vec<String>, timeout: Duration) -> Forwarder {
        Forwarder {
            failed_at: Mutex::new(vec![None; sources.len()]),
            sources,
            timeout,
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(timeout))
                .user_agent(concat!("astraea/", env!("CARGO_PKG_VERSION")))
                .build()
                .into(),
            next: AtomicUsize::new(0),
            cache: Mutex::new(HashMap::new()),
            down: Mutex::new(None),
            info: Mutex::new(None),
            info_refreshing: AtomicBool::new(false),
        }
    }

    /// The node's server_info, for the fields merged into ours. Never waits for
    /// a node: a client's server_info is answered from our own data, and with
    /// every node silent, waiting would outlast a client's timeout. Returns the
    /// last answer if it is younger than `INFO_KEEP`, and once it is older than
    /// `CACHE_FOR`, or there is none, refreshes it in the background.
    pub fn node_server_info(self: &Arc<Self>) -> Option<Map<String, Value>> {
        let (fresh, info) = match &*self.info.lock().unwrap_or_else(|p| p.into_inner()) {
            Some((at, m)) => (
                at.elapsed() < CACHE_FOR,
                (at.elapsed() < INFO_KEEP).then(|| m.clone()),
            ),
            None => (false, None),
        };
        if !fresh && !self.info_refreshing.swap(true, Ordering::AcqRel) {
            let f = self.clone();
            std::thread::spawn(move || {
                f.refresh_info();
                f.info_refreshing.store(false, Ordering::Release);
            });
        }
        info
    }

    fn refresh_info(&self) {
        if let Ok(r) = self.forward("server_info", &Map::new()) {
            *self.info.lock().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), r));
        }
    }

    /// `result` of the node's response. An error from the node itself (`status: error`)
    /// is returned as is, since it is an answer to the request; all nodes down gives `failedToForward`.
    pub fn forward(
        &self,
        method: &str,
        params: &Map<String, Value>,
    ) -> Result<Map<String, Value>, RpcError> {
        let key = format!("{method} {}", Value::Object(params.clone()));
        if let Some((at, hit)) = self.lock().get(&key)
            && at.elapsed() < CACHE_FOR
        {
            return Ok(hit.clone());
        }
        let failed = || RpcError {
            error: "failedToForward",
            code: 90,
            message: "Failed to forward request to p2p node".into(),
        };
        if self
            .down
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some_and(|t| t.elapsed() < DOWN_FOR)
        {
            return Err(failed());
        }
        let body = json!({ "method": method, "params": [params] }).to_string();
        let deadline = Instant::now() + TOTAL_LIMIT;
        let mut last = String::from("no nodes to forward to");
        for i in self.order() {
            let url = &self.sources[i];
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match self.ask(url, &body, self.timeout.min(left)) {
                Ok(r) => {
                    let mut c = self.lock();
                    if c.len() >= CACHE_MAX {
                        c.retain(|_, (at, _)| at.elapsed() < CACHE_FOR);
                    }
                    if c.len() < CACHE_MAX {
                        c.insert(key, (Instant::now(), r.clone()));
                    }
                    *self.down.lock().unwrap_or_else(|p| p.into_inner()) = None;
                    self.mark(i, None);
                    return Ok(r);
                }
                Err(e) => {
                    self.mark(i, Some(Instant::now()));
                    last = format!("{url}: {}", e.text);
                }
            }
        }
        tracing::warn!("forwarding {method} failed: {last}");
        *self.down.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        Err(failed())
    }

    /// Sends a signed transaction to one node. Unlike `forward` this is never
    /// cached: a retry has to reach the network. Another node is asked only when
    /// the first can't have received it. Sending it again after a timeout could
    /// give `tefPAST_SEQ` for a transaction that in fact went through, and the
    /// client would take that for a failure; so it gets `failedToForward` and
    /// must look the transaction up by hash.
    pub fn send_transaction(
        &self,
        params: &Map<String, Value>,
    ) -> Result<Map<String, Value>, RpcError> {
        let body = json!({ "method": "submit", "params": [params] }).to_string();
        let deadline = Instant::now() + TOTAL_LIMIT;
        let mut last = String::from("no nodes to forward to");
        for i in self.order() {
            let url = &self.sources[i];
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match self.ask(url, &body, self.timeout.min(left)) {
                Ok(r) => {
                    self.mark(i, None);
                    return Ok(r);
                }
                Err(e) => {
                    self.mark(i, Some(Instant::now()));
                    if !e.nothing_sent {
                        tracing::warn!("submit to {url} has no answer: {}", e.text);
                        return Err(RpcError {
                            error: "failedToForward",
                            code: 90,
                            message: "No answer from the node; the transaction may have been \
                                      sent. Look it up by hash before sending it again."
                                .into(),
                        });
                    }
                    last = format!("{url}: {}", e.text);
                }
            }
        }
        tracing::warn!("submit failed, nothing sent: {last}");
        Err(RpcError {
            error: "failedToForward",
            code: 90,
            message: "Failed to forward request to p2p node".into(),
        })
    }

    /// Nodes to try, in turn, with those that just failed last.
    fn order(&self) -> Vec<usize> {
        let n = self.sources.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let failed = self.failed_at.lock().unwrap_or_else(|p| p.into_inner());
        let mut order: Vec<usize> = (0..n).map(|k| (start + k) % n).collect();
        order.sort_by_key(|&i| failed[i].is_some_and(|t| t.elapsed() < DOWN_FOR));
        order
    }

    fn mark(&self, node: usize, failed: Option<Instant>) {
        self.failed_at.lock().unwrap_or_else(|p| p.into_inner())[node] = failed;
    }

    fn ask(&self, url: &str, body: &str, limit: Duration) -> Result<Map<String, Value>, AskError> {
        let mut resp = self
            .agent
            .post(url)
            .config()
            .timeout_global(Some(limit))
            .timeout_connect(Some(CONNECT_LIMIT.min(limit)))
            .build()
            .header("content-type", "application/json")
            .send(body)
            .map_err(|e| AskError {
                nothing_sent: nothing_sent(&e),
                text: e.to_string(),
            })?;
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| AskError::after_send(e.to_string()))?;
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(mut o)) => match o.remove("result") {
                Some(Value::Object(r)) => Ok(r),
                _ => Err(AskError::after_send("no result in the response")),
            },
            _ => Err(AskError::after_send("response is not JSON")),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_follows_clio_rule() {
        let on = |m: &str, v: Value| forwarded(m, v.as_object().unwrap());
        assert!(on("fee", json!({})));
        assert!(on("account_info", json!({"ledger_index": "current"})));
        assert!(on("account_lines", json!({"ledger_index": "closed"})));
        assert!(on("account_info", json!({"queue": true})));
        assert!(!on("account_info", json!({"ledger_index": "validated"})));
        assert!(!on("account_info", json!({"ledger_index": 5})));
        assert!(!on("mpt_holders", json!({"ledger_index": "current"})));
        assert!(!on("account_tx", json!({})));
        // Nothing goes to the node except public reads.
        for m in [
            "stop",
            "submit",
            "sign",
            "peers",
            "log_level",
            "ledger_accept",
        ] {
            assert!(!on(m, json!({"ledger_index": "current"})), "{m}");
        }
    }

    #[test]
    fn server_info_takes_load_factor_and_version_from_node() {
        let mut r = json!({"info": {"load_factor": 1, "complete_ledgers": "1-2"}});
        let r = r.as_object_mut().unwrap();
        let node = json!({"info": {"load_factor": 509.9, "build_version": "3.4.1"}});
        node_info(r, node.as_object().unwrap());
        assert_eq!(r["info"]["load_factor"], json!(509.9));
        assert_eq!(r["info"]["rippled_version"], json!("3.4.1"));
        // Node response without info: our own fields are left alone.
        node_info(r, json!({"error": "x"}).as_object().unwrap());
        assert_eq!(r["info"]["complete_ledgers"], json!("1-2"));
    }

    /// A node that answers server_info after `delay`, with a load factor
    /// counting its answers.
    fn slow_node(delay: Duration) -> String {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let mut s = s.unwrap();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                std::thread::sleep(delay);
                let body = json!({"result": {"info": {"load_factor": n + 1}}}).to_string();
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        url
    }

    #[test]
    fn server_info_from_the_node_is_refreshed_in_the_background() {
        let f = Arc::new(Forwarder::new(
            vec![slow_node(Duration::from_millis(150))],
            Duration::from_secs(5),
        ));
        let lf = |m: Map<String, Value>| m["info"]["load_factor"].as_u64().unwrap();
        // The first call has nothing to give yet and doesn't wait for the node.
        let t = Instant::now();
        assert!(f.node_server_info().is_none());
        assert!(t.elapsed() < Duration::from_millis(50));
        let deadline = Instant::now() + Duration::from_secs(10);
        while f.info.lock().unwrap().is_none() {
            assert!(Instant::now() < deadline, "no first answer");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(CACHE_FOR);
        // Stale: the old answer comes at once, the new one arrives behind it.
        let t = Instant::now();
        assert_eq!(lf(f.node_server_info().unwrap()), 1);
        assert_eq!(lf(f.node_server_info().unwrap()), 1);
        assert!(t.elapsed() < Duration::from_millis(50));
        // The refresh lands after the node's delay; a loaded machine may take longer.
        // A refresh that failed on the way still used up one of the node's answers,
        // so the next good one may count higher than 2.
        let deadline = Instant::now() + Duration::from_secs(10);
        while lf(f.node_server_info().unwrap()) < 2 {
            assert!(Instant::now() < deadline, "no refresh");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn server_info_does_not_wait_for_nodes_that_went_silent() {
        // Two hung nodes, as when their network is gone: a request to them only
        // ends at the timeout, 10 seconds in all. That is as long as clients wait.
        let hung = || slow_node(Duration::from_secs(60));
        let f = Arc::new(Forwarder::new(vec![hung(), hung()], Duration::from_secs(5)));
        // The last answer is too old to pass on.
        *f.info.lock().unwrap() = Some((
            Instant::now() - INFO_KEEP,
            json!({"info": {"load_factor": 7}})
                .as_object()
                .unwrap()
                .clone(),
        ));
        let t = Instant::now();
        for _ in 0..3 {
            assert!(f.node_server_info().is_none());
        }
        assert!(t.elapsed() < Duration::from_millis(50));
        assert!(f.info_refreshing.load(Ordering::Acquire));
    }

    #[test]
    fn a_request_has_one_deadline_over_all_nodes() {
        let hung = || slow_node(Duration::from_secs(60));
        // Two nodes at 5 s each would take 10 s; the deadline ends it at 8.
        let f = Forwarder::new(vec![hung(), hung()], Duration::from_secs(5));
        let t = Instant::now();
        assert!(f.forward("fee", &Map::new()).is_err());
        let took = t.elapsed();
        assert!(took >= TOTAL_LIMIT - Duration::from_millis(100), "{took:?}");
        assert!(took < TOTAL_LIMIT + Duration::from_secs(1), "{took:?}");
    }

    #[test]
    fn a_node_that_just_failed_is_tried_last() {
        let f = Forwarder::new(
            vec!["http://127.0.0.1:1".into(), "http://127.0.0.1:2".into()],
            Duration::from_secs(1),
        );
        f.mark(0, Some(Instant::now()));
        for _ in 0..4 {
            assert_eq!(f.order(), vec![1, 0]);
        }
        // Once the mark is old, the nodes take turns again.
        f.mark(0, Some(Instant::now() - DOWN_FOR));
        let (a, b) = (f.order()[0], f.order()[0]);
        assert_ne!(a, b);
    }

    #[test]
    fn signing_on_the_node_is_refused() {
        let p = |v: Value| v.as_object().unwrap().clone();
        for k in ["secret", "seed", "seed_hex", "passphrase", "key_type"] {
            for m in ["submit", "simulate"] {
                let e = submission_params(m, &p(json!({"tx_blob": "00", k: "x"}))).unwrap_err();
                assert_eq!(e.error, "invalidParams");
                assert_eq!(e.message, "signingNotSupported");
            }
        }
        assert!(submission_params("submit", &p(json!({"tx_json": {}}))).is_err());
        let kept = submission_params(
            "submit",
            &p(json!({"tx_blob": "00", "fail_hard": true, "admin": 1})),
        )
        .unwrap();
        assert_eq!(kept, p(json!({"tx_blob": "00", "fail_hard": true})));
        let kept = submission_params(
            "simulate",
            &p(json!({"tx_json": {"TransactionType": "Payment"}, "other": 1})),
        )
        .unwrap();
        assert_eq!(kept, p(json!({"tx_json": {"TransactionType": "Payment"}})));
    }

    #[test]
    fn a_transaction_goes_to_the_next_node_only_if_nothing_was_sent() {
        let p = json!({"tx_blob": "00"}).as_object().unwrap().clone();
        // The first node refuses the connection, so the second one gets it.
        let (up, seen) = counting_node();
        let f = Forwarder::new(
            vec!["http://127.0.0.1:1".into(), up],
            Duration::from_secs(2),
        );
        f.mark(1, Some(Instant::now()));
        assert!(f.send_transaction(&p).is_ok());
        assert_eq!(seen.load(Ordering::Relaxed), 1);

        // A node that took it and went silent: no second attempt, and the client
        // is told the outcome is unknown.
        let (up, seen) = counting_node();
        let hung = slow_node(Duration::from_secs(60));
        let f = Forwarder::new(vec![hung, up], Duration::from_millis(300));
        f.mark(1, Some(Instant::now()));
        let e = f.send_transaction(&p).unwrap_err();
        assert_eq!(e.error, "failedToForward");
        assert!(e.message.contains("may have been sent"), "{}", e.message);
        assert_eq!(seen.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_transaction_is_never_answered_from_the_cache() {
        let (url, seen) = counting_node();
        let f = Forwarder::new(vec![url], Duration::from_secs(2));
        let p = json!({"tx_blob": "00"}).as_object().unwrap().clone();
        f.send_transaction(&p).unwrap();
        f.send_transaction(&p).unwrap();
        assert_eq!(seen.load(Ordering::Relaxed), 2);
    }

    /// A node that answers at once and counts the requests it got.
    fn counting_node() -> (String, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(AtomicUsize::new(0));
        let count = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                count.fetch_add(1, Ordering::Relaxed);
                let body = r#"{"result":{"engine_result":"tesSUCCESS"}}"#;
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (url, seen)
    }

    #[test]
    fn unreachable_nodes_give_failed_to_forward_quickly() {
        let f = Forwarder::new(
            vec!["http://127.0.0.1:1".into(), "http://127.0.0.1:2".into()],
            Duration::from_secs(2),
        );
        let t = Instant::now();
        let e = f.forward("fee", &Map::new()).unwrap_err();
        assert_eq!((e.error, e.code), ("failedToForward", 90));
        assert!(t.elapsed() < Duration::from_secs(5));
        // Right after a failure: respond without waiting for nodes.
        let t = Instant::now();
        assert!(f.forward("server_state", &Map::new()).is_err());
        assert!(t.elapsed() < Duration::from_millis(50));
    }
}
