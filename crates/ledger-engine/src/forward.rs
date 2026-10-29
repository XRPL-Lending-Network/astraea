//! Forwarding to a node: methods that Clio does not serve itself but passes
//! to xrpld (node state, fees, the current ledger, field definitions).
//! Nodes are tried round-robin, each with its own timeout; the node's
//! response is returned as is and marked `forwarded`, as in Clio. Identical
//! requests within `CACHE_FOR` get the same response; this is how Clio absorbs
//! bursts of fee polling.

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

/// How old the node's server_info may be and still be merged into ours while
/// a refresh runs; older than this (the node stopped answering), it is dropped.
const INFO_KEEP: Duration = Duration::from_secs(10);

/// Method and params → when the node response was received, and the response.
type Cache = HashMap<String, (Instant, Map<String, Value>)>;

#[derive(Debug)]
pub struct Forwarder {
    /// Node JSON-RPC endpoints, e.g. `http://<node>:51234`.
    sources: Vec<String>,
    agent: ureq::Agent,
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
            sources,
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

    /// The node's server_info, for the fields merged into ours. Returns the
    /// last answer at once and, once it is older than `CACHE_FOR`, refreshes
    /// it in the background, so a client's server_info doesn't wait for the
    /// node. Only the first call, or one after the node has been silent for
    /// `INFO_KEEP`, waits.
    pub fn node_server_info(self: &Arc<Self>) -> Option<Map<String, Value>> {
        let last = self
            .info
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|(at, _)| at.elapsed() < INFO_KEEP)
            .map(|(at, m)| (at.elapsed() >= CACHE_FOR, m.clone()));
        let Some((stale, info)) = last else {
            return self.refresh_info();
        };
        if stale && !self.info_refreshing.swap(true, Ordering::AcqRel) {
            let f = self.clone();
            std::thread::spawn(move || {
                f.refresh_info();
                f.info_refreshing.store(false, Ordering::Release);
            });
        }
        Some(info)
    }

    fn refresh_info(&self) -> Option<Map<String, Value>> {
        let r = self.forward("server_info", &Map::new()).ok()?;
        *self.info.lock().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), r.clone()));
        Some(r)
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
        let n = self.sources.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut last = String::from("no nodes to forward to");
        for k in 0..n {
            let url = &self.sources[(start + k) % n];
            match self.ask(url, &body) {
                Ok(r) => {
                    let mut c = self.lock();
                    if c.len() >= CACHE_MAX {
                        c.retain(|_, (at, _)| at.elapsed() < CACHE_FOR);
                    }
                    if c.len() < CACHE_MAX {
                        c.insert(key, (Instant::now(), r.clone()));
                    }
                    *self.down.lock().unwrap_or_else(|p| p.into_inner()) = None;
                    return Ok(r);
                }
                Err(e) => last = format!("{url}: {e}"),
            }
        }
        tracing::warn!("forwarding {method} failed: {last}");
        *self.down.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        Err(failed())
    }

    fn ask(&self, url: &str, body: &str) -> Result<Map<String, Value>, String> {
        let mut resp = self
            .agent
            .post(url)
            .header("content-type", "application/json")
            .send(body)
            .map_err(|e| e.to_string())?;
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| e.to_string())?;
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(mut o)) => match o.remove("result") {
                Some(Value::Object(r)) => Ok(r),
                _ => Err("no result in the response".into()),
            },
            _ => Err("response is not JSON".into()),
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
        // The first call has nothing to give yet and waits for the node.
        let t = Instant::now();
        assert_eq!(lf(f.node_server_info().unwrap()), 1);
        assert!(t.elapsed() >= Duration::from_millis(150));
        std::thread::sleep(CACHE_FOR);
        // Stale: the old answer comes at once, the new one arrives behind it.
        let t = Instant::now();
        assert_eq!(lf(f.node_server_info().unwrap()), 1);
        assert_eq!(lf(f.node_server_info().unwrap()), 1);
        assert!(t.elapsed() < Duration::from_millis(50));
        // The refresh lands after the node's delay; a loaded machine may take longer.
        let deadline = Instant::now() + Duration::from_secs(10);
        while lf(f.node_server_info().unwrap()) != 2 {
            assert!(Instant::now() < deadline, "no refresh");
            std::thread::sleep(Duration::from_millis(20));
        }
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
