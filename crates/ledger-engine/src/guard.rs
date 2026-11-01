//! Request limits per client, like Clio's DOS guard.
//!
//! Each client (IP address) has, per sweep interval, a budget of weighted
//! requests and of response bytes, and a cap on connections open at once
//! (HTTP requests in progress and WebSocket sessions). Past either budget, or
//! at the connection cap, the client gets `slowDown` until the next sweep: over
//! HTTP as status 503 with the error in the body, as Clio does, over
//! WebSocket as an error response. Whitelisted addresses are not counted.
//!
//! Behind a proxy every request comes from the proxy's address. Only for a
//! peer listed as a trusted proxy is the client taken from the request: from
//! `CF-Connecting-IP` (Cloudflare), else the last `for=` of `Forwarded` (as
//! Clio), else the first address of `X-Forwarded-For`. From anyone else these
//! headers are ignored, so a client can't pose as another.
//!
//! Off unless configured: with no budgets set nothing is counted.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use axum::http::HeaderMap;
use serde_json::{Map, Value};

/// Limits; `None` means no limit of that kind.
#[derive(Debug, Clone, Default)]
pub struct GuardConfig {
    /// Weighted requests per client per sweep.
    pub max_requests: Option<u64>,
    /// Response bytes per client per sweep.
    pub max_bytes: Option<u64>,
    /// Connections per client open at once.
    pub max_connections: Option<u32>,
    pub sweep: Duration,
    /// Addresses and networks that are never limited.
    pub whitelist: Vec<Net>,
    /// Peers whose forwarding headers name the real client.
    pub trusted_proxies: Vec<Net>,
}

impl GuardConfig {
    pub fn enabled(&self) -> bool {
        self.max_requests.is_some() || self.max_bytes.is_some() || self.max_connections.is_some()
    }
}

/// An address or a network in CIDR notation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    bits: u8,
}

impl std::str::FromStr for Net {
    type Err = String;

    fn from_str(s: &str) -> Result<Net, String> {
        let (a, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .trim()
            .parse()
            .map_err(|_| format!("not an address: {s}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            Some(b) => b
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= max)
                .ok_or_else(|| format!("bad prefix length: {s}"))?,
            None => max,
        };
        Ok(Net { addr, bits })
    }
}

impl Net {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => prefix(
                u128::from(u32::from(n)) << 96,
                u128::from(u32::from(a)) << 96,
                self.bits,
            ),
            (IpAddr::V6(n), IpAddr::V6(a)) => prefix(u128::from(n), u128::from(a), self.bits),
            _ => false,
        }
    }
}

fn prefix(n: u128, a: u128, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - u32::from(bits));
    n & mask == a & mask
}

/// An IPv4 address seen as IPv6 (`::ffff:a.b.c.d`) is the IPv4 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// How much a request counts against the budget: reads that walk many objects
/// or build proofs count more.
pub fn weight(method: &str, params: &Map<String, Value>) -> u64 {
    let flag = |k: &str| params.get(k).and_then(Value::as_bool).unwrap_or(false);
    match method {
        "proof_ledger" | "proof_tx" | "proof_entry" => 10,
        "ledger_data" => 5,
        "ledger" if flag("transactions") && flag("expand") => 5,
        "account_tx" | "nft_history" | "book_changes" | "nfts_by_issuer" => 2,
        _ => 1,
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Usage {
    requests: u64,
    bytes: u64,
    connections: u32,
}

#[derive(Debug, Default)]
pub struct Guard {
    config: GuardConfig,
    usage: Mutex<HashMap<IpAddr, Usage>>,
}

/// An open connection; closing it gives the slot back.
#[derive(Debug)]
pub struct Connection<'a> {
    guard: &'a Guard,
    ip: Option<IpAddr>,
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        if let Some(ip) = self.ip {
            let mut u = self.guard.lock();
            if let Some(e) = u.get_mut(&ip) {
                e.connections = e.connections.saturating_sub(1);
            }
        }
    }
}

impl Guard {
    pub fn new(config: GuardConfig) -> Guard {
        Guard {
            config,
            usage: Mutex::default(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Usage>> {
        self.usage.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn counted(&self, ip: IpAddr) -> bool {
        self.config.enabled() && !self.config.whitelist.iter().any(|n| n.contains(ip))
    }

    /// The client behind a connection from `peer`.
    pub fn client(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = canonical(peer);
        if !self.config.trusted_proxies.iter().any(|n| n.contains(peer)) {
            return peer;
        }
        forwarded_client(headers).map_or(peer, canonical)
    }

    fn within(&self, u: &Usage) -> bool {
        self.config.max_requests.is_none_or(|m| u.requests <= m)
            && self.config.max_bytes.is_none_or(|m| u.bytes <= m)
    }

    /// Opens a connection for `ip`; `None` if the client is at its cap or
    /// over budget.
    pub fn connect(&self, ip: IpAddr) -> Option<Connection<'_>> {
        if !self.counted(ip) {
            return Some(Connection {
                guard: self,
                ip: None,
            });
        }
        let mut all = self.lock();
        let u = all.entry(ip).or_default();
        if !self.within(u)
            || self
                .config
                .max_connections
                .is_some_and(|m| u.connections >= m)
        {
            return None;
        }
        u.connections += 1;
        Some(Connection {
            guard: self,
            ip: Some(ip),
        })
    }

    /// Counts a request; `false` if the client is over budget with it.
    pub fn request(&self, ip: IpAddr, weight: u64) -> bool {
        if !self.counted(ip) {
            return true;
        }
        let mut all = self.lock();
        let u = all.entry(ip).or_default();
        if !self.within(u) {
            return false;
        }
        u.requests += weight;
        self.within(u)
    }

    /// Counts the bytes of a response sent to `ip`.
    pub fn sent(&self, ip: IpAddr, bytes: usize) {
        if self.counted(ip) {
            self.lock().entry(ip).or_default().bytes += bytes as u64;
        }
    }

    /// Starts a new interval: budgets are full again, open connections stay.
    pub fn sweep(&self) {
        let mut all = self.lock();
        all.retain(|_, u| u.connections > 0);
        for u in all.values_mut() {
            u.requests = 0;
            u.bytes = 0;
        }
    }

    pub fn sweep_every(&self) -> Option<Duration> {
        self.config.enabled().then_some(self.config.sweep)
    }
}

/// The client a proxy names in its headers.
fn forwarded_client(headers: &HeaderMap) -> Option<IpAddr> {
    let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(ip) = text("cf-connecting-ip").and_then(|v| v.trim().parse().ok()) {
        return Some(ip);
    }
    if let Some(v) = text("forwarded") {
        let lower = v.to_ascii_lowercase();
        if let Some(at) = lower.rfind("for=") {
            let rest = &v[at + 4..];
            let end = rest.find([';', ',']).unwrap_or(rest.len());
            if let Some(ip) = parse_node(&rest[..end]) {
                return Some(ip);
            }
        }
    }
    text("x-forwarded-for")
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
}

/// A `Forwarded` node: `192.0.2.4`, `"192.0.2.4:80"`, `"[2001:db8::1]:80"`.
fn parse_node(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_matches('"');
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next()?.parse().ok();
    }
    s.parse()
        .ok()
        .or_else(|| s.rsplit_once(':').and_then(|(a, _)| a.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn guard(c: GuardConfig) -> Guard {
        Guard::new(GuardConfig {
            sweep: Duration::from_secs(1),
            ..c
        })
    }

    #[test]
    fn networks() {
        let n: Net = "10.1.0.0/16".parse().unwrap();
        assert!(n.contains(ip("10.1.200.3")));
        assert!(!n.contains(ip("10.2.0.1")));
        assert!(n.contains(ip("::ffff:10.1.0.9")));
        let one: Net = "2001:db8::1".parse().unwrap();
        assert!(one.contains(ip("2001:db8::1")) && !one.contains(ip("2001:db8::2")));
        assert!("10.0.0.0/33".parse::<Net>().is_err());
        assert!("0.0.0.0/0".parse::<Net>().unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn budgets_reset_on_sweep_and_whitelist_is_free() {
        let g = guard(GuardConfig {
            max_requests: Some(3),
            whitelist: vec!["127.0.0.1".parse().unwrap()],
            ..GuardConfig::default()
        });
        let a = ip("192.0.2.1");
        assert!(g.request(a, 2));
        assert!(g.request(a, 1));
        assert!(!g.request(a, 1));
        assert!(!g.request(a, 1));
        assert!(g.request(ip("192.0.2.2"), 1));
        for _ in 0..100 {
            assert!(g.request(ip("127.0.0.1"), 10));
        }
        g.sweep();
        assert!(g.request(a, 3));
        let bytes = guard(GuardConfig {
            max_bytes: Some(100),
            ..GuardConfig::default()
        });
        bytes.sent(a, 101);
        assert!(!bytes.request(a, 1));
    }

    #[test]
    fn connections_are_capped_and_given_back() {
        let g = guard(GuardConfig {
            max_connections: Some(2),
            ..GuardConfig::default()
        });
        let a = ip("192.0.2.1");
        let c1 = g.connect(a).unwrap();
        let _c2 = g.connect(a).unwrap();
        assert!(g.connect(a).is_none());
        drop(c1);
        g.sweep();
        assert!(g.connect(a).is_some());
        let off = guard(GuardConfig::default());
        let _held: Vec<_> = (0..10).map(|_| off.connect(a).unwrap()).collect();
    }

    #[test]
    fn forwarding_headers_count_only_from_trusted_proxies() {
        let g = guard(GuardConfig {
            max_requests: Some(1),
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
            ..GuardConfig::default()
        });
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(g.client(ip("127.0.0.1"), &h), ip("203.0.113.7"));
        assert_eq!(g.client(ip("198.51.100.1"), &h), ip("198.51.100.1"));
        h.insert(
            "forwarded",
            "for=192.0.2.60;proto=http, for=\"[2001:db8::7]:4711\""
                .parse()
                .unwrap(),
        );
        assert_eq!(g.client(ip("127.0.0.1"), &h), ip("2001:db8::7"));
        h.insert("cf-connecting-ip", "198.51.100.9".parse().unwrap());
        assert_eq!(g.client(ip("::ffff:127.0.0.1"), &h), ip("198.51.100.9"));
    }

    #[test]
    fn heavy_requests_weigh_more() {
        let p = |v: Value| v.as_object().cloned().unwrap();
        assert_eq!(weight("server_info", &Map::new()), 1);
        assert_eq!(
            weight("ledger", &p(serde_json::json!({"transactions": true}))),
            1
        );
        assert_eq!(
            weight(
                "ledger",
                &p(serde_json::json!({"transactions": true, "expand": true}))
            ),
            5
        );
        assert_eq!(weight("proof_tx", &Map::new()), 10);
    }
}
