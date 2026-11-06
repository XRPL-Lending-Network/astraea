//! API server: JSON-RPC over HTTP and WebSocket on one port, as in Clio.
//!
//! HTTP: `POST /` with `{"method": ..., "params": [{...}]}`, response is
//! `{"result": {..., "status": "success"}}`. WebSocket: `GET /` with an
//! upgrade, requests `{"command": ..., "id": ..., ...}`, response is `result`
//! plus `id`, `api_version`, `status`, `type` at the top level. Errors follow
//! Clio: inside `result` over HTTP, at the top level over WebSocket.
//!
//! Requests are served on a blocking task pool (fjall and zstd are synchronous),
//! at most `MAX_INFLIGHT` at a time; proof bundles have their own
//! budget, `MAX_PROOFS`, and no queue: when it is full they are refused with `tooBusy`.
//! Requests to a node have their own budget too, `MAX_FORWARDS`, so that nodes
//! that stopped answering can't hold the slots that reads need. A request waits
//! at most `QUEUE_WAIT` for a slot and has `REQUEST_LIMIT` to finish (`limits`);
//! past either it ends with `tooBusy`.
//!
//! Public listeners (`PublicConfig`) are a separate door to the same data: their
//! slots are their own, so public load can't fill those of `--api-addr`, the
//! limits of `guard` apply there and only there, and when the other door has
//! fewer than `OWN_HEADROOM` free slots they step aside with `tooBusy`. This
//! protects the queue, not the machine: disk and CPU stay shared, which is why
//! the public slots are few.
//!
//! subscribe and unsubscribe work only over WebSocket; `subs` keeps the subscriptions.
//! A session interleaves responses to requests with messages from its queue.
//!
//! Node methods and requests about the current ledger (`forward::forwarded`) go to
//! xrpld; the response follows Clio:
//! the node's `result` as is, with `forwarded: true`, `status`, `type` on top.
//!
//! Clients are limited per address by `guard` when it is configured.
//!
//! HTTP answers say whether they can be cached: an answer about a ledger named
//! by sequence or hash, or about a transaction, never changes once given, and
//! gets `Cache-Control: public, max-age=86400, immutable`; everything else
//! gets `no-store`. A cache in front can rely on that. JSON-RPC requests are
//! POSTs, which CDNs don't cache on their own, so the cache keys on the body.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::SinkExt;
use serde_json::{Map, Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

use crate::api::{Engine, RpcError, api_version};
use crate::forward::{Forwarder, forwarded, node_info, submission, submission_params};
use crate::guard::{Guard, GuardConfig, weight};
use crate::metrics::{self, lock};
use crate::subs::{self, Hub};

const MAX_INFLIGHT: usize = 32;
/// Proof bundles are expensive to build: at most this many at a time.
const MAX_PROOFS: usize = 4;
/// Requests to a node at a time.
const MAX_FORWARDS: usize = 16;
/// How long a request waits for a slot before it is refused.
const QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// The same on a public listener, and how long a request may run there.
const PUBLIC_QUEUE_WAIT: std::time::Duration = std::time::Duration::from_millis(500);
const PUBLIC_REQUEST_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);
/// A public listener refuses requests when `--api-addr` has fewer free slots than this.
const OWN_HEADROOM: usize = 8;
/// Largest request a public listener takes, over HTTP or in one WebSocket message.
const PUBLIC_MESSAGE: usize = 256 * 1024;
/// Methods a public listener doesn't take: they change the network or make a
/// node do unbounded work on behalf of a stranger.
const NOT_PUBLIC: [&str; 3] = ["submit", "simulate", "ripple_path_find"];
/// `/health` reports a problem when the last ledger is older than this; ledgers
/// close every 3 to 5 seconds, and a network-wide pause has been seen to last 49.
const HEALTHY_AGE: i64 = 60;
/// How long one request may run (see `limits`). Real requests take well under
/// a second; the slowest, a full `ledger_data` page, about 0.7 s.
const REQUEST_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);
/// Built bundles per ledger and transaction kept in memory; they never change.
const PROOF_CACHE: usize = 128;
/// How long a cache may keep an answer that never changes. A day rather than
/// a year, so a wrong answer, should one ever be served, doesn't outlive a fix.
const IMMUTABLE: &str = "public, max-age=86400, immutable";

type ProofCache = std::sync::Mutex<std::collections::VecDeque<(String, Map<String, Value>)>>;

/// How the server listens beyond its addresses.
#[derive(Debug, Clone, Default)]
pub struct ServeConfig {
    /// Limits per client on `--api-addr`; off when there is a public listener.
    pub own_limits: GuardConfig,
    /// Forward `submit` and `simulate` on `--api-addr`.
    pub forward_submissions: bool,
    pub public: Option<PublicConfig>,
}

/// Listeners for strangers, with their own slots and limits.
#[derive(Debug, Clone)]
pub struct PublicConfig {
    pub addrs: Vec<SocketAddr>,
    pub limits: GuardConfig,
    pub max_inflight: usize,
    pub max_proofs: usize,
    pub max_forwards: usize,
    pub max_sessions: usize,
    pub max_accounts: usize,
}

/// What differs between `--api-addr` and a public listener.
#[derive(Debug, Clone)]
struct Public {
    /// Slots of `--api-addr`, to step aside when they run low.
    own_inflight: Arc<Semaphore>,
    sessions: Arc<Semaphore>,
    max_accounts: usize,
}

#[derive(Debug, Clone)]
struct Shared {
    engine: Arc<Engine>,
    inflight: Arc<Semaphore>,
    proofs: Arc<Semaphore>,
    forwards: Arc<Semaphore>,
    cache: Arc<ProofCache>,
    forwarder: Option<Arc<Forwarder>>,
    hub: Arc<Hub>,
    metrics: metrics::Shared,
    guard: Arc<Guard>,
    forward_submissions: bool,
    public: Option<Public>,
}

fn too_busy() -> RpcError {
    RpcError {
        error: "tooBusy",
        code: 9,
        message: "The server is too busy to help you now.".into(),
    }
}

fn internal(e: impl std::fmt::Display) -> RpcError {
    RpcError {
        error: "internal",
        code: 73,
        message: e.to_string(),
    }
}

fn unknown_method() -> RpcError {
    RpcError {
        error: "unknownCmd",
        code: 32,
        message: "Unknown method.".into(),
    }
}

impl Shared {
    /// A public listener steps aside while the other one is short of slots.
    fn must_step_aside(&self) -> bool {
        self.public
            .as_ref()
            .is_some_and(|p| p.own_inflight.available_permits() < OWN_HEADROOM)
    }

    /// A slot from `pool`, waiting only so long.
    async fn slot(&self, pool: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, RpcError> {
        if self.must_step_aside() {
            return Err(too_busy());
        }
        let wait = if self.public.is_some() {
            PUBLIC_QUEUE_WAIT
        } else {
            QUEUE_WAIT
        };
        match tokio::time::timeout(wait, pool.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(e)) => Err(internal(e)),
            Err(_) => Err(too_busy()),
        }
    }

    /// The name a request is counted under: public traffic apart from our own.
    fn transport(&self, own: &'static str, public: &'static str) -> &'static str {
        if self.public.is_some() { public } else { own }
    }
}

fn slow_down() -> RpcError {
    RpcError {
        error: "slowDown",
        code: 10,
        message: "You are placing too much load on the server.".into(),
    }
}

/// Clio's answer to a client over its limit over HTTP: 503 with the error.
fn slow_down_http() -> Response {
    let e = slow_down();
    let body = json!({
        "error": e.error,
        "error_code": e.code,
        "error_message": e.message,
        "status": "error",
        "type": "response",
    });
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        body.to_string(),
    )
        .into_response()
}

/// Methods whose answer depends only on the ledger asked for.
const FIXED_BY_LEDGER: [&str; 18] = [
    "account_info",
    "account_lines",
    "account_nfts",
    "account_objects",
    "account_offers",
    "account_tx",
    "book_changes",
    "ledger",
    "ledger_data",
    "ledger_entry",
    "mpt_holders",
    "nft_buy_offers",
    "nft_history",
    "nft_info",
    "nft_sell_offers",
    "nfts_by_issuer",
    "proof_entry",
    "proof_ledger",
];

/// Whether a successful answer of our own can never change: about a
/// transaction, or about a ledger named by sequence or hash. Errors and
/// forwarded answers can.
fn immutable(method: &str, params: &Map<String, Value>, result: &Result<Reply, RpcError>) -> bool {
    if !matches!(result, Ok(Reply::Own(_))) {
        return false;
    }
    let fixed = params.get("ledger_hash").is_some_and(Value::is_string)
        || params
            .get("ledger_index")
            .is_some_and(|v| v.is_u64() || v.as_str().is_some_and(|s| s.parse::<u32>().is_ok()));
    match method {
        "tx" | "proof_tx" => true,
        // A range bound alongside the ledger is an error anyway; a marker
        // pages within the same fixed ledger.
        m if FIXED_BY_LEDGER.contains(&m) => fixed,
        _ => false,
    }
}

/// Counts a finished request and its response. A method name a client made up
/// would be a new series each time, so names the server didn't take are
/// counted as `other`.
fn record(
    s: &Shared,
    transport: &'static str,
    method: &str,
    result: &Result<Reply, RpcError>,
    started: Instant,
    bytes: usize,
) {
    let status = status_of(result);
    let known = !matches!(status.as_str(), "unknownCmd" | "badSyntax")
        && (1..=40).contains(&method.len())
        && method.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    let method = if known { method } else { "other" };
    let forwarded = matches!(result, Ok(Reply::Forwarded(_)));
    lock(&s.metrics).api.record(
        transport,
        method,
        &status,
        started.elapsed().as_secs_f64(),
        bytes,
        forwarded,
    );
}

/// `success`, or the error name the client sees.
fn status_of(result: &Result<Reply, RpcError>) -> String {
    match result {
        Ok(Reply::Forwarded(m)) if m.get("status") == Some(&json!("error")) => m
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("error")
            .to_owned(),
        Ok(_) => "success".into(),
        Err(e) => e.error.into(),
    }
}

fn warnings() -> Value {
    json!([{ "id": 2001, "message": "This is an Astraea server. It serves only validated data." }])
}

fn error_fields(e: &RpcError, request: &Value) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("error".into(), json!(e.error));
    m.insert("error_code".into(), json!(e.code));
    m.insert("error_message".into(), json!(e.message));
    m.insert("status".into(), json!("error"));
    m.insert("type".into(), json!("response"));
    m.insert("request".into(), request.clone());
    m
}

/// Request params: the first element of `params`, or an empty object.
fn params_of(params: Option<&Value>) -> Result<Map<String, Value>, RpcError> {
    match params {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::String(s)) if s.is_empty() => Ok(Map::new()),
        Some(Value::Object(o)) => Ok(o.clone()),
        Some(Value::Array(a)) => match a.first() {
            None | Some(Value::Null) => Ok(Map::new()),
            Some(Value::String(s)) if s.is_empty() => Ok(Map::new()),
            Some(Value::Object(o)) => Ok(o.clone()),
            Some(_) => Err(bad_syntax()),
        },
        Some(_) => Err(bad_syntax()),
    }
}

fn bad_syntax() -> RpcError {
    RpcError {
        error: "badSyntax",
        code: 1,
        message: "Syntax error.".into(),
    }
}

/// A method's response: our own, or forwarded from a node.
enum Reply {
    Own(Map<String, Value>),
    Forwarded(Map<String, Value>),
}

async fn call(s: &Shared, method: String, params: Map<String, Value>) -> Result<Reply, RpcError> {
    if s.public.is_some() && NOT_PUBLIC.contains(&method.as_str()) {
        return Err(RpcError {
            error: "notSupported",
            code: 75,
            message: "Not supported on the public endpoint.".into(),
        });
    }
    if submission(&method) {
        let (true, Some(f)) = (s.forward_submissions, s.forwarder.clone()) else {
            return Err(unknown_method());
        };
        let params = submission_params(&method, &params)?;
        let _permit = s.slot(&s.forwards).await?;
        return tokio::task::spawn_blocking(move || {
            if method == "submit" {
                f.send_transaction(&params)
            } else {
                f.forward(&method, &params)
            }
        })
        .await
        .unwrap_or_else(|e| Err(internal(e)))
        .map(Reply::Forwarded);
    }
    if forwarded(&method, &params) {
        let Some(f) = s.forwarder.clone() else {
            return Err(unknown_method());
        };
        let _permit = s.slot(&s.forwards).await?;
        return tokio::task::spawn_blocking(move || f.forward(&method, &params))
            .await
            .unwrap_or_else(|e| Err(internal(e)))
            .map(Reply::Forwarded);
    }
    let info = method == "server_info";
    let mut r = call_own(s, method, params).await?;
    // Fee multiplier and version come from the node, as in Clio; if the node is
    // unavailable, our own response stays. The node's answer is refreshed in the
    // background, so this never waits for the node.
    if info && let Some(node) = s.forwarder.as_ref().and_then(|f| f.node_server_info()) {
        node_info(&mut r, &node);
    }
    Ok(Reply::Own(r))
}

async fn call_own(
    s: &Shared,
    method: String,
    params: Map<String, Value>,
) -> Result<Map<String, Value>, RpcError> {
    let is_proof = method.starts_with("proof_");
    // Bundles have their own budget and no queue: if it is full, refuse at once so
    // that waiting bundles don't take slots from the regular API.
    let _permit = if is_proof {
        if s.must_step_aside() {
            return Err(too_busy());
        }
        s.proofs
            .clone()
            .try_acquire_owned()
            .map_err(|_| too_busy())?
    } else {
        s.slot(&s.inflight).await?
    };
    // A bundle for a transaction, or for a ledger given by explicit sequence or hash,
    // never changes, so it comes from the cache. An object bundle is for the latest
    // ledger, and "validated" or a request without a sequence moves with
    // validation, so those are not cached.
    let fixed_ledger = params.get("ledger_hash").is_some_and(|v| !v.is_null())
        || params
            .get("ledger_index")
            .is_some_and(|v| v.is_u64() || v.as_str().is_some_and(|s| s.parse::<u32>().is_ok()));
    let cacheable = method == "proof_tx" || (method == "proof_ledger" && fixed_ledger);
    let cache_key = cacheable.then(|| format!("{method} {}", Value::Object(params.clone())));
    if let Some(k) = &cache_key
        && let Some((_, hit)) = s
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(c, _)| c == k)
    {
        lock(&s.metrics).api.proof_cache_hits += 1;
        return Ok(hit.clone());
    }
    let engine = s.engine.clone();
    let name = method.clone();
    let limit = if s.public.is_some() {
        PUBLIC_REQUEST_LIMIT
    } else {
        REQUEST_LIMIT
    };
    let result = tokio::task::spawn_blocking(move || {
        let _limit = crate::limits::start(limit);
        engine.handle(&method, &params)
    })
    .await
    .unwrap_or_else(|e| Err(internal(e)));
    if is_proof
        && let Ok(r) = &result
        && let Some(by) = r
            .get("guarantee")
            .and_then(|g| g.get("target_confirmed_by"))
            .and_then(Value::as_str)
    {
        *lock(&s.metrics)
            .api
            .proofs
            .entry((name, by.to_owned()))
            .or_default() += 1;
    }
    if let (Some(k), Ok(r)) = (cache_key, &result) {
        let mut c = s.cache.lock().unwrap_or_else(|p| p.into_inner());
        c.push_front((k, r.clone()));
        c.truncate(PROOF_CACHE);
    }
    result
}

async fn http_rpc(
    State(s): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let transport = s.transport("http", "public_http");
    let client = s.guard.client(peer.ip(), &headers);
    let Some(_connection) = s.guard.connect(client) else {
        record(&s, transport, "", &Err(slow_down()), Instant::now(), 0);
        return slow_down_http();
    };
    let request: Value = match serde_json::from_str(&body) {
        Ok(v @ Value::Object(_)) => v,
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                "Unable to parse JSON from the request",
            )
                .into_response();
        }
    };
    let started = Instant::now();
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let params = params_of(request.get("params"));
    if let Ok(p) = &params
        && !s.guard.request(client, weight(&method, p))
    {
        record(&s, transport, &method, &Err(slow_down()), started, 0);
        return slow_down_http();
    }
    let result = match &params {
        Ok(p) if !method.is_empty() => call(&s, method.clone(), p.clone()).await,
        Ok(_) => Err(unknown_method()),
        Err(e) => Err(e.clone()),
    };
    let cache = match &params {
        Ok(p) if immutable(&method, p, &result) => IMMUTABLE,
        _ => "no-store",
    };
    let body = match &result {
        Ok(Reply::Own(m)) => {
            let mut m = m.clone();
            m.insert("status".into(), json!("success"));
            json!({ "result": m, "warnings": warnings() })
        }
        Ok(Reply::Forwarded(m)) => json!({
            "result": m,
            "status": "success",
            "type": "response",
            "forwarded": true,
            "warnings": warnings(),
        }),
        Err(e) => json!({ "result": error_fields(e, &request), "warnings": warnings() }),
    }
    .to_string();
    record(&s, transport, &method, &result, started, body.len());
    s.guard.sent(client, body.len());
    (
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::header::CACHE_CONTROL, cache),
        ],
        body,
    )
        .into_response()
}

async fn ws_upgrade(
    State(s): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let transport = s.transport("ws", "public_ws");
    let client = s.guard.client(peer.ip(), &headers);
    if s.guard.connect(client).is_none() {
        record(&s, transport, "", &Err(slow_down()), Instant::now(), 0);
        return slow_down_http();
    }
    // Cap on all public sessions together: per-client limits don't bound a crowd.
    let session = match &s.public {
        Some(p) => match p.sessions.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                record(&s, transport, "", &Err(slow_down()), Instant::now(), 0);
                return slow_down_http();
            }
        },
        None => None,
    };
    let ws = if s.public.is_some() {
        ws.max_message_size(PUBLIC_MESSAGE)
    } else {
        ws
    };
    ws.on_upgrade(move |socket| ws_session(s, socket, client, session))
}

async fn ws_session(
    s: Shared,
    mut socket: WebSocket,
    client: std::net::IpAddr,
    _session: Option<OwnedSemaphorePermit>,
) {
    // The session holds a connection slot for as long as it is open. A client
    // that reached its cap between the upgrade check and here is closed.
    let guard = s.guard.clone();
    let Some(_connection) = guard.connect(client) else {
        let _ = socket.close().await;
        return;
    };
    let (id, mut rx) = s.hub.join();
    {
        let mut m = lock(&s.metrics);
        m.api.ws_sessions += 1;
        m.api.ws_sessions_total += 1;
    }
    loop {
        tokio::select! {
            msg = socket.recv() => {
                let text = match msg {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Close(_))) => {
                        // The reply to a close is queued, not sent, until the next
                        // write. Without it the client sees an abnormal close (1006),
                        // and xrpl.js then reconnects a client it had disconnected.
                        let _ = socket.flush().await;
                        break;
                    }
                    Some(Err(_)) | None => break,
                    Some(Ok(_)) => continue,
                };
                let reply = ws_answer(&s, id, &text, client).await;
                if socket.send(Message::Text(reply.into())).await.is_err() {
                    break;
                }
            }
            out = rx.recv() => {
                // Queue closed: the session was disconnected for falling behind.
                let Some(out) = out else { break };
                if socket.send(Message::Text(out.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    s.hub.leave(id);
    let mut m = lock(&s.metrics);
    m.api.ws_sessions = m.api.ws_sessions.saturating_sub(1);
}

/// subscribe and unsubscribe for session `id`; with the ledger stream the response
/// carries the fields of the latest validated ledger.
async fn subscription(
    s: &Shared,
    id: u64,
    method: &str,
    params: &Map<String, Value>,
) -> Result<Reply, RpcError> {
    let api = api_version(params)?;
    let r = subs::parse(params)?;
    if method == "unsubscribe" {
        s.hub.unsubscribe(id, &r);
        return Ok(Reply::Own(Map::new()));
    }
    if let Some(p) = &s.public
        && s.hub.accounts_of(id) + r.accounts.len() > p.max_accounts
    {
        return Err(RpcError {
            error: "invalidParams",
            code: 31,
            message: "accountsTooMany".into(),
        });
    }
    if !r.ledger {
        s.hub.subscribe(id, &r, api, 0);
        return Ok(Reply::Own(Map::new()));
    }
    // Take the tip before subscribing: publishing starts with the next ledger.
    let (engine, hub) = (s.engine.clone(), s.hub.clone());
    tokio::task::spawn_blocking(move || {
        let (_, max) = engine.range()?;
        hub.subscribe(id, &r, api, max);
        engine.ledger_stream(max, None)
    })
    .await
    .unwrap_or_else(|e| Err(internal(e)))
    .map(Reply::Own)
}

async fn ws_answer(s: &Shared, id: u64, text: &str, client: std::net::IpAddr) -> String {
    let transport = s.transport("ws", "public_ws");
    let started = Instant::now();
    let Ok(Value::Object(request)) = serde_json::from_str::<Value>(text) else {
        let e = bad_syntax();
        let mut m = error_fields(&e, &json!(text));
        m.insert("warnings".into(), warnings());
        let body = Value::Object(m).to_string();
        record(s, transport, "", &Err(e), started, body.len());
        return body;
    };
    let method = request
        .get("command")
        .or_else(|| request.get("method"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let mut params = request.clone();
    for k in ["command", "method", "id"] {
        params.remove(k);
    }
    let result = if !s.guard.request(client, weight(&method, &params)) {
        Err(slow_down())
    } else if method == "subscribe" || method == "unsubscribe" {
        subscription(s, id, &method, &params).await
    } else {
        call(s, method.clone(), params).await
    };
    let mut m = match &result {
        Ok(r) => {
            let mut m = Map::new();
            let forwarded = matches!(r, Reply::Forwarded(_));
            let (Reply::Own(r) | Reply::Forwarded(r)) = r;
            let mut r = r.clone();
            if forwarded && r.get("status") == Some(&json!("error")) {
                // A node error stays an error over WebSocket too, as in xrpld: error
                // fields at the top, otherwise the client would take it for success.
                r.remove("status");
                r.remove("request");
                m.extend(r);
                m.insert("request".into(), Value::Object(request.clone()));
                m.insert("status".into(), json!("error"));
            } else {
                // Over WebSocket Clio removes the node's `status` from `result`.
                if forwarded && r.get("status") == Some(&json!("success")) {
                    r.remove("status");
                }
                m.insert("result".into(), Value::Object(r));
                m.insert("status".into(), json!("success"));
            }
            if forwarded {
                m.insert("forwarded".into(), json!(true));
            }
            m
        }
        Err(e) => error_fields(e, &Value::Object(request.clone())),
    };
    for k in ["id", "api_version"] {
        if let Some(v) = request.get(k).filter(|v| !v.is_null()) {
            m.insert(k.into(), v.clone());
        }
    }
    m.insert("type".into(), json!("response"));
    m.insert("warnings".into(), warnings());
    let body = Value::Object(m).to_string();
    record(s, transport, &method, &result, started, body.len());
    s.guard.sent(client, body.len());
    body
}

/// Whether the server keeps up: 200 while the last ledger is recent, 503 when it
/// is old or there is none. This is what stopped being true on the day the nodes'
/// network went down, while the connection gauges still read 1.
async fn health(
    State(s): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let client = s.guard.client(peer.ip(), &headers);
    if !s.guard.request(client, 1) {
        return slow_down_http();
    }
    let engine = s.engine.clone();
    let last = tokio::task::spawn_blocking(move || engine.last_ledger_age())
        .await
        .unwrap_or_else(|e| Err(internal(e)));
    let (status, body) = health_answer(last.ok());
    (
        status,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

fn health_answer(last: Option<(u32, i64)>) -> (axum::http::StatusCode, Value) {
    use axum::http::StatusCode;
    match last {
        Some((ledger, age)) if age <= HEALTHY_AGE => (
            StatusCode::OK,
            json!({"status": "ok", "ledger": ledger, "age": age}),
        ),
        Some((ledger, age)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "lagging", "ledger": ledger, "age": age}),
        ),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "noLedger"}),
        ),
    }
}

fn start_guard(config: GuardConfig) -> Arc<Guard> {
    let guard = Arc::new(Guard::new(config));
    if let Some(every) = guard.sweep_every() {
        let g = guard.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                g.sweep();
            }
        });
    }
    guard
}

fn routes(shared: Shared) -> Router {
    Router::new()
        .route("/", get(ws_upgrade).post(http_rpc))
        .route("/health", get(health))
        .with_state(shared)
}

/// The routes of `--api-addr` and of the public listeners, over one set of
/// subscriptions, which starts publishing here.
fn apps(
    engine: Arc<Engine>,
    forwarder: Option<Arc<Forwarder>>,
    metrics: metrics::Shared,
    config: ServeConfig,
    streams: Option<crate::confirm::NodeStreams>,
) -> (Router, Option<Router>) {
    let shared = Shared {
        engine,
        inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
        proofs: Arc::new(Semaphore::new(MAX_PROOFS)),
        forwards: Arc::new(Semaphore::new(MAX_FORWARDS)),
        cache: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        forwarder,
        hub: Arc::new(Hub::default()),
        metrics,
        guard: start_guard(config.own_limits),
        forward_submissions: config.forward_submissions,
        public: None,
    };
    tokio::spawn(subs::run(shared.engine.clone(), shared.hub.clone()));
    if let Some(s) = streams {
        tokio::spawn(subs::forward_streams(shared.hub.clone(), s.subscribe()));
    }
    let public = config.public.map(|p| {
        let public = Shared {
            inflight: Arc::new(Semaphore::new(p.max_inflight)),
            proofs: Arc::new(Semaphore::new(p.max_proofs)),
            forwards: Arc::new(Semaphore::new(p.max_forwards)),
            guard: start_guard(p.limits),
            forward_submissions: false,
            public: Some(Public {
                own_inflight: shared.inflight.clone(),
                sessions: Arc::new(Semaphore::new(p.max_sessions)),
                max_accounts: p.max_accounts,
            }),
            ..shared.clone()
        };
        tokio::spawn(sample_public(
            public.clone(),
            p.max_inflight,
            p.max_proofs,
            p.max_forwards,
            p.max_sessions,
        ));
        routes(public).layer(DefaultBodyLimit::max(PUBLIC_MESSAGE))
    });
    tokio::spawn(sample(shared.clone()));
    (routes(shared), public)
}

/// Every few seconds, how much of the public listeners' budgets is in use.
async fn sample_public(
    s: Shared,
    max_inflight: usize,
    max_proofs: usize,
    max_forwards: usize,
    max_sessions: usize,
) {
    loop {
        {
            let free = s
                .public
                .as_ref()
                .map_or(max_sessions, |p| p.sessions.available_permits());
            let mut m = lock(&s.metrics);
            m.api.public_inflight = (max_inflight - s.inflight.available_permits()) as u64;
            m.api.public_inflight_proofs = (max_proofs - s.proofs.available_permits()) as u64;
            m.api.public_inflight_forwards = (max_forwards - s.forwards.available_permits()) as u64;
            m.api.public_sessions = (max_sessions - free) as u64;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// Every few seconds, what is happening now: requests in progress and
/// subscriptions.
async fn sample(s: Shared) {
    loop {
        let h = s.hub.stats();
        {
            let mut m = lock(&s.metrics);
            m.api.inflight = (MAX_INFLIGHT - s.inflight.available_permits()) as u64;
            m.api.inflight_proofs = (MAX_PROOFS - s.proofs.available_permits()) as u64;
            m.api.inflight_forwards = (MAX_FORWARDS - s.forwards.available_permits()) as u64;
            m.api.subscribers = [
                ("ledger", h.ledger),
                ("transactions", h.transactions),
                ("book_changes", h.book_changes),
                ("validations", h.validations),
                ("manifests", h.manifests),
                ("accounts", h.account_sessions),
            ]
            .into_iter()
            .collect();
            m.api.subscribed_accounts = h.accounts;
            m.api.ws_dropped = h.dropped;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// Listens on every address in `addrs` for the life of the process, with one
/// set of subscriptions behind them all. An address that can't be bound is
/// retried on its own: ingestion matters more than the API, and an address
/// still held by the server being replaced is taken over once it is freed.
pub async fn serve(
    addrs: Vec<SocketAddr>,
    engine: Arc<Engine>,
    forwarder: Option<Arc<Forwarder>>,
    metrics: metrics::Shared,
    config: ServeConfig,
    streams: Option<crate::confirm::NodeStreams>,
) {
    let public_addrs = config
        .public
        .as_ref()
        .map_or_else(Vec::new, |p| p.addrs.clone());
    let (own, public) = apps(engine, forwarder, metrics, config, streams);
    let mut listeners: Vec<(SocketAddr, Router)> =
        addrs.into_iter().map(|a| (a, own.clone())).collect();
    if let Some(public) = public {
        listeners.extend(public_addrs.into_iter().map(|a| (a, public.clone())));
    }
    for (addr, app) in listeners {
        tokio::spawn(async move {
            loop {
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        info!("API at http://{addr}/ and ws://{addr}/");
                        let svc = app
                            .clone()
                            .into_make_service_with_connect_info::<SocketAddr>();
                        if let Err(e) = axum::serve(listener, svc).await {
                            warn!("API: {e}");
                        }
                    }
                    Err(e) => warn!("API: cannot listen on {addr}: {e}; retrying in 10 s"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message as Client;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    /// Starts a router on a free port.
    async fn listen(routes: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let svc = routes.into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, svc).await });
        addr
    }

    fn public_config() -> PublicConfig {
        PublicConfig {
            addrs: Vec::new(),
            limits: GuardConfig {
                max_requests: Some(1000),
                sweep: std::time::Duration::from_secs(3600),
                ..GuardConfig::default()
            },
            max_inflight: 2,
            max_proofs: 1,
            max_forwards: 1,
            max_sessions: 1,
            max_accounts: 1,
        }
    }

    /// HTTP status and body of one JSON-RPC request.
    async fn post(addr: SocketAddr, body: String) -> (u16, String) {
        tokio::task::spawn_blocking(move || {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into();
            let mut r = agent.post(&format!("http://{addr}/")).send(body).unwrap();
            (r.status().as_u16(), r.body_mut().read_to_string().unwrap())
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn the_public_door_has_its_own_slots_and_steps_aside() {
        let dir = tempfile::tempdir().unwrap();
        let shared = Shared {
            engine: Arc::new(test_engine(dir.path())),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            proofs: Arc::new(Semaphore::new(MAX_PROOFS)),
            forwards: Arc::new(Semaphore::new(MAX_FORWARDS)),
            cache: Default::default(),
            forwarder: None,
            hub: Default::default(),
            metrics: Default::default(),
            guard: Arc::new(Guard::default()),
            forward_submissions: false,
            public: None,
        };
        let public = Shared {
            inflight: Arc::new(Semaphore::new(2)),
            public: Some(Public {
                own_inflight: shared.inflight.clone(),
                sessions: Arc::new(Semaphore::new(1)),
                max_accounts: 1,
            }),
            ..shared.clone()
        };
        // Filling the public slots leaves our own untouched.
        let held: Vec<_> = (0..2)
            .map(|_| public.inflight.clone().try_acquire_owned().unwrap())
            .collect();
        assert_eq!(shared.inflight.available_permits(), MAX_INFLIGHT);
        let t = Instant::now();
        let e = public.slot(&public.inflight).await.unwrap_err();
        assert_eq!(e.error, "tooBusy");
        assert!(t.elapsed() < QUEUE_WAIT);
        assert!(shared.slot(&shared.inflight).await.is_ok());
        drop(held);
        // With our own slots running out, the public door refuses at once.
        assert!(public.slot(&public.inflight).await.is_ok());
        let busy: Vec<_> = (0..=MAX_INFLIGHT - OWN_HEADROOM)
            .map(|_| shared.inflight.clone().try_acquire_owned().unwrap())
            .collect();
        let t = Instant::now();
        assert_eq!(
            public.slot(&public.inflight).await.unwrap_err().error,
            "tooBusy"
        );
        assert!(t.elapsed() < std::time::Duration::from_millis(100));
        assert!(shared.slot(&shared.inflight).await.is_ok());
        drop(busy);
    }

    #[tokio::test]
    async fn submissions_stay_off_the_public_door_and_off_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let forwarder = Arc::new(Forwarder::new(
            vec!["http://127.0.0.1:1".into()],
            std::time::Duration::from_secs(1),
        ));
        let config = ServeConfig {
            forward_submissions: true,
            public: Some(public_config()),
            ..ServeConfig::default()
        };
        let (own, public) = apps(
            Arc::new(test_engine(dir.path())),
            Some(forwarder.clone()),
            metrics::Shared::default(),
            config,
            None,
        );
        let own = listen(own).await;
        let public = listen(public.unwrap()).await;
        let submit = r#"{"method":"submit","params":[{"tx_blob":"00"}]}"#.to_owned();
        let (_, on_public) = post(public, submit.clone()).await;
        assert!(
            on_public.contains(r#""error":"notSupported""#),
            "{on_public}"
        );
        let path = r#"{"method":"ripple_path_find","params":[{"ledger_index":"current"}]}"#;
        let (_, on_public) = post(public, path.to_owned()).await;
        assert!(
            on_public.contains(r#""error":"notSupported""#),
            "{on_public}"
        );
        // On our own door it goes to the node, which is down here.
        let (_, on_own) = post(own, submit.clone()).await;
        assert!(on_own.contains(r#""error":"failedToForward""#), "{on_own}");
        let secret = r#"{"method":"submit","params":[{"tx_blob":"00","secret":"s"}]}"#;
        let (_, refused) = post(own, secret.to_owned()).await;
        assert!(refused.contains("signingNotSupported"), "{refused}");
        // Not turned on: as if the method didn't exist.
        let (off, _) = apps(
            Arc::new(test_engine(other.path())),
            Some(forwarder),
            metrics::Shared::default(),
            ServeConfig::default(),
            None,
        );
        let (_, unknown) = post(listen(off).await, submit).await;
        assert!(unknown.contains(r#""error":"unknownCmd""#), "{unknown}");
    }

    #[tokio::test]
    async fn the_public_door_caps_sessions_and_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let config = ServeConfig {
            public: Some(public_config()),
            ..ServeConfig::default()
        };
        let (_, public) = apps(
            Arc::new(test_engine(dir.path())),
            None,
            metrics::Shared::default(),
            config,
            None,
        );
        let addr = listen(public.unwrap()).await;
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        // The only session is taken.
        assert!(
            tokio_tungstenite::connect_async(format!("ws://{addr}/"))
                .await
                .is_err()
        );
        let subscribe = serde_json::json!({
            "command": "subscribe",
            "accounts": ["rrrrrrrrrrrrrrrrrrrrrhoLvTp", "rrrrrrrrrrrrrrrrrrrrBZbvji"],
        });
        ws.send(Client::Text(subscribe.to_string().into()))
            .await
            .unwrap();
        let Some(Ok(Client::Text(reply))) = ws.next().await else {
            panic!("no reply");
        };
        assert!(reply.contains("accountsTooMany"), "{reply}");
    }

    #[test]
    fn health_reports_a_server_that_stopped_advancing() {
        use axum::http::StatusCode;
        assert_eq!(health_answer(Some((5, 3))).0, StatusCode::OK);
        assert_eq!(health_answer(Some((5, HEALTHY_AGE))).0, StatusCode::OK);
        let (status, body) = health_answer(Some((5, HEALTHY_AGE + 1)));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "lagging");
        assert_eq!(health_answer(None).0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn health_on_an_empty_server_is_503() {
        let dir = tempfile::tempdir().unwrap();
        let (own, _) = apps(
            Arc::new(test_engine(dir.path())),
            None,
            metrics::Shared::default(),
            ServeConfig::default(),
            None,
        );
        let addr = listen(own).await;
        let got = tokio::task::spawn_blocking(move || {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into();
            let mut r = agent.get(&format!("http://{addr}/health")).call().unwrap();
            (r.status().as_u16(), r.body_mut().read_to_string().unwrap())
        })
        .await
        .unwrap();
        assert_eq!(got.0, 503);
        assert!(got.1.contains("noLedger"), "{}", got.1);
    }

    fn test_engine(dir: &std::path::Path) -> Engine {
        Engine {
            state: Arc::new(crate::state::StateStore::open(&dir.join("state")).unwrap()),
            blocks: crate::history::HistoryReader::open(&dir.join("history")).unwrap(),
            network_id: 0,
            started: Instant::now(),
            confirmer: None,
            quorum: Default::default(),
        }
    }

    #[tokio::test]
    async fn a_client_over_its_budget_gets_slow_down() {
        let dir = tempfile::tempdir().unwrap();
        let metrics = metrics::Shared::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let guard = GuardConfig {
            max_requests: Some(2),
            sweep: std::time::Duration::from_secs(3600),
            ..GuardConfig::default()
        };
        let config = ServeConfig {
            own_limits: guard,
            ..ServeConfig::default()
        };
        let routes = apps(
            Arc::new(test_engine(dir.path())),
            None,
            metrics.clone(),
            config,
            None,
        )
        .0
        .into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, routes).await });
        let got = tokio::task::spawn_blocking(move || {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into();
            (0..3)
                .map(|_| {
                    let mut r = agent
                        .post(&format!("http://{addr}/"))
                        .send(r#"{"method":"ping"}"#)
                        .unwrap();
                    let cache = r
                        .headers()
                        .get("cache-control")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    (
                        r.status().as_u16(),
                        cache,
                        r.body_mut().read_to_string().unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();
        assert_eq!((got[0].0, got[0].1.as_str()), (200, "no-store"));
        assert_eq!(got[1].0, 200);
        assert_eq!(got[2].0, 503);
        assert!(got[2].2.contains(r#""error":"slowDown""#), "{}", got[2].2);
        assert_eq!(
            lock(&metrics)
                .api
                .requests
                .get(&("http", "ping".into(), "slowDown".into())),
            Some(&1)
        );
    }

    #[test]
    fn only_answers_that_cannot_change_are_cacheable() {
        let ok = Ok(Reply::Own(Map::new()));
        let p = |v: Value| v.as_object().cloned().unwrap();
        assert!(immutable("tx", &Map::new(), &ok));
        assert!(immutable("ledger", &p(json!({"ledger_index": 5})), &ok));
        assert!(immutable(
            "account_info",
            &p(json!({"ledger_index": "5"})),
            &ok
        ));
        assert!(immutable(
            "ledger_entry",
            &p(json!({"ledger_hash": "AB"})),
            &ok
        ));
        assert!(!immutable(
            "ledger",
            &p(json!({"ledger_index": "validated"})),
            &ok
        ));
        assert!(!immutable("account_info", &Map::new(), &ok));
        assert!(!immutable(
            "server_info",
            &p(json!({"ledger_index": 5})),
            &ok
        ));
        assert!(!immutable("tx", &Map::new(), &Err(slow_down())));
        let fwd = Ok(Reply::Forwarded(Map::new()));
        assert!(!immutable("ledger", &p(json!({"ledger_index": 5})), &fwd));
    }

    #[tokio::test]
    async fn a_client_close_is_answered_and_requests_are_counted() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine {
            state: Arc::new(crate::state::StateStore::open(&dir.path().join("state")).unwrap()),
            blocks: crate::history::HistoryReader::open(&dir.path().join("history")).unwrap(),
            network_id: 0,
            started: Instant::now(),
            confirmer: None,
            quorum: Default::default(),
        };
        let metrics = metrics::Shared::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let routes = apps(
            Arc::new(engine),
            None,
            metrics.clone(),
            ServeConfig::default(),
            None,
        )
        .0
        .into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, routes).await });
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        ws.send(Client::Text(r#"{"command":"ping","id":1}"#.into()))
            .await
            .unwrap();
        let Some(Ok(Client::Text(reply))) = ws.next().await else {
            panic!("no reply to ping");
        };
        assert!(reply.contains(r#""status":"success""#), "{reply}");
        // xrpl.js closes with 4000 and reconnects unless the same code comes back.
        ws.send(Client::Close(Some(CloseFrame {
            code: CloseCode::Library(4000),
            reason: "".into(),
        })))
        .await
        .unwrap();
        match ws.next().await {
            Some(Ok(Client::Close(Some(f)))) => assert_eq!(f.code, CloseCode::Library(4000)),
            other => panic!("expected a close reply, got {other:?}"),
        }
        for _ in 0..100 {
            if lock(&metrics).api.ws_sessions == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let m = lock(&metrics);
        assert_eq!((m.api.ws_sessions, m.api.ws_sessions_total), (0, 1));
        assert_eq!(
            m.api.requests.get(&("ws", "ping".into(), "success".into())),
            Some(&1)
        );
    }
}
