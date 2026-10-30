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
//!
//! subscribe and unsubscribe work only over WebSocket; `subs` keeps the subscriptions.
//! A session interleaves responses to requests with messages from its queue.
//!
//! Node methods and requests about the current ledger (`forward::forwarded`) go to
//! xrpld; the response follows Clio:
//! the node's `result` as is, with `forwarded: true`, `status`, `type` on top.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::SinkExt;
use serde_json::{Map, Value, json};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::api::{Engine, RpcError, api_version};
use crate::forward::{Forwarder, forwarded, node_info};
use crate::metrics::{self, lock};
use crate::subs::{self, Hub};

const MAX_INFLIGHT: usize = 32;
/// Proof bundles are expensive to build: at most this many at a time.
const MAX_PROOFS: usize = 4;
/// Built bundles per ledger and transaction kept in memory; they never change.
const PROOF_CACHE: usize = 128;

type ProofCache = std::sync::Mutex<std::collections::VecDeque<(String, Map<String, Value>)>>;

#[derive(Debug, Clone)]
struct Shared {
    engine: Arc<Engine>,
    inflight: Arc<Semaphore>,
    proofs: Arc<Semaphore>,
    cache: Arc<ProofCache>,
    forwarder: Option<Arc<Forwarder>>,
    hub: Arc<Hub>,
    metrics: metrics::Shared,
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
    if forwarded(&method, &params) {
        let Some(f) = s.forwarder.clone() else {
            return Err(RpcError {
                error: "unknownCmd",
                code: 32,
                message: "Unknown method.".into(),
            });
        };
        let _permit = s
            .inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| RpcError {
                error: "internal",
                code: 73,
                message: e.to_string(),
            })?;
        return tokio::task::spawn_blocking(move || f.forward(&method, &params))
            .await
            .unwrap_or_else(|e| {
                Err(RpcError {
                    error: "internal",
                    code: 73,
                    message: e.to_string(),
                })
            })
            .map(Reply::Forwarded);
    }
    let info = method == "server_info";
    let mut r = call_own(s, method, params).await?;
    // Fee multiplier and version come from the node, as in Clio; if the node is
    // unavailable, our own response stays. The node's answer is refreshed in the
    // background, so this doesn't wait for the node.
    if let (true, Some(f)) = (info, s.forwarder.clone()) {
        let node = tokio::task::spawn_blocking(move || f.node_server_info()).await;
        if let Ok(Some(node)) = node {
            node_info(&mut r, &node);
        }
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
        s.proofs.clone().try_acquire_owned().map_err(|_| RpcError {
            error: "tooBusy",
            code: 9,
            message: "The server is too busy to help you now.".into(),
        })?
    } else {
        s.inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| RpcError {
                error: "internal",
                code: 73,
                message: e.to_string(),
            })?
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
    let result = tokio::task::spawn_blocking(move || engine.handle(&method, &params))
        .await
        .unwrap_or_else(|e| {
            Err(RpcError {
                error: "internal",
                code: 73,
                message: e.to_string(),
            })
        });
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

async fn http_rpc(State(s): State<Shared>, body: String) -> Response {
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
    let result = match params_of(request.get("params")) {
        Ok(p) if !method.is_empty() => call(&s, method.clone(), p).await,
        Ok(_) => Err(RpcError {
            error: "unknownCmd",
            code: 32,
            message: "Unknown method.".into(),
        }),
        Err(e) => Err(e),
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
    record(&s, "http", &method, &result, started, body.len());
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

async fn ws_upgrade(State(s): State<Shared>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| ws_session(s, socket))
}

async fn ws_session(s: Shared, mut socket: WebSocket) {
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
                let reply = ws_answer(&s, id, &text).await;
                if socket.send(Message::Text(reply)).await.is_err() {
                    break;
                }
            }
            out = rx.recv() => {
                // Queue closed: the session was disconnected for falling behind.
                let Some(out) = out else { break };
                if socket.send(Message::Text(out)).await.is_err() {
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
    .unwrap_or_else(|e| {
        Err(RpcError {
            error: "internal",
            code: 73,
            message: e.to_string(),
        })
    })
    .map(Reply::Own)
}

async fn ws_answer(s: &Shared, id: u64, text: &str) -> String {
    let started = Instant::now();
    let Ok(Value::Object(request)) = serde_json::from_str::<Value>(text) else {
        let e = bad_syntax();
        let mut m = error_fields(&e, &json!(text));
        m.insert("warnings".into(), warnings());
        let body = Value::Object(m).to_string();
        record(s, "ws", "", &Err(e), started, body.len());
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
    let result = if method == "subscribe" || method == "unsubscribe" {
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
    record(s, "ws", &method, &result, started, body.len());
    body
}

/// The API routes over one set of subscriptions, which starts publishing here.
fn app(engine: Arc<Engine>, forwarder: Option<Arc<Forwarder>>, metrics: metrics::Shared) -> Router {
    let shared = Shared {
        engine,
        inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
        proofs: Arc::new(Semaphore::new(MAX_PROOFS)),
        cache: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        forwarder,
        hub: Arc::new(Hub::default()),
        metrics,
    };
    tokio::spawn(subs::run(shared.engine.clone(), shared.hub.clone()));
    tokio::spawn(sample(shared.clone()));
    Router::new()
        .route("/", get(ws_upgrade).post(http_rpc))
        .with_state(shared)
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
            m.api.subscribers = [
                ("ledger", h.ledger),
                ("transactions", h.transactions),
                ("book_changes", h.book_changes),
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
) {
    let app = app(engine, forwarder, metrics);
    for addr in addrs {
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        info!("API at http://{addr}/ and ws://{addr}/");
                        if let Err(e) = axum::serve(listener, app.clone()).await {
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
        let routes = app(Arc::new(engine), None, metrics.clone());
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
