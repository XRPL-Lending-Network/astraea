//! WebSocket subscriptions, as in Clio 2.8: the `ledger` stream
//! (ledgerClosed), the `transactions` stream, the `book_changes` stream, and
//! per-account transactions via `accounts`. Other Clio streams (validations,
//! manifests, *_proposed, books) return notSupported: a subscription that never
//! sends messages would mislead the client.
//!
//! Every ledger validated by a quorum (the upper bound of
//! `range`) is published in order: ledgerClosed first, then transactions by
//! TransactionIndex, then bookChanges. An account gets a transaction if it is among the affected accounts (the
//! same set as account_tx). The message format follows the api_version of the session's
//! latest subscription. The session queue is bounded, like
//! `ws_max_sending_queue_size` in Clio: a session that can't keep up is disconnected.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tracing::warn;
use witness_core::ledger::LedgerHeader;

use crate::api::{
    Engine, Res, RpcError, account_id, currency_code, internal, invalid_params, keylet, rpc_err,
    time_iso,
};
use crate::index::{AccountId, affected_accounts};
use crate::xrpl_json;

/// Maximum messages in a session queue.
pub const QUEUE: usize = 1500;
/// How often to check whether a new ledger has been validated.
const POLL: Duration = Duration::from_millis(250);
/// Lag beyond which missed ledgers are not caught up.
const MAX_BEHIND: u32 = 256;
/// Maximum accounts in one subscribe: parsing and copying the set on every
/// ledger must not depend on the size of someone else's request.
pub const MAX_ACCOUNTS: usize = 10_000;

const LSF_GLOBAL_FREEZE: u32 = 0x0040_0000;
const LSF_LOW_FREEZE: u32 = 0x0040_0000;
const LSF_HIGH_FREEZE: u32 = 0x0080_0000;

#[derive(Debug)]
struct Sub {
    api: u32,
    ledger: bool,
    /// Ledger from the subscribe response: ledgerClosed messages come only after it,
    /// with no repeats and no going backwards when publishing catches up on a batch.
    ledger_after: u32,
    transactions: bool,
    book_changes: bool,
    accounts: HashSet<AccountId>,
    out: mpsc::Sender<String>,
}

/// Subscribers of all sessions.
#[derive(Debug, Default)]
pub struct Hub {
    subs: Mutex<HashMap<u64, Sub>>,
    next: AtomicU64,
    /// Sessions disconnected for falling behind.
    dropped: AtomicU64,
}

/// Subscriptions right now, for metrics.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HubStats {
    pub ledger: u64,
    pub transactions: u64,
    pub book_changes: u64,
    /// Sessions subscribed to at least one account, and accounts over all of them.
    pub account_sessions: u64,
    pub accounts: u64,
    pub dropped: u64,
}

/// What subscribe or unsubscribe asks for.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub ledger: bool,
    pub transactions: bool,
    pub book_changes: bool,
    pub accounts: Vec<AccountId>,
}

fn not_supported(what: &str) -> RpcError {
    rpc_err(
        "notSupported",
        75,
        format!("Operation not supported: {what}."),
    )
}

/// Parsing of streams and accounts, with Clio's errors.
pub fn parse(p: &Map<String, Value>) -> Result<Request, RpcError> {
    let mut r = Request::default();
    match p.get("streams") {
        None => {}
        Some(Value::Array(a)) => {
            for s in a {
                match s.as_str() {
                    None => return Err(invalid_params("streamNotString")),
                    Some("ledger") => r.ledger = true,
                    Some("transactions") => r.transactions = true,
                    Some("book_changes") => r.book_changes = true,
                    Some(s @ ("validations" | "manifests" | "transactions_proposed")) => {
                        return Err(not_supported(s));
                    }
                    Some(_) => return Err(rpc_err("malformedStream", 71, "Stream malformed.")),
                }
            }
        }
        Some(_) => return Err(invalid_params("streamsNotArray")),
    }
    match p.get("accounts") {
        None => {}
        Some(Value::Array(a)) if a.is_empty() => {
            return Err(rpc_err("actMalformed", 35, "accounts malformed."));
        }
        Some(Value::Array(a)) if a.len() > MAX_ACCOUNTS => {
            return Err(invalid_params("accountsTooMany"));
        }
        Some(Value::Array(a)) => {
            for v in a {
                if !v.is_string() {
                    return Err(invalid_params("accounts'sItemNotString"));
                }
                r.accounts.push(
                    account_id(v)
                        .map_err(|_| rpc_err("actMalformed", 35, "accounts'sItemMalformed"))?,
                );
            }
        }
        Some(_) => return Err(invalid_params("accountsNotArray")),
    }
    for k in ["accounts_proposed", "books"] {
        if p.contains_key(k) {
            return Err(not_supported(k));
        }
    }
    Ok(r)
}

impl Hub {
    /// New session: its id and message queue.
    pub fn join(&self) -> (u64, mpsc::Receiver<String>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (out, rx) = mpsc::channel(QUEUE);
        self.lock().insert(
            id,
            Sub {
                api: 2,
                ledger: false,
                ledger_after: 0,
                transactions: false,
                book_changes: false,
                accounts: HashSet::new(),
                out,
            },
        );
        (id, rx)
    }

    pub fn leave(&self, id: u64) {
        self.lock().remove(&id);
    }

    pub fn stats(&self) -> HubStats {
        let g = self.lock();
        let mut st = HubStats {
            dropped: self.dropped.load(Ordering::Relaxed),
            ..HubStats::default()
        };
        for s in g.values() {
            st.ledger += u64::from(s.ledger);
            st.transactions += u64::from(s.transactions);
            st.book_changes += u64::from(s.book_changes);
            st.account_sessions += u64::from(!s.accounts.is_empty());
            st.accounts += s.accounts.len() as u64;
        }
        st
    }

    /// `top` is the ledger the subscribe response will report.
    pub fn subscribe(&self, id: u64, r: &Request, api: u32, top: u32) {
        if let Some(s) = self.lock().get_mut(&id) {
            s.api = api;
            if r.ledger {
                s.ledger_after = top;
            }
            s.ledger |= r.ledger;
            s.transactions |= r.transactions;
            s.book_changes |= r.book_changes;
            s.accounts.extend(r.accounts.iter().copied());
        }
    }

    pub fn unsubscribe(&self, id: u64, r: &Request) {
        if let Some(s) = self.lock().get_mut(&id) {
            s.ledger &= !r.ledger;
            s.transactions &= !r.transactions;
            s.book_changes &= !r.book_changes;
            for a in &r.accounts {
                s.accounts.remove(a);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Sub>> {
        self.subs.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn wants_anything(&self) -> bool {
        self.lock()
            .values()
            .any(|s| s.ledger || s.transactions || s.book_changes || !s.accounts.is_empty())
    }

    /// Sends to the session queue; if the queue is full or closed, the session
    /// is disconnected (its queue is closed together with the entry).
    fn deliver(&self, targets: &[(u64, String)]) {
        let mut dead = Vec::new();
        {
            let g = self.lock();
            for (id, msg) in targets {
                if let Some(s) = g.get(id)
                    && s.out.try_send(msg.clone()).is_err()
                {
                    dead.push(*id);
                }
            }
        }
        for id in dead {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            warn!("subscriptions: session {id} can't keep up reading, disconnected");
            self.leave(id);
        }
    }
}

impl Engine {
    /// Ledger fields for the subscribe response and the ledgerClosed message.
    pub(crate) fn ledger_stream(
        &self,
        seq: u32,
        txn_count: Option<usize>,
    ) -> Res<Map<String, Value>> {
        let (min, max) = self.range()?;
        let (_, h) = self.header(seq)?;
        let (base, reserve, inc) = self
            .fee_drops(seq)?
            .ok_or_else(|| internal(format!("no FeeSettings for ledger {seq}")))?;
        let mut m = Map::new();
        if txn_count.is_some() {
            m.insert("type".into(), json!("ledgerClosed"));
        }
        m.insert("ledger_index".into(), json!(seq));
        m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
        m.insert("ledger_time".into(), json!(h.close_time));
        m.insert("fee_base".into(), json!(base));
        m.insert("reserve_base".into(), json!(reserve));
        m.insert("reserve_inc".into(), json!(inc));
        m.insert("validated_ledgers".into(), json!(format!("{min}-{max}")));
        if let Some(n) = txn_count {
            m.insert("txn_count".into(), json!(n));
        }
        m.insert("network_id".into(), json!(self.network_id));
        Ok(m)
    }

    /// Transaction message in the format of API version `api`.
    pub(crate) fn tx_stream(
        &self,
        seq: u32,
        h: &LedgerHeader,
        tx: &[u8],
        meta: &[u8],
        api: u32,
    ) -> Res<Map<String, Value>> {
        let e = self.expand(tx, meta, seq, api, false, true)?;
        let mut t = e.tx;
        t.insert("date".into(), json!(h.close_time));
        if t.get("TransactionType").and_then(Value::as_str) == Some("OfferCreate")
            && let Some(f) = self.owner_funds(seq, &t)?
        {
            t.insert("owner_funds".into(), json!(f));
        }
        let result = e
            .meta
            .get("TransactionResult")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let mut m = Map::new();
        if api < 2 {
            m.insert("transaction".into(), Value::Object(t));
        } else {
            let hash = t.remove("hash").unwrap_or(Value::Null);
            m.insert("tx_json".into(), Value::Object(t));
            m.insert("hash".into(), hash);
        }
        m.insert("meta".into(), Value::Object(e.meta));
        if let Some(c) = self.ctid(seq, e.index) {
            m.insert("ctid".into(), json!(c));
        }
        m.insert("type".into(), json!("transaction"));
        m.insert("validated".into(), json!(true));
        m.insert("status".into(), json!("closed"));
        m.insert("close_time_iso".into(), json!(time_iso(h.close_time)));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
        if let Some((code, message)) = crate::ter::result(&result) {
            m.insert("engine_result_code".into(), json!(code));
            m.insert("engine_result_message".into(), json!(message));
        }
        m.insert("engine_result".into(), json!(result));
        Ok(m)
    }

    /// owner_funds for OfferCreate, as in Clio: how much TakerGets the owner can
    /// fund as of this ledger. The field is absent for the TakerGets issuer and for MPT.
    fn owner_funds(&self, seq: u32, t: &Map<String, Value>) -> Res<Option<String>> {
        let Some(acc) = t.get("Account").and_then(|a| account_id(a).ok()) else {
            return Ok(None);
        };
        let obj = |k: &[u8; 32]| -> Res<Option<Map<String, Value>>> {
            match self.state.get(k, seq).map_err(internal)? {
                None => Ok(None),
                Some(d) => xrpl_json::ledger_entry(k, &d).map(Some).map_err(internal),
            }
        };
        let flags =
            |o: &Map<String, Value>| o.get("Flags").and_then(Value::as_u64).unwrap_or(0) as u32;
        match t.get("TakerGets") {
            Some(Value::String(_)) => {
                let Some(root) = obj(&keylet(b'a', &[&acc]))? else {
                    return Ok(Some("0".into()));
                };
                let balance = root
                    .get("Balance")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let owners = root.get("OwnerCount").and_then(Value::as_u64).unwrap_or(0);
                let (_, reserve, inc) = self.fee_drops(seq)?.unwrap_or((0, 0, 0));
                let need = reserve.saturating_add(owners.saturating_mul(inc));
                Ok(Some(balance.saturating_sub(need).to_string()))
            }
            Some(Value::Object(g)) => {
                let (Some(issuer), Some(cur)) = (
                    g.get("issuer").and_then(|a| account_id(a).ok()),
                    g.get("currency")
                        .and_then(Value::as_str)
                        .and_then(currency_code),
                ) else {
                    return Ok(None);
                };
                if issuer == acc {
                    return Ok(None);
                }
                if obj(&keylet(b'a', &[&issuer]))?
                    .is_some_and(|r| flags(&r) & LSF_GLOBAL_FREEZE != 0)
                {
                    return Ok(Some("0".into()));
                }
                let (lo, hi) = if acc < issuer {
                    (acc, issuer)
                } else {
                    (issuer, acc)
                };
                let Some(line) = obj(&keylet(b'r', &[&lo, &hi, &cur]))? else {
                    return Ok(Some("0".into()));
                };
                let freeze = if issuer > acc {
                    LSF_HIGH_FREEZE
                } else {
                    LSF_LOW_FREEZE
                };
                if flags(&line) & freeze != 0 {
                    return Ok(Some("0".into()));
                }
                let v = line
                    .get("Balance")
                    .and_then(|b| b.get("value"))
                    .and_then(Value::as_str)
                    .unwrap_or("0");
                Ok(Some(if acc > issuer {
                    crate::owned::negate(v)
                } else {
                    v.to_owned()
                }))
            }
            _ => Ok(None),
        }
    }
}

/// What one session gets for a ledger.
struct Wants {
    id: u64,
    api: u32,
    ledger: bool,
    transactions: bool,
    book_changes: bool,
    accounts: HashSet<AccountId>,
}

/// Messages for ledger `seq` to subscribers.
fn publish(engine: &Engine, hub: &Hub, seq: u32) -> Res<()> {
    // Snapshot of subscriptions: who gets what.
    let subs: Vec<Wants> = hub
        .lock()
        .iter()
        .map(|(id, s)| Wants {
            id: *id,
            api: s.api,
            ledger: s.ledger && seq > s.ledger_after,
            transactions: s.transactions,
            book_changes: s.book_changes,
            accounts: s.accounts.clone(),
        })
        .collect();
    let l = engine.ledger(seq)?;
    if subs.iter().any(|s| s.ledger) {
        let msg = Value::Object(engine.ledger_stream(seq, Some(l.transactions.len()))?).to_string();
        let targets: Vec<(u64, String)> = subs
            .iter()
            .filter(|s| s.ledger)
            .map(|s| (s.id, msg.clone()))
            .collect();
        hub.deliver(&targets);
    }
    let (_, h) = engine.header(seq)?;
    if subs
        .iter()
        .any(|s| s.transactions || !s.accounts.is_empty())
    {
        publish_transactions(engine, hub, seq, &h, &l, &subs);
    }
    if subs.iter().any(|s| s.book_changes) {
        let mut m = Map::new();
        m.insert("type".into(), json!("bookChanges"));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
        m.insert("ledger_time".into(), json!(h.close_time));
        m.insert(
            "changes".into(),
            Value::Array(crate::bookchanges::compute(&l.transactions)),
        );
        let msg = Value::Object(m).to_string();
        let targets: Vec<(u64, String)> = subs
            .iter()
            .filter(|s| s.book_changes)
            .map(|s| (s.id, msg.clone()))
            .collect();
        hub.deliver(&targets);
    }
    Ok(())
}

fn publish_transactions(
    engine: &Engine,
    hub: &Hub,
    seq: u32,
    h: &LedgerHeader,
    l: &crate::ledger::Ledger,
    subs: &[Wants],
) {
    let mut txs = Vec::with_capacity(l.transactions.len());
    // A transaction that fails to parse is skipped on its own; subscribers still
    // get the rest of the ledger's transactions.
    for (tx, meta) in &l.transactions {
        match affected_accounts(meta) {
            Ok((index, accounts)) => txs.push((index, tx, meta, accounts)),
            Err(e) => warn!("subscriptions: ledger {seq}, transaction skipped: {e}"),
        }
    }
    txs.sort_by_key(|t| t.0);
    for (_, tx, meta, accounts) in txs {
        let to: Vec<&Wants> = subs
            .iter()
            .filter(|s| s.transactions || accounts.iter().any(|a| s.accounts.contains(a)))
            .collect();
        if to.is_empty() {
            continue;
        }
        let mut by_api: HashMap<u32, String> = HashMap::new();
        let mut targets = Vec::with_capacity(to.len());
        for s in to {
            let msg = match by_api.get(&s.api) {
                Some(m) => m.clone(),
                None => match engine.tx_stream(seq, h, tx, meta, s.api) {
                    Ok(m) => {
                        let m = Value::Object(m).to_string();
                        by_api.insert(s.api, m.clone());
                        m
                    }
                    Err(e) => {
                        warn!(
                            "subscriptions: ledger {seq}, transaction skipped: {}",
                            e.message
                        );
                        break;
                    }
                },
            };
            targets.push((s.id, msg));
        }
        hub.deliver(&targets);
    }
}

/// Publishes validated ledgers for the life of the process. With no subscribers
/// it only tracks the tip: new subscribers don't get old ledgers.
pub async fn run(engine: Arc<Engine>, hub: Arc<Hub>) {
    let mut last: Option<u32> = None;
    loop {
        tokio::time::sleep(POLL).await;
        let Ok((_, max)) = engine.range() else {
            continue;
        };
        let from = match last {
            Some(l) if l >= max => continue,
            Some(l) if max - l > MAX_BEHIND => {
                warn!(
                    "subscriptions: {} ledgers behind, catching up from {}",
                    max - l,
                    max - MAX_BEHIND
                );
                max - MAX_BEHIND + 1
            }
            Some(l) => l + 1,
            None => max,
        };
        last = Some(max);
        if !hub.wants_anything() {
            continue;
        }
        let (e, h) = (engine.clone(), hub.clone());
        let done = tokio::task::spawn_blocking(move || {
            for seq in from..=max {
                if let Err(err) = publish(&e, &h, seq) {
                    warn!("subscriptions: ledger {seq} not published: {}", err.message);
                }
            }
        })
        .await;
        if let Err(e) = done {
            warn!("subscriptions: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn requests_parse_with_clio_errors() {
        let err = |v: Value| parse(&p(v)).unwrap_err();
        assert_eq!(err(json!({"streams": "ledger"})).message, "streamsNotArray");
        assert_eq!(err(json!({"streams": [1]})).message, "streamNotString");
        assert_eq!(err(json!({"streams": ["nope"]})).error, "malformedStream");
        assert_eq!(
            err(json!({"streams": ["validations"]})).error,
            "notSupported"
        );
        assert_eq!(err(json!({"accounts": "x"})).message, "accountsNotArray");
        assert_eq!(err(json!({"accounts": []})).message, "accounts malformed.");
        assert_eq!(
            err(json!({"accounts": [1]})).message,
            "accounts'sItemNotString"
        );
        assert_eq!(
            err(json!({"accounts": ["x"]})).message,
            "accounts'sItemMalformed"
        );
        assert_eq!(err(json!({"books": []})).error, "notSupported");
        let r = parse(&p(json!({
            "streams": ["ledger", "transactions", "book_changes"],
            "accounts": ["rrrrrrrrrrrrrrrrrrrrrhoLvTp"],
        })))
        .unwrap();
        assert!(r.ledger && r.transactions && r.book_changes);
        assert_eq!(r.accounts, vec![[0u8; 20]]);
        assert_eq!(parse(&Map::new()).unwrap(), Request::default());
    }

    #[test]
    fn hub_tracks_and_drops_slow_sessions() {
        let hub = Hub::default();
        let (a, mut rx) = hub.join();
        let r = Request {
            ledger: true,
            ..Request::default()
        };
        hub.subscribe(a, &r, 1, 0);
        assert!(hub.wants_anything());
        let st = hub.stats();
        assert_eq!((st.ledger, st.transactions, st.dropped), (1, 0, 0));
        hub.deliver(&[(a, "x".into())]);
        assert_eq!(rx.try_recv().unwrap(), "x");
        let flood: Vec<(u64, String)> = (0..=QUEUE).map(|_| (a, "y".into())).collect();
        hub.deliver(&flood);
        assert!(!hub.wants_anything());
        assert_eq!(
            hub.stats(),
            HubStats {
                dropped: 1,
                ..HubStats::default()
            }
        );
        hub.unsubscribe(a, &r);
    }
}
