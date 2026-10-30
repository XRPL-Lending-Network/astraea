//! Ledger Engine v0 API, compatible with Clio: ledger, tx, account_tx,
//! ledger_entry, account_info, server_info, ping; account objects and
//! ledger_data live in the `owned` module.
//!
//! Responses match Clio 2.8 field for field, in API v1 and v2 (v2 by default,
//! as in a stock Clio): the same object JSON (the `xrpl_json` module), the same
//! transaction additions (delivered_amount, DeliverMax, ctid, synthetic
//! NFT fields, mpt_issuance_id), the same account_tx marker, the same error codes.
//!
//! Data covers only validated ledgers, starting with the first one after the state snapshot:
//! there is no "current" or "closed" here. Requests are served from the same
//! process that writes ledgers, because only one process can open the fjall store.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{Map, Value, json};
use witness_core::keys::decode_base58;
use witness_core::ledger::LedgerHeader;
use witness_core::sha512_half;

use crate::history::HistoryReader;
use crate::ledger::Ledger;
use crate::state::{AccountTx, StateStore, TxPosition};
use crate::xrpl_json::{self, definitions};

/// Seconds from the Unix epoch to the XRPL epoch (2000-01-01).
const RIPPLE_EPOCH: i64 = 946_684_800;
const ACCOUNT_TX_LIMIT_DEFAULT: usize = 200;
const ACCOUNT_TX_LIMIT_MAX: usize = 1000;
/// How often the history directory is checked for new cold files.
const COLD_RESCAN: std::time::Duration = std::time::Duration::from_secs(30);

/// Response error: code, number and message, as in Clio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub error: &'static str,
    pub code: i32,
    pub message: String,
}

pub(crate) fn rpc_err(error: &'static str, code: i32, message: impl Into<String>) -> RpcError {
    RpcError {
        error,
        code,
        message: message.into(),
    }
}

pub(crate) fn invalid_params(message: &str) -> RpcError {
    rpc_err("invalidParams", 31, message)
}

pub(crate) fn lgr_not_found() -> RpcError {
    rpc_err("lgrNotFound", 21, "ledgerNotFound")
}

pub(crate) fn internal(e: String) -> RpcError {
    if e == crate::limits::EXCEEDED {
        return crate::limits::exceeded();
    }
    rpc_err("internal", 73, e)
}

pub(crate) type Res<T> = Result<T, RpcError>;

/// Date from a number of days since 1970-01-01 (Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn split_time(ripple_secs: u32) -> (i64, u32, u32, i64, i64, i64) {
    let t = i64::from(ripple_secs) + RIPPLE_EPOCH;
    let (y, m, d) = civil(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    (y, m, d, s / 3600, s / 60 % 60, s % 60)
}

/// Like `toStringIso` in xrpld: 2026-10-24T17:39:52Z.
pub fn time_iso(ripple_secs: u32) -> String {
    let (y, m, d, hh, mm, ss) = split_time(ripple_secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Like `to_string(NetClock::time_point)`: 2026-Oct-24 17:39:52.000000000 UTC.
pub fn time_human(ripple_secs: u32) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, m, d, hh, mm, ss) = split_time(ripple_secs);
    format!(
        "{y:04}-{}-{d:02} {hh:02}:{mm:02}:{ss:02}.000000000 UTC",
        MONTHS[(m - 1) as usize]
    )
}

/// Object key: SHA-512Half of the namespace and fields.
pub(crate) fn keylet(space: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut b = vec![0, space];
    for p in parts {
        b.extend_from_slice(p);
    }
    sha512_half(&b)
}

/// Request api_version: 1 or 2, default 2, as in Clio.
pub(crate) fn api_version(p: &Map<String, Value>) -> Res<u32> {
    match p.get("api_version") {
        None | Some(Value::Null) => Ok(2),
        Some(v) => match as_u32(v) {
            Some(a @ 1..=2) => Ok(a),
            _ => Err(rpc_err(
                "invalid_API_version",
                6000,
                "API version must be an integer between 1 and 2",
            )),
        },
    }
}

pub(crate) fn account_id(v: &Value) -> Res<[u8; 20]> {
    let s = v
        .as_str()
        .ok_or_else(|| rpc_err("actMalformed", 35, "accountMalformed"))?;
    match decode_base58(s) {
        Some((0, a)) if a.len() == 20 => {
            let mut out = [0u8; 20];
            out.copy_from_slice(&a);
            Ok(out)
        }
        _ => Err(rpc_err("actMalformed", 35, "accountMalformed")),
    }
}

pub(crate) fn hash256(v: &Value, what: &str) -> Res<[u8; 32]> {
    v.as_str()
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| invalid_params(&format!("{what}Malformed")))
}

pub(crate) fn as_bool(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64().is_some_and(|n| n != 0),
        _ => false,
    }
}

pub(crate) fn as_u32(v: &Value) -> Option<u32> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Reads validated ledgers, state and indexes.
#[derive(Debug)]
pub struct Engine {
    pub state: Arc<StateStore>,
    pub blocks: HistoryReader,
    pub network_id: u32,
    pub started: Instant,
    /// Quorum confirmation, for evidence bundles (Proof API).
    pub confirmer: Option<crate::confirm::Confirmer>,
    /// Latest quorum for server_info: ledger and count.
    pub quorum: std::sync::Mutex<(u32, usize)>,
}

/// Transaction with metadata as JSON, plus what responses need to know about it.
pub(crate) struct Expanded {
    pub(crate) tx: Map<String, Value>,
    pub(crate) meta: Map<String, Value>,
    pub(crate) index: u32,
}

impl Engine {
    /// Range of ledgers that have history, state and quorum
    /// confirmation: anything loaded but not yet confirmed
    /// is not served.
    pub fn range(&self) -> Res<(u32, u32)> {
        // Cold history published to the directory without a restart.
        if let Err(e) = self.blocks.refresh_cold_every(COLD_RESCAN) {
            tracing::warn!("cold history not reread: {e}");
        }
        let base = self.state.base().map_err(internal)?;
        let confirmed = self.state.confirmed().map_err(internal)?;
        match (base, confirmed) {
            // Cold history with indexes that reaches the snapshot extends
            // the range downward without a gap.
            (Some(b), Some(c)) if c > b => {
                let cold = self.blocks.cold_index().first_contiguous_to(b);
                Ok((cold.unwrap_or(b + 1).min(b + 1), c))
            }
            _ => Err(rpc_err("notReady", 13, "Not ready to handle this request.")),
        }
    }

    /// First ledger of hot history; everything before it is cold.
    fn hot_first(&self) -> Res<u32> {
        Ok(self.state.base().map_err(internal)?.map_or(0, |b| b + 1))
    }

    pub(crate) fn header(&self, seq: u32) -> Res<(Vec<u8>, LedgerHeader)> {
        let raw = match self.state.header(seq).map_err(internal)? {
            Some(r) => r,
            // Before the snapshot: header from cold history, read alone; a
            // ledger kept in hot history files falls back to its frame.
            None if seq < self.hot_first()? => {
                match self.blocks.cold_header(seq).map_err(internal)? {
                    Some(h) => h,
                    None => {
                        self.blocks
                            .get_txs(seq)
                            .map_err(internal)?
                            .ok_or_else(lgr_not_found)?
                            .header
                    }
                }
            }
            None => return Err(lgr_not_found()),
        };
        let h = LedgerHeader::parse(&raw).map_err(|e| internal(e.to_string()))?;
        Ok((raw, h))
    }

    pub(crate) fn ledger(&self, seq: u32) -> Res<Ledger> {
        // Responses need only the header and transactions: the transaction frame
        // is read without the state changes. If it isn't in history, it is still
        // pending; between the two checks the ledger can move from pending to
        // history, hence the second look at history.
        if let Some(l) = self.blocks.get_txs_known(seq).map_err(internal)? {
            return Ok(l);
        }
        match self.state.pending_ledger(seq).map_err(internal)? {
            Some(b) => Ledger::decode(&b).map_err(internal),
            None => {
                // Outside the range, rereading the directory is pointless: such a request
                // (a ctid for some other ledger) would otherwise cost two full scans.
                let (lo, hi) = self.range()?;
                if seq < lo || seq > hi {
                    return Err(lgr_not_found());
                }
                self.blocks.refresh().map_err(internal)?;
                self.blocks
                    .get_txs(seq)
                    .map_err(internal)?
                    .ok_or_else(lgr_not_found)
            }
        }
    }

    pub(crate) fn resolve_ledger(&self, p: &Map<String, Value>) -> Res<u32> {
        self.resolve(p)
    }

    pub(crate) fn ledger_txs(&self, seq: u32) -> Res<Ledger> {
        self.ledger(seq)
    }

    pub(crate) fn entry_key_of(&self, p: &Map<String, Value>) -> Res<[u8; 32]> {
        Ok(crate::selector::entry_key(p)?.0)
    }

    /// The requested ledger: ledger_hash, ledger_index, or the latest validated one.
    pub(crate) fn resolve(&self, p: &Map<String, Value>) -> Res<u32> {
        let (min, max) = self.range()?;
        let by_hash = match p.get("ledger_hash") {
            Some(v) if !v.is_null() => {
                let h = hash256(v, "ledgerHash")?;
                let hot = self.state.ledger_by_hash(&h).map_err(internal)?;
                let seq = match hot {
                    Some(s) => Some(s),
                    None => self
                        .blocks
                        .cold_index()
                        .ledger_by_hash(&h)
                        .map_err(internal)?,
                };
                Some(seq.ok_or_else(lgr_not_found)?)
            }
            _ => None,
        };
        let by_index = match p.get("ledger_index") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s == "validated" => None,
            Some(v) => Some(as_u32(v).ok_or_else(|| invalid_params("ledgerIndexMalformed"))?),
        };
        let seq = match (by_hash, by_index) {
            (Some(h), Some(i)) if h != i => return Err(lgr_not_found()),
            (Some(h), _) => h,
            (None, Some(i)) => i,
            (None, None) => max,
        };
        if seq < min || seq > max {
            return Err(lgr_not_found());
        }
        Ok(seq)
    }

    /// Like `resolve`, for state methods: state exists only from the snapshot on,
    /// and below it there is only transaction history. There the ledger is reported
    /// as missing, as on a server without that ledger, not as an internal error.
    pub(crate) fn resolve_state(&self, p: &Map<String, Value>) -> Res<u32> {
        let seq = self.resolve(p)?;
        match self.state.base().map_err(internal)? {
            Some(b) if seq >= b => Ok(seq),
            _ => Err(lgr_not_found()),
        }
    }

    pub(crate) fn header_json(
        &self,
        raw: &[u8],
        h: &LedgerHeader,
        binary: bool,
        api: u32,
    ) -> Map<String, Value> {
        let mut m = Map::new();
        if binary {
            m.insert("ledger_data".into(), json!(hex::encode_upper(raw)));
        } else {
            m.insert(
                "account_hash".into(),
                json!(hex::encode_upper(h.account_hash)),
            );
            m.insert("close_flags".into(), json!(h.close_flags));
            m.insert("close_time".into(), json!(h.close_time));
            m.insert("close_time_human".into(), json!(time_human(h.close_time)));
            m.insert(
                "close_time_resolution".into(),
                json!(h.close_time_resolution),
            );
            m.insert("close_time_iso".into(), json!(time_iso(h.close_time)));
            m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
            m.insert("parent_close_time".into(), json!(h.parent_close_time));
            m.insert(
                "parent_hash".into(),
                json!(hex::encode_upper(h.parent_hash)),
            );
            m.insert("total_coins".into(), json!(h.total_drops.to_string()));
            m.insert(
                "transaction_hash".into(),
                json!(hex::encode_upper(h.transaction_hash)),
            );
            m.insert(
                "ledger_index".into(),
                if api < 2 {
                    json!(h.sequence.to_string())
                } else {
                    json!(h.sequence)
                },
            );
        }
        m.insert("closed".into(), json!(true));
        m
    }

    /// Like `toExpandedJson` in Clio.
    /// `nft` adds synthetic NFT fields: Clio adds them in tx and account_tx,
    /// but not in ledger.
    pub(crate) fn expand(
        &self,
        tx: &[u8],
        meta: &[u8],
        seq: u32,
        api: u32,
        ctid: bool,
        nft: bool,
    ) -> Res<Expanded> {
        let mut t = xrpl_json::transaction(tx).map_err(internal)?;
        let mut m = xrpl_json::metadata(meta).map_err(internal)?;
        let index = m
            .get("TransactionIndex")
            .and_then(Value::as_u64)
            .and_then(|i| u32::try_from(i).ok())
            .unwrap_or(0);
        let tt = t
            .get("TransactionType")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let success = m.get("TransactionResult").and_then(Value::as_str) == Some("tesSUCCESS");

        if success && matches!(tt.as_str(), "Payment" | "CheckCash" | "AccountDelete") {
            let delivered = m
                .get("DeliveredAmount")
                .or_else(|| t.get("Amount"))
                .cloned()
                .unwrap_or_else(|| json!("unavailable"));
            m.insert("delivered_amount".into(), delivered);
        }
        if tt == "Payment"
            && let Some(a) = t.get("Amount").cloned()
        {
            t.insert("DeliverMax".into(), a);
            if api > 1 {
                t.remove("Amount");
            }
        }
        if success
            && tt == "MPTokenIssuanceCreate"
            && let Some(id) = created_mpt_issuance(&m)
        {
            m.insert("mpt_issuance_id".into(), json!(id));
        }
        if success && nft {
            nft_synthetic(&tt, &t, &mut m);
        }
        if ctid && let Some(c) = self.ctid(seq, index) {
            t.insert("ctid".into(), json!(c));
        }
        Ok(Expanded {
            tx: t,
            meta: m,
            index,
        })
    }

    pub(crate) fn ctid(&self, seq: u32, index: u32) -> Option<String> {
        if seq > 0x0FFF_FFFF || index > 0xFFFF || self.network_id > 0xFFFF {
            return None;
        }
        let v = ((0xC000_0000u64 + u64::from(seq)) << 32)
            + (u64::from(index) << 16)
            + u64::from(self.network_id);
        Some(format!("{v:016X}"))
    }

    pub fn handle(&self, method: &str, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let api = api_version(p)?;
        match method {
            "ping" => Ok(Map::new()),
            "server_info" => self.server_info(),
            "ledger" => self.ledger_rpc(p, api),
            "tx" => self.tx(p, api),
            "account_tx" => self.account_tx(p, api),
            "ledger_entry" => self.ledger_entry(p),
            "account_info" => self.account_info(p, api),
            "account_objects" => self.account_objects(p),
            "account_lines" => self.account_lines(p),
            "account_offers" => self.account_offers(p),
            "mpt_holders" => self.mpt_holders(p),
            "ledger_data" => self.ledger_data(p, api),
            "book_changes" => self.book_changes(p),
            "proof_ledger" => self.proof_ledger(p),
            "proof_tx" => self.proof_tx(p),
            "proof_entry" => self.proof_entry(p),
            _ => Err(rpc_err("unknownCmd", 32, "Unknown method.")),
        }
    }

    fn server_info(&self) -> Res<Map<String, Value>> {
        let (min, max) = self.range()?;
        let (_, h) = self.header(max)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let age = (now - RIPPLE_EPOCH - i64::from(h.close_time)).max(0);
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_micros())
            .unwrap_or(0);
        let mut validated = json!({
            "age": age,
            "hash": hex::encode_upper(h.hash()),
            "seq": max,
        });
        // Fees and reserves come from the FeeSettings object.
        if let Some((base, reserve, inc)) = self.fee_drops(max)? {
            validated["base_fee_xrp"] = json!(base as f64 / 1e6);
            validated["reserve_base_xrp"] = json!(reserve as f64 / 1e6);
            validated["reserve_inc_xrp"] = json!(inc as f64 / 1e6);
        }
        let mut info = json!({
            "complete_ledgers": format!("{min}-{max}"),
            "load_factor": 1,
            "astraea_version": env!("CARGO_PKG_VERSION"),
            "network_id": self.network_id,
            "uptime": self.started.elapsed().as_secs(),
            "time": time_human((now - RIPPLE_EPOCH).max(0) as u32)
                .replace(".000000000", &format!(".{micros:06}")),
            "validated_ledger": validated,
            // Our own: what is loaded and how much of it is confirmed by quorum.
            "astraea": {
                "loaded_ledger": self.state.last().map_err(internal)?,
                "confirmed_ledger": max,
                "confirmation_rule": "full-unl",
                "state_root_checked": true,
            },
        });
        if let Some(q) = self.quorum_at(max, &h.hash()) {
            info["validation_quorum"] = json!(q);
        }
        let mut m = Map::new();
        m.insert("info".into(), info);
        m.insert("validated".into(), json!(true));
        Ok(m)
    }

    /// Fee and reserves for the ledger from FeeSettings, in drops: base
    /// fee, account reserve, owner reserve. Fields after XRPFees are
    /// BaseFeeDrops and the rest; before it, BaseFee (hex) and ReserveBase/Increment.
    pub(crate) fn fee_drops(&self, seq: u32) -> Res<Option<(u64, u64, u64)>> {
        let Some(fees) = self.state.get(&keylet(b'e', &[]), seq).map_err(internal)? else {
            return Ok(None);
        };
        let Ok(Value::Object(f)) = xrpl_json::object(definitions(), &fees) else {
            return Ok(None);
        };
        let drops = |k: &str, old: &str| {
            f.get(k)
                .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                .or_else(|| f.get(old).and_then(Value::as_u64))
                .or_else(|| {
                    f.get(old)
                        .and_then(|v| v.as_str())
                        .and_then(|s| u64::from_str_radix(s, 16).ok())
                })
        };
        Ok(
            match (
                drops("BaseFeeDrops", "BaseFee"),
                drops("ReserveBaseDrops", "ReserveBase"),
                drops("ReserveIncrementDrops", "ReserveIncrement"),
            ) {
                (Some(b), Some(r), Some(i)) => Some((b, r, i)),
                _ => None,
            },
        )
    }

    /// UNL quorum per ledger: server_info is requested often, and deciding from
    /// validations isn't cheap, so it's done once per ledger.
    fn quorum_at(&self, seq: u32, hash: &[u8; 32]) -> Option<usize> {
        let c = self.confirmer.as_ref()?;
        let mut g = self.quorum.lock().unwrap_or_else(|p| p.into_inner());
        if g.0 != seq {
            *g = (seq, c.check(seq, hash).quorum);
        }
        (g.1 > 0).then_some(g.1)
    }

    fn ledger_rpc(&self, p: &Map<String, Value>, api: u32) -> Res<Map<String, Value>> {
        let seq = self.resolve(p)?;
        let (raw, h) = self.header(seq)?;
        let binary = as_bool(p.get("binary"));
        let mut header = self.header_json(&raw, &h, binary, api);
        if as_bool(p.get("transactions")) {
            let l = self.ledger(seq)?;
            // Clio returns a ledger's transactions in hash order.
            let mut txs: Vec<(String, &[u8], &[u8])> = l
                .transactions
                .iter()
                .map(|(t, m)| {
                    (
                        hex::encode_upper(witness_core::shamap::tx_id(t)),
                        &t[..],
                        &m[..],
                    )
                })
                .collect();
            txs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = Vec::with_capacity(txs.len());
            for (hash, tx, meta) in txs {
                crate::limits::check_rpc()?;
                if !as_bool(p.get("expand")) {
                    out.push(json!(hash));
                    continue;
                }
                let e = self.expand(tx, meta, seq, api, false, false)?;
                let mut entry = Map::new();
                if api < 2 {
                    if binary {
                        entry.insert("meta".into(), json!(hex::encode_upper(meta)));
                        entry.insert("tx_blob".into(), json!(hex::encode_upper(tx)));
                    } else {
                        entry = e.tx;
                        entry.insert("metaData".into(), Value::Object(e.meta));
                    }
                } else if binary {
                    entry.insert("meta_blob".into(), json!(hex::encode_upper(meta)));
                    entry.insert("tx_blob".into(), json!(hex::encode_upper(tx)));
                    entry.insert("hash".into(), json!(hash));
                } else {
                    let mut t = e.tx;
                    t.remove("hash");
                    entry.insert("validated".into(), json!(true));
                    entry.insert("ledger_index".into(), json!(seq));
                    entry.insert("close_time_iso".into(), json!(time_iso(h.close_time)));
                    entry.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
                    entry.insert("hash".into(), json!(hash));
                    entry.insert("tx_json".into(), Value::Object(t));
                    entry.insert("meta".into(), Value::Object(e.meta));
                }
                out.push(Value::Object(entry));
            }
            header.insert("transactions".into(), Value::Array(out));
        }
        let mut m = Map::new();
        m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("validated".into(), json!(true));
        m.insert("ledger".into(), Value::Object(header));
        Ok(m)
    }

    fn book_changes(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let seq = self.resolve(p)?;
        let (_, h) = self.header(seq)?;
        let l = self.ledger(seq)?;
        let mut m = Map::new();
        m.insert("type".into(), json!("bookChanges"));
        m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("ledger_time".into(), json!(h.close_time));
        m.insert("validated".into(), json!(true));
        m.insert(
            "changes".into(),
            Value::Array(crate::bookchanges::compute(&l.transactions)),
        );
        Ok(m)
    }

    fn tx(&self, p: &Map<String, Value>, api: u32) -> Res<Map<String, Value>> {
        let (seq, pos) = match (p.get("transaction"), p.get("ctid")) {
            (Some(_), Some(_)) | (None, None) => return Err(invalid_params("Invalid parameters.")),
            (Some(t), None) => {
                let id = t
                    .as_str()
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or_else(|| rpc_err("notImpl", 74, "Not implemented."))?;
                match self.state.tx_location(&id).map_err(internal)? {
                    Some(at) => at,
                    None => self
                        .cold_tx(&id)?
                        .ok_or_else(|| rpc_err("txnNotFound", 29, "Transaction not found."))?,
                }
            }
            (None, Some(c)) => {
                let v = c
                    .as_str()
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .filter(|v| v >> 60 == 0xC)
                    .ok_or_else(|| invalid_params("Invalid parameters."))?;
                let seq = ((v >> 32) & 0x0FFF_FFFF) as u32;
                let index = ((v >> 16) & 0xFFFF) as u32;
                let net = (v & 0xFFFF) as u32;
                if net != self.network_id {
                    return Err(rpc_err(
                        "wrongNetwork",
                        4,
                        format!(
                            "Wrong network. You should submit this request to a node running on NetworkID: {net}"
                        ),
                    ));
                }
                let l = self
                    .ledger(seq)
                    .map_err(|_| rpc_err("txnNotFound", 29, "Transaction not found."))?;
                let pos = l
                    .transactions
                    .iter()
                    .position(|(_, m)| {
                        xrpl_json::metadata(m)
                            .ok()
                            .and_then(|m| m.get("TransactionIndex").and_then(Value::as_u64))
                            == Some(u64::from(index))
                    })
                    .ok_or_else(|| rpc_err("txnNotFound", 29, "Transaction not found."))?;
                (seq, pos as u32)
            }
        };
        let (min, max) = self.range()?;
        if seq < min || seq > max {
            return Err(rpc_err("txnNotFound", 29, "Transaction not found."));
        }
        let l = self.ledger(seq)?;
        let (tx, meta) = l
            .transactions
            .get(pos as usize)
            .ok_or_else(|| internal("no transaction at this position".into()))?;
        let (_, h) = self.header(seq)?;
        let e = self.expand(tx, meta, seq, api, true, true)?;
        let ctid = self.ctid(seq, e.index);
        let hash = e.tx.get("hash").cloned().unwrap_or(Value::Null);
        let binary = as_bool(p.get("binary"));
        let mut m = Map::new();
        if api < 2 {
            if binary {
                m.insert("meta".into(), json!(hex::encode_upper(meta)));
                m.insert("tx".into(), json!(hex::encode_upper(tx)));
                m.insert("hash".into(), hash);
            } else {
                m = e.tx;
                m.insert("meta".into(), Value::Object(e.meta));
            }
            m.insert("validated".into(), json!(true));
            m.insert("date".into(), json!(h.close_time));
            m.insert("ledger_index".into(), json!(seq));
            m.insert("inLedger".into(), json!(seq));
        } else {
            if binary {
                m.insert("meta_blob".into(), json!(hex::encode_upper(meta)));
                m.insert("tx_blob".into(), json!(hex::encode_upper(tx)));
                m.insert("hash".into(), hash);
            } else {
                let mut t = e.tx;
                t.insert("date".into(), json!(h.close_time));
                if let Some(c) = &ctid {
                    t.insert("ctid".into(), json!(c));
                }
                t.insert("ledger_index".into(), json!(seq));
                if let Some(hv) = t.remove("hash") {
                    m.insert("hash".into(), hv);
                }
                m.insert("tx_json".into(), Value::Object(t));
                m.insert("meta".into(), Value::Object(e.meta));
            }
            m.insert("validated".into(), json!(true));
            m.insert("ledger_index".into(), json!(seq));
            m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
            m.insert("close_time_iso".into(), json!(time_iso(h.close_time)));
        }
        if let Some(c) = ctid {
            m.insert("ctid".into(), json!(c));
        }
        Ok(m)
    }

    /// Transaction by hash in cold history: XTXH candidates are checked by
    /// recomputing the hash.
    pub(crate) fn cold_tx(&self, id: &[u8; 32]) -> Res<Option<(u32, u32)>> {
        for (seq, pos) in self
            .blocks
            .cold_index()
            .tx_candidates(id)
            .map_err(internal)?
        {
            if let Some(l) = self.blocks.get_txs(seq).map_err(internal)?
                && l.transactions
                    .get(pos as usize)
                    .is_some_and(|(t, _)| witness_core::shamap::tx_id(t) == *id)
            {
                return Ok(Some((seq, pos)));
            }
        }
        Ok(None)
    }

    /// Account history positions in [min, max] starting from `start` (inclusive):
    /// the hot part uses fjall indexes, deeper ones use cold indexes, and a page
    /// continues across the boundary. Cold entries have u32::MAX as the position in the ledger.
    fn account_positions(
        &self,
        account: &[u8; 20],
        min: u32,
        max: u32,
        forward: bool,
        take: usize,
        start: Option<TxPosition>,
    ) -> Res<Vec<AccountTx>> {
        let hot_first = self.hot_first()?;
        let cold_max = hot_first.checked_sub(1);
        let mut out = Vec::new();
        let cold = |lo: TxPosition, hi: TxPosition, n: usize| -> Res<Vec<AccountTx>> {
            Ok(self
                .blocks
                .cold_index()
                .account_tx(account, lo, hi, forward, n)
                .map_err(internal)?
                .into_iter()
                .map(|at| AccountTx { at, pos: u32::MAX })
                .collect())
        };
        let hot = |n: usize, s: Option<TxPosition>| -> Res<Vec<AccountTx>> {
            Ok(self
                .state
                .account_tx(account, min.max(hot_first), max, forward, n, s)
                .map_err(internal)?
                .transactions)
        };
        let lowest = TxPosition {
            ledger: min,
            index: 0,
        };
        let cold_top = cold_max.map(|c| TxPosition {
            ledger: max.min(c),
            index: u32::MAX,
        });
        if forward {
            if let Some(top) = cold_top
                && min <= top.ledger
                && start.is_none_or(|s| s <= top)
            {
                out.extend(cold(start.unwrap_or(lowest).max(lowest), top, take)?);
            }
            if out.len() < take && max >= hot_first {
                out.extend(hot(
                    take - out.len(),
                    start.filter(|s| s.ledger >= hot_first),
                )?);
            }
        } else {
            if max >= hot_first && start.is_none_or(|s| s.ledger >= hot_first) {
                out.extend(hot(take, start)?);
            }
            if out.len() < take
                && let Some(top) = cold_top
                && min <= top.ledger
            {
                let hi = start.filter(|s| *s <= top).unwrap_or(top);
                out.extend(cold(lowest, hi, take - out.len())?);
            }
        }
        Ok(out)
    }

    fn account_tx(&self, p: &Map<String, Value>, api: u32) -> Res<Map<String, Value>> {
        let account = account_id(
            p.get("account")
                .ok_or_else(|| invalid_params("Required field 'account' missing"))?,
        )?;
        let (range_min, range_max) = self.range()?;
        let (mut min, mut max) = (range_min, range_max);
        let bound = |k: &str| -> Res<Option<u32>> {
            match p.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => match v.as_i64() {
                    Some(-1) => Ok(None),
                    Some(n) => u32::try_from(n)
                        .map(Some)
                        .map_err(|_| invalid_params("Invalid parameters.")),
                    None => Err(invalid_params("Invalid parameters.")),
                },
            }
        };
        let (lo, hi) = (bound("ledger_index_min")?, bound("ledger_index_max")?);
        if let Some(lo) = lo {
            if api > 1 && (lo > range_max || lo < range_min) {
                return Err(rpc_err("lgrIdxMalformed", 58, "ledgerSeqMinOutOfRange"));
            }
            min = min.max(lo);
        }
        if let Some(hi) = hi {
            if api > 1 && (hi > range_max || hi < range_min) {
                return Err(rpc_err("lgrIdxMalformed", 58, "ledgerSeqMaxOutOfRange"));
            }
            max = max.min(hi);
        }
        if min > max {
            return Err(if api == 1 {
                rpc_err("lgrIdxsInvalid", 57, "Ledger indexes invalid.")
            } else {
                rpc_err("invalidLgrRange", 79, "Ledger range is invalid.")
            });
        }
        if p.contains_key("ledger_hash") || p.contains_key("ledger_index") {
            if api > 1 && (lo.is_some() || hi.is_some()) {
                return Err(invalid_params("containsLedgerSpecifierAndRange"));
            }
            if lo.is_none() && hi.is_none() {
                let seq = self.resolve(p)?;
                (min, max) = (seq, seq);
            }
        }
        let forward = as_bool(p.get("forward"));
        let limit = match p.get("limit") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_u64()
                    .filter(|n| *n >= 1)
                    .ok_or_else(|| invalid_params("Invalid parameters."))? as usize,
            ),
        };
        let take = limit
            .unwrap_or(ACCOUNT_TX_LIMIT_DEFAULT)
            .clamp(1, ACCOUNT_TX_LIMIT_MAX);
        // Clio's marker is the position of the last returned transaction: the next
        // page starts strictly after it.
        let after = match p.get("marker") {
            None | Some(Value::Null) => None,
            Some(Value::Object(mk)) => {
                let ledger = mk
                    .get("ledger")
                    .and_then(as_u32)
                    .ok_or_else(|| invalid_params("Invalid parameters."))?;
                let seq = mk
                    .get("seq")
                    .and_then(as_u32)
                    .ok_or_else(|| invalid_params("Invalid parameters."))?;
                Some(TxPosition { ledger, index: seq })
            }
            Some(_) => return Err(invalid_params("Invalid parameters.")),
        };
        // The next position after marker. There may be none if marker is right at
        // the edge: then the page is empty rather than starting over.
        let start = after.map(|a| after_marker(a, forward));
        let page = match start {
            Some(None) => crate::state::AccountTxPage {
                transactions: Vec::new(),
                marker: None,
            },
            start => crate::state::AccountTxPage {
                transactions: self.account_positions(
                    &account,
                    min,
                    max,
                    forward,
                    take,
                    start.flatten(),
                )?,
                marker: None,
            },
        };
        let binary = as_bool(p.get("binary"));
        // Cold transactions of the page are read up front, block by block in
        // parallel, and only those: a ledger's other transactions are not decoded.
        let hot_first = self.hot_first()?;
        let wants: Vec<(u32, u32)> = page
            .transactions
            .iter()
            .filter(|t| t.at.ledger < hot_first && t.pos == u32::MAX)
            .map(|t| (t.at.ledger, t.at.index))
            .collect();
        let mut cold = self.blocks.cold_transactions(&wants).map_err(internal)?;
        let mut out = Vec::with_capacity(page.transactions.len());
        let mut cache: Option<(u32, Ledger)> = None;
        for t in &page.transactions {
            crate::limits::check_rpc()?;
            if cache.as_ref().is_none_or(|(s, _)| *s != t.at.ledger) {
                let l = match cold.remove(&t.at.ledger) {
                    Some(l) => l,
                    None => self.ledger(t.at.ledger)?,
                };
                cache = Some((t.at.ledger, l));
            }
            let Some((_, l)) = &cache else { continue };
            // Cold indexes don't know the position in the ledger, so look it up by
            // TransactionIndex.
            let pos = if t.pos == u32::MAX {
                l.transactions
                    .iter()
                    .position(|(_, m)| tx_index_of(m) == Some(t.at.index))
                    .ok_or_else(|| internal("no transaction with this TransactionIndex".into()))?
            } else {
                t.pos as usize
            };
            let (tx, meta) = l
                .transactions
                .get(pos)
                .ok_or_else(|| internal("no transaction at this position".into()))?;
            let mut obj = Map::new();
            if binary {
                obj.insert(
                    if api > 1 { "meta_blob" } else { "meta" }.into(),
                    json!(hex::encode_upper(meta)),
                );
                obj.insert("tx_blob".into(), json!(hex::encode_upper(tx)));
                obj.insert("validated".into(), json!(true));
                obj.insert("ledger_index".into(), json!(t.at.ledger));
                out.push(Value::Object(obj));
                continue;
            }
            let e = self.expand(tx, meta, t.at.ledger, api, false, true)?;
            let mut tj = e.tx;
            if let Some(c) = self.ctid(t.at.ledger, e.index) {
                tj.insert("ctid".into(), json!(c));
            }
            // The header comes with the ledger already read for this page.
            let h = LedgerHeader::parse(&l.header).map_err(|e| internal(e.to_string()))?;
            tj.insert("date".into(), json!(h.close_time));
            tj.insert("ledger_index".into(), json!(t.at.ledger));
            if api < 2 {
                tj.insert("inLedger".into(), json!(t.at.ledger));
            } else {
                obj.insert("ledger_index".into(), json!(t.at.ledger));
                if let Some(hv) = tj.remove("hash") {
                    obj.insert("hash".into(), hv);
                }
                obj.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
                obj.insert("close_time_iso".into(), json!(time_iso(h.close_time)));
            }
            obj.insert("meta".into(), Value::Object(e.meta));
            obj.insert(
                if api < 2 { "tx" } else { "tx_json" }.into(),
                Value::Object(tj),
            );
            obj.insert("validated".into(), json!(true));
            out.push(Value::Object(obj));
        }
        let mut m = Map::new();
        m.insert("account".into(), json!(xrpl_json::account(&account)));
        m.insert("ledger_index_min".into(), json!(min));
        m.insert("ledger_index_max".into(), json!(max));
        // Full page: marker points to the last returned one, as in Clio.
        if page.transactions.len() == take
            && let Some(last) = page.transactions.last()
        {
            m.insert(
                "marker".into(),
                json!({ "ledger": last.at.ledger, "seq": last.at.index }),
            );
        }
        m.insert("transactions".into(), Value::Array(out));
        m.insert("validated".into(), json!(true));
        if let Some(l) = limit {
            m.insert("limit".into(), json!(l.clamp(1, ACCOUNT_TX_LIMIT_MAX)));
        }
        Ok(m)
    }

    fn ledger_entry(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let (key, expected) = crate::selector::entry_key(p)?;
        let seq = self.resolve_state(p)?;
        let (_, h) = self.header(seq)?;
        let not_found = || rpc_err("entryNotFound", 98, "Entry not found.");
        // include_deleted, as in Clio: a deleted object as it was in the
        // ledger before the one that deleted it.
        let base = self.state.base().map_err(internal)?.unwrap_or(u32::MAX);
        let (data, deleted) = match self.state.version(&key, seq).map_err(internal)? {
            Some((_, v)) if !v.is_empty() => (v, None),
            Some((at, _)) if as_bool(p.get("include_deleted")) && at > base => {
                let v = self
                    .state
                    .get(&key, at - 1)
                    .map_err(internal)?
                    .ok_or_else(not_found)?;
                (v, Some(at))
            }
            _ => return Err(not_found()),
        };
        let mut node = xrpl_json::ledger_entry(&key, &data).map_err(internal)?;
        if let Some(t) = expected
            && node.get("LedgerEntryType").and_then(Value::as_str) != Some(t)
        {
            return Err(rpc_err(
                "unexpectedLedgerType",
                37,
                "Unexpected ledger type.",
            ));
        }
        gravatar(&mut node);
        let mut m = Map::new();
        m.insert("index".into(), json!(hex::encode_upper(key)));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
        if let Some(at) = deleted {
            m.insert("deleted_ledger_index".into(), json!(at));
        }
        if as_bool(p.get("binary")) {
            m.insert("node_binary".into(), json!(hex::encode_upper(&data)));
        } else {
            m.insert("node".into(), Value::Object(node));
        }
        m.insert("validated".into(), json!(true));
        Ok(m)
    }

    fn account_info(&self, p: &Map<String, Value>, api: u32) -> Res<Map<String, Value>> {
        let v = p
            .get("account")
            .or_else(|| p.get("ident"))
            .ok_or_else(|| invalid_params("Missing field 'account'."))?;
        let seq = self.resolve_state(p)?;
        let a = account_id(v)?;
        let (_, h) = self.header(seq)?;
        let key = keylet(b'a', &[&a]);
        let data = self
            .state
            .get(&key, seq)
            .map_err(internal)?
            .ok_or_else(|| rpc_err("actNotFound", 19, "Account not found."))?;
        let mut node = xrpl_json::ledger_entry(&key, &data).map_err(internal)?;
        gravatar(&mut node);
        let flags = node.get("Flags").and_then(Value::as_u64).unwrap_or(0);
        const FLAGS: [(&str, u64); 15] = [
            ("defaultRipple", 0x0080_0000),
            ("depositAuth", 0x0100_0000),
            ("disableMasterKey", 0x0010_0000),
            ("disallowIncomingXRP", 0x0008_0000),
            ("globalFreeze", 0x0040_0000),
            ("noFreeze", 0x0020_0000),
            ("passwordSpent", 0x0001_0000),
            ("requireAuthorization", 0x0004_0000),
            ("requireDestinationTag", 0x0002_0000),
            ("disallowIncomingNFTokenOffer", 0x0400_0000),
            ("disallowIncomingCheck", 0x0800_0000),
            ("disallowIncomingPayChan", 0x1000_0000),
            ("disallowIncomingTrustline", 0x2000_0000),
            ("allowTrustLineClawback", 0x8000_0000),
            ("allowTrustLineLocking", 0x4000_0000),
        ];
        let account_flags: Map<String, Value> = FLAGS
            .iter()
            .map(|(n, f)| ((*n).to_owned(), json!(flags & f != 0)))
            .collect();
        let pseudo = ["AMMID", "VaultID", "LoanBrokerID"]
            .iter()
            .find(|f| node.contains_key(**f))
            .map(|f| f.trim_end_matches("ID").to_owned());
        let mut m = Map::new();
        let signers = if as_bool(p.get("signer_lists")) {
            let k = keylet(b'S', &[&a, &0u32.to_be_bytes()]);
            let mut list = Vec::new();
            if let Some(d) = self.state.get(&k, seq).map_err(internal)? {
                list.push(Value::Object(
                    xrpl_json::ledger_entry(&k, &d).map_err(internal)?,
                ));
            }
            Some(Value::Array(list))
        } else {
            None
        };
        if api == 1
            && let Some(s) = &signers
        {
            node.insert("signer_lists".into(), s.clone());
        }
        m.insert("account_data".into(), Value::Object(node));
        m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("validated".into(), json!(true));
        m.insert("account_flags".into(), Value::Object(account_flags));
        if let Some(t) = pseudo {
            m.insert("pseudo_account".into(), json!({ "type": t }));
        }
        if api > 1
            && let Some(s) = signers
        {
            m.insert("signer_lists".into(), s);
        }
        Ok(m)
    }
}

/// The position right after an account_tx marker in the walk direction; `None` means
/// there is nothing further.
/// TransactionIndex from metadata.
fn tx_index_of(meta: &[u8]) -> Option<u32> {
    use witness_core::stobject::{self, FieldId, types};
    // Canonical metadata starts with TransactionIndex (UInt32 is the lowest
    // type in it): header 0x20 0x1C, then the value. Parsing all fields walks
    // AffectedNodes, and a cold account_tx page does that for every
    // transaction of every ledger it reads. Anything else is parsed in full.
    if let [0x20, 0x1C, a, b, c, d, ..] = *meta {
        return Some(u32::from_be_bytes([a, b, c, d]));
    }
    let fs = stobject::fields(meta).ok()?;
    stobject::find(&fs, FieldId::new(types::UINT32, 28)).and_then(stobject::u32_of)
}

fn after_marker(a: TxPosition, forward: bool) -> Option<TxPosition> {
    if forward {
        match a.index.checked_add(1) {
            Some(i) => Some(TxPosition {
                ledger: a.ledger,
                index: i,
            }),
            None => a.ledger.checked_add(1).map(|l| TxPosition {
                ledger: l,
                index: 0,
            }),
        }
    } else if a.index > 0 {
        Some(TxPosition {
            ledger: a.ledger,
            index: a.index - 1,
        })
    } else {
        a.ledger.checked_sub(1).map(|l| TxPosition {
            ledger: l,
            index: u32::MAX,
        })
    }
}

/// Clio adds a Gravatar link to an AccountRoot with EmailHash.
pub(crate) fn gravatar(node: &mut Map<String, Value>) {
    if node.get("LedgerEntryType").and_then(Value::as_str) == Some("AccountRoot")
        && let Some(h) = node.get("EmailHash").and_then(Value::as_str)
    {
        let url = format!("http://www.gravatar.com/avatar/{}", h.to_lowercase());
        node.insert("urlgravatar".into(), json!(url));
    }
}

/// Currency code from a request: a three-letter ISO code or 40 hex chars.
pub(crate) fn currency_code(s: &str) -> Option<[u8; 20]> {
    let mut c = [0u8; 20];
    if s.len() == 3 {
        if s == "XRP" {
            return Some(c);
        }
        c[12..15].copy_from_slice(s.as_bytes());
        return Some(c);
    }
    hex::decode(s)
        .ok()
        .and_then(|b| <[u8; 20]>::try_from(b).ok())
}

fn affected(meta: &Map<String, Value>) -> impl Iterator<Item = (&str, &Map<String, Value>)> {
    meta.get("AffectedNodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|n| n.as_object()?.iter().next())
        .filter_map(|(k, v)| Some((k.as_str(), v.as_object()?)))
}

fn nft_ids(fields: Option<&Value>) -> Vec<String> {
    fields
        .and_then(|f| f.get("NFTokens"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| {
            t.get("NFToken")?
                .get("NFTokenID")?
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

/// MPTID of the issuance created by a transaction: sequence and issuer.
fn created_mpt_issuance(meta: &Map<String, Value>) -> Option<String> {
    for (kind, node) in affected(meta) {
        if kind != "CreatedNode"
            || node.get("LedgerEntryType").and_then(Value::as_str) != Some("MPTokenIssuance")
        {
            continue;
        }
        let f = node.get("NewFields")?;
        let seq = u32::try_from(f.get("Sequence")?.as_u64()?).ok()?;
        let issuer = decode_base58(f.get("Issuer")?.as_str()?)?.1;
        let mut id = seq.to_be_bytes().to_vec();
        id.extend(issuer);
        return Some(hex::encode_upper(id));
    }
    None
}

/// Synthetic NFT fields in metadata, like insertNFTSyntheticInJson
/// in xrpld: nftoken_id, nftoken_ids, offer_id.
fn nft_synthetic(tt: &str, tx: &Map<String, Value>, meta: &mut Map<String, Value>) {
    let deleted_offers = |meta: &Map<String, Value>| {
        let mut ids: Vec<String> = affected(meta)
            .filter(|(k, n)| {
                *k == "DeletedNode"
                    && n.get("LedgerEntryType").and_then(Value::as_str) == Some("NFTokenOffer")
            })
            .filter_map(|(_, n)| {
                n.get("FinalFields")?
                    .get("NFTokenID")?
                    .as_str()
                    .map(str::to_owned)
            })
            .collect();
        ids.sort();
        ids.dedup();
        ids
    };
    match tt {
        "NFTokenMint" => {
            let (mut prev, mut fin) = (Vec::new(), Vec::new());
            for (kind, n) in affected(meta) {
                if n.get("LedgerEntryType").and_then(Value::as_str) != Some("NFTokenPage") {
                    continue;
                }
                if kind == "CreatedNode" {
                    fin.extend(nft_ids(n.get("NewFields")));
                } else if kind == "ModifiedNode" {
                    let pf = n.get("PreviousFields");
                    if pf.and_then(|p| p.get("NFTokens")).is_none() {
                        continue;
                    }
                    prev.extend(nft_ids(pf));
                    fin.extend(nft_ids(n.get("FinalFields")));
                }
            }
            if fin.len() == prev.len() + 1 {
                let id = fin
                    .iter()
                    .zip(prev.iter().map(Some).chain(std::iter::once(None)))
                    .find(|(f, p)| p.is_none_or(|p| p != *f))
                    .map(|(f, _)| f.clone());
                if let Some(id) = id {
                    meta.insert("nftoken_id".into(), json!(id));
                }
            }
        }
        "NFTokenAcceptOffer" => {
            if let Some(id) = deleted_offers(meta).into_iter().next() {
                meta.insert("nftoken_id".into(), json!(id));
            }
        }
        "NFTokenCancelOffer" => {
            let ids = deleted_offers(meta);
            meta.insert("nftoken_ids".into(), json!(ids));
        }
        _ => {}
    }
    if tt == "NFTokenCreateOffer" || (tt == "NFTokenMint" && tx.contains_key("Amount")) {
        let id = affected(meta)
            .find(|(k, n)| {
                *k == "CreatedNode"
                    && n.get("LedgerEntryType").and_then(Value::as_str) == Some("NFTokenOffer")
            })
            .and_then(|(_, n)| n.get("LedgerIndex")?.as_str().map(str::to_owned));
        if let Some(id) = id {
            meta.insert("offer_id".into(), json!(id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_index_read_from_the_header_matches_a_full_parse() {
        use witness_core::stobject::{self, FieldId, types};
        let full = |m: &[u8]| {
            stobject::find(
                &stobject::fields(m).unwrap(),
                FieldId::new(types::UINT32, 28),
            )
            .and_then(stobject::u32_of)
        };
        // TransactionIndex 7, TransactionResult tesSUCCESS, empty AffectedNodes.
        let meta = [0x20, 0x1C, 0, 0, 0, 7, 0x03, 0x10, 0x00, 0xF8, 0xF1];
        assert_eq!(tx_index_of(&meta), Some(7));
        assert_eq!(tx_index_of(&meta), full(&meta));
        // Without TransactionIndex up front the full parse decides.
        let other = [0x03, 0x10, 0x00, 0xF8, 0xF1];
        assert_eq!(tx_index_of(&other), full(&other));
        assert_eq!(tx_index_of(&other), None);
        assert_eq!(tx_index_of(&[0x20, 0x1C, 0]), None);
    }

    #[test]
    fn marker_at_the_edges() {
        let p = |ledger, index| TxPosition { ledger, index };
        assert_eq!(after_marker(p(5, 7), true), Some(p(5, 8)));
        assert_eq!(after_marker(p(5, u32::MAX), true), Some(p(6, 0)));
        assert_eq!(after_marker(p(u32::MAX, u32::MAX), true), None);
        assert_eq!(after_marker(p(5, 0), false), Some(p(4, u32::MAX)));
        assert_eq!(after_marker(p(0, 0), false), None);
    }

    #[test]
    fn times_render_like_xrpld() {
        // 846178792 is the close time of ledger 107876000.
        assert_eq!(time_iso(846_178_792), "2026-10-24T17:39:52Z");
        assert_eq!(
            time_human(846_178_792),
            "2026-Oct-24 17:39:52.000000000 UTC"
        );
        assert_eq!(time_iso(0), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn account_keylet() {
        // AccountRoot rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq: index from a Clio response.
        let a = account_id(&json!("rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq")).unwrap();
        assert_eq!(
            hex::encode_upper(keylet(b'a', &[&a])),
            "BF1F2A23D614916E3C6ED2DCC389468CFA09045BEDB54C71A05C5E94EA6C6CFE"
        );
    }
}
