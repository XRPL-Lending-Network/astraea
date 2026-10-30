//! NFT methods, as in Clio 2.8. account_nfts, nft_buy_offers and
//! nft_sell_offers read the ledger state; nft_info, nft_history and
//! nfts_by_issuer read the NFT index (`nftindex`, kept in the state store),
//! and answer `notReady` until its backfill is done.
//!
//! account_nfts walks the account's NFT pages from the last one down through
//! `PreviousPageMin`; `limit` counts pages, and the marker is the key of the
//! next page. The offer methods walk the token's buy or sell offer directory
//! like the owner directory; their marker is the key of the first offer of
//! the next page, and that offer comes back as the first one of the page.

use serde_json::{Map, Value, json};

use crate::api::{
    Engine, Res, RpcError, account_id, decode_account, internal, invalid_params, keylet, rpc_err,
    time_iso,
};
use crate::owned::{corrupt, h256};
use crate::state::{AccountTx, TxPosition};
use crate::xrpl_json;

const NFTS_LIMIT_MIN: u32 = 20;
const NFTS_LIMIT_MAX: u32 = 400;
const NFTS_LIMIT_DEFAULT: u32 = 100;
const OFFERS_LIMIT_MIN: u32 = 50;
const OFFERS_LIMIT_MAX: u32 = 500;
const OFFERS_LIMIT_DEFAULT: u32 = 250;
const HISTORY_LIMIT_MAX: u32 = 100;
const HISTORY_LIMIT_DEFAULT: u32 = 50;
const ISSUER_LIMIT_MAX: u32 = 100;
const ISSUER_LIMIT_DEFAULT: u32 = 50;

/// The parts an NFTokenID is made of.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TokenId {
    pub flags: u16,
    pub transfer_fee: u16,
    pub issuer: [u8; 20],
    pub taxon: u32,
    pub serial: u32,
}

/// Splits an NFTokenID; the taxon is stored ciphered with the serial
/// (xrpld's `cipheredTaxon`), so it is deciphered here.
pub(crate) fn token_id(id: &[u8; 32]) -> TokenId {
    let be16 = |i: usize| u16::from_be_bytes([id[i], id[i + 1]]);
    let be32 = |i: usize| u32::from_be_bytes([id[i], id[i + 1], id[i + 2], id[i + 3]]);
    let serial = be32(28);
    let mut issuer = [0u8; 20];
    issuer.copy_from_slice(&id[4..24]);
    TokenId {
        flags: be16(0),
        transfer_fee: be16(2),
        issuer,
        taxon: be32(24) ^ 384_160_001u32.wrapping_mul(serial).wrapping_add(2459),
        serial,
    }
}

/// `limit` as Clio takes it: an integer of at least 1, clamped to [min, max].
fn limit(p: &Map<String, Value>, min: u32, max: u32, default: u32) -> Res<u32> {
    match p.get("limit") {
        None => Ok(default),
        Some(v) => v
            .as_u64()
            .filter(|n| *n >= 1)
            .and_then(|n| u32::try_from(n).ok())
            .map(|n| n.clamp(min, max))
            .ok_or_else(|| invalid_params("Invalid parameters.")),
    }
}

/// An optional 256-bit hex field, with Clio's errors.
fn hex256(p: &Map<String, Value>, key: &str) -> Res<Option<[u8; 32]>> {
    match p.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => hex::decode(s)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(Some)
            .ok_or_else(|| invalid_params(&format!("{key}Malformed"))),
        Some(_) => Err(invalid_params(&format!("{key}NotString"))),
    }
}

fn entry_type(node: &Map<String, Value>) -> &str {
    node.get("LedgerEntryType")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// One NFToken of a page as account_nfts shows it: the stored fields, then
/// the parts of the ID.
fn token_json(key: &[u8; 32], token: &Value) -> Res<Value> {
    let mut o = token
        .get("NFToken")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| corrupt(key, "NFTokens entry without NFToken"))?;
    let id = o
        .get("NFTokenID")
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| corrupt(key, "NFToken without NFTokenID"))?;
    let t = token_id(&id);
    o.insert("Flags".into(), json!(t.flags));
    o.insert("Issuer".into(), json!(xrpl_json::account(&t.issuer)));
    o.insert("NFTokenTaxon".into(), json!(t.taxon));
    o.insert("nft_serial".into(), json!(t.serial));
    if t.transfer_fee != 0 {
        o.insert("TransferFee".into(), json!(t.transfer_fee));
    }
    Ok(Value::Object(o))
}

/// An offer as nft_buy_offers and nft_sell_offers show it.
fn offer_json(key: &[u8; 32], node: &Map<String, Value>) -> Res<Value> {
    let mut o = Map::new();
    o.insert("nft_offer_index".into(), json!(hex::encode_upper(key)));
    o.insert(
        "flags".into(),
        json!(node.get("Flags").and_then(Value::as_u64).unwrap_or(0)),
    );
    for (out, field) in [("owner", "Owner"), ("amount", "Amount")] {
        let v = node
            .get(field)
            .ok_or_else(|| corrupt(key, &format!("NFTokenOffer without {field}")))?;
        o.insert(out.into(), v.clone());
    }
    if let Some(d) = node.get("Destination") {
        o.insert("destination".into(), d.clone());
    }
    if let Some(e) = node.get("Expiration") {
        o.insert("expiration".into(), e.clone());
    }
    Ok(Value::Object(o))
}

/// A required account field with Clio's `accountValidator` errors.
fn account_field(p: &Map<String, Value>, key: &str) -> Res<[u8; 20]> {
    match p.get(key) {
        None => Err(invalid_params(&format!("Required field '{key}' missing"))),
        Some(Value::String(s)) => {
            decode_account(s).ok_or_else(|| rpc_err("actMalformed", 35, format!("{key}Malformed")))
        }
        Some(_) => Err(invalid_params(&format!("{key}NotString"))),
    }
}

/// An optional field that must be a boolean.
fn bool_field(p: &Map<String, Value>, key: &str) -> Res<bool> {
    match p.get(key) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(invalid_params("Invalid parameters.")),
    }
}

/// `ledger_index_min` or `_max` of nft_history: a 32-bit integer, -1 for none.
fn bound(p: &Map<String, Value>, key: &str) -> Res<Option<u32>> {
    match p.get(key) {
        None => Ok(None),
        Some(v) => match v.as_i64().and_then(|n| i32::try_from(n).ok()) {
            Some(-1) => Ok(None),
            Some(n) => u32::try_from(n)
                .map(Some)
                .map_err(|_| invalid_params("Invalid parameters.")),
            None => Err(invalid_params("Invalid parameters.")),
        },
    }
}

fn not_ready() -> RpcError {
    rpc_err("notReady", 13, "Not ready to handle this request.")
}

/// The fields nft_info and each nfts_by_issuer entry share.
fn token_info(m: &mut Map<String, Value>, id: &[u8; 32]) {
    let t = token_id(id);
    m.insert("flags".into(), json!(t.flags));
    m.insert("transfer_fee".into(), json!(t.transfer_fee));
    m.insert("issuer".into(), json!(xrpl_json::account(&t.issuer)));
    m.insert("nft_taxon".into(), json!(t.taxon));
    m.insert("nft_serial".into(), json!(t.serial));
}

impl Engine {
    /// The NFT index is filled down to its start.
    fn nft_ready(&self) -> Res<()> {
        match self.state.nft_coverage().map_err(internal)? {
            Some(_) => Ok(()),
            None => Err(not_ready()),
        }
    }

    pub(crate) fn nft_info(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let id = hex256(p, "nft_id")?
            .ok_or_else(|| invalid_params("Required field 'nft_id' missing"))?;
        let seq = self.resolve(p)?;
        self.nft_ready()?;
        let (at, owner, burned) = self
            .state
            .nft_at(&id, seq)
            .map_err(internal)?
            .ok_or_else(|| rpc_err("objectNotFound", 92, "NFT not found"))?;
        let uri = self.state.nft_uri_at(&id, seq).map_err(internal)?;
        let mut m = Map::new();
        m.insert("nft_id".into(), json!(hex::encode_upper(id)));
        m.insert("ledger_index".into(), json!(at));
        m.insert("owner".into(), json!(xrpl_json::account(&owner)));
        m.insert("is_burned".into(), json!(burned));
        token_info(&mut m, &id);
        m.insert("validated".into(), json!(true));
        m.insert(
            "uri".into(),
            json!(hex::encode_upper(uri.unwrap_or_default())),
        );
        Ok(m)
    }

    /// Clio's `NFTsByIssuerHandler`: the issuer's tokens by taxon and ID, each
    /// as of the ledger asked; a token minted after it is left out, but still
    /// counts toward the page.
    pub(crate) fn nfts_by_issuer(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let issuer = account_field(p, "issuer")?;
        let taxon = match p.get("nft_taxon") {
            None => None,
            Some(v) => Some(
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| invalid_params("Invalid parameters."))?,
            ),
        };
        let limit = limit(p, 1, ISSUER_LIMIT_MAX, ISSUER_LIMIT_DEFAULT)?;
        let marker = hex256(p, "marker")?;
        let seq = self.resolve_state(p)?;
        if self.fetch(&keylet(b'a', &[&issuer]), seq)?.is_none() {
            return Err(rpc_err("actNotFound", 19, "Account not found."));
        }
        self.nft_ready()?;
        let after = marker.map(|c| (taxon.unwrap_or_else(|| token_id(&c).taxon), c));
        let ids = self
            .state
            .nfts_by_issuer(&issuer, taxon, after, limit as usize)
            .map_err(internal)?;
        let mut nfts = Vec::with_capacity(ids.len());
        for id in &ids {
            crate::limits::check_rpc()?;
            let Some((at, owner, burned)) = self.state.nft_at(id, seq).map_err(internal)? else {
                continue;
            };
            let uri = self.state.nft_uri_at(id, seq).map_err(internal)?;
            let mut n = Map::new();
            n.insert("nft_id".into(), json!(hex::encode_upper(id)));
            n.insert("ledger_index".into(), json!(at));
            n.insert("owner".into(), json!(xrpl_json::account(&owner)));
            n.insert("is_burned".into(), json!(burned));
            n.insert(
                "uri".into(),
                json!(hex::encode_upper(uri.unwrap_or_default())),
            );
            token_info(&mut n, id);
            nfts.push(Value::Object(n));
        }
        let mut m = Map::new();
        m.insert("issuer".into(), json!(xrpl_json::account(&issuer)));
        m.insert("limit".into(), json!(limit));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("nfts".into(), Value::Array(nfts));
        m.insert("validated".into(), json!(true));
        if ids.len() == limit as usize
            && let Some(last) = ids.last()
        {
            m.insert("marker".into(), json!(hex::encode_upper(last)));
        }
        if let Some(t) = taxon {
            m.insert("nft_taxon".into(), json!(t));
        }
        Ok(m)
    }

    /// Clio's `NFTHistoryHandler`. Unlike account_tx, the marker of a
    /// forward page is the position right after the last transaction, and
    /// transactions carry neither ctid nor the synthetic NFT fields.
    pub(crate) fn nft_history(&self, p: &Map<String, Value>, api: u32) -> Res<Map<String, Value>> {
        let id = hex256(p, "nft_id")?
            .ok_or_else(|| invalid_params("Required field 'nft_id' missing"))?;
        let (lo, hi) = (bound(p, "ledger_index_min")?, bound(p, "ledger_index_max")?);
        let binary = bool_field(p, "binary")?;
        let forward = bool_field(p, "forward")?;
        let take = match p.get("limit") {
            None => None,
            Some(_) => Some(limit(p, 1, HISTORY_LIMIT_MAX, HISTORY_LIMIT_DEFAULT)?),
        };
        let marker = match p.get("marker") {
            None => None,
            Some(Value::Object(mk)) => {
                let part = |k: &str| -> Res<u32> {
                    match mk.get(k) {
                        None => Err(invalid_params(&format!("Required field '{k}' missing"))),
                        Some(v) => v
                            .as_u64()
                            .and_then(|n| u32::try_from(n).ok())
                            .ok_or_else(|| invalid_params("Invalid parameters.")),
                    }
                };
                Some(TxPosition {
                    ledger: part("ledger")?,
                    index: part("seq")?,
                })
            }
            Some(_) => return Err(invalid_params("invalidMarker")),
        };
        let (range_min, range_max) = self.range()?;
        let (mut min, mut max) = (range_min, range_max);
        if let Some(lo) = lo {
            if lo > range_max || lo < range_min {
                return Err(rpc_err("lgrIdxMalformed", 58, "ledgerSeqMinOutOfRange"));
            }
            min = lo;
        }
        if let Some(hi) = hi {
            if hi > range_max || hi < range_min {
                return Err(rpc_err("lgrIdxMalformed", 58, "ledgerSeqMaxOutOfRange"));
            }
            max = hi;
        }
        if min > max {
            return Err(rpc_err("lgrIdxsInvalid", 57, "Ledger indexes invalid."));
        }
        // Like Clio, `"validated"` counts as no ledger given.
        let index_given = p
            .get("ledger_index")
            .is_some_and(|v| crate::api::as_u32(v).is_some());
        if p.contains_key("ledger_hash") || index_given {
            if lo.is_some() || hi.is_some() {
                return Err(invalid_params("containsLedgerSpecifierAndRange"));
            }
            let seq = self.resolve(p)?;
            (min, max) = (seq, seq);
        }
        self.nft_ready()?;
        let n = take.unwrap_or(HISTORY_LIMIT_DEFAULT) as usize;
        let cursor = marker.unwrap_or(if forward {
            TxPosition {
                ledger: min,
                index: 0,
            }
        } else {
            TxPosition {
                ledger: max,
                index: i32::MAX as u32,
            }
        });
        // Clio reads positions from the cursor on going forward, and strictly
        // before it going back; the range only cuts the page afterwards.
        let list = if forward {
            let end = TxPosition {
                ledger: u32::MAX,
                index: u32::MAX,
            };
            self.state.nft_txs(&id, cursor, end, true, n)
        } else {
            let end = match (cursor.ledger, cursor.index) {
                (0, 0) => None,
                (l, 0) => Some(TxPosition {
                    ledger: l - 1,
                    index: u32::MAX,
                }),
                (l, i) => Some(TxPosition {
                    ledger: l,
                    index: i - 1,
                }),
            };
            match end {
                Some(e) => self.state.nft_txs(
                    &id,
                    TxPosition {
                        ledger: 0,
                        index: 0,
                    },
                    e,
                    false,
                    n,
                ),
                None => Ok(Vec::new()),
            }
        }
        .map_err(internal)?;
        let mut next = None;
        if list.len() == n
            && let Some(last) = list.last()
        {
            next = Some(if forward {
                TxPosition {
                    ledger: last.at.ledger,
                    index: last.at.index.wrapping_add(1),
                }
            } else {
                last.at
            });
        }
        let mut keep: Vec<AccountTx> = Vec::with_capacity(list.len());
        for t in list {
            if (t.at.ledger < min && !forward) || (t.at.ledger > max && forward) {
                next = None;
                break;
            }
            if t.at.ledger > max && !forward {
                continue;
            }
            keep.push(t);
        }
        let mut out = Vec::with_capacity(keep.len());
        self.txs_at(&keep, &mut |t, tx, meta, h| {
            let mut obj = Map::new();
            if binary {
                obj.insert("tx_blob".into(), json!(hex::encode_upper(tx)));
                obj.insert(
                    if api > 1 { "meta_blob" } else { "meta" }.into(),
                    json!(hex::encode_upper(meta)),
                );
                obj.insert("ledger_index".into(), json!(t.at.ledger));
                obj.insert("date".into(), json!(h.close_time));
            } else {
                let e = self.expand(tx, meta, t.at.ledger, api, false, false)?;
                let mut tj = e.tx;
                tj.insert("ledger_index".into(), json!(t.at.ledger));
                tj.insert("date".into(), json!(h.close_time));
                if api > 1 {
                    obj.insert("ledger_index".into(), json!(t.at.ledger));
                    if let Some(hv) = tj.remove("hash") {
                        obj.insert("hash".into(), hv);
                    }
                    obj.insert("close_time_iso".into(), json!(time_iso(h.close_time)));
                    obj.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
                }
                obj.insert("meta".into(), Value::Object(e.meta));
                obj.insert(
                    if api > 1 { "tx_json" } else { "tx" }.into(),
                    Value::Object(tj),
                );
            }
            obj.insert("validated".into(), json!(true));
            out.push(Value::Object(obj));
            Ok(())
        })?;
        let mut m = Map::new();
        m.insert("nft_id".into(), json!(hex::encode_upper(id)));
        m.insert("ledger_index_min".into(), json!(min));
        m.insert("ledger_index_max".into(), json!(max));
        m.insert("transactions".into(), Value::Array(out));
        m.insert("validated".into(), json!(true));
        if let Some(mk) = next {
            m.insert(
                "marker".into(),
                json!({"ledger": mk.ledger, "seq": mk.index}),
            );
        }
        if let Some(l) = take {
            m.insert("limit".into(), json!(l));
        }
        Ok(m)
    }

    pub(crate) fn account_nfts(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        // Clio checks the fields in this order: account, marker, limit.
        account_id(
            p.get("account")
                .ok_or_else(|| invalid_params("Required field 'account' missing"))?,
        )?;
        let marker = hex256(p, "marker")?;
        let limit = limit(p, NFTS_LIMIT_MIN, NFTS_LIMIT_MAX, NFTS_LIMIT_DEFAULT)?;
        let (account, seq, hash) = self.owner_of(p)?;
        let mut m = Map::new();
        m.insert("ledger_hash".into(), json!(hex::encode_upper(hash)));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("validated".into(), json!(true));
        m.insert("account".into(), p["account"].clone());
        m.insert("limit".into(), json!(limit));
        let mut key = marker.unwrap_or_else(|| {
            let mut last = [0xFFu8; 32];
            last[..20].copy_from_slice(&account);
            last
        });
        let mut nfts = Vec::new();
        let Some(mut data) = self.fetch(&key, seq)? else {
            if marker.is_some() {
                return Err(invalid_params(
                    "Marker field does not match any valid Page ID",
                ));
            }
            m.insert("account_nfts".into(), Value::Array(nfts));
            return Ok(m);
        };
        let mut node = xrpl_json::ledger_entry(&key, &data).map_err(internal)?;
        // Like Clio, only the type of the marker's object is checked, not whose page it is.
        if entry_type(&node) != "NFTokenPage" {
            return Err(invalid_params(
                "Marker matches Page ID from another Account",
            ));
        }
        let mut pages = 0;
        loop {
            crate::limits::check_rpc()?;
            for t in node
                .get("NFTokens")
                .and_then(Value::as_array)
                .ok_or_else(|| corrupt(&key, "NFT page without NFTokens"))?
            {
                nfts.push(token_json(&key, t)?);
            }
            pages += 1;
            let previous = h256(&node, "PreviousPageMin");
            if previous == [0; 32] {
                break;
            }
            if pages == limit {
                m.insert("marker".into(), json!(hex::encode_upper(previous)));
                break;
            }
            data = self.fetch(&previous, seq)?.ok_or_else(|| {
                corrupt(
                    &previous,
                    "PreviousPageMin points to a nonexistent NFT page",
                )
            })?;
            key = previous;
            node = xrpl_json::ledger_entry(&key, &data).map_err(internal)?;
        }
        m.insert("account_nfts".into(), Value::Array(nfts));
        Ok(m)
    }

    pub(crate) fn nft_buy_offers(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        self.nft_offers(p, b'h')
    }

    pub(crate) fn nft_sell_offers(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        self.nft_offers(p, b'i')
    }

    /// Clio's `NFTOffersHandlerBase::iterateOfferDirectory`.
    fn nft_offers(&self, p: &Map<String, Value>, space: u8) -> Res<Map<String, Value>> {
        let id = hex256(p, "nft_id")?
            .ok_or_else(|| invalid_params("Required field 'nft_id' missing"))?;
        let limit = limit(p, OFFERS_LIMIT_MIN, OFFERS_LIMIT_MAX, OFFERS_LIMIT_DEFAULT)?;
        let marker = hex256(p, "marker")?;
        let seq = self.resolve_state(p)?;
        let root = keylet(space, &[&id]);
        if self.fetch(&root, seq)?.is_none() {
            return Err(rpc_err("objectNotFound", 92, "notFound"));
        }
        let mut offers = Vec::new();
        // Without a marker one more offer than the limit is read: it starts
        // the next page. With one, the marker's offer comes first and counts
        // as that extra one.
        let (reserve, after, hint) = match marker {
            Some(k) => {
                let node = self
                    .fetch(&k, seq)?
                    .map(|d| xrpl_json::ledger_entry(&k, &d).map_err(internal))
                    .transpose()?
                    .filter(|n| entry_type(n) == "NFTokenOffer" && h256(n, "NFTokenID") == id)
                    .ok_or_else(|| invalid_params("Invalid parameters."))?;
                // Clio passes the u64 page number on as u32.
                let hint = node
                    .get("NFTokenOfferNode")
                    .and_then(Value::as_str)
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .unwrap_or(0) as u32;
                offers.push((k, node));
                (limit, k, hint)
            }
            None => (limit + 1, [0; 32], 0),
        };
        let (keys, _) = self.dir_walk(&root, seq, reserve, after, hint)?;
        let objects = self.state.get_many(&keys, seq).map_err(internal)?;
        let mut walked = 0;
        for (key, data) in keys.iter().zip(objects) {
            let data =
                data.ok_or_else(|| corrupt(key, "offer from the NFT offer directory is missing"))?;
            let node = xrpl_json::ledger_entry(key, &data).map_err(internal)?;
            if entry_type(&node) == "NFTokenOffer" {
                offers.push((*key, node));
                walked += 1;
            }
        }
        let mut m = Map::new();
        m.insert("nft_id".into(), p["nft_id"].clone());
        m.insert("validated".into(), json!(true));
        let mut next = None;
        if walked == reserve {
            next = offers.pop().map(|(k, _)| k);
        }
        let offers = offers
            .iter()
            .map(|(k, n)| offer_json(k, n))
            .collect::<Res<Vec<_>>>()?;
        m.insert("offers".into(), Value::Array(offers));
        if let Some(k) = next {
            m.insert("marker".into(), json!(hex::encode_upper(k)));
            m.insert("limit".into(), json!(limit));
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_id_parts() {
        // An NFT minted with flags 8, a 5% transfer fee, taxon 0, serial 0.
        let mut id = [0u8; 32];
        id[0..2].copy_from_slice(&8u16.to_be_bytes());
        id[2..4].copy_from_slice(&5000u16.to_be_bytes());
        id[4..24].copy_from_slice(&[7u8; 20]);
        id[24..28].copy_from_slice(&2459u32.to_be_bytes());
        let t = token_id(&id);
        assert_eq!(
            t,
            TokenId {
                flags: 8,
                transfer_fee: 5000,
                issuer: [7; 20],
                taxon: 0,
                serial: 0,
            }
        );
    }

    #[test]
    fn limits_and_hex_fields_like_clio() {
        let p = |v: Value| v.as_object().cloned().unwrap();
        assert_eq!(limit(&p(json!({})), 20, 400, 100), Ok(100));
        assert_eq!(limit(&p(json!({"limit": 1})), 20, 400, 100), Ok(20));
        assert_eq!(limit(&p(json!({"limit": 9999})), 20, 400, 100), Ok(400));
        assert!(limit(&p(json!({"limit": 0})), 20, 400, 100).is_err());
        assert!(limit(&p(json!({"limit": "5"})), 20, 400, 100).is_err());
        assert_eq!(hex256(&p(json!({})), "marker"), Ok(None));
        let e = hex256(&p(json!({"marker": 5})), "marker").unwrap_err();
        assert_eq!(e.message, "markerNotString");
        let e = hex256(&p(json!({"marker": "AB"})), "marker").unwrap_err();
        assert_eq!(e.message, "markerMalformed");
    }
}
