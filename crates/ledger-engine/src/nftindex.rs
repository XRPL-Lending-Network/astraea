//! What NFT transactions do to tokens, for the NFT index (`nft_info`,
//! `nft_history`, `nfts_by_issuer`), following Clio's `NFTHelpers`.
//!
//! Only successful transactions count. Each one lists the tokens whose history
//! it belongs to; a mint, a burn or an accepted offer also gives the token's
//! owner after it (a burn marks the token burned), a mint and NFTokenModify its
//! URI. Owners come from the metadata, the way Clio finds them: the minted token
//! is the one added to the NFT pages, and the owner of a page is the first 20
//! bytes of its key.
//!
//! Within a ledger the last change of each kind wins. Clio keeps one record per
//! token per ledger, so a token minted and then sold in the same ledger loses
//! its URI and its place in the issuer's list there; here the mint's URI and
//! issuer entry stay.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::ledger::Ledger;
use crate::xrpl_json;

pub type TokenId = [u8; 32];

/// What one transaction did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NftTx {
    /// Tokens whose history includes this transaction, without repeats.
    pub tokens: Vec<TokenId>,
    /// Owner after the transaction, and whether the token is burned.
    pub owner: Option<(TokenId, [u8; 20], bool)>,
    /// URI after the transaction (empty if it has none).
    pub uri: Option<(TokenId, Vec<u8>)>,
    /// The token was minted.
    pub minted: bool,
}

/// What a ledger did to tokens.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NftLedger {
    /// Token, TransactionIndex and position in the ledger's transaction list.
    pub txs: Vec<(TokenId, u32, u32)>,
    pub owners: BTreeMap<TokenId, ([u8; 20], bool)>,
    pub uris: BTreeMap<TokenId, Vec<u8>>,
    pub minted: BTreeSet<TokenId>,
    /// Transactions whose effect could not be read, with the reason. Their
    /// history entries are kept; the owner or URI change is not.
    pub problems: Vec<String>,
}

/// TransactionType of a serialized transaction without decoding it: the
/// field is first in canonical order.
fn tx_type(tx: &[u8]) -> Option<&'static str> {
    if tx.len() < 3 || tx[0] != 0x12 {
        return None;
    }
    xrpl_json::definitions().transaction_type(u16::from_be_bytes([tx[1], tx[2]]))
}

fn h256(v: Option<&Value>) -> Option<TokenId> {
    v.and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| b.try_into().ok())
}

fn account(v: Option<&Value>) -> Option<[u8; 20]> {
    v.and_then(Value::as_str)
        .and_then(crate::api::decode_account)
}

/// Affected nodes as (kind, node): kind is CreatedNode, ModifiedNode or DeletedNode.
fn nodes(meta: &Map<String, Value>) -> Vec<(&str, &Map<String, Value>)> {
    meta.get("AffectedNodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|n| {
            let (k, v) = n.iter().next()?;
            Some((k.as_str(), v.as_object()?))
        })
        .collect()
}

fn entry_type(node: &Map<String, Value>) -> &str {
    node.get("LedgerEntryType")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn fields<'a>(node: &'a Map<String, Value>, which: &str) -> Option<&'a Map<String, Value>> {
    node.get(which).and_then(Value::as_object)
}

/// Token IDs of an NFTokens array.
fn token_ids(f: Option<&Map<String, Value>>) -> Option<Vec<TokenId>> {
    let arr = f?.get("NFTokens")?.as_array()?;
    Some(
        arr.iter()
            .filter_map(|t| h256(t.get("NFToken").and_then(|n| n.get("NFTokenID"))))
            .collect(),
    )
}

/// Owner of an NFT page: the first 20 bytes of its key.
fn page_owner(node: &Map<String, Value>) -> Option<[u8; 20]> {
    h256(node.get("LedgerIndex")).and_then(|k| k[..20].try_into().ok())
}

fn uri_of(tx: &Map<String, Value>) -> Vec<u8> {
    tx.get("URI")
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default()
}

fn mint(tx: &Map<String, Value>, meta: &Map<String, Value>) -> Result<NftTx, String> {
    let (mut prev, mut fin) = (Vec::new(), Vec::new());
    let mut owner = None;
    for (kind, n) in nodes(meta) {
        if entry_type(n) != "NFTokenPage" {
            continue;
        }
        if owner.is_none() {
            owner = page_owner(n);
        }
        if kind == "CreatedNode" {
            fin.extend(token_ids(fields(n, "NewFields")).unwrap_or_default());
        } else {
            // A page linked to a new one changes only its links: no tokens before.
            let Some(p) = token_ids(fields(n, "PreviousFields")) else {
                continue;
            };
            prev.extend(p);
            fin.extend(token_ids(fields(n, "FinalFields")).unwrap_or_default());
        }
    }
    prev.sort_unstable();
    fin.sort_unstable();
    let added = fin
        .iter()
        .zip(prev.iter().map(Some).chain(std::iter::repeat(None)))
        .find(|(f, p)| Some(*f) != *p)
        .map(|(f, _)| *f);
    match (added, owner) {
        (Some(id), Some(o)) if fin.len() == prev.len() + 1 => Ok(NftTx {
            tokens: vec![id],
            owner: Some((id, o, false)),
            uri: Some((id, uri_of(tx))),
            minted: true,
        }),
        _ => Err("NFTokenMint: no minted token in the metadata".into()),
    }
}

fn burn(tx: &Map<String, Value>, meta: &Map<String, Value>) -> Result<NftTx, String> {
    let id = h256(tx.get("NFTokenID")).ok_or("NFTokenBurn without NFTokenID")?;
    for (kind, n) in nodes(meta) {
        if entry_type(n) != "NFTokenPage" || kind == "CreatedNode" {
            continue;
        }
        // The page held the token before the burn: in PreviousFields if the
        // page was changed, else in FinalFields of a page deleted unchanged.
        let before = if n.contains_key("PreviousFields") {
            token_ids(fields(n, "PreviousFields"))
        } else if kind == "DeletedNode" {
            token_ids(fields(n, "FinalFields"))
        } else {
            None
        };
        if before.is_some_and(|b| b.contains(&id))
            && let Some(o) = page_owner(n)
        {
            return Ok(NftTx {
                tokens: vec![id],
                owner: Some((id, o, true)),
                ..NftTx::default()
            });
        }
    }
    Err("NFTokenBurn: owner at burn time not found".into())
}

fn accept(tx: &Map<String, Value>, meta: &Map<String, Value>) -> Result<NftTx, String> {
    let ns = nodes(meta);
    let offer = |field: &str| -> Option<&Map<String, Value>> {
        let key = h256(tx.get(field))?;
        ns.iter()
            .find(|(_, n)| h256(n.get("LedgerIndex")) == Some(key))
            .and_then(|(_, n)| fields(n, "FinalFields"))
    };
    let done = |id, o| NftTx {
        tokens: vec![id],
        owner: Some((id, o, false)),
        ..NftTx::default()
    };
    // With a buy offer the new owner is the buyer.
    if tx.contains_key("NFTokenBuyOffer") {
        let f = offer("NFTokenBuyOffer").ok_or("NFTokenAcceptOffer: buy offer not in metadata")?;
        let id = h256(f.get("NFTokenID")).ok_or("buy offer without NFTokenID")?;
        let o = account(f.get("Owner")).ok_or("buy offer without Owner")?;
        return Ok(done(id, o));
    }
    // Otherwise the page that now holds the token and isn't the seller's.
    let f = offer("NFTokenSellOffer").ok_or("NFTokenAcceptOffer: sell offer not in metadata")?;
    let id = h256(f.get("NFTokenID")).ok_or("sell offer without NFTokenID")?;
    let seller = account(f.get("Owner")).ok_or("sell offer without Owner")?;
    for (kind, n) in &ns {
        if entry_type(n) != "NFTokenPage" || *kind == "DeletedNode" {
            continue;
        }
        let Some(o) = page_owner(n).filter(|o| *o != seller) else {
            continue;
        };
        let now = if *kind == "CreatedNode" {
            fields(n, "NewFields")
        } else {
            fields(n, "FinalFields")
        };
        if token_ids(now).is_some_and(|t| t.contains(&id)) {
            return Ok(done(id, o));
        }
    }
    Err("NFTokenAcceptOffer: new owner not found".into())
}

/// The tokens of the offers a cancel deleted, each once.
fn cancel(meta: &Map<String, Value>) -> NftTx {
    let mut tokens: Vec<TokenId> = nodes(meta)
        .into_iter()
        .filter(|(_, n)| entry_type(n) == "NFTokenOffer")
        .filter_map(|(_, n)| h256(fields(n, "FinalFields")?.get("NFTokenID")))
        .collect();
    tokens.sort_unstable();
    tokens.dedup();
    NftTx {
        tokens,
        ..NftTx::default()
    }
}

/// What a transaction did to tokens, from its JSON; `Ok(None)` if it is not
/// a successful NFT transaction.
pub fn nft_tx_json(
    tx: &Map<String, Value>,
    meta: &Map<String, Value>,
) -> Result<Option<NftTx>, String> {
    if meta.get("TransactionResult").and_then(Value::as_str) != Some("tesSUCCESS") {
        return Ok(None);
    }
    let token = || h256(tx.get("NFTokenID")).ok_or("no NFTokenID");
    let out = match tx.get("TransactionType").and_then(Value::as_str) {
        Some("NFTokenMint") => mint(tx, meta)?,
        Some("NFTokenBurn") => burn(tx, meta)?,
        Some("NFTokenAcceptOffer") => accept(tx, meta)?,
        Some("NFTokenCancelOffer") => cancel(meta),
        Some("NFTokenCreateOffer") => NftTx {
            tokens: vec![token()?],
            ..NftTx::default()
        },
        Some("NFTokenModify") => {
            let id = token()?;
            NftTx {
                tokens: vec![id],
                uri: Some((id, uri_of(tx))),
                ..NftTx::default()
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(out))
}

/// What a ledger's transactions did to tokens, applied in TransactionIndex
/// order. It never fails: a transaction that can't be decoded or read (say, a
/// field from an amendment this build doesn't know) goes to `problems`, so the
/// index never holds up loading.
pub fn nft_ledger(ledger: &Ledger) -> NftLedger {
    let mut found = Vec::new();
    let mut out = NftLedger::default();
    for (pos, (tx, meta)) in ledger.transactions.iter().enumerate() {
        let Some(kind) = tx_type(tx).filter(|t| t.starts_with("NFToken")) else {
            continue;
        };
        let id = hex::encode_upper(witness_core::shamap::tx_id(tx));
        let decoded = xrpl_json::transaction(tx).and_then(|t| {
            let m = xrpl_json::metadata(meta)?;
            let index = m
                .get("TransactionIndex")
                .and_then(Value::as_u64)
                .and_then(|i| u32::try_from(i).ok())
                .ok_or("metadata without TransactionIndex")?;
            Ok((t, m, index))
        });
        let (t, m, index) = match decoded {
            Ok(d) => d,
            Err(e) => {
                out.problems.push(format!("{id} {kind}: {e}"));
                continue;
            }
        };
        let r = nft_tx_json(&t, &m).map_err(|e| format!("{id} {kind}: {e}"));
        found.push((index, pos as u32, r, h256(t.get("NFTokenID"))));
    }
    found.sort_by_key(|f| f.0);
    for (index, pos, r, named) in found {
        match r {
            Ok(Some(x)) => {
                for t in &x.tokens {
                    out.txs.push((*t, index, pos));
                }
                if let Some((t, o, burned)) = x.owner {
                    out.owners.insert(t, (o, burned));
                }
                if let Some((t, u)) = x.uri {
                    out.uris.insert(t, u);
                }
                if x.minted
                    && let Some(t) = x.tokens.first()
                {
                    out.minted.insert(*t);
                }
            }
            Ok(None) => {}
            Err(e) => {
                // The history entry is still known when the transaction names its token.
                if let Some(t) = named {
                    out.txs.push((t, index, pos));
                }
                out.problems.push(e);
            }
        }
    }
    out
}

/// The tokens of an NFT page in the state, as rows that put each token at
/// the page's owner: the starting point for a store whose history begins
/// after the first NFTs, as Clio fills its tables from its first ledger.
pub fn nft_page(key: &[u8; 32], data: &[u8]) -> Option<NftLedger> {
    // LedgerEntryType 0x0050, the first field of an object.
    if data.len() < 3 || data[0] != 0x11 || u16::from_be_bytes([data[1], data[2]]) != 0x0050 {
        return None;
    }
    let node = xrpl_json::ledger_entry(key, data).ok()?;
    let owner: [u8; 20] = key[..20].try_into().ok()?;
    let mut out = NftLedger::default();
    for t in node.get("NFTokens")?.as_array()? {
        let n = t.get("NFToken")?;
        let id = h256(n.get("NFTokenID"))?;
        let uri = n
            .get("URI")
            .and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok())
            .unwrap_or_default();
        out.owners.insert(id, (owner, false));
        out.uris.insert(id, uri);
        out.minted.insert(id);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn id(b: u8) -> String {
        hex::encode_upper([b; 32])
    }

    fn page(owner: u8, low: u8) -> String {
        let mut k = [owner; 32];
        k[20..].fill(low);
        hex::encode_upper(k)
    }

    fn tokens(ids: &[u8]) -> Value {
        json!(
            ids.iter()
                .map(|b| json!({"NFToken": {"NFTokenID": id(*b)}}))
                .collect::<Vec<_>>()
        )
    }

    const OK: &str = "tesSUCCESS";

    #[test]
    fn mint_finds_the_added_token_and_owner() {
        let tx = obj(json!({"TransactionType": "NFTokenMint", "URI": "ABCD"}));
        let meta = obj(json!({"TransactionResult": OK, "AffectedNodes": [
            {"ModifiedNode": {"LedgerEntryType": "AccountRoot", "LedgerIndex": id(9)}},
            {"ModifiedNode": {"LedgerEntryType": "NFTokenPage", "LedgerIndex": page(7, 0xFF),
                "PreviousFields": {"NFTokens": tokens(&[1, 3])},
                "FinalFields": {"NFTokens": tokens(&[1, 2, 3])}}},
        ]}));
        let r = nft_tx_json(&tx, &meta).unwrap().unwrap();
        assert_eq!(r.tokens, vec![[2; 32]]);
        assert_eq!(r.owner, Some(([2; 32], [7; 20], false)));
        assert_eq!(r.uri, Some(([2; 32], vec![0xAB, 0xCD])));
        assert!(r.minted);
    }

    #[test]
    fn mint_into_a_new_page_and_a_page_relinked_only() {
        let tx = obj(json!({"TransactionType": "NFTokenMint"}));
        let meta = obj(json!({"TransactionResult": OK, "AffectedNodes": [
            {"CreatedNode": {"LedgerEntryType": "NFTokenPage", "LedgerIndex": page(7, 0x10),
                "NewFields": {"NFTokens": tokens(&[1, 4])}}},
            {"ModifiedNode": {"LedgerEntryType": "NFTokenPage", "LedgerIndex": page(7, 0xFF),
                "PreviousFields": {"NFTokens": tokens(&[1, 5])},
                "FinalFields": {"NFTokens": tokens(&[5])}}},
            {"ModifiedNode": {"LedgerEntryType": "NFTokenPage", "LedgerIndex": page(7, 0x01),
                "PreviousFields": {"NextPageMin": page(7, 0xFF)},
                "FinalFields": {"NFTokens": tokens(&[0])}}},
        ]}));
        let r = nft_tx_json(&tx, &meta).unwrap().unwrap();
        assert_eq!(r.tokens, vec![[4; 32]]);
        assert_eq!(r.uri, Some(([4; 32], vec![])));
    }

    #[test]
    fn burn_takes_the_owner_from_the_page_that_held_it() {
        let tx = obj(json!({"TransactionType": "NFTokenBurn", "NFTokenID": id(2)}));
        let meta = obj(json!({"TransactionResult": OK, "AffectedNodes": [
            {"DeletedNode": {"LedgerEntryType": "NFTokenPage", "LedgerIndex": page(8, 0xFF),
                "FinalFields": {"NFTokens": tokens(&[2])}}},
        ]}));
        let r = nft_tx_json(&tx, &meta).unwrap().unwrap();
        assert_eq!(r.owner, Some(([2; 32], [8; 20], true)));
        assert!(!r.minted);
    }

    #[test]
    fn accept_by_buy_or_sell_offer() {
        let buyer = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
        let tx = obj(json!({"TransactionType": "NFTokenAcceptOffer", "NFTokenBuyOffer": id(5)}));
        let meta = obj(json!({"TransactionResult": OK, "AffectedNodes": [
            {"DeletedNode": {"LedgerEntryType": "NFTokenOffer", "LedgerIndex": id(5),
                "FinalFields": {"NFTokenID": id(2), "Owner": buyer}}},
        ]}));
        let r = nft_tx_json(&tx, &meta).unwrap().unwrap();
        let b = crate::api::decode_account(buyer).unwrap();
        assert_eq!(r.owner, Some(([2; 32], b, false)));

        let seller = crate::xrpl_json::account(&[8; 20]);
        let tx = obj(json!({"TransactionType": "NFTokenAcceptOffer", "NFTokenSellOffer": id(6)}));
        let meta = obj(json!({"TransactionResult": OK, "AffectedNodes": [
            {"DeletedNode": {"LedgerEntryType": "NFTokenOffer", "LedgerIndex": id(6),
                "FinalFields": {"NFTokenID": id(2), "Owner": seller}}},
            {"ModifiedNode": {"LedgerEntryType": "NFTokenPage", "LedgerIndex": page(8, 0xFF),
                "PreviousFields": {"NFTokens": tokens(&[2, 3])},
                "FinalFields": {"NFTokens": tokens(&[3])}}},
            {"CreatedNode": {"LedgerEntryType": "NFTokenPage", "LedgerIndex": page(9, 0xFF),
                "NewFields": {"NFTokens": tokens(&[2])}}},
        ]}));
        let r = nft_tx_json(&tx, &meta).unwrap().unwrap();
        assert_eq!(r.owner, Some(([2; 32], [9; 20], false)));
    }

    #[test]
    fn cancel_lists_each_token_once_and_failures_are_ignored() {
        let tx = obj(json!({"TransactionType": "NFTokenCancelOffer"}));
        let meta = obj(json!({"TransactionResult": OK, "AffectedNodes": [
            {"DeletedNode": {"LedgerEntryType": "NFTokenOffer", "LedgerIndex": id(5),
                "FinalFields": {"NFTokenID": id(2)}}},
            {"DeletedNode": {"LedgerEntryType": "NFTokenOffer", "LedgerIndex": id(6),
                "FinalFields": {"NFTokenID": id(2)}}},
            {"DeletedNode": {"LedgerEntryType": "NFTokenOffer", "LedgerIndex": id(7),
                "FinalFields": {"NFTokenID": id(1)}}},
        ]}));
        let r = nft_tx_json(&tx, &meta).unwrap().unwrap();
        assert_eq!(r.tokens, vec![[1; 32], [2; 32]]);
        assert_eq!(r.owner, None);
        let failed = obj(json!({"TransactionResult": "tecNO_ENTRY", "AffectedNodes": []}));
        assert_eq!(nft_tx_json(&tx, &failed), Ok(None));
    }

    #[test]
    fn modify_sets_the_uri_only() {
        let tx = obj(json!({"TransactionType": "NFTokenModify", "NFTokenID": id(2)}));
        let meta = obj(json!({"TransactionResult": OK, "AffectedNodes": []}));
        let r = nft_tx_json(&tx, &meta).unwrap().unwrap();
        assert_eq!(r.uri, Some(([2; 32], vec![])));
        assert_eq!(r.owner, None);
    }
}
