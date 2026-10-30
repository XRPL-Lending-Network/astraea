//! Account objects and whole state: account_objects, account_lines,
//! account_offers, ledger_data, as in Clio 2.8.
//!
//! Account objects come from walking the owner directory (Clio's `traverseOwnedNodes`):
//! directory pages via `IndexNext`; for account_objects they are preceded by the NFT
//! pages from last to first via `PreviousPageMin`. `limit` counts directory
//! entries, not response rows: account_lines can return fewer rows
//! than limit, plus a marker. The marker is "key of the last returned entry, directory
//! page number"; for NFT pages the page number is 4294967295.
//!
//! ledger_data returns objects in ascending key order after marker. Clio's
//! `out_of_order` branch (walking the cache with a ledger sequence as marker) is not replicated.

use serde_json::{Map, Value, json};

use crate::api::{
    Engine, Res, RpcError, account_id, as_bool, gravatar, hash256, internal, invalid_params,
    keylet, rpc_err,
};
use crate::xrpl_json::{self, iou_text};

const OWNED_LIMIT_MIN: u32 = 10;
const OWNED_LIMIT_MAX: u32 = 400;
const OWNED_LIMIT_DEFAULT: u32 = 200;
const DATA_LIMIT_JSON: u32 = 256;
const DATA_LIMIT_BINARY: u32 = 2048;
/// What to do with an account object during the walk: key and object.
type Visit<'a> = dyn FnMut(&[u8; 32], &[u8]) -> Res<()> + 'a;

/// Clio's mpt_holders limit: default and maximum.
const MPT_LIMIT_DEFAULT: u64 = 50;
const MPT_LIMIT_MAX: u64 = 100;

/// Page number in marker when marker points to an NFT page.
const NFT_HINT: u32 = u32::MAX;

/// Object kind for the `type` filter: name, RPC name, what it belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Network-wide object (Amendments, FeeSettings…); not filtered
    /// in account_objects.
    Chain,
    Owned,
    /// Account object that prevents deleting the account.
    Blocker,
}

/// Clio's `LedgerTypes` table.
const TYPES: &[(&str, &str, Kind)] = &[
    ("AccountRoot", "account", Kind::Owned),
    ("Amendments", "amendments", Kind::Chain),
    ("Check", "check", Kind::Blocker),
    ("DepositPreauth", "deposit_preauth", Kind::Owned),
    ("DirectoryNode", "directory", Kind::Chain),
    ("Escrow", "escrow", Kind::Blocker),
    ("FeeSettings", "fee", Kind::Chain),
    ("LedgerHashes", "hashes", Kind::Chain),
    ("Offer", "offer", Kind::Owned),
    ("PayChannel", "payment_channel", Kind::Blocker),
    ("SignerList", "signer_list", Kind::Owned),
    ("RippleState", "state", Kind::Blocker),
    ("Ticket", "ticket", Kind::Owned),
    ("NFTokenOffer", "nft_offer", Kind::Owned),
    ("NFTokenPage", "nft_page", Kind::Blocker),
    ("AMM", "amm", Kind::Owned),
    ("Bridge", "bridge", Kind::Blocker),
    ("XChainOwnedClaimID", "xchain_owned_claim_id", Kind::Blocker),
    (
        "XChainOwnedCreateAccountClaimID",
        "xchain_owned_create_account_claim_id",
        Kind::Blocker,
    ),
    ("DID", "did", Kind::Owned),
    ("Oracle", "oracle", Kind::Owned),
    ("Credential", "credential", Kind::Owned),
    ("Vault", "vault", Kind::Owned),
    ("LoanBroker", "loan_broker", Kind::Owned),
    ("Loan", "loan", Kind::Blocker),
    ("NegativeUNL", "nunl", Kind::Chain),
    ("MPTokenIssuance", "mpt_issuance", Kind::Blocker),
    ("MPToken", "mptoken", Kind::Blocker),
    ("PermissionedDomain", "permissioned_domain", Kind::Blocker),
    ("Delegate", "delegate", Kind::Owned),
];

/// Kind from the request string: RPC name or type name, case-insensitive.
fn kind_of(s: &str) -> Option<(&'static str, Kind)> {
    TYPES
        .iter()
        .find(|(_, rpc, _)| *rpc == s)
        .or_else(|| TYPES.iter().find(|(n, _, _)| n.eq_ignore_ascii_case(s)))
        .map(|(n, _, k)| (*n, *k))
}

/// Object type from `type`; `owned` restricts to account objects.
fn type_filter(p: &Map<String, Value>, owned: bool) -> Res<Option<&'static str>> {
    match p.get("type") {
        None => Ok(None),
        Some(Value::String(s)) => match kind_of(s) {
            Some((_, Kind::Chain)) if owned => Err(invalid_params("Invalid field 'type'.")),
            Some((n, _)) => Ok(Some(n)),
            None => Err(invalid_params("Invalid field 'type'.")),
        },
        Some(_) => Err(invalid_params("Invalid field 'type', not string.")),
    }
}

/// limit for account objects: integer ≥ 1, clamped to [10, 400].
fn owned_limit(p: &Map<String, Value>) -> Res<u32> {
    match p.get("limit") {
        None => Ok(OWNED_LIMIT_DEFAULT),
        Some(v) => v
            .as_u64()
            .filter(|n| *n >= 1)
            .and_then(|n| u32::try_from(n).ok())
            .map(|n| n.clamp(OWNED_LIMIT_MIN, OWNED_LIMIT_MAX))
            .ok_or_else(|| invalid_params("Invalid parameters.")),
    }
}

fn malformed_cursor() -> RpcError {
    invalid_params("Malformed cursor.")
}

fn invalid_marker() -> RpcError {
    invalid_params("Invalid marker.")
}

/// marker for account objects: "key hex,page number".
fn parse_cursor(p: &Map<String, Value>) -> Res<Option<([u8; 32], u32)>> {
    let s = match p.get("marker") {
        None => return Ok(None),
        Some(Value::String(s)) => s,
        Some(_) => return Err(invalid_params("markerNotString")),
    };
    let (k, h) = s.split_once(',').ok_or_else(malformed_cursor)?;
    let h = h.split(',').next().unwrap_or_default();
    let key = hex::decode(k)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(malformed_cursor)?;
    // Clio parses the number as u64 and stores it in u32.
    let hint = h.parse::<u64>().map_err(|_| malformed_cursor())? as u32;
    Ok(Some((key, hint)))
}

fn cursor_text(key: &[u8; 32], hint: u32) -> String {
    format!("{},{hint}", hex::encode_upper(key))
}

fn h256(node: &Map<String, Value>, field: &str) -> [u8; 32] {
    node.get(field)
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .unwrap_or([0; 32])
}

fn u32_field(node: &Map<String, Value>, field: &str) -> u64 {
    node.get(field).and_then(Value::as_u64).unwrap_or(0)
}

/// Directory page: entry keys and the next page number.
fn dir_page(key: &[u8; 32], data: &[u8]) -> Res<(Vec<[u8; 32]>, u64)> {
    let node = xrpl_json::ledger_entry(key, data).map_err(internal)?;
    // Indexes is required on a directory page (it may be empty); if it is missing or
    // holds something other than keys, the state is corrupt, not an empty page.
    let broken = || corrupt(key, "directory page without Indexes");
    let indexes = node
        .get("Indexes")
        .and_then(Value::as_array)
        .ok_or_else(broken)?
        .iter()
        .map(|v| {
            v.as_str()
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(broken)
        })
        .collect::<Res<Vec<_>>>()?;
    let next = node
        .get("IndexNext")
        .and_then(Value::as_str)
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    Ok((indexes, next))
}

/// A broken required link or field in the state: an error with the key,
/// not a truncated "successful" response.
fn corrupt(key: &[u8; 32], what: &str) -> RpcError {
    internal(format!("corrupt_state: {what}: {}", hex::encode_upper(key)))
}

/// Amount of a required object field: missing means corrupt state.
fn required_amount(node: &Map<String, Value>, field: &str, key: &[u8; 32]) -> Res<String> {
    match node.get(field) {
        Some(v @ (Value::Object(_) | Value::String(_))) => Ok(amount_value(Some(v))),
        _ => Err(corrupt(key, &format!("missing {field}"))),
    }
}

/// Directory page key: the root, or page number `n`.
fn dir_page_key(root: &[u8; 32], n: u64) -> [u8; 32] {
    if n == 0 {
        *root
    } else {
        keylet(b'd', &[root, &n.to_be_bytes()])
    }
}

/// Amount object in account_lines and account_offers responses: the value as text.
fn amount_value(v: Option<&Value>) -> String {
    match v {
        Some(Value::Object(o)) => o
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .to_owned(),
        Some(Value::String(s)) => s.clone(),
        _ => "0".into(),
    }
}

pub(crate) fn negate(v: &str) -> String {
    match v.strip_prefix('-') {
        Some(rest) => rest.to_owned(),
        None if v == "0" => v.to_owned(),
        None => format!("-{v}"),
    }
}

/// Offer rate from BookDirectory: `amountFromQuality(getQuality)`.
fn quality_text(book: &[u8; 32]) -> String {
    let q = u64::from_be_bytes(book[24..].try_into().unwrap_or_default());
    let mut m = q & ((1 << 56) - 1);
    let mut e = (q >> 56) as i32 - 100;
    if m == 0 {
        return "0".into();
    }
    while m < 1_000_000_000_000_000 {
        m *= 10;
        e -= 1;
    }
    while m > 9_999_999_999_999_999 {
        m /= 10;
        e += 1;
    }
    iou_text(false, m, e)
}

impl Engine {
    fn fetch(&self, key: &[u8; 32], seq: u32) -> Res<Option<Vec<u8>>> {
        self.state.get(key, seq).map_err(internal)
    }

    /// Account, ledger and request header; if the account doesn't exist, actNotFound.
    fn owner_of(&self, p: &Map<String, Value>) -> Res<([u8; 20], u32, [u8; 32])> {
        let a = account_id(
            p.get("account")
                .ok_or_else(|| invalid_params("Required field 'account' missing"))?,
        )?;
        let seq = self.resolve_state(p)?;
        let (_, h) = self.header(seq)?;
        if self.fetch(&keylet(b'a', &[&a]), seq)?.is_none() {
            return Err(rpc_err("actNotFound", 19, "Account not found."));
        }
        Ok((a, seq, h.hash()))
    }

    /// Walks account objects: `visit` gets the key and object. Returns a
    /// continuation marker if the entries ran out before the directory did.
    fn owned(
        &self,
        account: &[u8; 20],
        seq: u32,
        mut limit: u32,
        cursor: Option<([u8; 32], u32)>,
        nft: bool,
        visit: &mut Visit<'_>,
    ) -> Res<Option<String>> {
        let (mut marker, mut hint) = cursor.unwrap_or(([0; 32], 0));
        let nft_marker = hint == NFT_HINT && marker != [0; 32];
        let nft_marker_zero = hint == NFT_HINT && marker == [0; 32];
        if nft && (cursor.is_none() || nft_marker) {
            let (next, count) = self.nft_pages(account, seq, marker, limit, visit)?;
            if count >= limit {
                return Ok(Some(cursor_text(&next, NFT_HINT)));
            }
            limit -= count;
            (marker, hint) = ([0; 32], 0);
        } else if nft && nft_marker_zero {
            (marker, hint) = ([0; 32], 0);
        }

        let root = keylet(b'O', &[account]);
        let mut keys = Vec::new();
        // As in Clio: without a key in marker the walk starts at the directory root, and the
        // page number from marker only carries over into the next marker.
        let mut found = marker == [0; 32];
        let mut page = if found { 0 } else { u64::from(hint) };
        let mut number = hint;
        let mut next_cursor = None;
        if !found {
            let k = dir_page_key(&root, page);
            let data = self.fetch(&k, seq)?.ok_or_else(invalid_marker)?;
            if !dir_page(&k, &data)?.0.contains(&marker) {
                return Err(invalid_marker());
            }
        }
        let mut visited = std::collections::HashSet::new();
        loop {
            crate::limits::check_rpc()?;
            let k = dir_page_key(&root, page);
            if !visited.insert(page) {
                return Err(corrupt(&k, "owner directory pages form a cycle"));
            }
            let Some(data) = self.fetch(&k, seq)? else {
                // No root: the account has no objects. A missing page that
                // IndexNext points to means corrupt state.
                if page == 0 && marker == [0; 32] {
                    break;
                }
                if found && marker == [0; 32] {
                    return Err(corrupt(&k, "IndexNext points to a nonexistent page"));
                }
                return Err(invalid_params("Owner directory not found."));
            };
            let (indexes, next) = dir_page(&k, &data)?;
            for key in indexes {
                if !found {
                    found = key == marker;
                    continue;
                }
                keys.push(key);
                limit -= 1;
                if limit == 0 {
                    break;
                }
            }
            if limit == 0 {
                next_cursor = keys.last().map(|k| cursor_text(k, number));
                break;
            }
            if next == 0 {
                break;
            }
            page = next;
            // Clio stores the page number in u32.
            number = next as u32;
        }
        let objects = self.state.get_many(&keys, seq).map_err(internal)?;
        for (key, data) in keys.iter().zip(objects) {
            let data =
                data.ok_or_else(|| corrupt(key, "object from the owner directory is missing"))?;
            visit(key, &data)?;
        }
        Ok(next_cursor)
    }

    /// NFT pages from last to first; returns the key of the next
    /// page and how many were returned, like Clio's `traverseNFTObjects`.
    fn nft_pages(
        &self,
        account: &[u8; 20],
        seq: u32,
        next: [u8; 32],
        limit: u32,
        visit: &mut Visit<'_>,
    ) -> Res<([u8; 32], u32)> {
        let mut first = [0u8; 32];
        first[..20].copy_from_slice(account);
        let mut last = first;
        last[20..].fill(0xFF);
        if next != [0; 32] && next[..20] != first[..20] {
            return Err(invalid_marker());
        }
        let mut current = if next == [0; 32] { last } else { next };
        let Some(mut data) = self.fetch(&current, seq)? else {
            if next == [0; 32] {
                return Ok(([0; 32], 0));
            }
            return Err(invalid_marker());
        };
        let mut count = 0;
        loop {
            crate::limits::check_rpc()?;
            let node = xrpl_json::ledger_entry(&current, &data).map_err(internal)?;
            let previous = h256(&node, "PreviousPageMin");
            visit(&current, &data)?;
            count += 1;
            if count == limit || previous == [0; 32] {
                return Ok((previous, count));
            }
            match self.fetch(&previous, seq)? {
                Some(d) => {
                    current = previous;
                    data = d;
                }
                // Clio responds here as if there were no NFTs; in a complete
                // state this can't happen, so it is corruption.
                None => {
                    return Err(corrupt(
                        &previous,
                        "PreviousPageMin points to a nonexistent NFT page",
                    ));
                }
            }
        }
    }

    pub(crate) fn account_objects(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let limit = owned_limit(p)?;
        let only = type_filter(p, true)?;
        let cursor = parse_cursor(p)?;
        let (account, seq, hash) = self.owner_of(p)?;
        let blockers = as_bool(p.get("deletion_blockers_only"));
        let keep = |t: &str| -> bool {
            if blockers {
                kind_of(t).is_some_and(|(_, k)| k == Kind::Blocker) && only.is_none_or(|o| o == t)
            } else {
                only.is_none_or(|o| o == t)
            }
        };
        let mut objects = Vec::new();
        let marker = self.owned(&account, seq, limit, cursor, true, &mut |k, d| {
            let mut node = xrpl_json::ledger_entry(k, d).map_err(internal)?;
            if keep(
                node.get("LedgerEntryType")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ) {
                gravatar(&mut node);
                objects.push(Value::Object(node));
            }
            Ok(())
        })?;
        let mut m = Map::new();
        m.insert("ledger_hash".into(), json!(hex::encode_upper(hash)));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("validated".into(), json!(true));
        m.insert("limit".into(), json!(limit));
        m.insert("account".into(), p["account"].clone());
        m.insert("account_objects".into(), Value::Array(objects));
        if let Some(mk) = marker {
            m.insert("marker".into(), json!(mk));
        }
        Ok(m)
    }

    pub(crate) fn account_lines(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let limit = owned_limit(p)?;
        let cursor = parse_cursor(p)?;
        // For peer, Clio responds with a generic error message, not "accountMalformed".
        let peer = p
            .get("peer")
            .map(|v| account_id(v).map_err(|_| rpc_err("actMalformed", 35, "Account malformed.")))
            .transpose()?;
        let (account, seq, hash) = self.owner_of(p)?;
        let ignore_default = as_bool(p.get("ignore_default"));
        let mut lines = Vec::new();
        let marker = self.owned(&account, seq, limit, cursor, false, &mut |k, d| {
            let node = xrpl_json::ledger_entry(k, d).map_err(internal)?;
            if node.get("LedgerEntryType").and_then(Value::as_str) != Some("RippleState") {
                return Ok(());
            }
            if let Some(line) = line(k, &node, &account, peer.as_ref(), ignore_default)? {
                lines.push(line);
            }
            Ok(())
        })?;
        let mut m = Map::new();
        m.insert("account".into(), p["account"].clone());
        m.insert("ledger_hash".into(), json!(hex::encode_upper(hash)));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("validated".into(), json!(true));
        m.insert("limit".into(), json!(limit));
        m.insert("lines".into(), Value::Array(lines));
        if let Some(mk) = marker {
            m.insert("marker".into(), json!(mk));
        }
        Ok(m)
    }

    pub(crate) fn account_offers(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let limit = owned_limit(p)?;
        let cursor = parse_cursor(p)?;
        let (account, seq, hash) = self.owner_of(p)?;
        let mut offers = Vec::new();
        let marker = self.owned(&account, seq, limit, cursor, false, &mut |k, d| {
            let node = xrpl_json::ledger_entry(k, d).map_err(internal)?;
            if node.get("LedgerEntryType").and_then(Value::as_str) == Some("Offer") {
                offers.push(offer(k, &node)?);
            }
            Ok(())
        })?;
        let mut m = Map::new();
        m.insert("ledger_hash".into(), json!(hex::encode_upper(hash)));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("validated".into(), json!(true));
        m.insert("account".into(), json!(xrpl_json::account(&account)));
        m.insert("offers".into(), Value::Array(offers));
        if let Some(mk) = marker {
            m.insert("marker".into(), json!(mk));
        }
        Ok(m)
    }

    /// mpt_holders: holders of an MPT issuance, as in Clio 2.8: in ascending
    /// account order, limit 1…100 (default 50), marker is the last returned
    /// account (hex); a marker is present when the page is full.
    pub(crate) fn mpt_holders(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let id = p
            .get("mpt_issuance_id")
            .ok_or_else(|| invalid_params("Required field 'mpt_issuance_id' missing"))?;
        let id: [u8; 24] = id
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid_params("mpt_issuance_idMalformed"))?;
        let limit = match p.get("limit") {
            None => MPT_LIMIT_DEFAULT,
            Some(v) => v
                .as_u64()
                .filter(|n| *n >= 1)
                .map(|n| n.min(MPT_LIMIT_MAX))
                .ok_or_else(|| invalid_params("Invalid parameters."))?,
        };
        let after: Option<[u8; 20]> = match p.get("marker") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| invalid_params("markerMalformed"))?,
            ),
        };
        let seq = self.resolve_state(p)?;
        if self.fetch(&keylet(b'~', &[&id]), seq)?.is_none() {
            return Err(rpc_err("objectNotFound", 92, "objectNotFound"));
        }
        let holders = self
            .state
            .mpt_holders(&id, seq, after.as_ref(), limit as usize)
            .map_err(internal)?;
        let keys: Vec<[u8; 32]> = holders.iter().map(|h| h.1).collect();
        let objects = self.state.get_many(&keys, seq).map_err(internal)?;
        let mut tokens = Vec::with_capacity(holders.len());
        for ((acc, key), data) in holders.iter().zip(objects) {
            let data =
                data.ok_or_else(|| corrupt(key, "MPToken from the holder index is missing"))?;
            let node = xrpl_json::ledger_entry(key, &data).map_err(internal)?;
            tokens.push(json!({
                "account": xrpl_json::account(acc),
                "flags": u32_field(&node, "Flags"),
                "mpt_amount": node.get("MPTAmount").cloned().unwrap_or_else(|| json!("0")),
                "mptoken_index": hex::encode_upper(key),
            }));
        }
        let mut m = Map::new();
        m.insert("mpt_issuance_id".into(), json!(hex::encode_upper(id)));
        m.insert("limit".into(), json!(limit));
        m.insert("ledger_index".into(), json!(seq));
        if tokens.len() as u64 == limit
            && let Some((last, _)) = holders.last()
        {
            m.insert("marker".into(), json!(hex::encode_upper(last)));
        }
        m.insert("mptokens".into(), Value::Array(tokens));
        m.insert("validated".into(), json!(true));
        Ok(m)
    }

    pub(crate) fn ledger_data(&self, p: &Map<String, Value>, api: u32) -> Res<Map<String, Value>> {
        let binary = match p.get("binary") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(invalid_params("Invalid parameters.")),
        };
        let limit = match p.get("limit") {
            None => None,
            Some(v) => Some(
                v.as_u64()
                    .filter(|n| *n >= 1)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| invalid_params("Invalid parameters."))?,
            ),
        };
        if as_bool(p.get("out_of_order")) {
            return Err(rpc_err(
                "notSupported",
                75,
                "Operation not supported: out_of_order.",
            ));
        }
        let marker = match p.get("marker") {
            None => None,
            Some(Value::String(_)) => Some(hash256(&p["marker"], "marker")?),
            Some(_) => return Err(invalid_params("markerNotString")),
        };
        let only = type_filter(p, false)?;
        let seq = self.resolve_state(p)?;
        let (raw, h) = self.header(seq)?;
        let mut m = Map::new();
        match &marker {
            None => {
                m.insert(
                    "ledger".into(),
                    Value::Object(self.header_json(&raw, &h, binary, api)),
                );
            }
            Some(k) => {
                if self.fetch(k, seq)?.is_none() {
                    return Err(invalid_params("markerDoesNotExist"));
                }
            }
        }
        let cap = if binary {
            DATA_LIMIT_BINARY
        } else {
            DATA_LIMIT_JSON
        };
        let take = limit.unwrap_or(cap).min(cap) as usize;
        let mut state = Vec::new();
        let mut last = None;
        let mut count = 0;
        for item in self.state.objects_page(seq, marker.as_ref()) {
            crate::limits::check_rpc()?;
            let (k, d) = item.map_err(internal)?;
            count += 1;
            last = Some(k);
            let node = xrpl_json::ledger_entry(&k, &d).map_err(internal)?;
            let t = node.get("LedgerEntryType").and_then(Value::as_str);
            if only.is_none_or(|o| Some(o) == t) {
                if binary {
                    state.push(json!({
                        "data": hex::encode_upper(&d),
                        "index": hex::encode_upper(k),
                    }));
                } else {
                    let mut node = node;
                    gravatar(&mut node);
                    state.push(Value::Object(node));
                }
            }
            if count == take {
                break;
            }
        }
        m.insert("ledger_hash".into(), json!(hex::encode_upper(h.hash())));
        m.insert("ledger_index".into(), json!(seq));
        m.insert("validated".into(), json!(true));
        m.insert("state".into(), Value::Array(state));
        // As in Clio: once limit is reached, marker points to the last one, even if nothing
        // follows.
        if count == take
            && let Some(k) = last
        {
            m.insert("marker".into(), json!(hex::encode_upper(k)));
        }
        Ok(m)
    }
}

/// A trust line as seen by `account`: Clio's `AccountLinesHandler::addLine`.
fn line(
    key: &[u8; 32],
    node: &Map<String, Value>,
    account: &[u8; 20],
    peer: Option<&[u8; 20]>,
    ignore_default: bool,
) -> Res<Option<Value>> {
    const LOW_RESERVE: u64 = 0x0001_0000;
    const HIGH_RESERVE: u64 = 0x0002_0000;
    const LOW_AUTH: u64 = 0x0004_0000;
    const HIGH_AUTH: u64 = 0x0008_0000;
    const LOW_NO_RIPPLE: u64 = 0x0010_0000;
    const HIGH_NO_RIPPLE: u64 = 0x0020_0000;
    const LOW_FREEZE: u64 = 0x0040_0000;
    const HIGH_FREEZE: u64 = 0x0080_0000;
    const LOW_DEEP_FREEZE: u64 = 0x0200_0000;
    const HIGH_DEEP_FREEZE: u64 = 0x0400_0000;

    let flags = u32_field(node, "Flags");
    let issuer = |f: &str| -> Res<String> {
        node.get(f)
            .and_then(|v| v.get("issuer"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| corrupt(key, &format!("trust line without {f}")))
    };
    let (low, high) = (issuer("LowLimit")?, issuer("HighLimit")?);
    let me = xrpl_json::account(account);
    let view_lowest = low == me;
    if ignore_default {
        let reserve = if view_lowest {
            LOW_RESERVE
        } else {
            HIGH_RESERVE
        };
        if flags & reserve == 0 {
            return Ok(None);
        }
    }
    let peer_id = if view_lowest { &high } else { &low };
    if let Some(p) = peer
        && xrpl_json::account(p) != *peer_id
    {
        return Ok(None);
    }
    let (limit_f, limit_peer_f) = if view_lowest {
        ("LowLimit", "HighLimit")
    } else {
        ("HighLimit", "LowLimit")
    };
    let (q_in, q_out) = if view_lowest {
        ("LowQualityIn", "LowQualityOut")
    } else {
        ("HighQualityIn", "HighQualityOut")
    };
    let balance = required_amount(node, "Balance", key)?;
    let balance = if view_lowest {
        balance
    } else {
        negate(&balance)
    };
    let currency = node
        .get("Balance")
        .and_then(|v| v.get("currency"))
        .cloned()
        .unwrap_or(Value::Null);
    let mut l = Map::new();
    l.insert("account".into(), json!(peer_id));
    l.insert("balance".into(), json!(balance));
    l.insert("currency".into(), currency);
    l.insert("limit".into(), json!(required_amount(node, limit_f, key)?));
    l.insert(
        "limit_peer".into(),
        json!(required_amount(node, limit_peer_f, key)?),
    );
    l.insert("quality_in".into(), json!(u32_field(node, q_in)));
    l.insert("quality_out".into(), json!(u32_field(node, q_out)));
    let side = |lo: u64, hi: u64| if view_lowest { (lo, hi) } else { (hi, lo) };
    for (name, peer_name, lo, hi) in [
        ("no_ripple", "no_ripple_peer", LOW_NO_RIPPLE, HIGH_NO_RIPPLE),
        ("authorized", "peer_authorized", LOW_AUTH, HIGH_AUTH),
        ("freeze", "freeze_peer", LOW_FREEZE, HIGH_FREEZE),
        (
            "deep_freeze",
            "deep_freeze_peer",
            LOW_DEEP_FREEZE,
            HIGH_DEEP_FREEZE,
        ),
    ] {
        let (mine, theirs) = side(lo, hi);
        if flags & mine != 0 {
            l.insert(name.into(), json!(true));
        }
        if flags & theirs != 0 {
            l.insert(peer_name.into(), json!(true));
        }
    }
    Ok(Some(Value::Object(l)))
}

/// An offer in account_offers: Clio's `AccountOffersHandler::addOffer`.
fn offer(key: &[u8; 32], node: &Map<String, Value>) -> Res<Value> {
    for f in ["TakerPays", "TakerGets", "BookDirectory"] {
        if !node.contains_key(f) {
            return Err(corrupt(key, &format!("offer without {f}")));
        }
    }
    let mut o = Map::new();
    o.insert("seq".into(), json!(u32_field(node, "Sequence")));
    o.insert("flags".into(), json!(u32_field(node, "Flags")));
    o.insert(
        "quality".into(),
        json!(quality_text(&h256(node, "BookDirectory"))),
    );
    if let Some(e) = node.get("Expiration") {
        o.insert("expiration".into(), e.clone());
    }
    for (out, field) in [("taker_pays", "TakerPays"), ("taker_gets", "TakerGets")] {
        o.insert(out.into(), node[field].clone());
    }
    Ok(Value::Object(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing required field gives an error with the key, not a
    /// line full of zeros.
    #[test]
    fn missing_required_fields_are_corrupt_state() {
        let me = [1u8; 20];
        let amount = |issuer: &[u8; 20], v: &str| json!({"currency": "USD", "issuer": xrpl_json::account(issuer), "value": v});
        let mut node = Map::new();
        node.insert("Flags".into(), json!(0));
        node.insert("LowLimit".into(), amount(&me, "10"));
        node.insert("HighLimit".into(), amount(&[2; 20], "0"));
        node.insert("Balance".into(), amount(&[0; 20], "5"));
        let k = [7u8; 32];
        let got = line(&k, &node, &me, None, false).unwrap().unwrap();
        assert_eq!(got["balance"], "5");
        let mut broken = node.clone();
        broken.remove("Balance");
        let e = line(&k, &broken, &me, None, false).unwrap_err();
        assert!(e.message.starts_with("corrupt_state"), "{}", e.message);
        let mut broken = node;
        broken.remove("HighLimit");
        assert!(line(&k, &broken, &me, None, false).is_err());
        assert!(
            offer(&k, &Map::new())
                .unwrap_err()
                .message
                .contains("TakerPays")
        );
    }

    #[test]
    fn cursor_round_trip_and_errors() {
        let mut p = Map::new();
        let k = [0xAB; 32];
        p.insert("marker".into(), json!(cursor_text(&k, 7)));
        assert_eq!(parse_cursor(&p).unwrap(), Some((k, 7)));
        p.insert("marker".into(), json!("AB,1"));
        assert_eq!(parse_cursor(&p).unwrap_err().message, "Malformed cursor.");
        p.insert("marker".into(), json!(1));
        assert_eq!(parse_cursor(&p).unwrap_err().message, "markerNotString");
    }

    #[test]
    fn negation_and_quality() {
        assert_eq!(negate("0"), "0");
        assert_eq!(negate("-1.5"), "1.5");
        assert_eq!(negate("2e-30"), "-2e-30");
        // Rate 1: mantissa 10^15, exponent −15 → exponent byte 85.
        let mut book = [0u8; 32];
        book[24..].copy_from_slice(&((85u64 << 56) | 1_000_000_000_000_000).to_be_bytes());
        assert_eq!(quality_text(&book), "1");
    }

    #[test]
    fn type_names_like_clio() {
        assert_eq!(kind_of("state").map(|t| t.0), Some("RippleState"));
        assert_eq!(kind_of("ripplestate").map(|t| t.0), Some("RippleState"));
        assert!(kind_of("nope").is_none());
        let mut p = Map::new();
        p.insert("type".into(), json!("fee"));
        assert!(type_filter(&p, true).is_err());
        assert_eq!(type_filter(&p, false).unwrap(), Some("FeeSettings"));
    }
}
