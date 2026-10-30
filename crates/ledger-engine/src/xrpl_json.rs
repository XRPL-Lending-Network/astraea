//! XRPL binary objects as JSON, the same way `getJson` does it in xrpld.
//!
//! Clio builds the JSON in its responses by calling `getJson` from libxrpl, so
//! compatibility with Clio means character-for-character compatibility with xrpld: field names,
//! amounts as text, UInt64 as lowercase hex (five MPT fields
//! as decimal), currency codes, and the names of transaction types, objects and
//! results. Field and type names come from `server_definitions` of xrpld 3.4.1
//! (`definitions.json` next to the crate), not from memory.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::{Map, Value, json};
use witness_core::keys::encode_base58;
use witness_core::shamap::tx_id;
use witness_core::stobject::{self, Field, types};

/// UInt64 fields that xrpld writes as decimal (`kSmdBaseTen`): MaximumAmount,
/// OutstandingAmount, MPTAmount, LockedAmount, ConfidentialOutstandingAmount.
const BASE_TEN_UINT64: [u16; 5] = [24, 25, 26, 29, 32];

/// Granular delegation permissions (xrpld permissions.macro): values start at
/// 65537. Other values are the transaction type plus one.
const GRANULAR_PERMISSIONS: [&str; 12] = [
    "TrustlineAuthorize",
    "TrustlineFreeze",
    "TrustlineUnfreeze",
    "AccountDomainSet",
    "AccountEmailHashSet",
    "AccountMessageKeySet",
    "AccountTransferRateSet",
    "AccountTickSizeSet",
    "PaymentMint",
    "PaymentBurn",
    "MPTokenIssuanceLock",
    "MPTokenIssuanceUnlock",
];

/// Name tables from `server_definitions`.
#[derive(Debug)]
pub struct Definitions {
    fields: HashMap<(u16, u16), String>,
    transaction_types: HashMap<u16, String>,
    ledger_entry_types: HashMap<u16, String>,
    results: HashMap<i32, String>,
    permission_value: Option<(u16, u16)>,
}

fn load() -> Result<Definitions, String> {
    let d: Value =
        serde_json::from_str(include_str!("../definitions.json")).map_err(|e| e.to_string())?;
    let types = d["TYPES"].as_object().ok_or("TYPES")?;
    let mut fields = HashMap::new();
    let mut permission_value = None;
    for f in d["FIELDS"].as_array().ok_or("FIELDS")? {
        let (Some(name), Some(info)) = (f[0].as_str(), f[1].as_object()) else {
            continue;
        };
        let (Some(t), Some(nth)) = (
            info.get("type")
                .and_then(Value::as_str)
                .and_then(|t| types.get(t))
                .and_then(Value::as_i64),
            info.get("nth").and_then(Value::as_i64),
        ) else {
            continue;
        };
        if !(1..=255).contains(&t) || !(1..=255).contains(&nth) {
            continue;
        }
        let key = (t as u16, nth as u16);
        if name == "PermissionValue" {
            permission_value = Some(key);
        }
        fields.insert(key, name.to_owned());
    }
    let invert = |k: &str| -> Result<HashMap<i64, String>, String> {
        Ok(d[k]
            .as_object()
            .ok_or(k.to_owned())?
            .iter()
            .filter_map(|(n, v)| v.as_i64().map(|v| (v, n.clone())))
            .collect())
    };
    let u16s = |m: HashMap<i64, String>| {
        m.into_iter()
            .filter_map(|(k, v)| u16::try_from(k).ok().map(|k| (k, v)))
            .collect()
    };
    Ok(Definitions {
        fields,
        transaction_types: u16s(invert("TRANSACTION_TYPES")?),
        ledger_entry_types: u16s(invert("LEDGER_ENTRY_TYPES")?),
        results: invert("TRANSACTION_RESULTS")?
            .into_iter()
            .filter_map(|(k, v)| i32::try_from(k).ok().map(|k| (k, v)))
            .collect(),
        permission_value,
    })
}

pub fn definitions() -> &'static Definitions {
    static DEFS: OnceLock<Definitions> = OnceLock::new();
    DEFS.get_or_init(|| match load() {
        Ok(d) => d,
        // The file is embedded in the binary and checked by a test: unreachable.
        Err(e) => panic!("definitions.json: {e}"),
    })
}

impl Definitions {
    pub fn transaction_type(&self, code: u16) -> Option<&str> {
        self.transaction_types.get(&code).map(String::as_str)
    }

    pub fn ledger_entry_type(&self, code: u16) -> Option<&str> {
        self.ledger_entry_types.get(&code).map(String::as_str)
    }

    pub fn ledger_entry_code(&self, name: &str) -> Option<u16> {
        self.ledger_entry_types
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(name))
            .map(|(c, _)| *c)
    }

    pub fn field_name(&self, type_code: u16, field_code: u16) -> Option<&str> {
        self.fields
            .get(&(type_code, field_code))
            .map(String::as_str)
    }

    pub fn result(&self, code: i32) -> Option<&str> {
        self.results.get(&code).map(String::as_str)
    }
}

pub fn account(a: &[u8]) -> String {
    encode_base58(0, a)
}

fn hex_upper(b: &[u8]) -> String {
    hex::encode_upper(b)
}

fn be_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

/// Currency code as text: XRP, a three-letter ISO code, or 40 hex chars.
pub fn currency(c: &[u8]) -> String {
    const ISO: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789<>(){}[]|?!@#$%^&*";
    if c.iter().all(|b| *b == 0) {
        return "XRP".into();
    }
    let mut no_currency = [0u8; 20];
    no_currency[19] = 1;
    if c == no_currency {
        return "1".into();
    }
    let iso_bits_zero = c[..12].iter().all(|b| *b == 0) && c[15..].iter().all(|b| *b == 0);
    if iso_bits_zero {
        let code = &c[12..15];
        if code != b"XRP" && code.iter().all(|b| ISO.as_bytes().contains(b)) {
            return String::from_utf8_lossy(code).into_owned();
        }
    }
    hex_upper(c)
}

/// Text form of an issued currency amount, following `STAmount::getText`.
pub fn iou_text(negative: bool, mantissa: u64, offset: i32) -> String {
    if mantissa == 0 {
        return "0".into();
    }
    let raw = mantissa.to_string();
    let mut ret = String::new();
    if negative {
        ret.push('-');
    }
    let scientific = offset != 0 && !(-25..=-5).contains(&offset);
    if scientific {
        ret.push_str(&raw);
        ret.push('e');
        ret.push_str(&offset.to_string());
        return ret;
    }
    decimal(&mut ret, &raw, offset as isize + 43, 27, 23);
    ret
}

/// Integer and fractional parts without extra zeros: the part shared by `STAmount::getText`
/// and `to_string(Number)`: mantissa digits padded with zeros, decimal point at
/// `offset` from the start.
fn decimal(ret: &mut String, raw: &str, offset: isize, pad_prefix: usize, pad_suffix: usize) {
    let val = format!("{}{raw}{}", "0".repeat(pad_prefix), "0".repeat(pad_suffix));
    let v = val.as_bytes();
    let offset = offset.clamp(0, v.len() as isize) as usize;
    let mut pre_from = 0;
    if offset > pad_prefix {
        pre_from = pad_prefix;
    }
    while pre_from < offset && v[pre_from] == b'0' {
        pre_from += 1;
    }
    let mut post_to = v.len();
    if post_to - offset > pad_suffix {
        post_to -= pad_suffix;
    }
    while post_to > offset && v[post_to - 1] == b'0' {
        post_to -= 1;
    }
    if pre_from == offset {
        ret.push('0');
    } else {
        ret.push_str(&val[pre_from..offset]);
    }
    if post_to != offset {
        ret.push('.');
        ret.push_str(&val[offset..post_to]);
    }
}

/// Amount: XRP is a string in drops; issued currencies and MPT are objects.
pub fn amount(v: &[u8]) -> Value {
    match v.len() {
        48 => {
            let x = be_u64(v);
            let negative = x & 0x4000_0000_0000_0000 == 0;
            let mantissa = x & ((1 << 54) - 1);
            let offset = ((x >> 54) & 0xFF) as i32 - 97;
            json!({
                "currency": currency(&v[8..28]),
                "issuer": account(&v[28..48]),
                "value": iou_text(negative && mantissa != 0, mantissa, offset),
            })
        }
        33 => {
            let negative = v[0] & 0x40 == 0;
            let value = be_u64(&v[1..9]);
            let text = if negative && value != 0 {
                format!("-{value}")
            } else {
                value.to_string()
            };
            json!({ "mpt_issuance_id": hex_upper(&v[9..33]), "value": text })
        }
        _ => {
            let x = be_u64(v);
            let drops = x & 0x3FFF_FFFF_FFFF_FFFF;
            let negative = x & 0x4000_0000_0000_0000 == 0 && drops != 0;
            Value::String(if negative {
                format!("-{drops}")
            } else {
                drops.to_string()
            })
        }
    }
}

/// Number: an i64 mantissa and i32 exponent, normalized to the range
/// [10^15, 10^16), as Number in xrpld with the small mantissa range.
pub fn number(v: &[u8]) -> String {
    let m = i64::from_be_bytes(v[..8].try_into().unwrap_or_default());
    let e = i32::from_be_bytes(v[8..12].try_into().unwrap_or_default());
    number_text(m < 0, u128::from(m.unsigned_abs()), e, 15)
}

/// `to_string(Number)` in xrpld for a mantissa range of [10^log, 10^(log+1)):
/// 15 is the small range, 18 the large one.
pub(crate) fn number_text(negative: bool, mantissa: u128, exponent: i32, range_log: i32) -> String {
    if mantissa == 0 {
        return "0".into();
    }
    let min = 10u128.pow(range_log as u32);
    let max = min * 10 - 1;
    let (mut mantissa, mut exponent) = (mantissa, exponent);
    while mantissa < min {
        mantissa *= 10;
        exponent -= 1;
    }
    while mantissa > max {
        mantissa /= 10;
        exponent += 1;
    }
    let mut ret = String::new();
    if negative {
        ret.push('-');
    }
    if exponent != 0 && (exponent < -(range_log + 10) || exponent > -(range_log - 10)) {
        while mantissa % 10 == 0 {
            mantissa /= 10;
            exponent += 1;
        }
        ret.push_str(&mantissa.to_string());
        if exponent != 0 {
            ret.push('e');
            ret.push_str(&exponent.to_string());
        }
        return ret;
    }
    let pad_prefix = (range_log + 12) as usize;
    let pad_suffix = (range_log + 8) as usize;
    let offset = exponent as isize + pad_prefix as isize + range_log as isize + 1;
    decimal(
        &mut ret,
        &mantissa.to_string(),
        offset,
        pad_prefix,
        pad_suffix,
    );
    ret
}

fn issue(v: &[u8]) -> Value {
    match v.len() {
        20 => json!({ "currency": "XRP" }),
        44 => {
            // MPT: issuer, "no account", issuance sequence; the MPTID is the sequence plus the issuer.
            let mut id = Vec::with_capacity(24);
            id.extend_from_slice(&v[40..44]);
            id.extend_from_slice(&v[..20]);
            json!({ "mpt_issuance_id": hex_upper(&id) })
        }
        _ => json!({ "currency": currency(&v[..20]), "issuer": account(&v[20..40]) }),
    }
}

fn pathset(v: &[u8]) -> Value {
    let mut paths = Vec::new();
    let mut path = Vec::new();
    let mut at = 0;
    while at < v.len() {
        let t = v[at];
        at += 1;
        match t {
            0x00 => break,
            0xFF => {
                paths.push(Value::Array(std::mem::take(&mut path)));
                continue;
            }
            _ => {}
        }
        let mut step = Map::new();
        step.insert("type".into(), json!(t));
        let take20 = |at: &mut usize| {
            let s = &v[*at..(*at + 20).min(v.len())];
            *at += 20;
            s
        };
        if t & 0x01 != 0 {
            step.insert("account".into(), json!(account(take20(&mut at))));
        }
        if t & 0x10 != 0 {
            step.insert("currency".into(), json!(currency(take20(&mut at))));
        }
        if t & 0x20 != 0 {
            step.insert("issuer".into(), json!(account(take20(&mut at))));
        }
        path.push(Value::Object(step));
    }
    paths.push(Value::Array(path));
    Value::Array(paths)
}

fn xchain_bridge(v: &[u8]) -> Value {
    // Door (length 20 and account), Issue, door, Issue: stobject parses the Issue
    // lengths; here they have to be found again.
    let issue_len = |at: usize| -> usize {
        if v[at..at + 20].iter().all(|b| *b == 0) {
            20
        } else {
            40
        }
    };
    let mut at = 1;
    let locking_door = account(&v[at..at + 20]);
    at += 20;
    let l1 = issue_len(at);
    let locking_issue = issue(&v[at..at + l1]);
    at += l1 + 1;
    let issuing_door = account(&v[at..at + 20]);
    at += 20;
    let l2 = issue_len(at);
    let issuing_issue = issue(&v[at..at + l2]);
    json!({
        "LockingChainDoor": locking_door,
        "LockingChainIssue": locking_issue,
        "IssuingChainDoor": issuing_door,
        "IssuingChainIssue": issuing_issue,
    })
}

fn field_value(d: &Definitions, f: &Field<'_>) -> Result<Value, String> {
    let v = f.value;
    let id = f.id;
    Ok(match id.type_code {
        types::UINT8 => {
            if (id.type_code, id.field_code) == (types::UINT8, 3) {
                match d.result(i32::from(v[0])) {
                    Some(n) => json!(n),
                    None => json!(v[0]),
                }
            } else {
                json!(v[0])
            }
        }
        types::UINT16 => {
            let n = u16::from_be_bytes([v[0], v[1]]);
            let name = match id.field_code {
                1 => d.ledger_entry_type(n),
                2 => d.transaction_type(n),
                _ => None,
            };
            name.map_or(json!(n), |s| json!(s))
        }
        types::UINT32 => {
            let n = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
            if Some((id.type_code, id.field_code)) == d.permission_value {
                let name = if n > 65536 {
                    GRANULAR_PERMISSIONS.get((n - 65537) as usize).copied()
                } else if n > 0 {
                    u16::try_from(n - 1)
                        .ok()
                        .and_then(|t| d.transaction_type(t))
                } else {
                    None
                };
                if let Some(name) = name {
                    return Ok(json!(name));
                }
            }
            json!(n)
        }
        types::UINT64 => {
            let n = be_u64(v);
            if BASE_TEN_UINT64.contains(&id.field_code) {
                json!(n.to_string())
            } else {
                json!(format!("{n:x}"))
            }
        }
        types::INT32 => json!(i32::from_be_bytes([v[0], v[1], v[2], v[3]])),
        types::INT64 => json!(be_u64(v) as i64),
        types::HASH128
        | types::HASH160
        | types::HASH192
        | types::HASH256
        | types::UINT384
        | types::UINT512
        | types::UINT96
        | types::BLOB => json!(hex_upper(v)),
        types::AMOUNT => amount(v),
        types::ACCOUNT => json!(account(v)),
        types::NUMBER => json!(number(v)),
        types::OBJECT => object(d, v)?,
        types::ARRAY => {
            let mut out = Vec::new();
            for item in stobject::items(v).map_err(|e| e.to_string())? {
                let mut m = Map::new();
                m.insert(name(d, &item)?, object(d, item.value)?);
                out.push(Value::Object(m));
            }
            Value::Array(out)
        }
        types::PATHSET => pathset(v),
        types::VECTOR256 => Value::Array(v.chunks(32).map(|c| json!(hex_upper(c))).collect()),
        types::ISSUE => issue(v),
        types::XCHAIN_BRIDGE => xchain_bridge(v),
        types::CURRENCY => json!(currency(v)),
        t => return Err(format!("field type {t} is not supported")),
    })
}

fn name(d: &Definitions, f: &Field<'_>) -> Result<String, String> {
    d.fields
        .get(&(f.id.type_code, f.id.field_code))
        .cloned()
        .ok_or_else(|| format!("unknown field {}:{}", f.id.type_code, f.id.field_code))
}

/// A whole STObject as JSON.
pub fn object(d: &Definitions, buf: &[u8]) -> Result<Value, String> {
    let mut m = Map::new();
    for f in stobject::fields(buf).map_err(|e| e.to_string())? {
        m.insert(name(d, &f)?, field_value(d, &f)?);
    }
    Ok(Value::Object(m))
}

/// Transaction: fields and `hash`, as in `STTx::getJson`.
pub fn transaction(tx: &[u8]) -> Result<Map<String, Value>, String> {
    let Value::Object(mut m) = object(definitions(), tx)? else {
        return Err("transaction is not an object".into());
    };
    m.insert("hash".into(), json!(hex_upper(&tx_id(tx))));
    Ok(m)
}

/// State object: fields and `index`, as in `STLedgerEntry::getJson`.
pub fn ledger_entry(key: &[u8; 32], data: &[u8]) -> Result<Map<String, Value>, String> {
    let Value::Object(mut m) = object(definitions(), data)? else {
        return Err("state object is not an object".into());
    };
    m.insert("index".into(), json!(hex_upper(key)));
    Ok(m)
}

pub fn metadata(meta: &[u8]) -> Result<Map<String, Value>, String> {
    match object(definitions(), meta)? {
        Value::Object(m) => Ok(m),
        _ => Err("metadata is not an object".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definitions_load() {
        let d = load().unwrap();
        assert_eq!(d.transaction_type(0), Some("Payment"));
        assert_eq!(d.ledger_entry_type(0x61), Some("AccountRoot"));
        assert_eq!(d.result(0), Some("tesSUCCESS"));
        assert_eq!(d.fields.get(&(8, 1)).map(String::as_str), Some("Account"));
    }

    #[test]
    fn amounts_render_like_xrpld() {
        // XRP: 1000 drops, positive.
        let mut xrp = (0x4000_0000_0000_0000u64 | 1000).to_be_bytes().to_vec();
        assert_eq!(amount(&xrp), json!("1000"));
        xrp = 1000u64.to_be_bytes().to_vec();
        assert_eq!(amount(&xrp), json!("-1000"));
        // IOU: 1.5 = 1500000000000000e-15.
        let enc = |neg: bool, m: u64, e: i32| {
            let mut x = 0x8000_0000_0000_0000u64 | m | (((e + 97) as u64) << 54);
            if !neg {
                x |= 0x4000_0000_0000_0000;
            }
            let mut v = x.to_be_bytes().to_vec();
            let mut cur = [0u8; 20];
            cur[12..15].copy_from_slice(b"USD");
            v.extend(cur);
            v.extend([1u8; 20]);
            v
        };
        let text = |v: &Vec<u8>| amount(v)["value"].as_str().unwrap().to_owned();
        assert_eq!(text(&enc(false, 1_500_000_000_000_000, -15)), "1.5");
        assert_eq!(text(&enc(true, 1_000_000_000_000_000, -15)), "-1");
        assert_eq!(
            text(&enc(false, 1_234_567_890_123_456, -3)),
            "1234567890123456e-3"
        );
        assert_eq!(
            text(&enc(false, 1_000_000_000_000_000, -30)),
            "1000000000000000e-30"
        );
        assert_eq!(text(&enc(false, 1_200_000_000_000_000, -20)), "0.000012");
        assert_eq!(amount(&enc(false, 1, -15))["currency"], json!("USD"));
    }

    #[test]
    fn currency_codes() {
        let mut c = [0u8; 20];
        assert_eq!(currency(&c), "XRP");
        c[12..15].copy_from_slice(b"EUR");
        assert_eq!(currency(&c), "EUR");
        c[0] = 0x53;
        assert_eq!(currency(&c).len(), 40);
    }

    #[test]
    fn numbers() {
        let enc = |m: i64, e: i32| {
            let mut v = m.to_be_bytes().to_vec();
            v.extend(e.to_be_bytes());
            v
        };
        assert_eq!(number(&enc(15, -1)), "1.5");
        assert_eq!(number(&enc(-2, 0)), "-2");
        assert_eq!(number(&enc(0, 5)), "0");
    }
}
