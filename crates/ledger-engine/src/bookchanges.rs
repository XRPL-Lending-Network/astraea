//! `book_changes`: for every order book touched in a ledger, the volumes that
//! crossed and the open, close, high and low rates, as in Clio 2.8
//! (`BookChangesHelper.hpp`) and xrpld (`BookChanges.h`).
//!
//! Only offers that were partly or fully consumed count: a created offer has
//! nothing crossed yet, and an offer deleted by the transaction's own
//! `OfferSequence` (OfferCancel, or OfferCreate replacing an offer) was cancelled.
//!
//! Rates and sums follow xrpld's `STAmount` arithmetic to the last digit:
//! `divide` scales both mantissas to 16 digits and keeps 17 more in the
//! quotient; additions go through `Number` in the large mantissa range
//! (19 digits) and are rounded back to the 16 digits of an issued amount,
//! both times to nearest with ties to even.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::xrpl_json::{self, number_text};

/// Issued amount: sign, mantissa in [10^15, 10^16) (0 for zero), exponent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Iou {
    neg: bool,
    m: u64,
    e: i32,
}

const IOU_ZERO: Iou = Iou {
    neg: false,
    m: 0,
    e: 0,
};
const MIN16: u128 = 1_000_000_000_000_000;
const MAX16: u128 = 9_999_999_999_999_999;
const MIN19: u128 = 1_000_000_000_000_000_000;
const MAX19: u128 = 9_999_999_999_999_999_999;
/// `Number::kMaxRepUp`: a larger 19-digit mantissa does not fit an int64 and
/// loses one more digit before rounding.
const MAX_REP_UP: u128 = 9_223_372_036_854_775_810;
/// Exponent range of an issued amount.
const MIN_EXP: i32 = -96;
const MAX_EXP: i32 = 80;

/// Drops digits until `v` is at most `max`, then rounds to nearest with ties to
/// even, like `Number::Guard`: `digit` is the highest dropped digit and `sticky`
/// tells whether anything below it was nonzero. Starts with an empty guard.
fn round_to(mut v: u128, mut e: i32, max: u128) -> (u128, i32) {
    let (mut digit, mut sticky) = (0u128, false);
    while v > max {
        sticky |= digit != 0;
        digit = v % 10;
        v /= 10;
        e += 1;
    }
    if digit > 5 || (digit == 5 && (sticky || v % 2 == 1)) {
        v += 1;
        if v > max {
            v /= 10;
            e += 1;
        }
    }
    (v, e)
}

/// An exact value as `Number` holds it in the large range: 19 digits, or 18
/// when the 19-digit mantissa would not fit an int64.
fn number(mut v: u128, mut e: i32) -> (u128, i32) {
    while v < MIN19 {
        v *= 10;
        e -= 1;
    }
    // The first 19 digits decide whether one more goes; all dropped digits
    // share one guard in xrpld, so this is a single rounding.
    let head = v / 10u128.pow(digits(v).saturating_sub(19));
    let max = if head > MAX_REP_UP { MAX19 / 10 } else { MAX19 };
    let (mut v, mut e) = round_to(v, e, max);
    while v < MIN19 {
        v *= 10;
        e -= 1;
    }
    (v, e)
}

fn digits(v: u128) -> u32 {
    v.checked_ilog10().map_or(1, |l| l + 1)
}

/// `IOUAmount` from a `Number`: rounded to 16 digits; too small is zero, too
/// large is an overflow (xrpld throws).
fn iou(neg: bool, v: u128, e: i32) -> Option<Iou> {
    if v == 0 {
        return Some(IOU_ZERO);
    }
    let (v, e) = round_to(v, e, MAX16);
    let (v, e) = {
        let (mut v, mut e) = (v, e);
        while v < MIN16 {
            v *= 10;
            e -= 1;
        }
        (v, e)
    };
    if e > MAX_EXP {
        return None;
    }
    if e < MIN_EXP {
        return Some(IOU_ZERO);
    }
    Some(Iou {
        neg,
        m: v as u64,
        e,
    })
}

/// `IOUAmount` addition: both sides go to `Number`, the sum comes back as an issued amount.
fn iou_add(a: Iou, b: Iou) -> Option<Iou> {
    if b.m == 0 {
        return Some(a);
    }
    if a.m == 0 {
        return Some(b);
    }
    let (hi, lo) = if a.e >= b.e { (a, b) } else { (b, a) };
    let d = (hi.e - lo.e) as u32;
    // Past 22 digits apart, the smaller side is below half a unit of the 19th
    // digit of the larger and only decides the rounding, which keeps the larger.
    if d > 22 {
        return Some(hi);
    }
    let signed = |x: Iou, scale: u32| {
        let v = i128::from(x.m) * 10i128.pow(scale);
        if x.neg { -v } else { v }
    };
    let s = signed(hi, d) + signed(lo, 0);
    if s == 0 {
        return Some(IOU_ZERO);
    }
    let (v, e) = number(s.unsigned_abs(), lo.e);
    iou(s < 0, v, e)
}

/// Amount of an offer side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Amount {
    Drops(i64),
    Iou(Iou),
    Mpt(i64),
}

impl Amount {
    fn is_zero(&self) -> bool {
        match *self {
            Amount::Drops(v) | Amount::Mpt(v) => v == 0,
            Amount::Iou(x) => x.m == 0,
        }
    }

    fn is_negative(&self) -> bool {
        match *self {
            Amount::Drops(v) | Amount::Mpt(v) => v < 0,
            Amount::Iou(x) => x.neg && x.m != 0,
        }
    }

    fn neg(self) -> Amount {
        match self {
            Amount::Drops(v) => Amount::Drops(-v),
            Amount::Mpt(v) => Amount::Mpt(-v),
            Amount::Iou(x) => Amount::Iou(Iou {
                neg: x.m != 0 && !x.neg,
                ..x
            }),
        }
    }

    fn add(self, o: Amount) -> Option<Amount> {
        match (self, o) {
            (Amount::Drops(a), Amount::Drops(b)) => a.checked_add(b).map(Amount::Drops),
            (Amount::Mpt(a), Amount::Mpt(b)) => a.checked_add(b).map(Amount::Mpt),
            (Amount::Iou(a), Amount::Iou(b)) => iou_add(a, b).map(Amount::Iou),
            _ => None,
        }
    }

    /// Mantissa, exponent and sign for `divide`; integral amounts are brought
    /// up to 16 digits first.
    fn for_divide(&self) -> (u128, i32, bool) {
        match *self {
            Amount::Drops(v) | Amount::Mpt(v) => {
                let (mut m, mut e) = (u128::from(v.unsigned_abs()), 0);
                if m != 0 {
                    while m < MIN16 {
                        m *= 10;
                        e -= 1;
                    }
                }
                (m, e, v < 0)
            }
            Amount::Iou(x) => (u128::from(x.m), x.e, x.neg),
        }
    }

    /// Volume as text: drops or MPT units as an integer, an issued amount as
    /// `to_string(IOUAmount)`.
    fn text(&self) -> String {
        match *self {
            Amount::Drops(v) | Amount::Mpt(v) => v.to_string(),
            Amount::Iou(x) => rate_text(x),
        }
    }
}

/// `divide(num, den, noIssue())`: the rate of a crossing.
fn divide(num: Amount, den: Amount) -> Option<Iou> {
    if num.is_zero() {
        return Some(IOU_ZERO);
    }
    let (nv, ne, nneg) = num.for_divide();
    let (dv, de, dneg) = den.for_divide();
    if dv == 0 {
        return None;
    }
    let q = nv * 100_000_000_000_000_000 / dv;
    if q > u128::from(u64::MAX) {
        return None;
    }
    let (v, e) = number(q + 5, ne - de - 17);
    iou(nneg != dneg, v, e)
}

/// `STAmount` order for rates.
fn less(a: Iou, b: Iou) -> bool {
    let (an, bn) = (a.neg && a.m != 0, b.neg && b.m != 0);
    if an != bn {
        return an;
    }
    if a.m == 0 {
        return !bn && b.m != 0;
    }
    if b.m == 0 {
        return false;
    }
    if a.e != b.e {
        return (a.e < b.e) != an;
    }
    (a.m < b.m) != an
}

/// `to_string(IOUAmount)`: through `Number`, large range.
fn rate_text(x: Iou) -> String {
    number_text(x.neg && x.m != 0, u128::from(x.m), x.e, 18)
}

/// Issued amount from its JSON text, as `STAmount::getText` wrote it: exact,
/// at most 16 digits.
fn parse_iou(s: &str) -> Option<Iou> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let (num, exp) = match s.split_once('e') {
        Some((n, x)) => (n, x.parse::<i32>().ok()?),
        None => (s, 0),
    };
    let (int, frac) = num.split_once('.').unwrap_or((num, ""));
    let digits = format!("{int}{frac}");
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(IOU_ZERO);
    }
    if trimmed.len() > 19 {
        return None;
    }
    let v: u128 = trimmed.parse().ok()?;
    let e = exp - frac.len() as i32;
    iou(neg, v, e)
}

/// Offer side from its JSON form, with the asset as `to_string(Asset)` writes it.
fn amount(v: &Value) -> Option<(Amount, String)> {
    match v {
        Value::String(s) => Some((Amount::Drops(s.parse().ok()?), "XRP".into())),
        Value::Object(o) => {
            let value = o.get("value")?.as_str()?;
            if let Some(id) = o.get("mpt_issuance_id").and_then(Value::as_str) {
                return Some((Amount::Mpt(value.parse().ok()?), id.to_owned()));
            }
            let currency = o.get("currency")?.as_str()?;
            let issuer = o.get("issuer")?.as_str()?;
            Some((
                Amount::Iou(parse_iou(value)?),
                format!("{issuer}/{currency}"),
            ))
        }
        _ => None,
    }
}

/// One order book in the ledger.
#[derive(Debug)]
struct Change {
    a: (Amount, String),
    b: (Amount, String),
    high: Iou,
    low: Iou,
    open: Iou,
    close: Iou,
    domain: Option<String>,
}

#[derive(Debug, Default)]
struct Tally {
    books: BTreeMap<String, Change>,
}

impl Tally {
    /// Transactions of one ledger, in the order of their hashes (as both Clio and
    /// xrpld walk them: it decides the open and close rates).
    fn transaction(&mut self, tx: &Map<String, Value>, meta: &Map<String, Value>) {
        if !tx.contains_key("TransactionType") {
            return;
        }
        let cancel = match tx.get("TransactionType").and_then(Value::as_str) {
            Some("OfferCancel" | "OfferCreate") => tx.get("OfferSequence").and_then(Value::as_u64),
            _ => None,
        };
        let nodes = meta
            .get("AffectedNodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|n| n.as_object()?.iter().next());
        for (kind, node) in nodes {
            if let Some(node) = node.as_object() {
                self.node(kind, node, cancel);
            }
        }
    }

    fn node(&mut self, kind: &str, node: &Map<String, Value>, cancel: Option<u64>) {
        if node.get("LedgerEntryType").and_then(Value::as_str) != Some("Offer")
            || kind == "CreatedNode"
        {
            return;
        }
        let (Some(ff), Some(pf)) = (
            node.get("FinalFields").and_then(Value::as_object),
            node.get("PreviousFields").and_then(Value::as_object),
        ) else {
            return;
        };
        let side = |o: &Map<String, Value>, f: &str| o.get(f).and_then(amount);
        let (Some(fg), Some(fp), Some(pg), Some(pp)) = (
            side(ff, "TakerGets"),
            side(ff, "TakerPays"),
            side(pf, "TakerGets"),
            side(pf, "TakerPays"),
        ) else {
            return;
        };
        if kind == "DeletedNode"
            && cancel.is_some()
            && ff.get("Sequence").and_then(Value::as_u64) == cancel
        {
            return;
        }
        let (Some(gets), Some(pays)) = (fg.0.add(pg.0.neg()), fp.0.add(pp.0.neg())) else {
            return;
        };
        let domain = ff
            .get("DomainID")
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.store((gets, fg.1), (pays, fp.1), domain);
    }

    fn store(&mut self, gets: (Amount, String), pays: (Amount, String), domain: Option<String>) {
        let xrp = |s: &(Amount, String)| matches!(s.0, Amount::Drops(_));
        let noswap = xrp(&gets) || (!xrp(&pays) && gets.1 < pays.1);
        let (mut first, mut second) = if noswap { (gets, pays) } else { (pays, gets) };
        if second.0.is_zero() {
            return;
        }
        let Some(rate) = divide(first.0, second.0) else {
            return;
        };
        if first.0.is_negative() {
            first.0 = first.0.neg();
        }
        if second.0.is_negative() {
            second.0 = second.0.neg();
        }
        let key = format!("{}|{}", first.1, second.1);
        match self.books.get_mut(&key) {
            None => {
                self.books.insert(
                    key,
                    Change {
                        a: first,
                        b: second,
                        high: rate,
                        low: rate,
                        open: rate,
                        close: rate,
                        domain,
                    },
                );
            }
            Some(c) => {
                let (Some(a), Some(b)) = (c.a.0.add(first.0), c.b.0.add(second.0)) else {
                    return;
                };
                c.a.0 = a;
                c.b.0 = b;
                if less(c.high, rate) {
                    c.high = rate;
                }
                if less(rate, c.low) {
                    c.low = rate;
                }
                c.close = rate;
                c.domain = domain;
            }
        }
    }

    fn json(self) -> Vec<Value> {
        let side = |s: &(Amount, String), cur: &str, mpt: &str, m: &mut Map<String, Value>| {
            match s.0 {
                Amount::Drops(_) => m.insert(cur.into(), json!("XRP_drops")),
                Amount::Mpt(_) => m.insert(mpt.into(), json!(s.1)),
                Amount::Iou(_) => m.insert(cur.into(), json!(s.1)),
            };
        };
        self.books
            .into_values()
            .map(|c| {
                let mut m = Map::new();
                side(&c.a, "currency_a", "mpt_issuance_id_a", &mut m);
                side(&c.b, "currency_b", "mpt_issuance_id_b", &mut m);
                m.insert("volume_a".into(), json!(c.a.0.text()));
                m.insert("volume_b".into(), json!(c.b.0.text()));
                m.insert("high".into(), json!(rate_text(c.high)));
                m.insert("low".into(), json!(rate_text(c.low)));
                m.insert("open".into(), json!(rate_text(c.open)));
                m.insert("close".into(), json!(rate_text(c.close)));
                if let Some(d) = c.domain {
                    m.insert("domain".into(), json!(d));
                }
                Value::Object(m)
            })
            .collect()
    }
}

/// The `changes` array for a ledger's transactions (binary transaction and
/// metadata). A transaction that does not parse is skipped, as in Clio.
pub fn compute(transactions: &[(Vec<u8>, Vec<u8>)]) -> Vec<Value> {
    let mut txs: Vec<([u8; 32], &[u8], &[u8])> = transactions
        .iter()
        .map(|(t, m)| (witness_core::shamap::tx_id(t), &t[..], &m[..]))
        .collect();
    txs.sort_by_key(|t| t.0);
    let mut tally = Tally::default();
    for (_, tx, meta) in txs {
        let (Ok(tx), Ok(meta)) = (xrpl_json::transaction(tx), xrpl_json::metadata(meta)) else {
            continue;
        };
        tally.transaction(&tx, &meta);
    }
    tally.json()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x(s: &str) -> Iou {
        parse_iou(s).unwrap()
    }

    #[test]
    fn issued_amounts_round_trip_through_text() {
        for s in [
            "0.044229388832",
            "892.44067",
            "1",
            "-12.5",
            "1234567890123456e-90",
            "9999999999999999e80",
            "0.000001",
        ] {
            assert_eq!(rate_text(x(s)), s, "{s}");
        }
        assert_eq!(x("0"), IOU_ZERO);
        assert_eq!(parse_iou("1.2.3"), None);
    }

    #[test]
    fn rates_divide_as_xrpld() {
        // From xrpld 3.4.1 book_changes on mainnet ledger 107998249.
        let r = divide(Amount::Drops(-100), Amount::Iou(x("-0.044229388832"))).unwrap();
        assert_eq!(rate_text(r), "2260.940126933202");
        let r = divide(Amount::Drops(-712_300_000), Amount::Iou(x("-892.44067"))).unwrap();
        assert_eq!(rate_text(r), "798148.2959533882");
        let r = divide(Amount::Drops(-5_730_000), Amount::Iou(x("-7.178051"))).unwrap();
        assert_eq!(rate_text(r), "798266.827583142");
    }

    #[test]
    fn rounding_is_to_nearest_ties_to_even() {
        assert_eq!(round_to(12345, 0, 9999), (1234, 1));
        assert_eq!(round_to(12355, 0, 9999), (1236, 1));
        assert_eq!(round_to(12350, 0, 9999), (1235, 1));
        assert_eq!(round_to(12250, 0, 9999), (1225, 1));
        assert_eq!(round_to(1225, 0, 999), (122, 1));
        assert_eq!(round_to(12251, 0, 999), (123, 2));
        assert_eq!(round_to(99_999, 0, 9999), (1000, 2));
    }

    #[test]
    fn sums_keep_sixteen_digits() {
        let s = iou_add(x("1"), x("0.0000000000000001")).unwrap();
        assert_eq!(rate_text(s), "1");
        let s = iou_add(x("1"), x("0.000000000000001")).unwrap();
        assert_eq!(rate_text(s), "1.000000000000001");
        let s = iou_add(x("1"), x("-1")).unwrap();
        assert_eq!(s, IOU_ZERO);
        let s = iou_add(x("1e40"), x("1")).unwrap();
        assert_eq!(rate_text(s), "1e40");
    }

    #[test]
    fn rates_order_like_stamount() {
        assert!(less(x("1"), x("2")));
        assert!(less(x("-2"), x("-1")));
        assert!(less(x("-1"), IOU_ZERO));
        assert!(less(IOU_ZERO, x("0.1")));
        assert!(less(x("0.9"), x("1")));
        assert!(!less(x("1"), x("1")));
    }
}
