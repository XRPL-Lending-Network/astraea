//! Transaction and metadata codec with segment tables (experimental).
//!
//! In a per-ledger frame, zstd can't see repeats across ledgers: the same
//! object keys (LedgerIndex), PreviousTxnID, BookDirectory, accounts and
//! currencies show up in hundreds of neighboring ledgers. Segment tables of hashes
//! (32 bytes), accounts and currencies (20 each) seen at least twice, sorted by
//! descending frequency, are read once per segment; the frame stores the table
//! index instead of the value (varint, 0 means the value as is). Frames are still
//! per ledger, so random access to a single transaction is preserved.
//!
//! Parsing is the same as in `stobject` (`head`, `extent`); expansion must
//! return the original bytes, and the encoder checks this.

use std::collections::HashMap;

use witness_core::stobject::{self, ARRAY_END, OBJECT_END, types};

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

/// Table of values of one length: value → index from 1, by descending frequency.
#[derive(Debug, Default, Clone)]
pub struct Table<const N: usize> {
    pub values: Vec<[u8; N]>,
    index: HashMap<[u8; N], u32>,
}

impl<const N: usize> Table<N> {
    fn from_counts(counts: HashMap<[u8; N], u32>, min: u32) -> Table<N> {
        let mut v: Vec<([u8; N], u32)> = counts.into_iter().filter(|(_, c)| *c >= min).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let values: Vec<[u8; N]> = v.into_iter().map(|(k, _)| k).collect();
        let index = values
            .iter()
            .enumerate()
            .map(|(i, k)| (*k, i as u32 + 1))
            .collect();
        Table { values, index }
    }

    fn get(&self, n: u32) -> Res<&[u8; N]> {
        self.values
            .get(n as usize - 1)
            .ok_or_else(|| format!("index {n} outside a table of {}", self.values.len()))
    }

    /// Table as bytes: values in sequence.
    pub fn bytes(&self) -> Vec<u8> {
        self.values.iter().flatten().copied().collect()
    }

    pub fn from_bytes(b: &[u8]) -> Res<Table<N>> {
        if !b.len().is_multiple_of(N) {
            return Err("table is not a multiple of the value size".into());
        }
        let values: Vec<[u8; N]> = b.as_chunks::<N>().0.to_vec();
        let index = values
            .iter()
            .enumerate()
            .map(|(i, k)| (*k, i as u32 + 1))
            .collect();
        Ok(Table { values, index })
    }
}

/// Segment tables.
#[derive(Debug, Default, Clone)]
pub struct Tables {
    pub hashes: Table<32>,
    pub accounts: Table<20>,
    pub currencies: Table<20>,
}

impl Tables {
    /// Tables as bytes for storage: three u32 counters, then the values.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for n in [
            self.hashes.values.len(),
            self.accounts.values.len(),
            self.currencies.values.len(),
        ] {
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        out.extend(self.hashes.bytes());
        out.extend(self.accounts.bytes());
        out.extend(self.currencies.bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Res<Tables> {
        let count = |i: usize| -> Res<usize> {
            let x = b.get(i * 4..i * 4 + 4).ok_or("tables truncated")?;
            Ok(u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as usize)
        };
        let (h, a, c) = (count(0)?, count(1)?, count(2)?);
        let (hs, as_, cs) = (12, 12 + h * 32, 12 + h * 32 + a * 20);
        if b.len() != cs + c * 20 {
            return Err("table length does not match the counters".into());
        }
        Ok(Tables {
            hashes: Table::from_bytes(&b[hs..as_])?,
            accounts: Table::from_bytes(&b[as_..cs])?,
            currencies: Table::from_bytes(&b[cs..])?,
        })
    }
}

#[derive(Default)]
struct Counts {
    hashes: HashMap<[u8; 32], u32>,
    accounts: HashMap<[u8; 20], u32>,
    currencies: HashMap<[u8; 20], u32>,
}

/// What to do with a field value.
enum Slot {
    Hash,
    Account,
    /// Issued currency amount: 8 value bytes, currency, issuer.
    IouAmount,
    Raw,
}

fn slot(type_code: u16, value: &[u8], vl_ok: bool) -> Slot {
    match type_code {
        types::HASH256 => Slot::Hash,
        types::ACCOUNT if value.len() == 20 && vl_ok => Slot::Account,
        types::AMOUNT if value.len() == 48 => Slot::IouAmount,
        _ => Slot::Raw,
    }
}

/// Object fields or array elements (`array`): an array element is always
/// an object, whatever field names it.
fn parts(buf: &[u8], array: bool) -> Res<Vec<stobject::Field<'_>>> {
    if array {
        stobject::items(buf).map_err(e)
    } else {
        stobject::fields(buf).map_err(e)
    }
}

/// Walks object fields: `f(type, value, account of exactly 20 bytes)` for leaves.
fn walk(buf: &[u8], array: bool, depth: usize, f: &mut dyn FnMut(u16, &[u8], bool)) -> Res<()> {
    if depth > stobject::MAX_DEPTH {
        return Err("nesting too deep".into());
    }
    for fl in parts(buf, array)? {
        let t = fl.id.type_code;
        if array || t == types::OBJECT || t == types::ARRAY {
            walk(fl.value, !array && t == types::ARRAY, depth + 1, f)?;
        } else {
            f(t, fl.value, t != types::ACCOUNT || fl.value.len() == 20);
        }
    }
    Ok(())
}

impl Tables {
    /// Tables from segment objects: values seen `min` times or more.
    pub fn build<'a>(objects: impl Iterator<Item = &'a [u8]>, min: u32) -> Res<Tables> {
        let mut c = Counts::default();
        for o in objects {
            walk(o, false, 0, &mut |t, v, vl_ok| match slot(t, v, vl_ok) {
                Slot::Hash => *c.hashes.entry(v.try_into().unwrap_or([0; 32])).or_default() += 1,
                Slot::Account => {
                    *c.accounts
                        .entry(v.try_into().unwrap_or([0; 20]))
                        .or_default() += 1
                }
                Slot::IouAmount => {
                    *c.currencies
                        .entry(v[8..28].try_into().unwrap_or([0; 20]))
                        .or_default() += 1;
                    *c.accounts
                        .entry(v[28..48].try_into().unwrap_or([0; 20]))
                        .or_default() += 1;
                }
                Slot::Raw => {}
            })?;
        }
        Ok(Tables {
            hashes: Table::from_counts(c.hashes, min),
            accounts: Table::from_counts(c.accounts, min),
            currencies: Table::from_counts(c.currencies, min),
        })
    }
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_varint(b: &[u8], at: &mut usize) -> Res<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*at).ok_or("varint truncated")?;
        *at += 1;
        v |= u64::from(x & 0x7F) << shift;
        if x & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err("varint too long".into())
}

fn put_ref<const N: usize>(out: &mut Vec<u8>, t: &Table<N>, v: &[u8]) {
    match v.try_into().ok().and_then(|k: [u8; N]| t.index.get(&k)) {
        Some(n) => put_varint(out, u64::from(*n)),
        None => {
            out.push(0);
            out.extend_from_slice(v);
        }
    }
}

fn get_ref<const N: usize>(src: &[u8], at: &mut usize, t: &Table<N>, out: &mut Vec<u8>) -> Res<()> {
    let n = get_varint(src, at)?;
    if n == 0 {
        let v = src.get(*at..*at + N).ok_or("value truncated")?;
        out.extend_from_slice(v);
        *at += N;
    } else {
        out.extend_from_slice(t.get(u32::try_from(n).map_err(e)?)?);
    }
    Ok(())
}

/// Encodes an object: field headers and other values as is; hashes,
/// accounts, currencies and issuers as table indexes.
pub fn encode(buf: &[u8], t: &Tables, out: &mut Vec<u8>) -> Res<()> {
    encode_in(buf, false, t, out, 0)
}

fn encode_in(buf: &[u8], array: bool, t: &Tables, out: &mut Vec<u8>, depth: usize) -> Res<()> {
    if depth > stobject::MAX_DEPTH {
        return Err("nesting too deep".into());
    }
    for fl in parts(buf, array)? {
        let ty = fl.id.type_code;
        let (_, _, head_end) = stobject::head(fl.raw, 0).map_err(e)?;
        let header = &fl.raw[..head_end];
        if array || ty == types::OBJECT || ty == types::ARRAY {
            let inner_array = !array && ty == types::ARRAY;
            out.extend_from_slice(header);
            encode_in(fl.value, inner_array, t, out, depth + 1)?;
            out.push(if inner_array { ARRAY_END } else { OBJECT_END });
            continue;
        }
        match slot(ty, fl.value, true) {
            Slot::Hash => {
                out.extend_from_slice(header);
                put_ref(out, &t.hashes, fl.value);
            }
            Slot::IouAmount => {
                out.extend_from_slice(header);
                out.extend_from_slice(&fl.value[..8]);
                put_ref(out, &t.currencies, &fl.value[8..28]);
                put_ref(out, &t.accounts, &fl.value[28..48]);
            }
            // Account: table index, or 0 and the field as is with its original
            // length prefix, so that even the empty account `81 00` round-trips exactly.
            _ if ty == types::ACCOUNT => {
                out.extend_from_slice(header);
                match <[u8; 20]>::try_from(fl.value)
                    .ok()
                    .and_then(|k| t.accounts.index.get(&k))
                {
                    Some(n) => put_varint(out, u64::from(*n)),
                    None => {
                        out.push(0);
                        out.extend_from_slice(&fl.raw[head_end..]);
                    }
                }
            }
            _ => out.extend_from_slice(fl.raw),
        }
    }
    Ok(())
}

/// Expands an object of `len` source bytes from `src` starting at `at`.
pub fn decode(src: &[u8], at: &mut usize, len: usize, t: &Tables, out: &mut Vec<u8>) -> Res<()> {
    let start = out.len();
    while out.len() - start < len {
        decode_field(src, at, false, t, out, 0)?;
    }
    if out.len() - start != len {
        return Err("expanded object is longer than the original".into());
    }
    Ok(())
}

fn decode_field(
    src: &[u8],
    at: &mut usize,
    in_array: bool,
    t: &Tables,
    out: &mut Vec<u8>,
    depth: usize,
) -> Res<()> {
    if depth > stobject::MAX_DEPTH {
        return Err("nesting too deep".into());
    }
    let (ty, _, head_end) = stobject::head(src, *at).map_err(e)?;
    out.extend_from_slice(&src[*at..head_end]);
    *at = head_end;
    if in_array || ty == types::OBJECT || ty == types::ARRAY {
        let inner_array = !in_array && ty == types::ARRAY;
        let end = if inner_array { ARRAY_END } else { OBJECT_END };
        loop {
            let b = *src.get(*at).ok_or("object truncated")?;
            if b == end {
                out.push(end);
                *at += 1;
                return Ok(());
            }
            decode_field(src, at, inner_array, t, out, depth + 1)?;
        }
    }
    match ty {
        types::HASH256 => get_ref(src, at, &t.hashes, out),
        types::ACCOUNT => {
            // A table index means a 20-byte account with prefix 20; 0 means the field
            // as is, with its original length prefix.
            let n = get_varint(src, at)?;
            if n == 0 {
                let (value_at, len) = stobject::extent(src, *at, ty)
                    .map_err(e)?
                    .ok_or("unexpected type")?;
                let end = value_at + len;
                out.extend_from_slice(src.get(*at..end).ok_or("account truncated")?);
                *at = end;
            } else {
                out.push(20);
                out.extend_from_slice(t.accounts.get(u32::try_from(n).map_err(e)?)?);
            }
            Ok(())
        }
        types::AMOUNT if src.get(*at).is_some_and(|b| b & 0x80 != 0) => {
            out.extend_from_slice(src.get(*at..*at + 8).ok_or("amount truncated")?);
            *at += 8;
            get_ref(src, at, &t.currencies, out)?;
            get_ref(src, at, &t.accounts, out)
        }
        _ => {
            let (value_at, len) = stobject::extent(src, *at, ty)
                .map_err(e)?
                .ok_or("unexpected type")?;
            let end = value_at + len;
            out.extend_from_slice(src.get(*at..end).ok_or("value truncated")?);
            *at = end;
            Ok(())
        }
    }
}

/// Object in a frame: the source length as a varint with a flag in the low bit (1 if
/// the object was not parsed and is stored as is, so that early forms the parser doesn't
/// know don't break the segment), then the object itself.
fn put_object(out: &mut Vec<u8>, obj: &[u8], t: &Tables) -> bool {
    let mut enc = Vec::with_capacity(obj.len());
    let ok = encode(obj, t, &mut enc).is_ok() && {
        let (mut at, mut back) = (0, Vec::with_capacity(obj.len()));
        decode(&enc, &mut at, obj.len(), t, &mut back).is_ok() && at == enc.len() && back == obj
    };
    if ok {
        put_varint(out, (obj.len() as u64) << 1);
        out.extend_from_slice(&enc);
    } else {
        put_varint(out, ((obj.len() as u64) << 1) | 1);
        out.extend_from_slice(obj);
    }
    !ok
}

fn get_object(src: &[u8], at: &mut usize, t: &Tables) -> Res<Vec<u8>> {
    let v = get_varint(src, at)?;
    let len = usize::try_from(v >> 1).map_err(e)?;
    let mut out = Vec::with_capacity(len.min(1 << 24));
    if v & 1 == 1 {
        out.extend_from_slice(src.get(*at..*at + len).ok_or("object truncated")?);
        *at += len;
    } else {
        decode(src, at, len, t, &mut out)?;
    }
    Ok(out)
}

/// Ledger frame: the header as is, the transaction count, then for each transaction
/// the transaction and metadata (`put_object`). Each object is checked against
/// the source when written; on mismatch it is stored as is. Returns the frame and
/// the number of objects stored as is.
pub fn encode_frame(
    header: &[u8],
    txs: &[(Vec<u8>, Vec<u8>)],
    t: &Tables,
) -> Res<(Vec<u8>, usize)> {
    let mut out = header.to_vec();
    let mut literal = 0;
    put_varint(&mut out, txs.len() as u64);
    for (tx, meta) in txs {
        literal += usize::from(put_object(&mut out, tx, t));
        literal += usize::from(put_object(&mut out, meta, t));
    }
    Ok((out, literal))
}

/// Transaction `pos` (or all of them, `pos = None`) from a frame.
pub fn decode_frame(
    src: &[u8],
    header_len: usize,
    t: &Tables,
    pos: Option<usize>,
) -> Res<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut at = header_len;
    let n = get_varint(src, &mut at)? as usize;
    let mut out = Vec::new();
    for i in 0..n {
        let tx = get_object(src, &mut at, t)?;
        let meta = get_object(src, &mut at, t)?;
        if pos.is_none_or(|p| p == i) {
            out.push((tx, meta));
            if pos.is_some() {
                break;
            }
        }
    }
    if pos.is_none() && at != src.len() {
        return Err("trailing bytes after the frame".into());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Metadata as "views". FinalFields and PreviousFields of modified and
// deleted objects are relative to the object's current version: a field that matches
// it byte for byte is stored as a single header, the rest as usual.
// The encoder and decoder track the current version identically through the
// ledger: they start from the version at the start of the ledger (`Start`) and,
// after each transaction, apply its FinalFields and NewFields. Metadata is in
// execution order.
// ---------------------------------------------------------------------------

/// Object version at the start of the ledger; `None` means the object didn't exist or there is no version.
pub type Start<'a> = dyn Fn(&[u8; 32]) -> Option<Vec<u8>> + 'a;

type Fields = HashMap<(u16, u16), Vec<u8>>;

const AFFECTED_NODES: (u16, u16) = (types::ARRAY, 8);
const LEDGER_INDEX: (u16, u16) = (types::HASH256, 6);
const CREATED_NODE: u16 = 3;
const DELETED_NODE: u16 = 4;
const MODIFIED_NODE: u16 = 5;
const PREVIOUS_FIELDS: u16 = 6;
const FINAL_FIELDS: u16 = 7;
const NEW_FIELDS: u16 = 8;
const PREV_TXN_ID: (u16, u16) = (types::HASH256, 5);
const PREV_TXN_SEQ: (u16, u16) = (types::UINT32, 5);

/// Top-level object fields: (type, code) → the whole field.
fn field_map(obj: &[u8]) -> Fields {
    stobject::fields(obj)
        .map(|fs| {
            fs.into_iter()
                .map(|f| ((f.id.type_code, f.id.field_code), f.raw.to_vec()))
                .collect()
        })
        .unwrap_or_default()
}

/// Current versions of objects touched in the ledger.
struct Cur<'a> {
    map: HashMap<[u8; 32], Fields>,
    start: &'a Start<'a>,
}

impl Cur<'_> {
    fn get(&mut self, k: &[u8; 32]) -> &Fields {
        let start = self.start;
        self.map
            .entry(*k)
            .or_insert_with(|| start(k).map(|o| field_map(&o)).unwrap_or_default())
    }

    /// Applies a transaction's metadata: FinalFields and NewFields are the new
    /// field values, a deleted object is dropped; PreviousTxnID and
    /// PreviousTxnLgrSeq of a created or modified object now point to
    /// this transaction, so they match the node of the next touch.
    fn apply(&mut self, meta: &[u8], tx_id: &[u8; 32], seq: u32) {
        let Ok(fs) = stobject::fields(meta) else {
            return;
        };
        for f in fs
            .iter()
            .filter(|f| (f.id.type_code, f.id.field_code) == AFFECTED_NODES)
        {
            let Ok(nodes) = stobject::items(f.value) else {
                return;
            };
            for node in nodes {
                let Ok(inner) = stobject::fields(node.value) else {
                    continue;
                };
                let Some(key) = inner
                    .iter()
                    .find(|x| (x.id.type_code, x.id.field_code) == LEDGER_INDEX)
                    .and_then(|x| <[u8; 32]>::try_from(x.value).ok())
                else {
                    continue;
                };
                match node.id.field_code {
                    DELETED_NODE => {
                        self.map.remove(&key);
                    }
                    kind => {
                        let fields = inner.iter().find(|x| {
                            x.id.type_code == types::OBJECT
                                && x.id.field_code
                                    == if kind == CREATED_NODE {
                                        NEW_FIELDS
                                    } else {
                                        FINAL_FIELDS
                                    }
                        });
                        if kind == CREATED_NODE {
                            self.map.insert(key, Fields::new());
                        }
                        self.get(&key);
                        if let Some(ff) = fields
                            && let Ok(xs) = stobject::fields(ff.value)
                        {
                            let m = self.map.entry(key).or_default();
                            for x in xs {
                                m.insert((x.id.type_code, x.id.field_code), x.raw.to_vec());
                            }
                        }
                        let m = self.map.entry(key).or_default();
                        let mut id = vec![0x55];
                        id.extend_from_slice(tx_id);
                        m.insert(PREV_TXN_ID, id);
                        let mut sq = vec![0x25];
                        sq.extend_from_slice(&seq.to_be_bytes());
                        m.insert(PREV_TXN_SEQ, sq);
                    }
                }
            }
        }
    }
}

/// View of PreviousFields or FinalFields: field count, mask of changed fields, then
/// for each field either a header (matches the current version) or the field via the codec.
fn view_container(value: &[u8], current: &Fields, t: &Tables, out: &mut Vec<u8>) -> Res<()> {
    let fields = stobject::fields(value).map_err(e)?;
    put_varint(out, fields.len() as u64);
    let mut mask = vec![0u8; fields.len().div_ceil(8)];
    let mut body = Vec::new();
    for (j, f) in fields.iter().enumerate() {
        if current
            .get(&(f.id.type_code, f.id.field_code))
            .is_some_and(|v| *v == f.raw)
        {
            let (_, _, fh) = stobject::head(f.raw, 0).map_err(e)?;
            body.extend_from_slice(&f.raw[..fh]);
        } else {
            mask[j / 8] |= 1 << (j % 8);
            encode_in(f.raw, false, t, &mut body, 3)?;
        }
    }
    out.extend_from_slice(&mask);
    out.extend_from_slice(&body);
    Ok(())
}

fn unview_container(
    src: &[u8],
    at: &mut usize,
    current: &Fields,
    t: &Tables,
    out: &mut Vec<u8>,
) -> Res<()> {
    let n = usize::try_from(get_varint(src, at)?).map_err(e)?;
    if n > 1 << 16 {
        return Err("too many fields in view".into());
    }
    let mask = src
        .get(*at..*at + n.div_ceil(8))
        .ok_or("mask truncated")?
        .to_vec();
    *at += n.div_ceil(8);
    for j in 0..n {
        if mask[j / 8] & (1 << (j % 8)) != 0 {
            decode_field(src, at, false, t, out, 3)?;
        } else {
            copy_current(src, at, current, out)?;
        }
    }
    out.push(OBJECT_END);
    Ok(())
}

/// Field by header from the object's current version; the header must match.
fn copy_current(src: &[u8], at: &mut usize, current: &Fields, out: &mut Vec<u8>) -> Res<()> {
    let (ft, ff, fh) = stobject::head(src, *at).map_err(e)?;
    let v = current
        .get(&(ft, ff))
        .ok_or("field missing from the object's current version")?;
    if v.get(..fh - *at) != src.get(*at..fh) {
        return Err("view field header mismatch".into());
    }
    out.extend_from_slice(v);
    *at = fh;
    Ok(())
}

/// Metadata with views: top-level fields as usual, AffectedNodes
/// node by node; in a node of a modified or deleted object, PreviousFields and
/// FinalFields are a view against the current version.
fn encode_meta_view(meta: &[u8], t: &Tables, cur: &mut Cur<'_>, out: &mut Vec<u8>) -> Res<()> {
    for fl in stobject::fields(meta).map_err(e)? {
        if (fl.id.type_code, fl.id.field_code) != AFFECTED_NODES {
            encode_in(fl.raw, false, t, out, 1)?;
            continue;
        }
        let (_, _, head_end) = stobject::head(fl.raw, 0).map_err(e)?;
        out.extend_from_slice(&fl.raw[..head_end]);
        for node in stobject::items(fl.value).map_err(e)? {
            let (_, _, nh) = stobject::head(node.raw, 0).map_err(e)?;
            out.extend_from_slice(&node.raw[..nh]);
            let kind = node.id.field_code;
            let inner = stobject::fields(node.value).map_err(e)?;
            let key: Option<[u8; 32]> = inner
                .iter()
                .find(|x| (x.id.type_code, x.id.field_code) == LEDGER_INDEX)
                .and_then(|x| x.value.try_into().ok());
            let keyed = (kind == MODIFIED_NODE || kind == DELETED_NODE) && key.is_some();
            out.push(u8::from(keyed));
            if !keyed {
                for x in &inner {
                    encode_in(x.raw, false, t, out, 2)?;
                }
                out.push(OBJECT_END);
                continue;
            }
            let k = key.unwrap_or_default();
            put_ref(out, &t.hashes, &k);
            let current = cur.get(&k).clone();
            // Node fields: mask of "same as in the object's current version".
            put_varint(out, inner.len() as u64);
            let mut mask = vec![0u8; inner.len().div_ceil(8)];
            let mut body = Vec::new();
            for (j, x) in inner.iter().enumerate() {
                let id = (x.id.type_code, x.id.field_code);
                let (_, _, xh) = stobject::head(x.raw, 0).map_err(e)?;
                if id == LEDGER_INDEX {
                    body.extend_from_slice(&x.raw[..xh]);
                } else if x.id.type_code == types::OBJECT
                    && (x.id.field_code == PREVIOUS_FIELDS || x.id.field_code == FINAL_FIELDS)
                {
                    body.extend_from_slice(&x.raw[..xh]);
                    view_container(x.value, &current, t, &mut body)?;
                } else if current.get(&id).is_some_and(|v| *v == x.raw) {
                    mask[j / 8] |= 1 << (j % 8);
                    body.extend_from_slice(&x.raw[..xh]);
                } else {
                    encode_in(x.raw, false, t, &mut body, 2)?;
                }
            }
            out.extend_from_slice(&mask);
            out.extend_from_slice(&body);
            out.push(OBJECT_END);
        }
        out.push(ARRAY_END);
    }
    Ok(())
}

fn decode_meta_view(
    src: &[u8],
    at: &mut usize,
    len: usize,
    t: &Tables,
    cur: &mut Cur<'_>,
    out: &mut Vec<u8>,
) -> Res<()> {
    let start = out.len();
    while out.len() - start < len {
        let (ty, fc, head_end) = stobject::head(src, *at).map_err(e)?;
        if (ty, fc) != AFFECTED_NODES {
            decode_field(src, at, false, t, out, 1)?;
            continue;
        }
        out.extend_from_slice(&src[*at..head_end]);
        *at = head_end;
        loop {
            if *src.get(*at).ok_or("nodes truncated")? == ARRAY_END {
                out.push(ARRAY_END);
                *at += 1;
                break;
            }
            let (_, _, nh) = stobject::head(src, *at).map_err(e)?;
            out.extend_from_slice(&src[*at..nh]);
            *at = nh;
            let keyed = *src.get(*at).ok_or("node truncated")?;
            *at += 1;
            if keyed > 1 {
                return Err("node tag".into());
            }
            if keyed == 0 {
                loop {
                    if *src.get(*at).ok_or("node truncated")? == OBJECT_END {
                        out.push(OBJECT_END);
                        *at += 1;
                        break;
                    }
                    decode_field(src, at, false, t, out, 2)?;
                }
                continue;
            }
            let mut kb = Vec::with_capacity(32);
            get_ref(src, at, &t.hashes, &mut kb)?;
            let k: [u8; 32] = kb.try_into().map_err(|_| "node key")?;
            let current = cur.get(&k).clone();
            let n = usize::try_from(get_varint(src, at)?).map_err(e)?;
            if n > 1 << 16 {
                return Err("too many fields in node".into());
            }
            let mask = src
                .get(*at..*at + n.div_ceil(8))
                .ok_or("node mask truncated")?
                .to_vec();
            *at += n.div_ceil(8);
            for j in 0..n {
                let (xt, xf, xh) = stobject::head(src, *at).map_err(e)?;
                if (xt, xf) == LEDGER_INDEX {
                    out.extend_from_slice(&src[*at..xh]);
                    out.extend_from_slice(&k);
                    *at = xh;
                } else if xt == types::OBJECT && (xf == PREVIOUS_FIELDS || xf == FINAL_FIELDS) {
                    out.extend_from_slice(&src[*at..xh]);
                    *at = xh;
                    unview_container(src, at, &current, t, out)?;
                } else if mask[j / 8] & (1 << (j % 8)) != 0 {
                    copy_current(src, at, &current, out)?;
                } else {
                    decode_field(src, at, false, t, out, 2)?;
                }
            }
            if *src.get(*at).ok_or("node truncated")? != OBJECT_END {
                return Err("node not closed".into());
            }
            out.push(OBJECT_END);
            *at += 1;
        }
    }
    if out.len() - start != len {
        return Err("expanded metadata is longer than the original".into());
    }
    Ok(())
}

/// Metadata in a frame: the source length as a varint with the mode in the two low
/// bits: 0 codec with tables, 1 as is, 2 view.
fn put_meta(
    out: &mut Vec<u8>,
    meta: &[u8],
    thread: (&[u8; 32], u32),
    t: &Tables,
    cur: &mut Cur<'_>,
) -> u8 {
    let mut enc = Vec::with_capacity(meta.len());
    let mut mode = 1u8;
    if encode_meta_view(meta, t, cur, &mut enc).is_ok() {
        let (mut at, mut back) = (0, Vec::with_capacity(meta.len()));
        if decode_meta_view(&enc, &mut at, meta.len(), t, cur, &mut back).is_ok()
            && at == enc.len()
            && back == meta
        {
            mode = 2;
        }
    }
    if mode != 2 {
        enc.clear();
        if encode(meta, t, &mut enc).is_ok() {
            let (mut at, mut back) = (0, Vec::with_capacity(meta.len()));
            if decode(&enc, &mut at, meta.len(), t, &mut back).is_ok()
                && at == enc.len()
                && back == meta
            {
                mode = 0;
            }
        }
    }
    put_varint(out, ((meta.len() as u64) << 2) | u64::from(mode));
    if mode == 1 {
        out.extend_from_slice(meta);
    } else {
        out.extend_from_slice(&enc);
    }
    cur.apply(meta, thread.0, thread.1);
    mode
}

fn get_meta(
    src: &[u8],
    at: &mut usize,
    thread: (&[u8; 32], u32),
    t: &Tables,
    cur: &mut Cur<'_>,
) -> Res<Vec<u8>> {
    let v = get_varint(src, at)?;
    let len = usize::try_from(v >> 2).map_err(e)?;
    let mut out = Vec::with_capacity(len.min(1 << 24));
    match v & 3 {
        0 => decode(src, at, len, t, &mut out)?,
        1 => {
            out.extend_from_slice(src.get(*at..*at + len).ok_or("metadata truncated")?);
            *at += len;
        }
        2 => decode_meta_view(src, at, len, t, cur, &mut out)?,
        _ => return Err("unknown metadata mode".into()),
    }
    cur.apply(&out, thread.0, thread.1);
    Ok(out)
}

/// Ledger sequence from the header (first 4 bytes, big-endian).
fn ledger_seq(header: &[u8]) -> u32 {
    header
        .get(..4)
        .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Execution order: TransactionIndex at the start of the metadata (`20 1C`),
/// otherwise storage order.
fn execution_order(txs: &[(Vec<u8>, Vec<u8>)]) -> Vec<usize> {
    let idx: Vec<Option<u32>> = txs
        .iter()
        .map(|(_, m)| {
            (m.len() >= 6 && m[..2] == [0x20, 0x1C])
                .then(|| u32::from_be_bytes([m[2], m[3], m[4], m[5]]))
        })
        .collect();
    let mut order: Vec<usize> = (0..txs.len()).collect();
    if idx.iter().all(Option::is_some) {
        order.sort_by_key(|&i| idx[i]);
    }
    order
}

/// Counters for a frame with views: objects stored as is, and metadata by mode.
#[derive(Debug, Default, Clone, Copy)]
pub struct ViewStats {
    pub literal_tx: usize,
    pub meta_table: usize,
    pub meta_literal: usize,
    pub meta_view: usize,
}

/// Frame with views: header, transaction count, transactions in storage
/// order, then metadata in execution order (position index and
/// metadata). Each metadata blob is checked against the source when written.
pub fn encode_frame_views(
    header: &[u8],
    txs: &[(Vec<u8>, Vec<u8>)],
    t: &Tables,
    start: &Start<'_>,
) -> Res<(Vec<u8>, ViewStats)> {
    let mut out = header.to_vec();
    let mut st = ViewStats::default();
    put_varint(&mut out, txs.len() as u64);
    for (tx, _) in txs {
        st.literal_tx += usize::from(put_object(&mut out, tx, t));
    }
    let mut cur = Cur {
        map: HashMap::new(),
        start,
    };
    let seq = ledger_seq(header);
    for i in execution_order(txs) {
        put_varint(&mut out, i as u64);
        let id = witness_core::shamap::tx_id(&txs[i].0);
        match put_meta(&mut out, &txs[i].1, (&id, seq), t, &mut cur) {
            0 => st.meta_table += 1,
            1 => st.meta_literal += 1,
            _ => st.meta_view += 1,
        }
    }
    Ok((out, st))
}

/// Transactions of a frame with views; `pos` selects just one (metadata before it in
/// execution order is still expanded, since the current version depends on it).
pub fn decode_frame_views(
    src: &[u8],
    header_len: usize,
    t: &Tables,
    start: &Start<'_>,
    pos: Option<usize>,
) -> Res<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut at = header_len;
    let n = usize::try_from(get_varint(src, &mut at)?).map_err(e)?;
    if n > 1_000_000 {
        return Err("too many transactions in frame".into());
    }
    let mut txs = Vec::with_capacity(n);
    for _ in 0..n {
        txs.push(get_object(src, &mut at, t)?);
    }
    let mut metas: Vec<Option<Vec<u8>>> = vec![None; n];
    let mut cur = Cur {
        map: HashMap::new(),
        start,
    };
    let seq = ledger_seq(&src[..header_len.min(src.len())]);
    for _ in 0..n {
        let i = usize::try_from(get_varint(src, &mut at)?).map_err(e)?;
        if i >= n || metas[i].is_some() {
            return Err("metadata permutation".into());
        }
        let id = witness_core::shamap::tx_id(&txs[i]);
        metas[i] = Some(get_meta(src, &mut at, (&id, seq), t, &mut cur)?);
        if pos == Some(i) {
            let tx = txs.swap_remove(i);
            return Ok(vec![(tx, metas[i].take().unwrap_or_default())]);
        }
    }
    if at != src.len() {
        return Err("trailing bytes after the frame".into());
    }
    txs.into_iter()
        .zip(metas)
        .map(|(tx, m)| Ok((tx, m.ok_or("missing metadata")?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty account `81 00` and an all-zero account round-trip exactly.
    #[test]
    fn empty_and_zero_accounts_are_exact() {
        let zero = {
            let mut v = vec![0x81, 20];
            v.extend([0u8; 20]);
            v
        };
        for o in [vec![0x81, 0], zero] {
            for min in [1, 3] {
                let t = Tables::build([&o[..], &o[..]].into_iter(), min).unwrap();
                let mut enc = Vec::new();
                encode(&o, &t, &mut enc).unwrap();
                let (mut at, mut dec) = (0, Vec::new());
                decode(&enc, &mut at, o.len(), &t, &mut dec).unwrap();
                assert_eq!(dec, o);
                assert_eq!(at, enc.len());
            }
        }
    }

    /// An unparseable object goes into the frame as is and is restored.
    #[test]
    fn unparsable_object_is_kept_literally() {
        let bad = vec![0xE1, 0x00, 0x01];
        let ok = vec![0x81, 0];
        let txs = vec![(bad.clone(), ok.clone())];
        let t = Tables::default();
        let (f, literal) = encode_frame(&[7; 4], &txs, &t).unwrap();
        assert_eq!(literal, 1);
        assert_eq!(decode_frame(&f, 4, &t, None).unwrap(), txs);
    }

    #[test]
    fn roundtrip_with_and_without_table_hits() {
        // Object: Account (8,1), Hash256 (5,1), IOU amount (6,1), nested object with a hash.
        let mut o = vec![0x81, 20];
        o.extend([7u8; 20]);
        o.push(0x51);
        o.extend([9u8; 32]);
        o.push(0x61);
        let mut iou = vec![0xD4, 1, 2, 3, 4, 5, 6, 7];
        iou.extend([3u8; 20]);
        iou.extend([7u8; 20]);
        o.extend(&iou);
        o.extend([0xE2, 0x51]);
        o.extend([9u8; 32]);
        o.push(0xE1);
        for min in [1, 3] {
            let t = Tables::build([&o[..], &o[..]].into_iter(), min).unwrap();
            let mut enc = Vec::new();
            encode(&o, &t, &mut enc).unwrap();
            let (mut at, mut dec) = (0, Vec::new());
            decode(&enc, &mut at, o.len(), &t, &mut dec).unwrap();
            assert_eq!(dec, o);
            assert_eq!(at, enc.len());
            if min == 1 {
                assert!(enc.len() < o.len() / 2);
            }
        }
    }
}
