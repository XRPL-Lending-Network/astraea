//! ASTJ, the codec of Astraea's cold history: an exact structural transposition
//! of each ledger with a shared value journal. Transactions, metadata, patches,
//! record order and framing come back unchanged.
pub mod fast;
mod joint;
/// Pool of prepared blocks.
pub mod pool;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use witness_core::{ledger::LedgerHeader, sha512_half, shamap, stobject};
type Res<T> = Result<T, String>;
const MAX: usize = 256 << 20;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub seq: u32,
    pub header: Vec<u8>,
    pub txs: Vec<(Vec<u8>, Vec<u8>)>,
    pub patches: Vec<([u8; 32], Vec<u8>)>,
}
/// Digest of checked block bytes in a seal (`pool`): the directory hash and
/// the stored bytes.
pub(crate) fn seal_digest(hash: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(b"XWCS");
    h.update(hash);
    h.update(bytes);
    let mut out = [0; 32];
    out.copy_from_slice(&h.finalize()[..32]);
    out
}
fn er<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
fn put(out: &mut Vec<u8>, mut n: u64) {
    while n >= 128 {
        out.push(n as u8 | 128);
        n >>= 7;
    }
    out.push(n as u8)
}
fn blob(out: &mut Vec<u8>, b: &[u8]) {
    put(out, b.len() as u64);
    out.extend(b)
}
struct Read<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Read<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or("length overflow")?;
        let x = self.b.get(self.p..end).ok_or("truncated")?;
        self.p = end;
        Ok(x)
    }
    fn byte(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }
    fn var(&mut self) -> Res<u64> {
        let mut n = 0;
        for shift in (0..64).step_by(7) {
            let x = self.byte()?;
            if shift == 63 && x > 1 {
                return Err("varint overflow".into());
            }
            n |= u64::from(x & 127) << shift;
            if x < 128 {
                return Ok(n);
            }
        }
        Err("varint overflow".into())
    }
    fn count(&mut self) -> Res<usize> {
        let n = usize::try_from(self.var()?).map_err(er)?;
        if n > MAX {
            return Err("count limit".into());
        }
        Ok(n)
    }
    /// Count of records that each take at least one more input byte: a
    /// damaged count cannot allocate beyond the size of the input.
    fn items(&mut self) -> Res<usize> {
        let n = self.count()?;
        if n > self.b.len() - self.p {
            return Err("count exceeds input".into());
        }
        Ok(n)
    }
    fn blob(&mut self) -> Res<&'a [u8]> {
        let n = self.count()?;
        self.take(n)
    }
    fn array<const N: usize>(&mut self) -> Res<[u8; N]> {
        self.take(N)?.try_into().map_err(er)
    }
    fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn oldblob(&mut self) -> Res<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn end(&self) -> Res<()> {
        if self.p == self.b.len() {
            Ok(())
        } else {
            Err("trailing bytes".into())
        }
    }
}
pub fn load_rows(bytes: &[u8]) -> Res<Vec<Row>> {
    let mut r = Read::new(bytes);
    let n = r.u32()?;
    if n > 1_000_000 {
        return Err("row limit".into());
    }
    let mut rows = vec![];
    for _ in 0..n {
        let mut b = Read::new(r.oldblob()?);
        let seq = b.u32()?;
        let header = b.oldblob()?.to_vec();
        let nt = b.u32()?;
        if nt > 1_000_000 {
            return Err("tx count".into());
        }
        let mut txs = vec![];
        for _ in 0..nt {
            txs.push((b.oldblob()?.to_vec(), b.oldblob()?.to_vec()))
        }
        let np = b.u32()?;
        if np > 10_000_000 {
            return Err("patch count".into());
        }
        let mut patches = vec![];
        for _ in 0..np {
            let key = b.array()?;
            patches.push((key, b.oldblob()?.to_vec()))
        }
        b.end()?;
        rows.push(Row {
            seq,
            header,
            txs,
            patches,
        })
    }
    r.end()?;
    Ok(rows)
}
pub fn rows_bytes(rows: &[Row]) -> Vec<u8> {
    fn bb(o: &mut Vec<u8>, b: &[u8]) {
        o.extend((b.len() as u32).to_le_bytes());
        o.extend(b)
    }
    let mut out = (rows.len() as u32).to_le_bytes().to_vec();
    for r in rows {
        let mut b = r.seq.to_le_bytes().to_vec();
        bb(&mut b, &r.header);
        b.extend((r.txs.len() as u32).to_le_bytes());
        for (t, m) in &r.txs {
            bb(&mut b, t);
            bb(&mut b, m)
        }
        b.extend((r.patches.len() as u32).to_le_bytes());
        for (k, v) in &r.patches {
            b.extend(k);
            bb(&mut b, v)
        }
        bb(&mut out, &b)
    }
    out
}
pub fn verify(rows: &[Row]) -> Res<()> {
    let mut prev: Option<LedgerHeader> = None;
    for r in rows {
        let h = LedgerHeader::parse(&r.header).map_err(er)?;
        if h.sequence != r.seq {
            return Err("sequence mismatch".into());
        }
        let leaves: Vec<_> = r
            .txs
            .iter()
            .map(|(t, m)| {
                let id = shamap::tx_id(t);
                (id, shamap::tx_leaf_hash(t, m, &id))
            })
            .collect();
        if shamap::has_duplicates(&leaves) || shamap::root(&leaves) != h.transaction_hash {
            return Err(format!("tx root {}", r.seq));
        }
        if let Some(p) = prev
            && (h.parent_hash != p.hash() || h.sequence != p.sequence + 1)
        {
            return Err("chain gap".into());
        }
        prev = Some(h)
    }
    Ok(())
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum Spec {
    Lit(Rc<[u8]>),
    Slot(u32),
    Cached(u32),
    Child,
}
#[derive(Default)]
struct Build {
    templates: Vec<Vec<Spec>>,
    template_ids: HashMap<Vec<Spec>, usize>,
    shapes: Vec<usize>,
    contexts: Vec<usize>,
    context_ids: HashMap<Vec<u8>, usize>,
    last_values: HashMap<(usize, u32), Vec<u8>>,
    contextual: bool,
    cached_slots: bool,
    repeat_count: usize,
    columns: HashMap<u32, Vec<Option<Vec<u8>>>>,
    counts: HashMap<Vec<u8>, usize>,
    tx_values: HashSet<Vec<u8>>,
    literal_objects: usize,
    context_delta: bool,
    deltas: HashMap<u32, Vec<Option<(u8, u64)>>>,
    /// JC06: the current part, and the first and last part each value of 8
    /// bytes or more appears in.
    part: usize,
    value_parts: HashMap<Vec<u8>, (usize, usize)>,
}
/// One part's streams: shapes with contexts, and columns.
#[derive(Default)]
struct Part {
    shapes: Vec<usize>,
    contexts: Vec<usize>,
    columns: HashMap<u32, Vec<Option<Vec<u8>>>>,
    deltas: HashMap<u32, Vec<Option<(u8, u64)>>>,
}
impl Build {
    /// Ends the current part: its streams move out, and repeats and context
    /// deltas no longer refer to values before it.
    fn take_part(&mut self) -> Part {
        self.last_values.clear();
        self.part += 1;
        Part {
            shapes: std::mem::take(&mut self.shapes),
            contexts: std::mem::take(&mut self.contexts),
            columns: std::mem::take(&mut self.columns),
            deltas: std::mem::take(&mut self.deltas),
        }
    }
    fn slot(&mut self, spec: &mut Vec<Spec>, col: u32, value: &[u8], tx: bool, ctx: usize) {
        if self.cached_slots
            && self.contextual
            && ctx != 0
            && self
                .last_values
                .get(&(ctx, col))
                .is_some_and(|v| v == value)
        {
            spec.push(Spec::Cached(col));
            self.repeat_count += 1;
            return;
        }
        spec.push(Spec::Slot(col));
        if self.contextual && ctx != 0 {
            let key = (ctx, col);
            if self.last_values.get(&key).is_some_and(|v| v == value) {
                self.columns.entry(col).or_default().push(None);
                self.deltas.entry(col).or_default().push(None);
                self.repeat_count += 1;
                return;
            }
            let candidate = if self.context_delta && [4, 8].contains(&value.len()) {
                self.last_values
                    .get(&key)
                    .filter(|p| p.len() == value.len())
                    .map(|p| {
                        let mut a = [0u8; 8];
                        let mut b = [0u8; 8];
                        let width = value.len();
                        a[8 - width..].copy_from_slice(p);
                        b[8 - width..].copy_from_slice(value);
                        let d = u64::from_be_bytes(b).wrapping_sub(u64::from_be_bytes(a)) as i64;
                        (width as u8, ((d as u64) << 1) ^ ((d >> 63) as u64))
                    })
            } else {
                None
            };
            self.deltas.entry(col).or_default().push(candidate);
            self.last_values.insert(key, value.to_vec());
        }
        if !self.contextual || ctx == 0 {
            self.deltas.entry(col).or_default().push(None);
        }
        self.columns
            .entry(col)
            .or_default()
            .push(Some(value.to_vec()));
        if value.len() >= 8 {
            *self.counts.entry(value.to_vec()).or_default() += 1;
        }
        if tx && value.len() == 32 {
            self.tx_values.insert(value.to_vec());
        }
        if value.len() >= 8 {
            let part = self.part;
            self.value_parts
                .entry(value.to_vec())
                .and_modify(|p| p.1 = part)
                .or_insert((part, part));
        }
    }
    fn shape(&mut self, index: usize, spec: Vec<Spec>) {
        let id = if let Some(&id) = self.template_ids.get(&spec) {
            id
        } else {
            let id = self.templates.len();
            self.templates.push(spec.clone());
            self.template_ids.insert(spec, id);
            id
        };
        self.shapes[index] = id;
    }
    fn context(&mut self, key: &[u8]) -> usize {
        let next = self.context_ids.len() + 1;
        *self.context_ids.entry(key.to_vec()).or_insert(next)
    }
    fn external(&mut self, key: u32, buf: &[u8]) {
        let mut spec = vec![];
        let at = self.shapes.len();
        self.shapes.push(0);
        self.contexts.push(0);
        self.slot(&mut spec, key, buf, false, 0);
        self.shape(at, spec)
    }
    fn object(
        &mut self,
        buf: &[u8],
        array: bool,
        tx: bool,
        depth: usize,
        mut ctx: usize,
    ) -> Res<()> {
        if depth > 64 {
            return Err("depth".into());
        }
        let fields = if array {
            stobject::items(buf)
        } else {
            stobject::fields(buf)
        }
        .map_err(er)?;
        if fields.iter().map(|f| f.raw.len()).sum::<usize>() != buf.len() {
            return Err("parser does not cover object".into());
        }
        if !tx
            && let Some(f) = fields
                .iter()
                .find(|f| f.id.type_code == 5 && f.id.field_code == 6 && f.value.len() == 32)
        {
            ctx = self.context(f.value)
        }
        let at = self.shapes.len();
        self.shapes.push(0);
        self.contexts.push(ctx);
        let mut spec = vec![];
        for f in fields {
            let prefix = f.value.as_ptr() as usize - f.raw.as_ptr() as usize;
            let suffix = prefix + f.value.len();
            if suffix > f.raw.len() {
                return Err("field span".into());
            }
            if !f.raw[..prefix].is_empty() {
                spec.push(Spec::Lit(f.raw[..prefix].to_vec().into()))
            }
            let ty = f.id.type_code;
            let key = (u32::from(ty) << 16) | u32::from(f.id.field_code);
            if array || ty == 14 || ty == 15 {
                spec.push(Spec::Child);
                self.object(f.value, !array && ty == 15, tx, depth + 1, ctx)?;
            } else if ty == 6 && f.value.len() == 48 {
                self.slot(&mut spec, key, &f.value[..8], tx, ctx);
                self.slot(&mut spec, key | (1 << 24), &f.value[8..28], tx, ctx);
                self.slot(&mut spec, key | (2 << 24), &f.value[28..], tx, ctx);
            } else if ty == 19 && f.value.len() % 32 == 0 {
                for chunk in f.value.as_chunks::<32>().0 {
                    self.slot(&mut spec, key, chunk, tx, ctx)
                }
            } else if !f.value.is_empty() {
                self.slot(&mut spec, key, f.value, tx, ctx)
            }
            if !f.raw[suffix..].is_empty() {
                spec.push(Spec::Lit(f.raw[suffix..].to_vec().into()))
            }
        }
        self.shape(at, spec);
        Ok(())
    }
    fn document(&mut self, buf: &[u8], tx: bool, ctx: usize) -> Res<()> {
        // Parse first, including nested arrays, so a fallback never leaves partial columns.
        fn check(b: &[u8], array: bool, depth: usize) -> Res<()> {
            if depth > 64 {
                return Err("depth".into());
            }
            let fs = if array {
                stobject::items(b)
            } else {
                stobject::fields(b)
            }
            .map_err(er)?;
            if fs.iter().map(|f| f.raw.len()).sum::<usize>() != b.len() {
                return Err("coverage".into());
            }
            for f in fs {
                if array || f.id.type_code == 14 || f.id.type_code == 15 {
                    check(f.value, !array && f.id.type_code == 15, depth + 1)?
                }
            }
            Ok(())
        }
        if check(buf, false, 0).is_err() {
            self.literal_objects += 1;
            let mut s = vec![];
            let at = self.shapes.len();
            self.shapes.push(0);
            self.contexts.push(ctx);
            self.slot(&mut s, 0xffff_0001, buf, tx, ctx);
            self.shape(at, s);
            return Ok(());
        }
        self.object(buf, false, tx, 0, ctx)
    }
}
fn value_put(out: &mut Vec<u8>, b: &[u8], compact: bool) {
    if compact
        && (68..=72).contains(&b.len())
        && let Ok(s) = k256::ecdsa::Signature::from_der(b)
        && s.to_der().as_bytes() == b
    {
        put(out, 1);
        out.extend(s.to_bytes());
        return;
    }
    put(out, (b.len() as u64) << 1);
    out.extend(b);
}
#[cfg(test)]
fn value_get(r: &mut Read) -> Res<Vec<u8>> {
    let mut der = [0; DER_MAX];
    value_ref(r, &mut der).map(<[u8]>::to_vec)
}
/// A stored value: borrowed from the input or, for a compact signature, written
/// to `der`. Reading a part goes through every value, so nothing is allocated.
fn value_ref<'b, 'a: 'b>(r: &mut Read<'a>, der: &'b mut [u8; DER_MAX]) -> Res<&'b [u8]> {
    let tag = r.var()?;
    if tag == 1 {
        let n = der_signature(r.take(64)?, der)?;
        return Ok(&der[..n]);
    }
    if tag & 1 != 0 {
        return Err("value tag".into());
    }
    let n = usize::try_from(tag >> 1).map_err(er)?;
    if n > MAX {
        return Err("value size".into());
    }
    r.take(n)
}
/// Longest DER form of a secp256k1 signature.
const DER_MAX: usize = 72;
/// Order of secp256k1, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];
/// DER form of a 64-byte `r || s` signature, written to `out`; returns its
/// length. Almost every transaction carries one, so this works on the bytes
/// instead of going through curve scalars. It accepts and writes exactly what
/// `k256::ecdsa::Signature` does.
fn der_signature(rs: &[u8], out: &mut [u8; DER_MAX]) -> Res<usize> {
    if rs.len() != 64 {
        return Err("signature size".into());
    }
    let (r, s) = rs.split_at(32);
    let mut at = 2;
    for v in [r, s] {
        if v.iter().all(|&b| b == 0) || v >= &CURVE_ORDER[..] {
            return Err("signature scalar".into());
        }
        let v = &v[v.iter().take_while(|&&b| b == 0).count()..];
        let pad = usize::from(v[0] >= 0x80);
        out[at] = 2;
        out[at + 1] = (v.len() + pad) as u8;
        out[at + 2] = 0;
        out[at + 2 + pad..at + 2 + pad + v.len()].copy_from_slice(v);
        at += 2 + pad + v.len();
    }
    out[0] = 0x30;
    out[1] = (at - 2) as u8;
    Ok(at)
}
/// Shapes, contexts and columns of one part; returns delta columns and column bytes.
fn part_streams(
    out: &mut Vec<u8>,
    part: &Part,
    ids: &HashMap<Vec<u8>, usize>,
    opt: Options,
    v3: bool,
) -> Res<(usize, usize)> {
    put(out, part.shapes.len() as u64);
    if v3 {
        let mut shapes = vec![];
        let mut contexts = vec![];
        let mut prev = 0u64;
        for (&id, &ctx) in part.shapes.iter().zip(&part.contexts) {
            put(&mut shapes, id as u64);
            let d = (ctx as u64).wrapping_sub(prev) as i64;
            put(&mut contexts, ((d as u64) << 1) ^ ((d >> 63) as u64));
            prev = ctx as u64;
        }
        blob(out, &shapes);
        blob(out, &contexts);
    } else {
        for (&id, &ctx) in part.shapes.iter().zip(&part.contexts) {
            put(out, id as u64);
            put(out, ctx as u64);
        }
    }
    let mut columns: Vec<_> = part.columns.iter().collect();
    columns.sort_by_key(|x| *x.0);
    let column_start = out.len();
    put(out, columns.len() as u64);
    let mut ndelta = 0;
    for (&key, vs) in columns {
        put(out, u64::from(key));
        put(out, vs.len() as u64);
        let joint_encoded = if opt.joint {
            Some(joint::encode(
                vs,
                &part.deltas[&key],
                ids,
                opt.compact_signatures,
            )?)
        } else {
            None
        };
        if opt.joint && !opt.adaptive {
            out.push(2);
            blob(out, joint_encoded.as_ref().ok_or("joint column")?);
            continue;
        }
        let mut tokens = vec![];
        for (at, v) in vs.iter().enumerate() {
            if let Some(v) = v {
                let mut normal = vec![];
                if let Some(&id) = ids.get(v) {
                    put(&mut normal, (id + if v3 { 4 } else { 2 }) as u64);
                } else {
                    normal.push(0);
                    value_put(&mut normal, v, opt.compact_signatures);
                }
                if v3
                    && opt.context_delta
                    && let Some((width, z)) = part.deltas[&key][at]
                {
                    let mut d = vec![if width == 4 { 2 } else { 3 }];
                    put(&mut d, z);
                    if d.len() < normal.len() {
                        tokens.extend(d);
                        continue;
                    }
                }
                tokens.extend(normal);
            } else {
                tokens.push(1);
            }
        }
        let candidate = if opt.numeric_delta && vs.iter().all(Option::is_some) {
            delta(&vs.iter().flatten().cloned().collect::<Vec<_>>())
        } else {
            None
        };
        let (mode, encoded) = if let Some(d) = candidate {
            if compress(&d)?.len() < compress(&tokens)?.len() {
                ndelta += 1;
                (1, d)
            } else {
                (0, tokens)
            }
        } else {
            (0, tokens)
        };
        let (mode, encoded) = if let Some(joint) = joint_encoded {
            if compress(&joint)?.len() < compress(&encoded)?.len() {
                (2, joint)
            } else {
                (mode, encoded)
            }
        } else {
            (mode, encoded)
        };
        let (mode, encoded) = if opt.joint && opt.recent {
            let candidate =
                joint::encode_recent(vs, &part.deltas[&key], ids, opt.compact_signatures, true)?;
            if compress(&candidate)?.len() < compress(&encoded)?.len() {
                (2, candidate)
            } else {
                (mode, encoded)
            }
        } else {
            (mode, encoded)
        };
        out.push(mode);
        blob(out, &encoded);
    }
    Ok((ndelta, out.len() - column_start))
}
/// Exact bytes of a row as `rows_bytes` writes it.
fn row_size(row: &Row) -> usize {
    20 + row.header.len()
        + row
            .txs
            .iter()
            .map(|(t, m)| 8 + t.len() + m.len())
            .sum::<usize>()
        + row.patches.iter().map(|(_, v)| 36 + v.len()).sum::<usize>()
}
fn compress(b: &[u8]) -> Res<Vec<u8>> {
    zstd::bulk::compress(b, 19).map_err(er)
}
fn delta(values: &[Vec<u8>]) -> Option<Vec<u8>> {
    let width = values.first()?.len();
    if ![4, 8].contains(&width) || values.iter().any(|v| v.len() != width) {
        return None;
    }
    let mut out = vec![width as u8];
    let mut prev = 0u64;
    for b in values {
        let mut bytes = [0; 8];
        bytes[8 - width..].copy_from_slice(b);
        let v = u64::from_be_bytes(bytes);
        let d = v.wrapping_sub(prev) as i64;
        put(&mut out, ((d as u64) << 1) ^ ((d >> 63) as u64));
        prev = v;
    }
    Some(out)
}
fn field<'a>(fs: &[stobject::Field<'a>], t: u16, f: u16) -> Option<&'a [u8]> {
    fs.iter()
        .find(|x| x.id.type_code == t && x.id.field_code == f)
        .map(|x| x.value)
}
type KeyRecipe = (u8, Vec<Vec<u8>>);
fn key_recipe(ty: u16, fs: &[stobject::Field<'_>], key: &[u8]) -> Option<KeyRecipe> {
    let account = || field(fs, 8, 1).filter(|x| x.len() == 20).map(Vec::from);
    let seq = |id| field(fs, 2, id).filter(|x| x.len() == 4).map(Vec::from);
    let (domain, args) = match ty {
        97 => (b'a', vec![account()?]),
        111 => (b'o', vec![account()?, seq(4)?]),
        84 => (b'T', vec![account()?, seq(41)?]),
        67 => (b'C', vec![account()?, seq(4)?]),
        117 => (b'u', vec![account()?, seq(4)?]),
        73 => (b'I', vec![account()?]),
        100 => (
            b'O',
            vec![field(fs, 8, 2).filter(|x| x.len() == 20)?.to_vec()],
        ),
        83 => (b'S', vec![account()?, seq(38)?]),
        114 => {
            let lo = field(fs, 6, 6).filter(|x| x.len() == 48)?;
            let hi = field(fs, 6, 7).filter(|x| x.len() == 48)?;
            if lo[8..28] != hi[8..28] {
                return None;
            }
            let (mut a, mut b) = (lo[28..].to_vec(), hi[28..].to_vec());
            if a > b {
                std::mem::swap(&mut a, &mut b)
            }
            (b'r', vec![a, b, lo[8..28].to_vec()])
        }
        _ => return None,
    };
    let mut preimage = vec![0, domain];
    for a in &args {
        preimage.extend(a)
    }
    if sha512_half(&preimage).as_slice() == key {
        Some((domain, args))
    } else {
        None
    }
}
fn key_recipes(rows: &[Row]) -> HashMap<Vec<u8>, KeyRecipe> {
    let mut out = HashMap::new();
    for row in rows {
        for (k, v) in &row.patches {
            if let Ok(fs) = stobject::fields(v)
                && let Some(ty) = field(&fs, 1, 1).and_then(|x| <[u8; 2]>::try_from(x).ok())
                && let Some(recipe) = key_recipe(u16::from_be_bytes(ty), &fs, k)
            {
                out.entry(k.to_vec()).or_insert(recipe);
            }
        }
        for (_, m) in &row.txs {
            let Ok(fs) = stobject::fields(m) else {
                continue;
            };
            let Some(nodes) = fs
                .iter()
                .find(|f| f.id.type_code == 15 && f.id.field_code == 8)
            else {
                continue;
            };
            let Ok(nodes) = stobject::children(nodes) else {
                continue;
            };
            for node in nodes {
                let Ok(inn) = stobject::children(&node) else {
                    continue;
                };
                let Some(key) = field(&inn, 5, 6).filter(|x| x.len() == 32) else {
                    continue;
                };
                let Some(ty) = field(&inn, 1, 1).and_then(|x| <[u8; 2]>::try_from(x).ok()) else {
                    continue;
                };
                let ty = u16::from_be_bytes(ty);
                for group in inn
                    .iter()
                    .filter(|f| f.id.type_code == 14 && [7, 8].contains(&f.id.field_code))
                {
                    let Ok(fs) = stobject::fields(group.value) else {
                        continue;
                    };
                    if let Some(recipe) = key_recipe(ty, &fs, key) {
                        out.entry(key.to_vec()).or_insert(recipe);
                    }
                }
            }
        }
    }
    out
}
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub dictionaries: bool,
    pub derive_hashes: bool,
    pub numeric_delta: bool,
    pub compact_signatures: bool,
    pub contextual: bool,
    pub derive_keys: bool,
    pub split_shapes: bool,
    pub context_delta: bool,
    pub joint: bool,
    pub adaptive: bool,
    pub recent: bool,
    pub chronological: bool,
    pub hash_order: bool,
    pub cached_slots: bool,
    /// JC06: cut the block into parts of at most this many exact bytes (whole
    /// ledgers), each readable on its own; 0 keeps one part (JC05).
    pub part_raw: usize,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            dictionaries: true,
            derive_hashes: true,
            numeric_delta: true,
            compact_signatures: true,
            contextual: true,
            derive_keys: true,
            split_shapes: false,
            context_delta: false,
            joint: false,
            adaptive: false,
            recent: false,
            chronological: false,
            hash_order: false,
            cached_slots: false,
            part_raw: 0,
        }
    }
}
#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub dictionary_values: usize,
    pub derived_hashes: usize,
    pub templates: usize,
    pub columns: usize,
    pub literal_objects: usize,
    pub inner_bytes: usize,
    pub compressed_bytes: usize,
    pub delta_columns: usize,
    pub derived_keys: usize,
    pub context_repeats: usize,
    pub dictionary_bytes: usize,
    pub column_bytes: usize,
    pub reordered_ledgers: usize,
    pub canonical_ledgers: usize,
    pub order_bytes: usize,
    pub parts: usize,
    pub shared_bytes: usize,
    /// JC06: entries in the parts' own dictionaries, and their bytes.
    pub local_values: usize,
    pub local_bytes: usize,
}
/// Stable physical processing order; source order is restored by a stored permutation.
/// Malformed/missing/duplicate TransactionIndex falls back to original order.
fn processing_order(row: &Row) -> Vec<usize> {
    let mut indexed = Vec::with_capacity(row.txs.len());
    for (i, (_, m)) in row.txs.iter().enumerate() {
        let Ok(fs) = stobject::fields(m) else {
            return (0..row.txs.len()).collect();
        };
        let indices: Vec<_> = fs
            .iter()
            .filter(|f| f.id.type_code == 2 && f.id.field_code == 28)
            .collect();
        let [only] = indices.as_slice() else {
            return (0..row.txs.len()).collect();
        };
        let Ok(index) = <[u8; 4]>::try_from(only.value) else {
            return (0..row.txs.len()).collect();
        };
        indexed.push((u32::from_be_bytes(index), i));
    }
    indexed.sort_unstable();
    if indexed.windows(2).any(|w| w[0].0 == w[1].0) {
        return (0..row.txs.len()).collect();
    }
    indexed.into_iter().map(|(_, i)| i).collect()
}
pub fn encode_block(rows: &[Row], opt: Options) -> Res<(Vec<u8>, Stats)> {
    let v5 = opt.chronological || opt.cached_slots;
    if v5 && !opt.joint {
        return Err("sequential options require joint".into());
    }
    let mut b = Build {
        contextual: opt.contextual,
        context_delta: opt.context_delta,
        cached_slots: opt.cached_slots,
        ..Build::default()
    };
    let chunked = opt.part_raw > 0;
    if chunked && !v5 {
        return Err("parts require sequential options".into());
    }
    let (mut reordered_ledgers, mut canonical_ledgers, mut order_bytes) = (0, 0, 0);
    let mut layout = vec![];
    put(&mut layout, rows.len() as u64);
    let mut parts = vec![];
    let mut part_ledgers = vec![];
    let mut orders = vec![];
    let (mut part_raw, mut part_rows) = (0usize, 0usize);
    for r in rows {
        let size = row_size(r);
        if chunked && part_rows > 0 && part_raw + size > opt.part_raw {
            parts.push(b.take_part());
            part_ledgers.push(part_rows);
            (part_raw, part_rows) = (0, 0);
        }
        part_raw += size;
        part_rows += 1;
        put(&mut layout, u64::from(r.seq));
        b.external(0xffff_0002, &r.header);
        put(&mut layout, r.txs.len() as u64);
        let order: Vec<usize> = if opt.chronological {
            processing_order(r)
        } else {
            (0..r.txs.len()).collect()
        };
        if v5 {
            let order_start = layout.len();
            let changed = order.iter().enumerate().any(|(i, &j)| i != j);
            let hashes: Vec<_> = if opt.hash_order && changed {
                r.txs.iter().map(|(t, _)| shamap::tx_id(t)).collect()
            } else {
                vec![]
            };
            reordered_ledgers += usize::from(changed);
            let canonical = !hashes.is_empty() && hashes.windows(2).all(|w| w[0] < w[1]);
            canonical_ledgers += usize::from(canonical);
            layout.push(if canonical { 2 } else { u8::from(changed) });
            if changed && !canonical {
                for &i in &order {
                    put(&mut layout, i as u64);
                }
            }
            order_bytes += layout.len() - order_start;
        }
        for &i in &order {
            let (t, m) = &r.txs[i];
            b.document(t, true, 0)?;
            b.document(m, false, 0)?
        }
        orders.push(order);
        put(&mut layout, r.patches.len() as u64);
        for (k, v) in &r.patches {
            b.external(0xffff_0003, k);
            let ctx = b.context(k);
            b.document(v, false, ctx)?
        }
    }
    parts.push(b.take_part());
    part_ledgers.push(part_rows);
    // A derived hash names its transaction by position: in JC06 the position
    // in encoding order, which a reader finds without hashing a ledger; before
    // JC06 the position in the original order.
    let mut hashes: HashMap<Vec<u8>, usize> = if chunked {
        rows.iter()
            .zip(&orders)
            .flat_map(|(r, o)| o.iter().map(|&i| &r.txs[i].0))
            .enumerate()
            .map(|(i, t)| (shamap::tx_id(t).to_vec(), i))
            .collect()
    } else {
        rows.iter()
            .flat_map(|r| r.txs.iter())
            .enumerate()
            .map(|(i, (t, _))| (shamap::tx_id(t).to_vec(), i))
            .collect()
    };
    // In JC06 a derived hash names a transaction of the same part as every
    // use of it, so reading a part never compiles another.
    if chunked {
        let mut tx_part = vec![];
        let mut ledger = 0;
        for (p, &n) in part_ledgers.iter().enumerate() {
            for r in &rows[ledger..ledger + n] {
                tx_part.extend(std::iter::repeat_n(p, r.txs.len()));
            }
            ledger += n;
        }
        hashes.retain(|v, i| {
            b.value_parts
                .get(v)
                .is_none_or(|&(a, z)| a == z && a == tx_part[*i])
        });
    }
    let kr = if opt.derive_keys {
        key_recipes(rows)
    } else {
        HashMap::new()
    };
    let mut values: Vec<_> = b
        .counts
        .iter()
        .filter(|(v, n)| {
            (opt.dictionaries && **n >= 2 && !(opt.joint && [4, 8].contains(&v.len())))
                || ((opt.derive_hashes && hashes.contains_key(*v) || kr.contains_key(*v))
                    && v.len() == 32
                    && !b.tx_values.contains(*v))
        })
        .map(|(v, _)| v.clone())
        .collect();
    // Lexicographic dictionary order improves common prefixes; deterministic output.
    values.sort();
    // JC06: a value only one part uses goes to that part's own dictionary,
    // which only reading that part has to decode.
    let mut local: Vec<Vec<Vec<u8>>> = vec![vec![]; parts.len()];
    if chunked {
        values.retain(|v| match b.value_parts.get(v) {
            Some(&(a, z)) if a == z => {
                local[a].push(v.clone());
                false
            }
            _ => true,
        });
    }
    let ids: HashMap<_, _> = values
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, v)| (v, i))
        .collect();
    let v3 = opt.split_shapes || opt.context_delta || opt.joint;
    let mut out = if chunked {
        b"JC06"
    } else if v5 {
        b"JC05"
    } else if opt.joint {
        b"JC04"
    } else if v3 {
        b"JC03"
    } else {
        b"JC02"
    }
    .to_vec();
    blob(&mut out, &layout);
    if chunked {
        let mut p = vec![];
        put(&mut p, part_ledgers.len() as u64);
        for &n in &part_ledgers {
            put(&mut p, n as u64);
        }
        blob(&mut out, &p);
    }
    let dictionary_start = out.len();
    put(&mut out, values.len() as u64);
    let mut derived = 0;
    let mut derived_keys = 0;
    // A dictionary entry: a hash derived from a transaction of the block, a
    // key derived from its arguments (dictionary ids or literals), or the value.
    let mut entry = |out: &mut Vec<u8>, v: &Vec<u8>, ids: &HashMap<Vec<u8>, usize>| {
        if v.len() == 32 && !b.tx_values.contains(v) {
            if opt.derive_hashes
                && let Some(&i) = hashes.get(v)
            {
                out.push(1);
                put(out, i as u64);
                derived += 1;
                return;
            }
            if let Some((domain, args)) = kr.get(v) {
                out.push(2);
                out.push(*domain);
                put(out, args.len() as u64);
                for arg in args {
                    if let Some(&id) = ids.get(arg) {
                        put(out, (id + 1) as u64)
                    } else {
                        out.push(0);
                        blob(out, arg)
                    }
                }
                derived_keys += 1;
                return;
            }
        }
        out.push(0);
        value_put(out, v, opt.compact_signatures)
    };
    for v in &values {
        entry(&mut out, v, &ids);
    }
    let dictionary_bytes = out.len() - dictionary_start;
    put(&mut out, b.templates.len() as u64);
    for t in &b.templates {
        put(&mut out, t.len() as u64);
        for s in t {
            match s {
                Spec::Lit(v) => {
                    out.push(0);
                    blob(&mut out, v)
                }
                Spec::Slot(k) => {
                    out.push(1);
                    put(&mut out, u64::from(*k))
                }
                Spec::Child => out.push(2),
                Spec::Cached(k) => {
                    out.push(3);
                    put(&mut out, u64::from(*k));
                }
            }
        }
    }
    let shared_len = out.len();
    let mut part_bytes = vec![];
    let mut ndelta = 0;
    let mut column_bytes = 0;
    let mut local_bytes = 0;
    for (part, local) in parts.iter().zip(&local) {
        let mut o = vec![];
        // A part's dictionary ids follow the shared ones.
        let mut part_ids;
        let ids = if chunked {
            part_ids = ids.clone();
            for (j, v) in local.iter().enumerate() {
                part_ids.insert(v.clone(), values.len() + j);
            }
            put(&mut o, local.len() as u64);
            for v in local {
                entry(&mut o, v, &part_ids);
            }
            local_bytes += o.len();
            &part_ids
        } else {
            &ids
        };
        let (n, c) = part_streams(&mut o, part, ids, opt, v3)?;
        ndelta += n;
        column_bytes += c;
        part_bytes.push(o);
    }
    let columns_total: usize = parts.iter().map(|p| p.columns.len()).sum();
    if !chunked {
        out.extend(part_bytes.pop().ok_or("block without parts")?);
    }
    let inner = out.len() + part_bytes.iter().map(Vec::len).sum::<usize>();
    if out.len() > MAX || part_bytes.iter().any(|p| p.len() > MAX) {
        return Err("journal block exceeds 256 MiB; choose fewer ledgers".into());
    }
    let mut stats = Stats {
        dictionary_values: values.len(),
        derived_hashes: derived,
        templates: b.templates.len(),
        columns: columns_total,
        literal_objects: b.literal_objects,
        inner_bytes: inner,
        delta_columns: ndelta,
        derived_keys,
        context_repeats: b.repeat_count,
        dictionary_bytes: dictionary_bytes + local_bytes,
        column_bytes,
        reordered_ledgers,
        canonical_ledgers,
        order_bytes,
        parts: parts.len(),
        shared_bytes: shared_len,
        ..Stats::default()
    };
    stats.local_values = local.iter().map(Vec::len).sum();
    stats.local_bytes = local_bytes;
    let mut frame = vec![];
    if !chunked {
        let z = compress(&out)?;
        frame.extend((out.len() as u64).to_le_bytes());
        frame.extend(z);
    } else {
        // JC06 frame: sizes of the shared section and of every part, then the
        // shared section and each part compressed on their own, a part with the
        // shared section as its dictionary.
        let z = compress(&out)?;
        let mut c = zstd::bulk::Compressor::with_dictionary(19, &out).map_err(er)?;
        let zs = part_bytes
            .iter()
            .map(|p| c.compress(p).map_err(er))
            .collect::<Res<Vec<_>>>()?;
        frame.extend((out.len() as u64).to_le_bytes());
        frame.extend((z.len() as u64).to_le_bytes());
        frame.extend((zs.len() as u32).to_le_bytes());
        for (p, zp) in part_bytes.iter().zip(&zs) {
            frame.extend((p.len() as u64).to_le_bytes());
            frame.extend((zp.len() as u64).to_le_bytes());
        }
        frame.extend(z);
        for zp in zs {
            frame.extend(zp);
        }
    }
    stats.compressed_bytes = frame.len();
    Ok((frame, stats))
}
pub fn decode_block(frame: &[u8]) -> Res<Vec<Row>> {
    fast::Prepared::parse(frame)?.all_rows()
}

/// Independent blocks; footer-equivalent directory is in the fixed-size front table.
fn bounded_ranges(
    rows: &[Row],
    max_ledgers: usize,
    max_raw: usize,
) -> Res<Vec<std::ops::Range<usize>>> {
    if rows.is_empty() || max_ledgers == 0 || !(4..=MAX).contains(&max_raw) {
        return Err("invalid block limits".into());
    }
    let mut ranges = vec![];
    let mut start = 0;
    let mut raw = 4usize;
    for (i, row) in rows.iter().enumerate() {
        let mut size = 20usize.checked_add(row.header.len()).ok_or("row size")?;
        for (tx, meta) in &row.txs {
            size = size
                .checked_add(8)
                .and_then(|n| n.checked_add(tx.len()))
                .and_then(|n| n.checked_add(meta.len()))
                .ok_or("TX size")?;
        }
        for (_, value) in &row.patches {
            size = size
                .checked_add(36)
                .and_then(|n| n.checked_add(value.len()))
                .ok_or("patch size")?;
        }
        if size > max_raw - 4 {
            return Err("one ledger exceeds raw block limit".into());
        }
        if i > start && (i - start == max_ledgers || size > max_raw - raw) {
            ranges.push(start..i);
            start = i;
            raw = 4;
        }
        raw += size;
    }
    ranges.push(start..rows.len());
    Ok(ranges)
}
pub fn pack(rows: &[Row], block_ledgers: usize, opt: Options) -> Res<(Vec<u8>, Vec<Stats>)> {
    pack_bounded(rows, block_ledgers, MAX, opt)
}
/// Adaptive ledger boundaries; this constrains raw bytes, not total process RSS.
pub fn pack_bounded(
    rows: &[Row],
    max_ledgers: usize,
    max_raw: usize,
    opt: Options,
) -> Res<(Vec<u8>, Vec<Stats>)> {
    let ranges = bounded_ranges(rows, max_ledgers, max_raw)?;
    verify(rows)?;
    let mut blocks = vec![];
    let mut stats = vec![];
    for range in ranges {
        let rs = &rows[range];
        let raw = rows_bytes(rs);
        if raw.len() > max_raw {
            return Err("bounded size calculation".into());
        }
        if raw.len() > MAX {
            return Err("raw block exceeds 256 MiB; choose fewer ledgers".into());
        }
        let (frame, s) = encode_block(rs, opt)?;
        let mut payload = vec![];
        if opt.part_raw > 0 {
            // Parts are kept even where plain zstd of the raw rows would be
            // smaller (tiny blocks): a raw block is read whole. So that is not tried.
            payload.push(2);
            payload.extend(frame)
        } else {
            let z = compress(&raw)?;
            if frame.len() < z.len() + 8 {
                payload.push(1);
                payload.extend(frame)
            } else {
                payload.push(0);
                payload.extend((raw.len() as u64).to_le_bytes());
                payload.extend(z)
            }
        }
        blocks.push((rs[0].seq, rs.len(), sha512_half(&raw), payload));
        stats.push(s);
    }
    let mut out = if opt.part_raw > 0 {
        b"ASTJ6\0\0\0"
    } else if opt.chronological || opt.cached_slots {
        b"ASTJ5\0\0\0"
    } else if opt.joint {
        b"ASTJ4\0\0\0"
    } else if opt.split_shapes || opt.context_delta {
        b"ASTJ3\0\0\0"
    } else {
        b"ASTJ2\0\0\0"
    }
    .to_vec();
    out.extend((blocks.len() as u32).to_le_bytes());
    let mut offset = 12 + blocks.len() * 56;
    for (first, count, hash, payload) in &blocks {
        out.extend(first.to_le_bytes());
        out.extend((*count as u32).to_le_bytes());
        out.extend((offset as u64).to_le_bytes());
        out.extend((payload.len() as u64).to_le_bytes());
        out.extend(hash);
        offset += payload.len()
    }
    for (_, _, _, payload) in blocks {
        out.extend(payload)
    }
    Ok((out, stats))
}
pub fn unpack(archive: &[u8]) -> Res<Vec<Row>> {
    let mut r = Read::new(archive);
    let magic = r.take(8)?;
    if magic != b"ASTJ2\0\0\0"
        && magic != b"ASTJ3\0\0\0"
        && magic != b"ASTJ4\0\0\0"
        && magic != b"ASTJ5\0\0\0"
        && magic != b"ASTJ6\0\0\0"
    {
        return Err("archive magic".into());
    }
    let count = r.u32()? as usize;
    if count > 1_000_000 {
        return Err("block count".into());
    }
    let mut entries = vec![];
    let mut expected = 12usize
        .checked_add(count.checked_mul(56).ok_or("directory overflow")?)
        .ok_or("directory overflow")?;
    for _ in 0..count {
        let first = r.u32()?;
        let n = r.u32()? as usize;
        let off = r.u64()? as usize;
        let len = r.u64()? as usize;
        let hash: [u8; 32] = r.array()?;
        if off != expected {
            return Err("noncanonical directory offset".into());
        }
        expected = expected.checked_add(len).ok_or("length overflow")?;
        entries.push((first, n, off, len, hash));
    }
    if expected != archive.len() {
        return Err("archive length".into());
    }
    let mut rows = vec![];
    for (first, n, off, len, hash) in entries {
        let payload = archive.get(off..off + len).ok_or("block extent")?;
        let mut p = Read::new(payload);
        let rs = match p.byte()? {
            1 => decode_block(&payload[1..])?,
            2 => fast::Prepared::parse_parts(&payload[1..])?.all_rows()?,
            0 => {
                let rawlen = p.u64()?;
                if rawlen > MAX as u64 {
                    return Err("raw block limit".into());
                }
                let b = zstd::bulk::decompress(&payload[p.p..], rawlen as usize).map_err(er)?;
                if b.len() != rawlen as usize {
                    return Err("raw block length".into());
                }
                load_rows(&b)?
            }
            _ => return Err("block mode".into()),
        };
        if rs.len() != n
            || rs.first().is_none_or(|r| r.seq != first)
            || sha512_half(&rows_bytes(&rs)) != hash
        {
            return Err("block identity".into());
        }
        rows.extend(rs)
    }
    verify(&rows)?;
    Ok(rows)
}

#[derive(Clone, Debug)]
struct Entry {
    first: u32,
    count: usize,
    offset: u64,
    length: usize,
    hash: [u8; 32],
}
/// Reads only the front directory and the selected independent block from a file.
#[derive(Debug)]
pub struct ArchiveFile {
    file: std::fs::File,
    entries: Vec<Entry>,
}
impl ArchiveFile {
    pub fn open(path: impl AsRef<std::path::Path>) -> Res<Self> {
        use std::io::Read as _;
        let mut file = std::fs::File::open(path).map_err(er)?;
        let len = file.metadata().map_err(er)?.len();
        let mut head = [0u8; 12];
        file.read_exact(&mut head).map_err(er)?;
        if &head[..8] != b"ASTJ2\0\0\0"
            && &head[..8] != b"ASTJ3\0\0\0"
            && &head[..8] != b"ASTJ4\0\0\0"
            && &head[..8] != b"ASTJ5\0\0\0"
            && &head[..8] != b"ASTJ6\0\0\0"
        {
            return Err("archive magic".into());
        }
        let count = u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as usize;
        if count == 0 || count > 1_000_000 {
            return Err("directory count".into());
        }
        let mut expected = (12 + count * 56) as u64;
        if expected > len {
            return Err("truncated directory".into());
        }
        let mut entries = vec![];
        let mut next_seq = None;
        for _ in 0..count {
            let mut buf = [0u8; 56];
            file.read_exact(&mut buf).map_err(er)?;
            let mut r = Read::new(&buf);
            let first = r.u32()?;
            let count = r.u32()? as usize;
            let offset = r.u64()?;
            let length = r.u64()?;
            let hash = r.array()?;
            if count == 0
                || length > MAX as u64 + 1_048_576
                || offset != expected
                || next_seq.is_some_and(|x| x != u64::from(first))
            {
                return Err("invalid directory".into());
            }
            expected = expected.checked_add(length).ok_or("length overflow")?;
            next_seq = Some(u64::from(first) + count as u64);
            entries.push(Entry {
                first,
                count,
                offset,
                length: length as usize,
                hash,
            });
        }
        if expected != len {
            return Err("archive extent".into());
        }
        Ok(Self { file, entries })
    }
    pub fn read_block(&mut self, seq: u32) -> Res<Vec<Row>> {
        use std::io::{Read as _, Seek as _};
        let i = self
            .entries
            .partition_point(|e| e.first <= seq)
            .checked_sub(1)
            .ok_or("ledger outside archive")?;
        let e = &self.entries[i];
        if u64::from(seq) >= u64::from(e.first) + e.count as u64 {
            return Err("ledger outside block".into());
        }
        self.file
            .seek(std::io::SeekFrom::Start(e.offset))
            .map_err(er)?;
        let mut payload = vec![0; e.length];
        self.file.read_exact(&mut payload).map_err(er)?;
        let mut p = Read::new(&payload);
        let rows = match p.byte()? {
            1 => decode_block(&payload[1..])?,
            2 => fast::Prepared::parse_parts(&payload[1..])?.all_rows()?,
            0 => {
                let n = p.u64()?;
                if n > MAX as u64 {
                    return Err("raw block limit".into());
                }
                let raw = zstd::bulk::decompress(&payload[p.p..], n as usize).map_err(er)?;
                if raw.len() != n as usize {
                    return Err("raw size".into());
                }
                load_rows(&raw)?
            }
            _ => return Err("block mode".into()),
        };
        if rows.len() != e.count
            || rows.first().is_none_or(|r| r.seq != e.first)
            || sha512_half(&rows_bytes(&rows)) != e.hash
        {
            return Err("block identity".into());
        }
        verify(&rows)?;
        Ok(rows)
    }
    pub fn ledger(&mut self, seq: u32) -> Res<Row> {
        self.read_block(seq)?
            .into_iter()
            .find(|r| r.seq == seq)
            .ok_or_else(|| "ledger missing".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn primitives_and_unknown_exact() {
        let r = Row {
            seq: 1,
            header: vec![0; 118],
            txs: vec![
                (vec![0x81, 0], vec![0xff, 1, 2, 3]),
                (
                    vec![
                        0x81, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                    vec![],
                ),
            ],
            patches: vec![([3; 32], vec![])],
        };
        let (f, s) = encode_block(std::slice::from_ref(&r), Options::default()).unwrap();
        assert!(s.literal_objects > 0);
        assert_eq!(decode_block(&f).unwrap(), vec![r]);
    }
    #[test]
    fn delta_wrap_roundtrip() {
        let v = vec![0u64, u64::MAX, 0, 1, u64::MAX - 1];
        let values = v
            .iter()
            .map(|v| v.to_be_bytes().to_vec())
            .collect::<Vec<_>>();
        let bytes = delta(&values).unwrap();
        let mut r = Read::new(&bytes);
        assert_eq!(r.byte().unwrap(), 8);
        let mut p = 0u64;
        for &x in &v {
            let z = r.var().unwrap();
            let d = ((z >> 1) as i64) ^ -((z & 1) as i64);
            p = p.wrapping_add(d as u64);
            assert_eq!(p, x)
        }
        r.end().unwrap();
    }
    #[test]
    fn corruption_and_truncation_rejected() {
        let row = Row {
            seq: 2,
            header: vec![0; 118],
            txs: vec![],
            patches: vec![([0; 32], vec![0x81, 0])],
        };
        let (f, _) = encode_block(&[row], Options::default()).unwrap();
        for n in [0, 1, 7, 8, f.len() / 2, f.len() - 1] {
            assert!(decode_block(&f[..n]).is_err())
        }
        let mut bad = f.clone();
        bad[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_block(&bad).is_err());
    }
    #[test]
    fn high_s_der_is_not_normalized() {
        let r = [1u8; 32];
        let mut s = [0u8; 32];
        s[0] = 0x80;
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();
        let der = sig.to_der();
        let mut encoded = vec![];
        value_put(&mut encoded, der.as_bytes(), true);
        assert_eq!(encoded.len(), 65);
        let mut rd = Read::new(&encoded);
        assert_eq!(value_get(&mut rd).unwrap(), der.as_bytes());
        rd.end().unwrap();
    }
    #[test]
    fn der_signature_matches_k256() {
        let order = CURVE_ORDER;
        let mut below = order;
        below[31] -= 1;
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut high = [0u8; 32];
        high[0] = 0x80;
        let mut low_zeros = [0u8; 32];
        low_zeros[3] = 0x7F;
        let mut pad_after_zeros = [0u8; 32];
        pad_after_zeros[1] = 0xFF;
        let mut seed = 0x0123_4567_89AB_CDEFu64;
        let mut random = || {
            let mut v = [0u8; 32];
            for b in &mut v {
                seed = seed.wrapping_mul(0x5DEE_CE66D).wrapping_add(11);
                *b = (seed >> 24) as u8;
            }
            v
        };
        let mut scalars = vec![
            order,
            below,
            one,
            high,
            low_zeros,
            pad_after_zeros,
            [0; 32],
            [0xFF; 32],
        ];
        scalars.extend((0..200).map(|_| random()));
        for r in &scalars {
            for s in &scalars {
                let mut rs = r.to_vec();
                rs.extend(s);
                let mut out = [0; DER_MAX];
                let got = der_signature(&rs, &mut out).map(|n| out[..n].to_vec());
                match k256::ecdsa::Signature::from_slice(&rs) {
                    Ok(sig) => assert_eq!(got.unwrap(), sig.to_der().as_bytes()),
                    Err(_) => assert!(got.is_err()),
                }
            }
        }
        assert!(der_signature(&[1; 63], &mut [0; DER_MAX]).is_err());
    }
    #[test]
    fn key_recipes_require_exact_digest() {
        let account = [3u8; 20];
        let mut field_bytes = vec![0x81, 20];
        field_bytes.extend(account);
        let fs = stobject::fields(&field_bytes).unwrap();
        let mut pre = vec![0, b'a'];
        pre.extend(account);
        let correct = sha512_half(&pre);
        assert!(key_recipe(97, &fs, &correct).is_some());
        assert!(key_recipe(97, &fs, &[0; 32]).is_none());
    }
    #[test]
    fn archive_digest_and_directory_are_checked() {
        let mut header = vec![0; 118];
        header[..4].copy_from_slice(&1u32.to_be_bytes());
        let rows = vec![Row {
            seq: 1,
            header,
            txs: vec![],
            patches: vec![([3; 32], vec![0x81, 0])],
        }];
        let (a, _) = pack(&rows, 8, Options::default()).unwrap();
        assert_eq!(unpack(&a).unwrap(), rows);
        let mut bad = a.clone();
        bad[36] ^= 1;
        assert!(unpack(&bad).is_err());
        let mut extra = a;
        extra.push(0);
        assert!(unpack(&extra).is_err());
    }
    #[test]
    fn contextual_journal_keeps_intermediate_values() {
        let field = |n: u32| {
            let mut b = vec![0x24];
            b.extend(n.to_be_bytes());
            b
        };
        let r = Row {
            seq: 1,
            header: vec![],
            txs: vec![],
            patches: [7, 7, 9, 7, 7]
                .into_iter()
                .map(|n| ([3; 32], field(n)))
                .collect(),
        };
        let (a, stats) = encode_block(std::slice::from_ref(&r), Options::default()).unwrap();
        assert_eq!(stats.context_repeats, 2);
        assert_eq!(decode_block(&a).unwrap(), vec![r]);
    }
    #[test]
    fn file_reader_seeks_and_rejects_changed_block_hash() {
        let mut rows = vec![];
        for seq in 1..=3u32 {
            let mut header = vec![0; 118];
            header[..4].copy_from_slice(&seq.to_be_bytes());
            if let Some(p) = rows.last() {
                let p: &Row = p;
                header[12..44].copy_from_slice(&LedgerHeader::parse(&p.header).unwrap().hash());
            }
            rows.push(Row {
                seq,
                header,
                txs: vec![],
                patches: vec![([seq as u8; 32], vec![0x81, 0])],
            });
        }
        let (mut bytes, _) = pack(&rows, 1, Options::default()).unwrap();
        let path =
            std::env::temp_dir().join(format!("astj-reader-test-{}.astj", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let mut file = ArchiveFile::open(&path).unwrap();
        for seq in [3, 1, 2] {
            assert_eq!(file.ledger(seq).unwrap(), rows[(seq - 1) as usize]);
        }
        assert!(file.ledger(0).is_err());
        assert!(file.ledger(4).is_err());
        bytes[36 + 56] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(ArchiveFile::open(&path).unwrap().ledger(2).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn contextual_delta_v3_preserves_wrapping_values() {
        let mut patches = vec![];
        for n in [0u64, u64::MAX, 0, 1, 2, u64::MAX - 1, 7, 7] {
            let mut v = vec![0x32];
            v.extend(n.to_be_bytes());
            patches.push(([3; 32], v));
        }
        let row = Row {
            seq: 1,
            header: vec![],
            txs: vec![],
            patches,
        };
        let (f, _) = encode_block(
            std::slice::from_ref(&row),
            Options {
                context_delta: true,
                split_shapes: true,
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(decode_block(&f).unwrap(), vec![row]);
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    #[test]
    fn byte_and_ledger_caps_are_independent_and_exact() {
        let row = Row {
            seq: 1,
            header: vec![0; 118],
            txs: vec![(vec![1; 13], vec![2; 27])],
            patches: vec![([3; 32], vec![4; 31])],
        };
        let rows = vec![row; 5];
        let two = rows_bytes(&rows[..2]).len();
        assert_eq!(
            bounded_ranges(&rows, 1024, two).unwrap(),
            vec![0..2, 2..4, 4..5]
        );
        assert_eq!(
            bounded_ranges(&rows, 1, two).unwrap(),
            vec![0..1, 1..2, 2..3, 3..4, 4..5]
        );
        assert!(bounded_ranges(&rows, 1024, rows_bytes(&rows[..1]).len() - 1).is_err());
        assert!(bounded_ranges(&rows, 0, two).is_err());
    }
}

#[cfg(test)]
mod sequential_tests {
    use super::*;
    fn options(cached: bool) -> Options {
        Options {
            joint: true,
            adaptive: true,
            context_delta: true,
            split_shapes: true,
            chronological: true,
            cached_slots: cached,
            ..Options::default()
        }
    }
    fn value(n: u32) -> Vec<u8> {
        let mut b = vec![0x24];
        b.extend(n.to_be_bytes());
        b
    }
    fn meta(index: u32, hash: &[u8; 32], n: u32) -> Vec<u8> {
        let mut b = vec![0x20, 28];
        b.extend(index.to_be_bytes());
        b.push(0x55);
        b.extend(hash);
        b.push(0x56);
        b.extend([7; 32]);
        b.push(0xe7);
        b.extend(value(n));
        b.push(0xe1);
        b
    }
    #[test]
    fn chronological_restores_source_order_and_hash_ordinals() {
        let t0 = value(500);
        let t1 = value(501);
        let t2 = value(502);
        let r = Row {
            seq: 1,
            header: vec![],
            txs: vec![
                (t2.clone(), meta(2, &shamap::tx_id(&t0), 9)),
                (t0.clone(), meta(0, &shamap::tx_id(&t2), 7)),
                (t1.clone(), meta(1, &shamap::tx_id(&t0), 7)),
            ],
            patches: vec![([7; 32], value(9)), ([8; 32], vec![])],
        };
        assert_eq!(processing_order(&r), vec![1, 2, 0]);
        for cached in [false, true] {
            let (frame, s) = encode_block(std::slice::from_ref(&r), options(cached)).unwrap();
            assert!(s.derived_hashes > 0);
            assert!(s.context_repeats > 0);
            let mut p = fast::Prepared::parse(&frame).unwrap();
            for i in [2, 0, 1] {
                assert_eq!(p.tx(i).unwrap(), r.txs[i]);
            }
            assert_eq!(p.all_rows().unwrap(), vec![r.clone()]);
        }
    }
    #[test]
    fn missing_duplicate_or_malformed_index_preserves_source_order() {
        for metas in [
            vec![vec![], vec![]],
            vec![meta(0, &[0; 32], 1), meta(0, &[0; 32], 2)],
            vec![vec![0xff], meta(1, &[0; 32], 1)],
        ] {
            let r = Row {
                seq: 1,
                header: vec![],
                txs: metas
                    .into_iter()
                    .enumerate()
                    .map(|(i, m)| (value(i as u32), m))
                    .collect(),
                patches: vec![],
            };
            assert_eq!(processing_order(&r), vec![0, 1]);
            let (f, _) = encode_block(std::slice::from_ref(&r), options(true)).unwrap();
            assert_eq!(decode_block(&f).unwrap(), vec![r]);
        }
    }
    #[test]
    fn cached_fields_preserve_absence_tombstones_unknown_and_recreation() {
        let r = Row {
            seq: 1,
            header: vec![],
            txs: vec![],
            patches: vec![
                ([3; 32], value(7)),
                ([3; 32], value(7)),
                ([3; 32], vec![]),
                ([3; 32], vec![0xff, 7, 8]),
                ([3; 32], vec![0xff, 7, 8]),
                ([3; 32], value(9)),
                ([3; 32], value(7)),
                ([3; 32], value(7)),
            ],
        };
        let (f, s) = encode_block(std::slice::from_ref(&r), options(true)).unwrap();
        assert_eq!(s.context_repeats, 3);
        assert_eq!(decode_block(&f).unwrap(), vec![r]);
    }
    #[test]
    fn cached_field_without_prior_value_is_rejected() {
        let mut raw = b"JC05".to_vec();
        let layout = vec![1, 1, 0, 0, 0];
        blob(&mut raw, &layout);
        put(&mut raw, 0); // dictionary
        put(&mut raw, 1);
        put(&mut raw, 1);
        raw.push(3);
        put(&mut raw, 36); // cached template
        put(&mut raw, 1);
        blob(&mut raw, &[0]);
        blob(&mut raw, &[2]); // context 1
        put(&mut raw, 1);
        put(&mut raw, 36);
        put(&mut raw, 0);
        raw.push(0);
        blob(&mut raw, &[]);
        let mut frame = (raw.len() as u64).to_le_bytes().to_vec();
        frame.extend(zstd::bulk::compress(&raw, 1).unwrap());
        assert!(
            fast::Prepared::parse(&frame)
                .err()
                .unwrap()
                .contains("missing cached field")
        );
    }
    #[test]
    fn canonical_order_and_thin_reader_keep_original_hash_references() {
        let mut txs = vec![];
        let other = value(999);
        for i in 0..9 {
            let t = value(i);
            txs.push((t.clone(), meta(8 - i, &shamap::tx_id(&other), i)));
        }
        txs.push((other.clone(), meta(9, &shamap::tx_id(&value(0)), 9)));
        txs.sort_by_key(|(t, _)| shamap::tx_id(t));
        let mut r = Row {
            seq: 1,
            header: vec![],
            txs,
            patches: vec![],
        };
        for canonical_source in [true, false] {
            if !canonical_source {
                r.txs.reverse();
            }
            let opt = Options {
                hash_order: true,
                ..options(true)
            };
            let (f, _) = encode_block(std::slice::from_ref(&r), opt).unwrap();
            let mut p = fast::Prepared::for_read(&f).unwrap();
            assert!(p.tree.is_empty() && p.plans.is_empty() && p.tree_docs.is_empty());
            for i in (0..r.txs.len()).rev() {
                assert_eq!(p.tx(i).unwrap(), r.txs[i]);
            }
            assert_eq!(p.all_rows().unwrap(), vec![r.clone()]);
            assert_eq!(decode_block(&f).unwrap(), vec![r.clone()]);
        }
    }
}
#[cfg(test)]
mod part_tests {
    use super::*;
    fn value(n: u32) -> Vec<u8> {
        let mut b = vec![0x24];
        b.extend(n.to_be_bytes());
        b
    }
    fn meta(index: u32, hash: &[u8; 32], n: u32) -> Vec<u8> {
        let mut b = vec![0x20, 28];
        b.extend(index.to_be_bytes());
        b.push(0x55);
        b.extend(hash);
        b.push(0xe7);
        b.extend(value(n));
        b.push(0xe1);
        b
    }
    fn options(part_raw: usize) -> Options {
        Options {
            joint: true,
            adaptive: true,
            context_delta: true,
            split_shapes: true,
            chronological: true,
            cached_slots: true,
            hash_order: true,
            part_raw,
            ..Options::default()
        }
    }
    /// Ledgers whose metadata names transactions of other ledgers, some stored
    /// in hash order and some not, with changes to the same objects.
    fn rows() -> Vec<Row> {
        let tx = |k: u32, i: u32| value(k * 100 + i);
        (0..12u32)
            .map(|k| {
                let n = 2 + k % 4;
                let mut txs: Vec<_> = (0..n)
                    .map(|i| {
                        // The first transaction names one of another ledger, the
                        // rest name the first, which nothing else names.
                        let other = if i == 0 {
                            tx((k + 5) % 12, 1)
                        } else {
                            tx(k, 0)
                        };
                        (tx(k, i), meta(i, &shamap::tx_id(&other), k + i))
                    })
                    .collect();
                if k % 2 == 0 {
                    txs.sort_by_key(|(t, _)| shamap::tx_id(t));
                } else {
                    txs.reverse();
                }
                Row {
                    seq: 1 + k,
                    header: value(k),
                    txs,
                    patches: vec![([(k % 3) as u8; 32], value(k)), ([9; 32], value(k / 2))],
                }
            })
            .collect()
    }
    #[test]
    fn parts_restore_every_row() {
        let rs = rows();
        let (whole, _) = encode_block(&rs, options(0)).unwrap();
        let (frame, s) = encode_block(&rs, options(150)).unwrap();
        assert!(s.parts > 3 && s.derived_hashes > 0);
        assert_eq!(decode_block(&whole).unwrap(), rs);
        assert_eq!(
            fast::Prepared::parse_parts(&frame)
                .unwrap()
                .all_rows()
                .unwrap(),
            rs
        );
        let mut p = fast::Prepared::open_parts(&frame).unwrap();
        assert_eq!(p.compiled_parts(), 0);
        for k in [7, 0, 11, 3] {
            assert_eq!(p.row(k).unwrap(), rs[k]);
        }
        assert!(fast::Prepared::open(&frame).is_err());
        assert!(fast::Prepared::open_parts(&whole).is_err());
    }
    #[test]
    fn one_transaction_compiles_only_its_part() {
        let rs = rows();
        let (frame, s) = encode_block(&rs, options(150)).unwrap();
        let (whole, _) = encode_block(&rs, options(0)).unwrap();
        for k in [6usize, 1, 10] {
            let mut p = fast::Prepared::open_parts(&frame).unwrap();
            let mut q = fast::Prepared::open(&whole).unwrap();
            for i in 0..rs[k].txs.len() as u32 {
                let want = rs[k]
                    .txs
                    .iter()
                    .find(|(_, m)| m[2..6] == i.to_be_bytes())
                    .cloned();
                assert_eq!(p.tx_with_index(k, i).unwrap(), want);
                assert_eq!(q.tx_with_index(k, i).unwrap(), want);
            }
            assert_eq!(p.tx_with_index(k, 40).unwrap(), None);
            assert_eq!(p.header(k).unwrap(), rs[k].header);
            // Hashes of transactions in other parts are stored, not derived.
            assert_eq!(p.compiled_parts(), 1);
            assert!(s.parts > 1);
        }
    }
    #[test]
    fn a_damaged_part_fails_only_its_ledgers() {
        let rs = rows();
        let (mut frame, s) = encode_block(&rs, options(150)).unwrap();
        let last = frame.len() - 3;
        frame[last] ^= 0x55;
        let mut p = fast::Prepared::open_parts(&frame).unwrap();
        assert!(s.parts > 1);
        assert_eq!(p.row(0).unwrap(), rs[0]);
        assert_ne!(p.row(rs.len() - 1), Ok(rs[rs.len() - 1].clone()));
    }
}
