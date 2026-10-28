//! Reader for the XRPLA publication, a source of full mainnet history.
//!
//! The publication is a signed catalog (Ed25519, publisher key pinned on our side)
//! listing ledger ranges in XRPP containers. A container is a directory,
//! XRPH segments and a transaction index, each part with its own SHA-256. An
//! XRPH v2 segment holds up to 4096 ledgers in pages of 64: a shared segment dictionary
//! (field headers; values; hashes with computation recipes; "atoms", each a
//! field with a value; "shapes", each an object's set of fields), then for each page a
//! transaction section and a metadata section with object changes. Metadata and
//! objects are stored as "views": only the fields that changed since the previous version
//! of the same object on the page.
//!
//! The format was read from the public XRPLA documentation and code
//! (`tools/history_codec.py`, `tools/xrpp.py`, MIT; commit 24cb947); we don't
//! run their code. The publication doesn't have to be trusted: every page is checked against
//! the digest of its canonical bytes, every ledger against the transaction root and
//! the parent chain, every range against the hash in the signed catalog; state
//! roots are checked when the changes are replayed.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use witness_core::sha512_half;
use witness_core::shamap::tx_id;

use crate::ledger::{Change, Ledger, StateChange};

type Res<T> = Result<T, String>;

const MAX_RECORD: usize = 16 << 20;
const MAX_SECTION: usize = 128 << 20;
const MAX_SEGMENT: usize = 512 << 20;
const MAX_ITEMS: u64 = 4_000_000;
/// Number of arguments per hash recipe: 1 transaction hash (index in the segment);
/// 2 AccountRoot, 3 Offer, 4 RippleState; 5 Ticket; 6 Check; 7 owner
/// directory; 8 book directory; 9 directory page (root, then page
/// number); 10 ledger hash (ledger offset in the segment).
const RECIPE_ARGS: [usize; 11] = [0, 1, 1, 2, 3, 2, 2, 1, 5, 1, 1];

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Byte reader with bounds checks.
struct R<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> R<'a> {
    fn new(d: &'a [u8]) -> R<'a> {
        R { d, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.d.len());
        let end = end.ok_or_else(|| format!("data truncated at {}", self.pos))?;
        let v = &self.d[self.pos..end];
        self.pos = end;
        Ok(v)
    }

    fn u32(&mut self) -> Res<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// LEB128 of at most 19 bytes, without a redundant zero byte, no greater than `limit`.
    fn v(&mut self, limit: u64) -> Res<u64> {
        let mut n: u128 = 0;
        for i in 0..19 {
            let b = self.take(1)?[0];
            n |= u128::from(b & 0x7F) << (7 * i);
            if b & 0x80 == 0 {
                if (i > 0 && b == 0) || n > u128::from(limit) {
                    return Err("number is non-canonical or out of range".into());
                }
                return Ok(n as u64);
            }
        }
        Err("number too long".into())
    }

    fn vu(&mut self, limit: u64) -> Res<usize> {
        usize::try_from(self.v(limit)?).map_err(|e| e.to_string())
    }

    fn blob(&mut self) -> Res<&'a [u8]> {
        let n = self.vu(MAX_SECTION as u64)?;
        self.take(n)
    }

    fn end(&self) -> Res<()> {
        if self.pos != self.d.len() {
            return Err("trailing bytes".into());
        }
        Ok(())
    }
}

/// XRPP container directory: range, hashes and segments.
#[derive(Debug, Clone)]
pub struct Directory {
    pub first: u32,
    pub last: u32,
    pub parent_hash: [u8; 32],
    pub last_hash: [u8; 32],
    pub transactions: u64,
    /// (first ledger, ledger count, offset, length, SHA-256).
    pub rows: Vec<(u32, u32, u64, u64, [u8; 32])>,
    /// Directory size in bytes.
    pub size: usize,
}

const XRPP_HEAD: usize = 4 + 2 + 1 + 1 + 4 + 4 + 4 + 32 + 32 + 8;
const XRPP_ROW: usize = 4 + 4 + 8 + 8 + 32;
const XRPP_INDEX: usize = 8 + 8 + 32;

impl Directory {
    /// How many bytes the directory takes, from its header.
    pub fn size_from_head(head: &[u8]) -> Res<usize> {
        let mut r = R::new(head);
        if r.take(4)? != b"XRPP" {
            return Err("not an XRPP container".into());
        }
        r.take(2 + 1 + 1 + 4 + 4)?;
        let n = r.u32()? as usize;
        if !(1..=65536).contains(&n) {
            return Err("segment count out of range".into());
        }
        Ok(XRPP_HEAD + XRPP_ROW * n + XRPP_INDEX)
    }

    pub const HEAD: usize = XRPP_HEAD;

    /// Directory checked against the SHA-256 from the catalog.
    pub fn parse(data: &[u8], expected_sha256: &[u8; 32]) -> Res<Directory> {
        let size = Directory::size_from_head(data)?;
        let d = data.get(..size).ok_or("directory truncated")?;
        if &sha256(d) != expected_sha256 {
            return Err("directory does not match the catalog".into());
        }
        let mut r = R::new(d);
        r.take(4)?;
        let version = u16::from_le_bytes(r.take(2)?.try_into().map_err(|_| "version")?);
        let kind = r.take(1)?[0];
        r.take(1)?;
        let first = r.u32()?;
        let last = r.u32()?;
        let n = r.u32()? as usize;
        if version != 1 || kind > 1 || last < first {
            return Err("invalid container header".into());
        }
        let h32 =
            |r: &mut R| -> Res<[u8; 32]> { r.take(32)?.try_into().map_err(|_| "hash".to_string()) };
        let parent_hash = h32(&mut r)?;
        let last_hash = h32(&mut r)?;
        let transactions = u64::from_le_bytes(r.take(8)?.try_into().map_err(|_| "count")?);
        let mut rows = Vec::with_capacity(n);
        let (mut expected, mut offset) = (u64::from(first), size as u64);
        for _ in 0..n {
            let start = r.u32()?;
            let count = r.u32()?;
            let at = u64::from_le_bytes(r.take(8)?.try_into().map_err(|_| "offset")?);
            let len = u64::from_le_bytes(r.take(8)?.try_into().map_err(|_| "length")?);
            let sha = h32(&mut r)?;
            if u64::from(start) != expected || count == 0 || at != offset {
                return Err("segment table is not contiguous".into());
            }
            expected += u64::from(count);
            offset += len;
            rows.push((start, count, at, len, sha));
        }
        if expected != u64::from(last) + 1 {
            return Err("segments do not cover the range".into());
        }
        Ok(Directory {
            first,
            last,
            parent_hash,
            last_hash,
            transactions,
            rows,
            size,
        })
    }
}

/// Hash recipe from the segment dictionary.
#[derive(Debug, Clone)]
enum HashItem {
    Literal([u8; 32]),
    Recipe(u8, Vec<u64>),
}

/// Atom: field header (index) and value.
#[derive(Debug, Clone)]
struct Atom {
    header: usize,
    kind: u8,
    args: Vec<usize>,
}

/// Segment page: first ledger, ledger count, first transaction,
/// transaction count, digest of canonical bytes.
type Page = (u32, u32, u32, u32, [u8; 32]);

/// Parsed transaction page: (ledger, header, transactions) and all
/// transactions in sequence.
type TxPage = (Vec<(u32, Vec<u8>, Vec<Vec<u8>>)>, Vec<Vec<u8>>);

/// XRPH v2 segment.
pub struct Segment<'a> {
    data: &'a [u8],
    pub first: u32,
    pub count: u32,
    digest: [u8; 32],
    pages: Vec<Page>,
    /// (offset, compressed length, uncompressed size, SHA-256).
    sections: Vec<(usize, usize, usize, [u8; 32])>,
    headers: Vec<Vec<u8>>,
    values: Vec<Vec<u8>>,
    hashes: Vec<HashItem>,
    atoms: Vec<Atom>,
    shapes: Vec<Vec<usize>>,
    tx_cache: HashMap<usize, std::rc::Rc<TxPage>>,
    hash_cache: HashMap<usize, [u8; 32]>,
    atom_cache: HashMap<usize, std::rc::Rc<Vec<u8>>>,
    resolving: std::collections::HashSet<usize>,
}

impl std::fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("first", &self.first)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

const XRPH_HEAD: usize = 4 + 2 + 4 + 4 + 2 + 2 + 32;
const XRPH_PAGE: usize = 4 + 4 + 4 + 4 + 32;
const XRPH_SECTION: usize = 4 + 4 + 32;

impl<'a> Segment<'a> {
    /// Segment checked against the SHA-256 from the directory and against its own trailer.
    pub fn open(data: &'a [u8], expected_sha256: &[u8; 32]) -> Res<Segment<'a>> {
        if data.len() > MAX_SEGMENT || data.len() < XRPH_HEAD + 32 {
            return Err("segment size out of range".into());
        }
        if &sha256(data) != expected_sha256 {
            return Err("segment does not match the directory".into());
        }
        let body = &data[..data.len() - 32];
        if sha256(body)[..] != data[data.len() - 32..] {
            return Err("segment trailer mismatch".into());
        }
        let mut r = R::new(body);
        if r.take(4)? != b"XRPH" {
            return Err("not an XRPH segment".into());
        }
        let version = u16::from_le_bytes(r.take(2)?.try_into().map_err(|_| "version")?);
        let first = r.u32()?;
        let count = r.u32()?;
        let block = u16::from_le_bytes(r.take(2)?.try_into().map_err(|_| "page")?) as u32;
        let n = u16::from_le_bytes(r.take(2)?.try_into().map_err(|_| "pages")?) as usize;
        let digest: [u8; 32] = r.take(32)?.try_into().map_err(|_| "digest")?;
        if version != 2
            || !(1..=4096).contains(&count)
            || !(1..=256).contains(&block)
            || n as u32 != count.div_ceil(block)
        {
            return Err(format!(
                "segment: version {version} or header not supported"
            ));
        }
        let mut pages = Vec::with_capacity(n);
        let (mut seq, mut txfirst) = (first, 0u32);
        for _ in 0..n {
            let f = r.u32()?;
            let c = r.u32()?;
            let t = r.u32()?;
            let nt = r.u32()?;
            let d: [u8; 32] = r.take(32)?.try_into().map_err(|_| "digest")?;
            if f != seq || c != block.min(first + count - seq) || t != txfirst || nt > 1_000_000 {
                return Err("page index mismatch".into());
            }
            pages.push((f, c, t, nt, d));
            seq += c;
            txfirst += nt;
        }
        let mut start = XRPH_HEAD + n * XRPH_PAGE + (2 * n + 1) * XRPH_SECTION;
        let mut sections = Vec::with_capacity(2 * n + 1);
        let mut raw_total = 0usize;
        for _ in 0..2 * n + 1 {
            let size = r.u32()? as usize;
            let len = r.u32()? as usize;
            let sha: [u8; 32] = r.take(32)?.try_into().map_err(|_| "section hash")?;
            if size > MAX_SECTION || start + len > body.len() {
                return Err("section outside the segment".into());
            }
            sections.push((start, len, size, sha));
            start += len;
            raw_total += size;
        }
        if start != body.len() || raw_total > MAX_SEGMENT {
            return Err("sections do not cover the segment".into());
        }
        let mut s = Segment {
            data,
            first,
            count,
            digest,
            pages,
            sections,
            headers: Vec::new(),
            values: Vec::new(),
            hashes: Vec::new(),
            atoms: Vec::new(),
            shapes: Vec::new(),
            tx_cache: HashMap::new(),
            hash_cache: HashMap::new(),
            atom_cache: HashMap::new(),
            resolving: Default::default(),
        };
        let dict = s.section(0)?;
        s.dictionary(&dict)?;
        Ok(s)
    }

    fn section(&self, i: usize) -> Res<Vec<u8>> {
        let (at, len, size, sha) = self.sections[i];
        let frame = &self.data[at..at + len];
        if sha256(frame) != sha {
            return Err("section does not match its hash".into());
        }
        let raw = zstd::bulk::decompress(frame, size).map_err(|e| e.to_string())?;
        if raw.len() != size {
            return Err("section size mismatch".into());
        }
        Ok(raw)
    }

    fn dictionary(&mut self, data: &[u8]) -> Res<()> {
        let mut r = R::new(data);
        if r.take(4)? != b"XHD2" {
            return Err("not an XHD2 dictionary".into());
        }
        let limit = MAX_ITEMS.min(data.len() as u64);
        let n = r.vu(limit)?;
        for _ in 0..n {
            let h = r.blob()?;
            if !(1..=3).contains(&h.len()) {
                return Err("invalid field header".into());
            }
            self.headers.push(h.to_vec());
        }
        let n = r.vu(limit)?;
        for _ in 0..n {
            self.values.push(r.blob()?.to_vec());
        }
        let n = r.vu(limit)?;
        for _ in 0..n {
            let mode = r.take(1)?[0];
            if mode == 0 {
                self.hashes.push(HashItem::Literal(
                    r.take(32)?.try_into().map_err(|_| "hash")?,
                ));
                continue;
            }
            let args_n = *RECIPE_ARGS
                .get(usize::from(mode))
                .filter(|_| mode <= 10)
                .ok_or("invalid hash recipe")?;
            let mut args = Vec::with_capacity(args_n + 1);
            for _ in 0..args_n {
                args.push(r.v(MAX_ITEMS)?);
            }
            if mode == 9 {
                let page = r.v(u64::MAX)?;
                if page == 0 {
                    return Err("directory page number is zero".into());
                }
                args.push(page);
            }
            self.hashes.push(HashItem::Recipe(mode, args));
        }
        let n = r.vu(limit)?;
        for _ in 0..n {
            let header = r.vu(u64::MAX)?;
            let kind = r.vu(4)? as u8;
            let args = if kind == 4 {
                let prefix = r.vu(MAX_ITEMS)?;
                let k = r.vu((MAX_RECORD / 32) as u64)?;
                let mut a = vec![prefix];
                for _ in 0..k {
                    a.push(r.vu(MAX_ITEMS)?);
                }
                a
            } else {
                let k = if kind == 3 { 3 } else { 1 };
                (0..k).map(|_| r.vu(MAX_ITEMS)).collect::<Res<_>>()?
            };
            self.atoms.push(Atom { header, kind, args });
        }
        let n = r.vu(limit)?;
        for _ in 0..n {
            let k = r.vu(65536)?;
            self.shapes
                .push((0..k).map(|_| r.vu(u64::MAX)).collect::<Res<_>>()?);
        }
        r.end()
    }

    fn get<T>(v: &[T], i: usize) -> Res<&T> {
        v.get(i)
            .ok_or_else(|| "reference outside the dictionary".to_string())
    }

    fn tx_page(&mut self, i: usize) -> Res<std::rc::Rc<TxPage>> {
        if let Some(p) = self.tx_cache.get(&i) {
            return Ok(p.clone());
        }
        let raw = self.section(1 + 2 * i)?;
        let mut r = R::new(&raw);
        let (first, count, _, nt, _) = self.pages[i];
        if r.vu(256)? != count as usize {
            return Err("transaction page ledger count".into());
        }
        let (mut rows, mut flat) = (Vec::new(), Vec::new());
        for seq in first..first + count {
            if r.u32()? != seq {
                return Err("ledger sequence on transaction page".into());
            }
            let header = r.blob()?.to_vec();
            let n = r.vu(1_000_000)?;
            let mut txs = Vec::with_capacity(n);
            for _ in 0..n {
                let tx = r.blob()?;
                if tx.len() > MAX_RECORD {
                    return Err("transaction out of range".into());
                }
                txs.push(tx.to_vec());
            }
            flat.extend(txs.iter().cloned());
            rows.push((seq, header, txs));
        }
        r.end()?;
        if flat.len() != nt as usize {
            return Err("page transaction count mismatch".into());
        }
        let p = std::rc::Rc::new((rows, flat));
        self.tx_cache.insert(i, p.clone());
        Ok(p)
    }

    fn hash(&mut self, i: usize) -> Res<[u8; 32]> {
        if let Some(h) = self.hash_cache.get(&i) {
            return Ok(*h);
        }
        let item = Self::get(&self.hashes, i)?.clone();
        let h = match item {
            HashItem::Literal(h) => h,
            HashItem::Recipe(1, a) => {
                let t = u32::try_from(a[0]).map_err(|e| e.to_string())?;
                let page = self
                    .pages
                    .partition_point(|p| p.2 <= t)
                    .checked_sub(1)
                    .ok_or("transaction hash recipe outside the segment")?;
                let p = self.tx_page(page)?;
                let tx = Self::get(&p.1, (t - self.pages[page].2) as usize)?;
                tx_id(tx)
            }
            HashItem::Recipe(9, a) => {
                if !self.resolving.insert(i) {
                    return Err("hash recipe cycle".into());
                }
                // Real chains are short; a long one means corruption, not a reason
                // to exhaust the stack.
                if self.resolving.len() > 64 {
                    self.resolving.remove(&i);
                    return Err("hash recipe too deep".into());
                }
                let root = self.hash(usize::try_from(a[0]).map_err(|e| e.to_string())?);
                self.resolving.remove(&i);
                let mut b = b"\x00d".to_vec();
                b.extend(root?);
                b.extend(a[1].to_be_bytes());
                sha512_half(&b)
            }
            HashItem::Recipe(10, a) => {
                let off = u32::try_from(a[0]).map_err(|e| e.to_string())?;
                if off >= self.count {
                    return Err("ledger hash recipe outside the segment".into());
                }
                let seq = self.first + off;
                let page = self
                    .pages
                    .partition_point(|p| p.0 <= seq)
                    .checked_sub(1)
                    .ok_or("ledger hash recipe outside the segment")?;
                let p = self.tx_page(page)?;
                let header = &p.0[(seq - self.pages[page].0) as usize].1;
                let mut b = b"LWR\x00".to_vec();
                b.extend(header);
                sha512_half(&b)
            }
            HashItem::Recipe(mode, a) => {
                let vals: Vec<&[u8]> = a
                    .iter()
                    .map(|x| Self::get(&self.values, *x as usize).map(Vec::as_slice))
                    .collect::<Res<_>>()?;
                let lens: Vec<usize> = vals.iter().map(|v| v.len()).collect();
                let (prefix, expected): (&[u8], &[usize]) = match mode {
                    2 => (b"\x00a", &[20]),
                    3 => (b"\x00o", &[20, 4]),
                    4 => (b"\x00r", &[20, 20, 20]),
                    5 => (b"\x00T", &[20, 4]),
                    6 => (b"\x00C", &[20, 4]),
                    7 => (b"\x00O", &[20]),
                    8 => (b"\x00B", &[20, 20, 20, 20, 8]),
                    _ => return Err("unknown hash recipe".into()),
                };
                if lens != expected {
                    return Err("recipe argument sizes".into());
                }
                if mode == 8 {
                    let mut b = prefix.to_vec();
                    for v in &vals[..4] {
                        b.extend(*v);
                    }
                    let mut h = sha512_half(&b);
                    h[24..].copy_from_slice(vals[4]);
                    h
                } else {
                    let mut b = prefix.to_vec();
                    for v in &vals {
                        b.extend(*v);
                    }
                    sha512_half(&b)
                }
            }
        };
        self.hash_cache.insert(i, h);
        Ok(h)
    }

    fn atom(&mut self, i: usize) -> Res<std::rc::Rc<Vec<u8>>> {
        if let Some(a) = self.atom_cache.get(&i) {
            return Ok(a.clone());
        }
        let a = Self::get(&self.atoms, i)?.clone();
        let mut out = Self::get(&self.headers, a.header)?.clone();
        match a.kind {
            0 => out.extend(Self::get(&self.values, a.args[0])?),
            1 => {
                let h = self.hash(a.args[0])?;
                out.extend(h);
            }
            2 => {
                let acc = Self::get(&self.values, a.args[0])?;
                if acc.len() != 20 {
                    return Err("account size".into());
                }
                out.push(0x14);
                out.extend(acc);
            }
            3 => {
                let parts: Vec<Vec<u8>> = a
                    .args
                    .iter()
                    .map(|x| Self::get(&self.values, *x).cloned())
                    .collect::<Res<_>>()?;
                if parts.iter().map(Vec::len).collect::<Vec<_>>() != [8, 20, 20] {
                    return Err("amount size".into());
                }
                parts.iter().for_each(|p| out.extend(p));
            }
            4 => {
                let prefix = Self::get(&self.values, a.args[0])?.clone();
                let n = vl_len(&prefix)?;
                if n != 32 * (a.args.len() - 1) {
                    return Err("vector length mismatch".into());
                }
                out.extend(&prefix);
                for x in &a.args[1..] {
                    let h = self.hash(*x)?;
                    out.extend(h);
                }
            }
            _ => return Err("invalid atom kind".into()),
        }
        if out.len() > MAX_RECORD {
            return Err("atom out of range".into());
        }
        let out = std::rc::Rc::new(out);
        self.atom_cache.insert(i, out.clone());
        Ok(out)
    }

    /// Object view: shape, mask of changed fields, indexes of new atoms;
    /// unchanged fields come from the page cache by object key.
    fn view(
        &mut self,
        r: &mut R,
        key: usize,
        cache: &mut HashMap<usize, HashMap<usize, usize>>,
        budget: usize,
    ) -> Res<Vec<u8>> {
        let sid = r.vu(u64::MAX)?;
        let shape = Self::get(&self.shapes, sid)?.clone();
        let mask = r.take(shape.len().div_ceil(8))?.to_vec();
        if !shape.len().is_multiple_of(8)
            && !mask.is_empty()
            && mask[mask.len() - 1] >> (shape.len() % 8) != 0
        {
            return Err("extra bits in view mask".into());
        }
        let mut out = Vec::new();
        for (j, hid) in shape.iter().enumerate() {
            if mask[j / 8] & (1 << (j % 8)) != 0 {
                let aid = r.vu(u64::MAX)?;
                if Self::get(&self.atoms, aid)?.header != *hid {
                    return Err("field shape mismatch".into());
                }
                cache.entry(key).or_default().insert(*hid, aid);
            }
            let aid = *cache
                .get(&key)
                .and_then(|c| c.get(hid))
                .ok_or("no base version of the field on the page")?;
            out.extend(self.atom(aid)?.iter());
            if out.len() > budget {
                return Err("view expanded beyond the limit".into());
            }
        }
        Ok(out)
    }

    fn node(
        &mut self,
        r: &mut R,
        cache: &mut HashMap<usize, HashMap<usize, usize>>,
        budget: usize,
        depth: usize,
    ) -> Res<Vec<u8>> {
        if depth > 64 {
            return Err("too deep".into());
        }
        let tag = r.take(1)?[0];
        if tag == 0 {
            let a = self.atom(r.vu(u64::MAX)?)?;
            if a.len() > budget {
                return Err("node out of range".into());
            }
            return Ok(a.to_vec());
        }
        if tag != 1 && tag != 2 {
            return Err("invalid node tag".into());
        }
        let h = Self::get(&self.headers, r.vu(u64::MAX)?)?.clone();
        let end = r.blob()?.to_vec();
        if !(1..=3).contains(&end.len()) || h.len() + end.len() > budget {
            return Err("container out of range".into());
        }
        if tag == 2 {
            let key = r.vu(u64::MAX)?;
            Self::get(&self.hashes, key)?;
            let reset = r.take(1)?[0];
            if reset > 1 {
                return Err("reset flag".into());
            }
            if reset == 1 {
                cache.remove(&key);
            }
            let mut out = h.clone();
            out.extend(self.view(r, key, cache, budget - h.len() - end.len())?);
            out.extend(&end);
            return Ok(out);
        }
        let mut out = h;
        let n = r.vu(1_000_000)?;
        for _ in 0..n {
            let rest = budget
                .checked_sub(out.len() + end.len())
                .ok_or("container out of range")?;
            let child = self.node(r, cache, rest, depth + 1)?;
            out.extend(child);
        }
        out.extend(&end);
        Ok(out)
    }

    fn metadata(
        &mut self,
        r: &mut R,
        cache: &mut HashMap<usize, HashMap<usize, usize>>,
        length: usize,
    ) -> Res<Vec<u8>> {
        let tag = r.take(1)?[0];
        let v = match tag {
            0 => r.blob()?.to_vec(),
            1 => {
                let mut v = Vec::with_capacity(length);
                let n = r.vu(65536)?;
                for _ in 0..n {
                    let rest = length.checked_sub(v.len()).ok_or("metadata too long")?;
                    let x = self.node(r, cache, rest, 0)?;
                    v.extend(x);
                }
                v
            }
            _ => return Err("metadata tag".into()),
        };
        if v.len() != length {
            return Err("metadata length mismatch".into());
        }
        Ok(v)
    }

    /// Ledgers of page `i`, checked against the digest of canonical bytes.
    pub fn page(&mut self, i: usize) -> Res<Vec<Ledger>> {
        let txp = self.tx_page(i)?;
        let raw = self.section(2 + 2 * i)?;
        let mut r = R::new(&raw);
        let (_, count, _, _, digest) = self.pages[i];
        let mut cache: HashMap<usize, HashMap<usize, usize>> = HashMap::new();
        if r.vu(256)? != count as usize {
            return Err("history page ledger count".into());
        }
        let mut records: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut out = Vec::new();
        for (seq, header, txs) in txp.0.iter() {
            if r.vu(1_000_000)? != txs.len() {
                return Err("metadata count".into());
            }
            let mut metas: Vec<Option<Vec<u8>>> = vec![None; txs.len()];
            for _ in 0..txs.len() {
                let at = r.vu(u64::MAX)?;
                let len = r.vu(MAX_RECORD as u64)?;
                if at >= txs.len() || metas[at].is_some() {
                    return Err("transaction permutation".into());
                }
                metas[at] = Some(self.metadata(&mut r, &mut cache, len)?);
            }
            let mut row = Vec::new();
            row.extend(seq.to_le_bytes());
            row.extend((header.len() as u32).to_le_bytes());
            row.extend(header);
            row.extend((txs.len() as u32).to_le_bytes());
            let mut transactions = Vec::with_capacity(txs.len());
            for (tx, meta) in txs.iter().zip(metas) {
                let meta = meta.ok_or("missing metadata")?;
                row.extend((tx.len() as u32).to_le_bytes());
                row.extend(tx);
                row.extend((meta.len() as u32).to_le_bytes());
                row.extend(&meta);
                transactions.push((tx.clone(), meta));
            }
            let n = r.vu(1_000_000)?;
            row.extend((n as u32).to_le_bytes());
            let mut changes = Vec::with_capacity(n);
            let mut prior: Option<[u8; 32]> = None;
            for _ in 0..n {
                let kid = r.vu(u64::MAX)?;
                let key = self.hash(kid)?;
                if prior.is_some_and(|p| key <= p) {
                    return Err("object change order".into());
                }
                prior = Some(key);
                let len = r.vu(MAX_RECORD as u64)?;
                let value = if len == 0 {
                    cache.remove(&kid);
                    Vec::new()
                } else {
                    let v = match r.take(1)?[0] {
                        0 => r.blob()?.to_vec(),
                        1 => self.view(&mut r, kid, &mut cache, len)?,
                        _ => return Err("object tag".into()),
                    };
                    if v.len() != len {
                        return Err("object length mismatch".into());
                    }
                    v
                };
                row.extend(key);
                row.extend((value.len() as u32).to_le_bytes());
                row.extend(&value);
                changes.push(StateChange {
                    key,
                    // The publication doesn't distinguish created and modified objects:
                    // that is visible only from the previous state.
                    change: if value.is_empty() {
                        Change::Deleted
                    } else {
                        Change::Modified
                    },
                    data: value,
                });
            }
            if row.len() > MAX_SECTION {
                return Err("ledger out of range".into());
            }
            records.push((*seq, row));
            out.push(Ledger {
                header: header.clone(),
                transactions,
                changes,
            });
        }
        r.end()?;
        if sha256(&body_from_records(&records)) != digest {
            return Err("page canonical bytes digest mismatch".into());
        }
        Ok(out)
    }

    /// All ledgers of the segment, checked against the digest of the whole segment.
    pub fn ledgers(&mut self) -> Res<Vec<Ledger>> {
        let mut all = Vec::new();
        let mut h = Sha256::new();
        let mut table = Vec::new();
        let mut position = 0u64;
        for i in 0..self.pages.len() {
            for l in self.page(i)? {
                let row = canonical_row(&l)?;
                h.update(&row);
                table.extend(header_seq(&l)?.to_le_bytes());
                table.extend(position.to_le_bytes());
                position += row.len() as u64;
                all.push(l);
            }
            // The page is no longer needed: caches of expanded transactions and atoms
            // are kept only for recipes within the segment.
        }
        h.update(&table);
        if <[u8; 32]>::from(h.finalize()) != self.digest {
            return Err("segment canonical bytes digest mismatch".into());
        }
        Ok(all)
    }
}

fn header_seq(l: &Ledger) -> Res<u32> {
    let b = l.header.get(..4).ok_or("header truncated")?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Canonical bytes of a ledger in the XRPLA publication (v2 record).
fn canonical_row(l: &Ledger) -> Res<Vec<u8>> {
    let mut row = Vec::new();
    row.extend(header_seq(l)?.to_le_bytes());
    row.extend((l.header.len() as u32).to_le_bytes());
    row.extend(&l.header);
    row.extend((l.transactions.len() as u32).to_le_bytes());
    for (t, m) in &l.transactions {
        row.extend((t.len() as u32).to_le_bytes());
        row.extend(t);
        row.extend((m.len() as u32).to_le_bytes());
        row.extend(m);
    }
    row.extend((l.changes.len() as u32).to_le_bytes());
    for c in &l.changes {
        row.extend(c.key);
        row.extend((c.data.len() as u32).to_le_bytes());
        row.extend(&c.data);
    }
    Ok(row)
}

/// v2 body: records in sequence, then a table (u32 sequence, u64 offset).
fn body_from_records(records: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut table = Vec::new();
    for (seq, v) in records {
        table.extend(seq.to_le_bytes());
        table.extend((out.len() as u64).to_le_bytes());
        out.extend(v);
    }
    out.extend(table);
    out
}

/// Length from a VL prefix (1–3 bytes); the whole prefix must be present.
fn vl_len(prefix: &[u8]) -> Res<usize> {
    let a = usize::from(*prefix.first().ok_or("empty prefix")?);
    let (n, used) = match a {
        0..=192 => (a, 1),
        193..=240 => (
            193 + (a - 193) * 256 + usize::from(*prefix.get(1).ok_or("prefix")?),
            2,
        ),
        241..=254 => (
            12_481
                + (a - 241) * 65_536
                + usize::from(*prefix.get(1).ok_or("prefix")?) * 256
                + usize::from(*prefix.get(2).ok_or("prefix")?),
            3,
        ),
        _ => return Err("invalid length prefix".into()),
    };
    if used != prefix.len() {
        return Err("incomplete length prefix".into());
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_rules() {
        let mut r = R::new(&[0x80, 0x01]);
        assert_eq!(r.v(1000).unwrap(), 128);
        assert!(
            R::new(&[0x80, 0x00]).v(1000).is_err(),
            "redundant zero byte"
        );
        assert!(R::new(&[0xFF, 0x01]).v(100).is_err(), "out of range");
    }

    #[test]
    fn vl_prefixes() {
        assert_eq!(vl_len(&[64]).unwrap(), 64);
        assert_eq!(vl_len(&[193, 0]).unwrap(), 193);
        assert!(vl_len(&[193]).is_err());
    }
}
