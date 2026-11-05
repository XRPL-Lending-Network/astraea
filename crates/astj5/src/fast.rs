//! Compiled, byte-exact document programs. No per-field Rc/Vec allocation at read time.
use super::*;
#[derive(Clone, Copy, Debug)]
pub(crate) struct Atom {
    pub(crate) at: u32,
    pub(crate) len: u32,
}
pub(crate) const NODE: u32 = u32::MAX - 3;
#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) enum PlanOp {
    Fixed(Vec<u8>),
    Value,
    Child,
}
pub(crate) const FIXED: u32 = 1 << 31;
pub(crate) const TX: u32 = u32::MAX;
pub(crate) const KEY: u32 = u32::MAX - 2;
const REPEAT: u32 = u32::MAX - 1;
#[derive(Clone, Copy)]
enum Item {
    Value(Atom),
    Delta(u8, u64),
}
#[derive(Clone, Copy)]
enum Op {
    Value(Atom),
    Column(usize),
    Cached(usize),
    Child,
}
struct Column {
    items: Vec<Item>,
    pos: usize,
}
#[derive(Clone)]
pub(crate) struct Doc {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) size: usize,
}
#[derive(Clone)]
pub(crate) struct Layout {
    pub(crate) seq: u32,
    pub(crate) header: usize,
    pub(crate) tx: Vec<(usize, usize)>,
    pub(crate) patches: Vec<(usize, usize)>,
}
fn append(pool: &mut Vec<u8>, value: &[u8]) -> Res<Atom> {
    let at = u32::try_from(pool.len()).map_err(er)?;
    if pool.len().checked_add(value.len()).is_none_or(|n| n > MAX) {
        return Err("arena limit".into());
    }
    pool.extend(value);
    Ok(Atom {
        at,
        len: value.len() as u32,
    })
}
fn bytes(pool: &[u8], atom: Atom) -> Res<&[u8]> {
    pool.get(atom.at as usize..atom.at as usize + (atom.len & !FIXED) as usize)
        .ok_or("atom extent".into())
}
/// Hasher for the compiler's field cache, keyed by pairs of small indexes.
/// SipHash took a quarter of block preparation; the keys come from the block
/// being read, so a multiplicative mix is enough. Added during integration.
#[derive(Default, Clone, Copy)]
struct PairHasher(u64);
impl std::hash::Hasher for PairHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }
}
type PairMap<V> = HashMap<(usize, usize), V, std::hash::BuildHasherDefault<PairHasher>>;
type IdMap = HashMap<usize, usize, std::hash::BuildHasherDefault<PairHasher>>;
/// A stored value appended to the arena without an intermediate copy.
fn value_append(r: &mut Read<'_>, pool: &mut Vec<u8>) -> Res<Atom> {
    let tag = r.var()?;
    if tag == 1 {
        let s = k256::ecdsa::Signature::from_slice(r.take(64)?).map_err(er)?;
        return append(pool, s.to_der().as_bytes());
    }
    if tag & 1 != 0 {
        return Err("value tag".into());
    }
    let n = usize::try_from(tag >> 1).map_err(er)?;
    if n > MAX {
        return Err("value size".into());
    }
    append(pool, r.take(n)?)
}
/// A ledger as the layout stream describes it, known before any part of the
/// block is compiled.
#[derive(Clone)]
struct Planned {
    seq: u32,
    txs: usize,
    patches: usize,
    /// Encoded position -> original position, when they differ and the
    /// stream says how.
    order: Option<Vec<usize>>,
    /// Position of the ledger's first transaction among all of the block's.
    first_tx: usize,
    part: usize,
    /// Header document, once the ledger's part is compiled.
    header_doc: usize,
    /// `Layout::tx` is in original order.
    sorted: bool,
}
/// Compressed parts and (offset, length, raw length) of each.
type Frames = (Vec<u8>, Vec<(usize, usize, usize)>);
/// What compiling a part needs from the shared section.
struct Shared {
    templates: Vec<Vec<Op>>,
    /// Column key -> dense id used by `Op::Column` / `Op::Cached`.
    dense: IdMap,
    dict: Vec<Atom>,
    v3: bool,
    v4: bool,
    v6: bool,
    auxiliary: bool,
    /// JC06: compressed parts, (offset, length, raw length) of each in
    /// `frames`, and the shared section as their dictionary.
    frames: Vec<u8>,
    spans: Vec<(usize, usize, usize)>,
    parts: Vec<std::ops::Range<usize>>,
    done: Vec<bool>,
    dictionary: Option<zstd::dict::DecoderDictionary<'static>>,
    dictionary_bytes: usize,
    /// Block hash and part digests from a seal (`check_parts`).
    sealed: Option<([u8; 32], Vec<[u8; 32]>)>,
}
/// JC06 frame: the shared section, and every part with its raw size, as
/// ranges of the frame. `head` ends where the parts begin.
pub(crate) struct FrameParts {
    pub(crate) head: usize,
    pub(crate) shared: std::ops::Range<usize>,
    pub(crate) shared_raw: usize,
    pub(crate) parts: Vec<(std::ops::Range<usize>, usize)>,
}
/// Layout of a JC06 frame: u64 raw and compressed size of the shared section,
/// u32 part count, u64 raw and compressed size of every part, then the
/// shared section and the parts.
pub(crate) fn frame_parts(frame: &[u8]) -> Res<FrameParts> {
    fn size(fr: &mut Read<'_>) -> Res<usize> {
        let n = u64::from_le_bytes(fr.take(8)?.try_into().unwrap());
        if n > MAX as u64 {
            return Err("part limit".into());
        }
        Ok(n as usize)
    }
    let mut fr = Read::new(frame);
    let (shared_raw, shared_z) = (size(&mut fr)?, size(&mut fr)?);
    let n = fr.u32()? as usize;
    if n == 0 || n > (frame.len() - fr.p) / 16 {
        return Err("part count".into());
    }
    let mut sizes = vec![];
    for _ in 0..n {
        sizes.push((size(&mut fr)?, size(&mut fr)?));
    }
    let start = fr.p;
    fr.take(shared_z)?;
    let shared = start..fr.p;
    let head = fr.p;
    let mut parts = vec![];
    for (raw, z) in sizes {
        let at = fr.p;
        fr.take(z)?;
        parts.push((at..fr.p, raw));
    }
    fr.end()?;
    Ok(FrameParts {
        head,
        shared,
        shared_raw,
        parts,
    })
}
/// Prepared block: shared literal arena plus flat document instructions.
/// Preparing does not itself authenticate the archive or recompute ledger roots.
///
/// JC06 blocks (added during integration) are cut into parts that compile on
/// their own; `open` compiles a part the first time one of its ledgers is
/// read. Ledgers stored in hash order are put back into it only when a whole
/// ledger is read.
pub struct Prepared {
    pub(crate) pool: Vec<u8>,
    pub(crate) atoms: Vec<Atom>,
    pub(crate) docs: Vec<Doc>,
    pub(crate) layout: Vec<Layout>,
    pub(crate) tree: Vec<Atom>,
    pub(crate) tree_docs: Vec<(usize, usize)>,
    pub(crate) plans: Vec<Vec<PlanOp>>,
    pub(crate) keys: Vec<(u8, Vec<Atom>)>,
    key_hashes: Vec<Option<[u8; 32]>>,
    tx_hashes: Vec<Option<[u8; 32]>>,
    ledgers: Vec<Planned>,
    shared: Box<Shared>,
}
struct Compiler<'a> {
    auxiliary: bool,
    pool: &'a mut Vec<u8>,
    templates: &'a [Vec<Op>],
    local: &'a [usize],
    shapes: &'a [usize],
    contexts: &'a [usize],
    columns: &'a mut [Column],
    at: usize,
    cache: PairMap<Atom>,
    atoms: &'a mut Vec<Atom>,
    docs: &'a mut Vec<Doc>,
    tree: &'a mut Vec<Atom>,
    tree_docs: &'a mut Vec<(usize, usize)>,
}
impl Compiler<'_> {
    fn column(&self, dense: usize) -> Res<usize> {
        match self.local.get(dense) {
            Some(&k) if k != usize::MAX => Ok(k),
            _ => Err("missing column".into()),
        }
    }
    fn visit(&mut self, depth: usize) -> Res<()> {
        if depth > 64 {
            return Err("template depth".into());
        }
        let id = *self.shapes.get(self.at).ok_or("shape exhausted")?;
        let ctx = self.contexts[self.at];
        self.at += 1;
        if self.auxiliary {
            self.tree.push(Atom {
                at: id as u32,
                len: NODE,
            });
        }
        let t = self.templates.get(id).ok_or("template id")?;
        for &op in t {
            match op {
                Op::Value(a) => self.atoms.push(Atom {
                    at: a.at,
                    len: a.len | FIXED,
                }),
                Op::Child => self.visit(depth + 1)?,
                Op::Cached(k) => {
                    if ctx == 0 {
                        return Err("cached field without context".into());
                    }
                    let a = *self.cache.get(&(ctx, k)).ok_or("missing cached field")?;
                    self.atoms.push(a);
                    if self.auxiliary {
                        self.tree.push(a);
                    }
                }
                Op::Column(k) => {
                    let c = &mut self.columns[self.column(k)?];
                    let item = *c.items.get(c.pos).ok_or("column exhausted")?;
                    c.pos += 1;
                    let a = match item {
                        Item::Value(Atom { len: REPEAT, .. }) => {
                            *self.cache.get(&(ctx, k)).ok_or("missing repeat")?
                        }
                        Item::Value(a) => a,
                        Item::Delta(width, z) => {
                            let a = *self.cache.get(&(ctx, k)).ok_or("missing delta base")?;
                            if a.len != u32::from(width) {
                                return Err("context delta width".into());
                            }
                            let mut b = [0u8; 8];
                            b[8 - width as usize..].copy_from_slice(bytes(self.pool, a)?);
                            let d = ((z >> 1) as i64) ^ -((z & 1) as i64);
                            let n = u64::from_be_bytes(b).wrapping_add(d as u64);
                            if width == 4 && n > u32::MAX as u64 {
                                return Err("context delta overflow".into());
                            }
                            append(self.pool, &n.to_be_bytes()[8 - width as usize..])?
                        }
                    };
                    if ctx != 0 {
                        self.cache.insert((ctx, k), a);
                    }
                    self.atoms.push(a);
                    if self.auxiliary {
                        self.tree.push(a);
                    }
                }
            }
            if self.atoms.len() > MAX / 8 {
                return Err("instruction limit".into());
            }
        }
        Ok(())
    }
    fn doc(&mut self) -> Res<usize> {
        let start = self.atoms.len();
        let tree_start = self.tree.len();
        self.visit(0)?;
        let end = self.atoms.len();
        if self.auxiliary {
            self.tree_docs.push((tree_start, self.tree.len()));
        }
        let size = self.atoms[start..end]
            .iter()
            .map(|a| {
                if [TX, KEY].contains(&a.len) {
                    32
                } else {
                    (a.len & !FIXED) as usize
                }
            })
            .sum();
        if size > MAX {
            return Err("document size".into());
        }
        let id = self.docs.len();
        self.docs.push(Doc { start, end, size });
        Ok(id)
    }
}
/// Dictionary entries: values, hashes of the block's transactions, and keys
/// derived from arguments. An id names `base` first, then these entries.
fn read_dictionary(
    r: &mut Read<'_>,
    pool: &mut Vec<u8>,
    base: &[Atom],
    keys: &mut Vec<(u8, Vec<Atom>)>,
) -> Res<Vec<Atom>> {
    let nd = r.items()?;
    let mut dict = Vec::with_capacity(nd);
    let mut recipes = vec![];
    for i in 0..nd {
        let atom = match r.byte()? {
            0 => value_append(r, pool)?,
            1 => Atom {
                at: u32::try_from(r.var()?).map_err(er)?,
                len: TX,
            },
            2 => {
                let domain = r.byte()?;
                let n = r.count()?;
                if n > 4 {
                    return Err("key args".into());
                }
                let mut args = vec![];
                for _ in 0..n {
                    let x = r.count()?;
                    args.push(if x == 0 {
                        Ok(append(pool, r.blob()?)?)
                    } else {
                        Err(x - 1)
                    })
                }
                recipes.push((i, domain, args));
                Atom { at: 0, len: REPEAT }
            }
            _ => return Err("dictionary tag".into()),
        };
        dict.push(atom)
    }
    for (i, domain, args) in recipes {
        let mut arguments = vec![];
        for arg in args {
            let a = match arg {
                Ok(a) => a,
                Err(id) if id < base.len() => base[id],
                Err(id) => *dict.get(id - base.len()).ok_or("key reference")?,
            };
            if ![4, 20].contains(&a.len) {
                return Err("key argument is not literal".into());
            }
            arguments.push(a);
        }
        dict[i] = Atom {
            at: keys.len() as u32,
            len: KEY,
        };
        keys.push((domain, arguments));
    }
    Ok(dict)
}
fn decompress_frame(frame: &[u8]) -> Res<Vec<u8>> {
    let mut fr = Read::new(frame);
    let size = u64::from_le_bytes(fr.take(8)?.try_into().unwrap());
    if size > MAX as u64 {
        return Err("block limit".into());
    }
    let raw = zstd::bulk::decompress(&frame[8..], size as usize).map_err(er)?;
    if raw.len() != size as usize {
        return Err("journal size".into());
    }
    Ok(raw)
}
impl Prepared {
    pub fn parse(frame: &[u8]) -> Res<Self> {
        let mut p = Self::shared(&decompress_frame(frame)?, true, None)?;
        p.finish()?;
        Ok(p)
    }
    /// Serving needs flat programs only; encoder inspection trees are optional.
    pub fn for_read(frame: &[u8]) -> Res<Self> {
        let mut p = Self::open(frame)?;
        p.finish()?;
        Ok(p)
    }
    /// For reading: JC02-JC05 frame, compiled except for the hash order of
    /// ledgers, which is restored when a whole ledger is read.
    pub fn open(frame: &[u8]) -> Res<Self> {
        Self::shared(&decompress_frame(frame)?, false, None)
    }
    /// JC06 frame (payload mode 2): `open_parts` compiles no part yet,
    /// `parse_parts` all of them with inspection trees.
    pub fn open_parts(frame: &[u8]) -> Res<Self> {
        Self::parts_frame(frame, false)
    }
    pub fn parse_parts(frame: &[u8]) -> Res<Self> {
        let mut p = Self::parts_frame(frame, true)?;
        p.finish()?;
        Ok(p)
    }
    fn parts_frame(frame: &[u8], auxiliary: bool) -> Res<Self> {
        let l = frame_parts(frame)?;
        let raw = zstd::bulk::decompress(&frame[l.shared.clone()], l.shared_raw).map_err(er)?;
        if raw.len() != l.shared_raw {
            return Err("shared section size".into());
        }
        let base = l.head;
        let spans = l
            .parts
            .iter()
            .map(|(r, raw)| (r.start - base, r.len(), *raw))
            .collect();
        Self::shared(&raw, auxiliary, Some((frame[base..].to_vec(), spans)))
    }
    /// Checks every part against its digest before compiling it: the block
    /// passed the full check when the digests were taken (`pool` seals).
    pub fn check_parts(&mut self, hash: [u8; 32], digests: Vec<[u8; 32]>) -> Res<()> {
        if digests.len() != self.shared.spans.len() || !self.shared.v6 {
            return Err("part digests".into());
        }
        self.shared.sealed = Some((hash, digests));
        Ok(())
    }
    /// Shared section of `raw`; for JC02-JC05 the single part that follows it is
    /// compiled too, for JC06 `parts` holds the compressed parts.
    fn shared(raw: &[u8], auxiliary: bool, parts: Option<Frames>) -> Res<Self> {
        let mut r = Read::new(raw);
        let magic = r.take(4)?;
        let v6 = magic == b"JC06";
        let v5 = magic == b"JC05" || v6;
        let v4 = magic == b"JC04" || v5;
        let v3 = magic == b"JC03" || v4;
        if !v3 && magic != b"JC02" {
            return Err("journal magic".into());
        }
        if v6 != parts.is_some() {
            return Err("journal parts".into());
        }
        let layout_bytes = r.blob()?;
        let mut part_ledgers = vec![];
        if v6 {
            let mut pr = Read::new(r.blob()?);
            for _ in 0..pr.items()? {
                part_ledgers.push(pr.count()?);
            }
            pr.end()?;
        }
        let mut pool = Vec::with_capacity(raw.len());
        let mut keys = vec![];
        let dict = read_dictionary(&mut r, &mut pool, &[], &mut keys)?;
        let mut templates = vec![];
        let mut dense = IdMap::default();
        for _ in 0..r.items()? {
            let mut t = vec![];
            for _ in 0..r.items()? {
                t.push(match r.byte()? {
                    0 => Op::Value(append(&mut pool, r.blob()?)?),
                    tag @ (1 | 3) => {
                        if tag == 3 && !v5 {
                            return Err("template tag".into());
                        }
                        let key = usize::try_from(r.var()?).map_err(er)?;
                        let next = dense.len();
                        let k = *dense.entry(key).or_insert(next);
                        if tag == 1 {
                            Op::Column(k)
                        } else {
                            Op::Cached(k)
                        }
                    }
                    2 => Op::Child,
                    _ => return Err("template tag".into()),
                })
            }
            templates.push(t)
        }
        // The layout of every ledger, before any document is compiled.
        let total_raw = parts
            .as_ref()
            .map_or(raw.len(), |(_, s)| s.iter().map(|x| x.2).sum::<usize>());
        let mut lr = Read::new(layout_bytes);
        let mut ledgers = vec![];
        let mut first_tx = 0;
        for _ in 0..lr.count()? {
            let seq = u32::try_from(lr.var()?).map_err(er)?;
            let nt = lr.count()?;
            // Every transaction takes at least two shapes of a byte each.
            if nt > total_raw / 4 {
                return Err("TX layout count".into());
            }
            let canonical = v5 && lr.b.get(lr.p) == Some(&2);
            let order = if canonical {
                lr.byte()?;
                None
            } else if v5 {
                Some(read_order(&mut lr, nt)?)
                    .filter(|o| o.iter().enumerate().any(|(i, &j)| i != j))
            } else {
                None
            };
            let patches = lr.count()?;
            if patches > total_raw / 4 {
                return Err("patch layout count".into());
            }
            ledgers.push(Planned {
                seq,
                txs: nt,
                patches,
                order,
                first_tx,
                part: 0,
                header_doc: usize::MAX,
                sorted: !canonical,
            });
            first_tx += nt;
        }
        lr.end()?;
        let (frames, spans) = parts.unwrap_or_default();
        let mut ranges = vec![];
        if v6 {
            if part_ledgers.len() != spans.len()
                || part_ledgers.contains(&0)
                || part_ledgers.iter().sum::<usize>() != ledgers.len()
            {
                return Err("part ledgers".into());
            }
            let mut at = 0;
            for (p, &n) in part_ledgers.iter().enumerate() {
                for l in &mut ledgers[at..at + n] {
                    l.part = p;
                }
                ranges.push(at..at + n);
                at += n;
            }
        } else {
            ranges.push(0..ledgers.len());
        }
        let dictionary = v6.then(|| zstd::dict::DecoderDictionary::copy(raw));
        let layout = ledgers
            .iter()
            .map(|l| Layout {
                seq: l.seq,
                header: usize::MAX,
                tx: vec![],
                patches: vec![],
            })
            .collect();
        let plans = if auxiliary {
            templates
                .iter()
                .map(|t| {
                    t.iter()
                        .map(|op| match op {
                            Op::Value(a) => PlanOp::Fixed(bytes(&pool, *a).unwrap().to_vec()),
                            Op::Column(_) | Op::Cached(_) => PlanOp::Value,
                            Op::Child => PlanOp::Child,
                        })
                        .collect()
                })
                .collect()
        } else {
            vec![]
        };
        let n_parts = ranges.len();
        let mut prepared = Self {
            pool,
            atoms: vec![],
            docs: vec![],
            layout,
            tree: vec![],
            tree_docs: vec![],
            plans,
            key_hashes: vec![None; keys.len()],
            keys,
            tx_hashes: vec![None; first_tx],
            ledgers,
            shared: Box::new(Shared {
                templates,
                dense,
                dict,
                v3,
                v4,
                v6,
                auxiliary,
                frames,
                spans,
                parts: ranges,
                done: vec![false; n_parts],
                dictionary_bytes: if v6 { raw.len() } else { 0 },
                dictionary,
                sealed: None,
            }),
        };
        if !v6 {
            prepared.compile(0, &raw[r.p..])?;
        }
        Ok(prepared)
    }
    /// Compiles every part and restores the original order of every ledger.
    fn finish(&mut self) -> Res<()> {
        for i in 0..self.ledgers.len() {
            self.sorted(i)?;
        }
        Ok(())
    }
    /// Parts compiled so far.
    pub fn compiled_parts(&self) -> usize {
        self.shared.done.iter().filter(|d| **d).count()
    }
    fn ledger_part(&mut self, i: usize) -> Res<()> {
        let p = self.ledgers.get(i).ok_or("ledger index")?.part;
        if self.shared.done[p] {
            return Ok(());
        }
        let (at, len, raw) = self.shared.spans[p];
        if let Some((hash, digests)) = &self.shared.sealed
            && seal_digest(hash, &self.shared.frames[at..at + len]) != digests[p]
        {
            return Err("part does not match its seal".into());
        }
        let bytes = {
            let d = self.shared.dictionary.as_ref().ok_or("journal parts")?;
            let mut z = zstd::bulk::Decompressor::with_prepared_dictionary(d).map_err(er)?;
            z.decompress(&self.shared.frames[at..at + len], raw)
                .map_err(er)?
        };
        if bytes.len() != raw {
            return Err("part size".into());
        }
        self.compile(p, &bytes)
    }
    /// Ledger `i` with `Layout::tx` in original order.
    fn sorted(&mut self, i: usize) -> Res<()> {
        self.ledger_part(i)?;
        if self.ledgers[i].sorted {
            return Ok(());
        }
        let l = &self.ledgers[i];
        let (first, header) = (l.first_tx, l.header_doc);
        let v6 = self.shared.v6;
        let mut tx = Vec::with_capacity(self.layout[i].tx.len());
        for (id, meta) in self.layout[i].tx.clone() {
            // TX programs cannot refer to TX-derived hashes (checked when compiled).
            let hash = shamap::tx_id(&self.document(id)?);
            // Derived hashes name encoded positions in JC06, original ones before.
            if v6 {
                self.tx_hashes[first + (id - header - 1) / 2] = Some(hash);
            }
            tx.push((hash, id, meta));
        }
        tx.sort_unstable();
        if tx.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err("canonical TX hash duplicate".into());
        }
        if !v6 {
            for (k, (hash, _, _)) in tx.iter().enumerate() {
                self.tx_hashes[first + k] = Some(*hash);
            }
        }
        self.layout[i].tx = tx.into_iter().map(|(_, id, m)| (id, m)).collect();
        self.ledgers[i].sorted = true;
        Ok(())
    }
    /// Compiles part `p` from its bytes: shapes, contexts and columns.
    fn compile(&mut self, p: usize, raw: &[u8]) -> Res<()> {
        let sh = &*self.shared;
        let (v3, v4) = (sh.v3, sh.v4);
        let mut r = Read::new(raw);
        let pool = &mut self.pool;
        pool.reserve(raw.len() / 2);
        // A JC06 part starts with its own dictionary; its ids follow the shared ones.
        let local = if sh.v6 {
            let local = read_dictionary(&mut r, pool, &sh.dict, &mut self.keys)?;
            self.key_hashes.resize(self.keys.len(), None);
            local
        } else {
            vec![]
        };
        let base = &sh.dict;
        let lookup = |id: usize| -> Option<Atom> {
            if id < base.len() {
                Some(base[id])
            } else {
                local.get(id - base.len()).copied()
            }
        };
        let dict_len = base.len() + local.len();
        let ns = r.count()?;
        let mut shapes = Vec::with_capacity(ns.min(1_000_000));
        let mut contexts = vec![];
        if v3 {
            let mut s = Read::new(r.blob()?);
            let mut c = Read::new(r.blob()?);
            if ns > s.b.len() || ns > c.b.len() {
                return Err("count exceeds input".into());
            }
            let mut prev = 0u64;
            for _ in 0..ns {
                shapes.push(s.count()?);
                let z = c.var()?;
                let d = ((z >> 1) as i64) ^ -((z & 1) as i64);
                prev = prev.wrapping_add(d as u64);
                contexts.push(usize::try_from(prev).map_err(er)?);
            }
            s.end()?;
            c.end()?;
        } else {
            if ns > r.b.len() - r.p {
                return Err("count exceeds input".into());
            }
            for _ in 0..ns {
                shapes.push(r.count()?);
                contexts.push(r.count()?);
            }
        }
        let mut columns = vec![];
        let mut map = vec![usize::MAX; sh.dense.len()];
        for _ in 0..r.items()? {
            let key = usize::try_from(r.var()?).map_err(er)?;
            let count = r.count()?;
            let mode = r.byte()?;
            let mut c = Read::new(r.blob()?);
            // Modes 0 and 1 spend at least a byte per item.
            if mode != 2 && count > c.b.len() {
                return Err("count exceeds input".into());
            }
            let mut items = vec![];
            match mode {
                0 => {
                    for _ in 0..count {
                        let tag = c.count()?;
                        items.push(if tag == 0 {
                            Item::Value(value_append(&mut c, pool)?)
                        } else if tag == 1 {
                            Item::Value(Atom { at: 0, len: REPEAT })
                        } else if v3 && [2, 3].contains(&tag) {
                            Item::Delta(if tag == 2 { 4 } else { 8 }, c.var()?)
                        } else {
                            let id = tag
                                .checked_sub(if v3 { 4 } else { 2 })
                                .ok_or("dictionary id")?;
                            Item::Value(lookup(id).ok_or("dictionary id")?)
                        });
                    }
                }
                1 => {
                    let width = c.byte()? as usize;
                    if ![4, 8].contains(&width) {
                        return Err("delta width".into());
                    }
                    let mut prev = 0u64;
                    for _ in 0..count {
                        let z = c.var()?;
                        let d = ((z >> 1) as i64) ^ -((z & 1) as i64);
                        prev = prev.wrapping_add(d as u64);
                        if width == 4 && prev > u32::MAX as u64 {
                            return Err("delta overflow".into());
                        }
                        items.push(Item::Value(append(pool, &prev.to_be_bytes()[8 - width..])?));
                    }
                }
                2 if v4 => {
                    let data = c.take(c.b.len() - c.p)?;
                    joint::decode_into(data, count, dict_len, |token| {
                        items.push(match token {
                            joint::Scalar::Literal(v) => Item::Value(append(pool, &v)?),
                            joint::Scalar::Dictionary(id) => {
                                Item::Value(lookup(id).ok_or("dictionary id")?)
                            }
                            joint::Scalar::Repeat => Item::Value(Atom { at: 0, len: REPEAT }),
                            joint::Scalar::ContextDelta(w, z) => Item::Delta(w, z),
                        });
                        Ok(())
                    })?;
                }
                _ => return Err("column mode".into()),
            }
            c.end()?;
            // A column no template names would stay unread.
            let Some(&d) = sh.dense.get(&key) else {
                if items.is_empty() {
                    continue;
                }
                return Err("unused programs".into());
            };
            if map[d] != usize::MAX {
                return Err("duplicate column".into());
            }
            map[d] = columns.len();
            columns.push(Column { items, pos: 0 });
        }
        r.end()?;
        let range = sh.parts[p].clone();
        let mut atoms = std::mem::take(&mut self.atoms);
        let mut docs = std::mem::take(&mut self.docs);
        atoms.reserve(raw.len() / 4);
        docs.reserve(
            self.ledgers[range.clone()]
                .iter()
                .map(|l| 1 + 2 * (l.txs + l.patches))
                .sum(),
        );
        let mut tree = std::mem::take(&mut self.tree);
        let mut tree_docs = std::mem::take(&mut self.tree_docs);
        let mut c = Compiler {
            auxiliary: sh.auxiliary,
            pool,
            templates: &sh.templates,
            local: &map,
            shapes: &shapes,
            contexts: &contexts,
            columns: &mut columns,
            at: 0,
            cache: PairMap::with_capacity_and_hasher(shapes.len() / 2, Default::default()),
            atoms: &mut atoms,
            docs: &mut docs,
            tree: &mut tree,
            tree_docs: &mut tree_docs,
        };
        let mut built = vec![];
        let mut tx_ids = vec![];
        for i in range.clone() {
            let l = &self.ledgers[i];
            if l.txs > shapes.len() / 2 {
                return Err("TX layout count".into());
            }
            let header = c.doc()?;
            let mut tx = vec![(0, 0); l.txs];
            for k in 0..l.txs {
                let id = c.doc()?;
                let meta = c.doc()?;
                tx_ids.push(id);
                tx[l.order.as_ref().map_or(k, |o| o[k])] = (id, meta);
            }
            let mut patches = vec![];
            for _ in 0..l.patches {
                patches.push((c.doc()?, c.doc()?));
            }
            built.push((header, tx, patches));
        }
        let unused = c.at != shapes.len() || c.columns.iter().any(|c| c.pos != c.items.len());
        drop(c);
        self.atoms = atoms;
        self.docs = docs;
        self.tree = tree;
        self.tree_docs = tree_docs;
        if unused {
            return Err("unused programs".into());
        }
        for &id in &tx_ids {
            let d = &self.docs[id];
            if self.atoms[d.start..d.end].iter().any(|a| a.len == TX) {
                return Err("TX depends on TX hash".into());
            }
        }
        for (i, (header, tx, patches)) in range.zip(built) {
            self.ledgers[i].header_doc = header;
            self.layout[i].header = header;
            self.layout[i].tx = tx;
            self.layout[i].patches = patches;
        }
        self.shared.done[p] = true;
        Ok(())
    }
    /// Document of the transaction a derived hash names.
    fn tx_document(&mut self, index: usize) -> Res<usize> {
        let i = self
            .ledgers
            .partition_point(|l| l.first_tx <= index)
            .checked_sub(1)
            .ok_or("TX document")?;
        let k = index - self.ledgers[i].first_tx;
        if k >= self.ledgers[i].txs {
            return Err("TX document".into());
        }
        if self.shared.v6 {
            self.ledger_part(i)?;
            Ok(self.ledgers[i].header_doc + 1 + 2 * k)
        } else {
            self.sorted(i)?;
            Ok(self.layout[i].tx[k].0)
        }
    }
    fn document(&mut self, id: usize) -> Res<Vec<u8>> {
        let d = self.docs.get(id).ok_or("document index")?;
        let (start, end, size) = (d.start, d.end, d.size);
        let mut out = Vec::with_capacity(size);
        for at in start..end {
            let a = self.atoms[at];
            if a.len == TX {
                let index = a.at as usize;
                let hash = if let Some(hash) = self.tx_hashes.get(index).ok_or("TX hash index")? {
                    *hash
                } else {
                    let doc = self.tx_document(index)?;
                    let hash = shamap::tx_id(&self.document(doc)?);
                    self.tx_hashes[index] = Some(hash);
                    hash
                };
                out.extend(hash)
            } else if a.len == KEY {
                let i = a.at as usize;
                let h = if let Some(h) = self.key_hashes.get(i).ok_or("key id")? {
                    *h
                } else {
                    let (domain, args) = self.keys.get(i).ok_or("key recipe")?;
                    let mut pre = vec![0, *domain];
                    for &v in args {
                        pre.extend(bytes(&self.pool, v)?)
                    }
                    let h = sha512_half(&pre);
                    self.key_hashes[i] = Some(h);
                    h
                };
                out.extend(h);
            } else {
                out.extend(bytes(&self.pool, a)?)
            }
        }
        Ok(out)
    }
    /// Transaction at position `index` of the block, in original order.
    pub fn tx(&mut self, index: usize) -> Res<(Vec<u8>, Vec<u8>)> {
        let i = self
            .ledgers
            .partition_point(|l| l.first_tx <= index)
            .checked_sub(1)
            .ok_or("TX index")?;
        let k = index - self.ledgers[i].first_tx;
        if k >= self.ledgers[i].txs {
            return Err("TX index".into());
        }
        self.sorted(i)?;
        let (t, m) = self.layout[i].tx[k];
        Ok((self.document(t)?, self.document(m)?))
    }
    /// Transaction of ledger `ledger` whose metadata has TransactionIndex
    /// `index`, without the rest of the ledger. Ledgers are encoded in
    /// TransactionIndex order, so the position is tried first.
    pub fn tx_with_index(&mut self, ledger: usize, index: u32) -> Res<Option<(Vec<u8>, Vec<u8>)>> {
        self.ledger_part(ledger)?;
        let (header, n) = (self.ledgers[ledger].header_doc, self.ledgers[ledger].txs);
        let at = index as usize;
        let tries = (at < n)
            .then_some(at)
            .into_iter()
            .chain((0..n).filter(|&k| k != at));
        for k in tries {
            let meta = self.document(header + 2 + 2 * k)?;
            if tx_index(&meta) == Some(index) {
                return Ok(Some((self.document(header + 1 + 2 * k)?, meta)));
            }
        }
        Ok(None)
    }
    pub fn patch(&mut self, ledger: usize, index: usize) -> Res<([u8; 32], Vec<u8>)> {
        self.ledger_part(ledger)?;
        let (k, v) = *self
            .layout
            .get(ledger)
            .ok_or("ledger index")?
            .patches
            .get(index)
            .ok_or("patch index")?;
        Ok((
            self.document(k)?
                .try_into()
                .map_err(|_| "patch key width")?,
            self.document(v)?,
        ))
    }
    /// Number of ledgers in the block.
    pub fn ledger_count(&self) -> usize {
        self.ledgers.len()
    }
    /// Sequence of ledger `index`.
    pub fn seq(&self, index: usize) -> Option<u32> {
        self.ledgers.get(index).map(|l| l.seq)
    }
    /// Transactions in ledger `index`.
    pub fn txs_in(&self, index: usize) -> Option<usize> {
        self.ledgers.get(index).map(|l| l.txs)
    }
    pub fn row(&mut self, index: usize) -> Res<Row> {
        self.sorted(index)?;
        let l = self.layout.get(index).ok_or("ledger index")?.clone();
        let header = self.document(l.header)?;
        let mut txs = vec![];
        let mut patches = vec![];
        for (t, m) in l.tx {
            txs.push((self.document(t)?, self.document(m)?));
        }
        for (k, v) in l.patches {
            patches.push((
                self.document(k)?
                    .try_into()
                    .map_err(|_| "patch key width")?,
                self.document(v)?,
            ));
        }
        Ok(Row {
            seq: l.seq,
            header,
            txs,
            patches,
        })
    }
    /// Header of ledger `index`, without touching its transactions or patches.
    pub fn header(&mut self, index: usize) -> Res<Vec<u8>> {
        self.ledger_part(index)?;
        let h = self.layout.get(index).ok_or("ledger index")?.header;
        self.document(h)
    }
    /// Ledger `index` with its transactions but without patches (left empty):
    /// readers that serve transactions don't pay for state changes.
    pub fn row_txs(&mut self, index: usize) -> Res<Row> {
        self.sorted(index)?;
        let l = self.layout.get(index).ok_or("ledger index")?;
        let (seq, h, tx) = (l.seq, l.header, l.tx.clone());
        let header = self.document(h)?;
        let mut txs = Vec::with_capacity(tx.len());
        for (t, m) in tx {
            txs.push((self.document(t)?, self.document(m)?));
        }
        Ok(Row {
            seq,
            header,
            txs,
            patches: Vec::new(),
        })
    }
    pub fn all_rows(&mut self) -> Res<Vec<Row>> {
        (0..self.layout.len()).map(|i| self.row(i)).collect()
    }
    pub fn memory_bytes(&self) -> usize {
        self.tree.capacity() * 8
            + self.tree_docs.capacity() * 16
            + self
                .plans
                .iter()
                .map(|p| {
                    p.capacity() * 32
                        + p.iter()
                            .map(|op| match op {
                                PlanOp::Fixed(v) => v.capacity(),
                                _ => 0,
                            })
                            .sum::<usize>()
                })
                .sum::<usize>()
            + self
                .keys
                .iter()
                .map(|(_, v)| 24 + v.capacity() * 8)
                .sum::<usize>()
            + self.key_hashes.capacity() * 33
            + self.pool.capacity()
            + self.atoms.capacity() * std::mem::size_of::<Atom>()
            + self.docs.capacity() * std::mem::size_of::<Doc>()
            + self.tx_hashes.capacity() * std::mem::size_of::<Option<[u8; 32]>>()
            + self.ledgers.capacity() * std::mem::size_of::<Planned>()
            + self.shared.frames.capacity()
            + self.shared.dictionary_bytes
            + self
                .shared
                .templates
                .iter()
                .map(|t| 24 + t.capacity() * 16)
                .sum::<usize>()
            + self.layout.capacity() * std::mem::size_of::<Layout>()
            + self
                .layout
                .iter()
                .map(|l| (l.tx.capacity() + l.patches.capacity()) * 16)
                .sum::<usize>()
    }
}

/// TransactionIndex of canonical metadata: its first field.
fn tx_index(meta: &[u8]) -> Option<u32> {
    match *meta {
        [0x20, 0x1C, a, b, c, d, ..] => Some(u32::from_be_bytes([a, b, c, d])),
        _ => None,
    }
}
/// Encoded-position -> original-position permutation, checked before document compilation.
fn read_order(r: &mut Read<'_>, n: usize) -> Res<Vec<usize>> {
    match r.byte()? {
        0 => Ok((0..n).collect()),
        1 => {
            if n > r.b.len() - r.p {
                return Err("permutation count".into());
            }
            let mut seen = vec![false; n];
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                let i = r.count()?;
                if i >= n || seen[i] {
                    return Err("invalid permutation".into());
                }
                seen[i] = true;
                out.push(i);
            }
            Ok(out)
        }
        _ => Err("permutation mode".into()),
    }
}
#[cfg(test)]
mod order_tests {
    use super::*;
    #[test]
    fn permutation_validation() {
        assert_eq!(
            read_order(&mut Read::new(&[1, 2, 0, 1]), 3).unwrap(),
            vec![2, 0, 1]
        );
        for b in [&[1, 0, 0, 2][..], &[1, 0, 1, 3], &[1, 0, 1], &[2]] {
            assert!(read_order(&mut Read::new(b), 3).is_err());
        }
    }
}
