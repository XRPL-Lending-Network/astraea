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
/// Prepared block: shared literal arena plus flat document instructions.
/// Preparing does not itself authenticate the archive or recompute ledger roots.
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
    pub(crate) tx_docs: Vec<usize>,
    tx_hashes: Vec<Option<[u8; 32]>>,
}
impl Prepared {
    pub fn parse(frame: &[u8]) -> Res<Self> {
        Self::parse_mode(frame, true)
    }
    /// Serving needs flat programs only; encoder inspection trees are optional.
    pub fn for_read(frame: &[u8]) -> Res<Self> {
        Self::parse_mode(frame, false)
    }
    fn parse_mode(frame: &[u8], auxiliary: bool) -> Res<Self> {
        let mut fr = Read::new(frame);
        let size = u64::from_le_bytes(fr.take(8)?.try_into().unwrap());
        if size > MAX as u64 {
            return Err("block limit".into());
        }
        let raw = zstd::bulk::decompress(&frame[8..], size as usize).map_err(er)?;
        if raw.len() != size as usize {
            return Err("journal size".into());
        }
        let mut r = Read::new(&raw);
        let magic = r.take(4)?;
        let v5 = magic == b"JC05";
        let v4 = magic == b"JC04" || v5;
        let v3 = magic == b"JC03" || v4;
        if !v3 && magic != b"JC02" {
            return Err("journal magic".into());
        }
        let layout_bytes = r.blob()?;
        let mut pool = vec![];
        let nd = r.items()?;
        let mut dict = vec![];
        let mut recipes = vec![];
        for i in 0..nd {
            let atom = match r.byte()? {
                0 => append(&mut pool, &value_get(&mut r)?)?,
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
                            Ok(append(&mut pool, r.blob()?)?)
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
        let mut keys = vec![];
        for (i, domain, args) in recipes {
            let mut arguments = vec![];
            for arg in args {
                let a = match arg {
                    Ok(a) => a,
                    Err(id) => *dict.get(id).ok_or("key reference")?,
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
        let mut templates = vec![];
        for _ in 0..r.items()? {
            let mut t = vec![];
            for _ in 0..r.items()? {
                t.push(match r.byte()? {
                    0 => Op::Value(append(&mut pool, r.blob()?)?),
                    1 => Op::Column(usize::try_from(r.var()?).map_err(er)?),
                    2 => Op::Child,
                    3 if v5 => Op::Cached(usize::try_from(r.var()?).map_err(er)?),
                    _ => return Err("template tag".into()),
                })
            }
            templates.push(t)
        }
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
        let mut ids = HashMap::new();
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
                            Item::Value(append(&mut pool, &value_get(&mut c)?)?)
                        } else if tag == 1 {
                            Item::Value(Atom { at: 0, len: REPEAT })
                        } else if v3 && [2, 3].contains(&tag) {
                            Item::Delta(if tag == 2 { 4 } else { 8 }, c.var()?)
                        } else {
                            let id = tag
                                .checked_sub(if v3 { 4 } else { 2 })
                                .ok_or("dictionary id")?;
                            Item::Value(*dict.get(id).ok_or("dictionary id")?)
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
                        items.push(Item::Value(append(
                            &mut pool,
                            &prev.to_be_bytes()[8 - width..],
                        )?));
                    }
                }
                2 if v4 => {
                    let data = c.take(c.b.len() - c.p)?;
                    joint::decode_into(data, count, dict.len(), |token| {
                        items.push(match token {
                            joint::Scalar::Literal(v) => Item::Value(append(&mut pool, &v)?),
                            joint::Scalar::Dictionary(id) => Item::Value(dict[id]),
                            joint::Scalar::Repeat => Item::Value(Atom { at: 0, len: REPEAT }),
                            joint::Scalar::ContextDelta(w, z) => Item::Delta(w, z),
                        });
                        Ok(())
                    })?;
                }
                _ => return Err("column mode".into()),
            }
            c.end()?;
            if ids.insert(key, columns.len()).is_some() {
                return Err("duplicate column".into());
            }
            columns.push(Column { items, pos: 0 });
        }
        r.end()?;
        for t in &mut templates {
            for op in t {
                if let Op::Column(key) | Op::Cached(key) = op {
                    *key = *ids.get(key).ok_or("missing column")?;
                }
            }
        }
        struct Compiler<'a> {
            auxiliary: bool,
            pool: &'a mut Vec<u8>,
            templates: &'a [Vec<Op>],
            shapes: &'a [usize],
            contexts: &'a [usize],
            columns: &'a mut [Column],
            at: usize,
            cache: HashMap<(usize, usize), Atom>,
            atoms: Vec<Atom>,
            docs: Vec<Doc>,
            tree: Vec<Atom>,
            tree_docs: Vec<(usize, usize)>,
        }
        impl Compiler<'_> {
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
                            let c = &mut self.columns[k];
                            let item = *c.items.get(c.pos).ok_or("column exhausted")?;
                            c.pos += 1;
                            let a = match item {
                                Item::Value(Atom { len: REPEAT, .. }) => {
                                    *self.cache.get(&(ctx, k)).ok_or("missing repeat")?
                                }
                                Item::Value(a) => a,
                                Item::Delta(width, z) => {
                                    let a =
                                        *self.cache.get(&(ctx, k)).ok_or("missing delta base")?;
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
        let mut c = Compiler {
            auxiliary,
            pool: &mut pool,
            templates: &templates,
            shapes: &shapes,
            contexts: &contexts,
            columns: &mut columns,
            at: 0,
            cache: HashMap::new(),
            atoms: vec![],
            docs: vec![],
            tree: vec![],
            tree_docs: vec![],
        };
        let mut lr = Read::new(layout_bytes);
        let mut layout = vec![];
        let mut tx_docs = vec![];
        let mut hash_order_rows = vec![];
        for _ in 0..lr.count()? {
            let seq = u32::try_from(lr.var()?).map_err(er)?;
            let header = c.doc()?;
            let nt = lr.count()?;
            // Bound allocations by the number of root shapes available.
            if nt > shapes.len() / 2 {
                return Err("TX layout count".into());
            }
            let canonical = v5 && lr.b.get(lr.p) == Some(&2);
            hash_order_rows.push(canonical);
            let order = if canonical {
                lr.byte()?;
                (0..nt).collect()
            } else if v5 {
                read_order(&mut lr, nt)?
            } else {
                (0..nt).collect()
            };
            let mut tx = vec![(0, 0); nt];
            for i in order {
                let id = c.doc()?;
                tx[i] = (id, c.doc()?);
            }
            tx_docs.extend(tx.iter().map(|&(id, _)| id));
            let mut patches = vec![];
            for _ in 0..lr.count()? {
                patches.push((c.doc()?, c.doc()?));
            }
            layout.push(Layout {
                seq,
                header,
                tx,
                patches,
            });
        }
        lr.end()?;
        if c.at != shapes.len() || c.columns.iter().any(|c| c.pos != c.items.len()) {
            return Err("unused programs".into());
        }
        for &id in &tx_docs {
            let d = &c.docs[id];
            if c.atoms[d.start..d.end].iter().any(|a| a.len == TX) {
                return Err("TX depends on TX hash".into());
            }
        }
        let Compiler {
            atoms,
            docs,
            tree,
            tree_docs,
            ..
        } = c;
        let tx_hashes = vec![None; tx_docs.len()];
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
        let key_hashes = vec![None; keys.len()];
        let mut prepared = Self {
            pool,
            atoms,
            docs,
            layout,
            tx_docs,
            tx_hashes,
            keys,
            key_hashes,
            tree,
            tree_docs,
            plans,
        };
        let mut known_hashes = HashMap::new();
        for (i, canonical) in hash_order_rows.into_iter().enumerate() {
            if !canonical {
                continue;
            }
            let mut tx = Vec::with_capacity(prepared.layout[i].tx.len());
            for (id, meta) in prepared.layout[i].tx.clone() {
                // TX programs cannot refer to TX-derived hashes (checked above).
                let hash = shamap::tx_id(&prepared.document(id)?);
                known_hashes.insert(id, hash);
                tx.push((hash, id, meta));
            }
            tx.sort_unstable();
            if tx.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err("canonical TX hash duplicate".into());
            }
            prepared.layout[i].tx = tx.into_iter().map(|(_, id, m)| (id, m)).collect();
        }
        prepared.tx_docs = prepared
            .layout
            .iter()
            .flat_map(|l| l.tx.iter().map(|&(id, _)| id))
            .collect();
        prepared.tx_hashes = prepared
            .tx_docs
            .iter()
            .map(|id| known_hashes.get(id).copied())
            .collect();
        Ok(prepared)
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
                    let hash = shamap::tx_id(
                        &self.document(*self.tx_docs.get(index).ok_or("TX document")?)?,
                    );
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
    pub fn tx(&mut self, index: usize) -> Res<(Vec<u8>, Vec<u8>)> {
        let id = *self.tx_docs.get(index).ok_or("TX index")?;
        Ok((self.document(id)?, self.document(id + 1)?))
    }
    pub fn patch(&mut self, ledger: usize, index: usize) -> Res<([u8; 32], Vec<u8>)> {
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
    pub fn row(&mut self, index: usize) -> Res<Row> {
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
    pub fn all_rows(&mut self) -> Res<Vec<Row>> {
        (0..self.layout.len()).map(|i| self.row(i)).collect()
    }
    pub fn tx_count(&self) -> usize {
        self.tx_docs.len()
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
            + self.tx_docs.capacity() * std::mem::size_of::<usize>()
            + self.tx_hashes.capacity() * std::mem::size_of::<Option<[u8; 32]>>()
            + self.layout.capacity() * std::mem::size_of::<Layout>()
            + self
                .layout
                .iter()
                .map(|l| (l.tx.capacity() + l.patches.capacity()) * 16)
                .sum::<usize>()
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
