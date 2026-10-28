//! Shared exact field views for metadata groups and object patches.
//! These are observed byte sets, not transaction execution or inferred complete ledger state.
use super::*;
use fast::{Atom, FIXED, KEY, NODE, PlanOp, Prepared, TX};
use std::collections::VecDeque;
pub(crate) const SHARED: u32 = u32::MAX - 4;
pub(crate) const VIEW: u64 = u64::MAX;
#[derive(Clone)]
pub(crate) struct View {
    pub schema: usize,
    pub base: Option<usize>,
    pub edits: Vec<(usize, usize)>,
}
pub(crate) enum Program {
    Tree(Vec<Atom>),
    View(View),
}
#[derive(Default, Clone)]
pub struct Stats {
    pub groups: usize,
    pub patches: usize,
    pub fields: usize,
    pub unique_fields: usize,
    pub views: usize,
    pub exact_view_hits: usize,
    pub inherited_fields: usize,
    pub edited_fields: usize,
    pub delta_views: usize,
    pub max_depth: usize,
    pub fallback_groups: usize,
    pub fallback_patches: usize,
    pub skipped_small: usize,
    pub numeric4: usize,
    pub numeric8: usize,
    pub raw_field_bytes: usize,
    pub unique_raw_field_bytes: usize,
    pub cross_role_fields: usize,
}
impl Stats {
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({"numeric_4byte_deltas":self.numeric4,"numeric_8byte_deltas":self.numeric8,"skipped_small_views":self.skipped_small,"metadata_groups":self.groups,"patch_views":self.patches,"field_occurrences":self.fields,"unique_fields":self.unique_fields,"views":self.views,"exact_view_hits":self.exact_view_hits,"inherited_fields":self.inherited_fields,"edited_fields":self.edited_fields,"delta_views":self.delta_views,"max_depth":self.max_depth,"fallback_groups":self.fallback_groups,"fallback_patches":self.fallback_patches,"raw_field_bytes":self.raw_field_bytes,"unique_raw_field_bytes":self.unique_raw_field_bytes,"fields_used_by_both_metadata_and_patches":self.cross_role_fields})
    }
}
pub(crate) struct Journal {
    pub programs: Vec<Program>,
    pub plans: Vec<Vec<PlanOp>>,
    pub schemas: Vec<Vec<u32>>,
    pub depth_limit: usize,
    pub stats: Stats,
}
struct Saved {
    doc: usize,
    sorted: Vec<(u32, usize)>,
    depth: usize,
}
struct Builder<'a> {
    prepared: &'a Prepared,
    j: Journal,
    min_fields: usize,
    field_ids: HashMap<Vec<u8>, (usize, u8)>,
    plan_ids: HashMap<Vec<PlanOp>, usize>,
    schema_ids: HashMap<Vec<u32>, usize>,
    view_ids: HashMap<Vec<usize>, usize>,
    views: Vec<Saved>,
    recent: HashMap<[u8; 32], VecDeque<usize>>,
}
fn atom_bytes(a: Atom) -> usize {
    if a.len == TX || a.len == KEY {
        32
    } else {
        (a.len & !FIXED) as usize
    }
}
/// Match each prepared subtree to the exact byte interval it serializes.
fn tree_spans(p: &Prepared, doc: usize) -> Res<HashMap<(usize, usize), (usize, usize)>> {
    fn walk(
        p: &Prepared,
        tree: &[Atom],
        at: &mut usize,
        offset: &mut usize,
        out: &mut HashMap<(usize, usize), (usize, usize)>,
        depth: usize,
    ) -> Res<()> {
        if depth > 64 {
            return Err("tree depth".into());
        }
        let start = *at;
        let byte_start = *offset;
        let root = *tree.get(*at).ok_or("tree node")?;
        *at += 1;
        if root.len != NODE {
            return Err("tree root marker".into());
        }
        for op in p.plans.get(root.at as usize).ok_or("tree plan")? {
            match op {
                PlanOp::Fixed(b) => *offset += b.len(),
                PlanOp::Value => {
                    let a = *tree.get(*at).ok_or("tree atom")?;
                    *at += 1;
                    *offset += atom_bytes(a);
                }
                PlanOp::Child => walk(p, tree, at, offset, out, depth + 1)?,
            }
        }
        out.insert((byte_start, *offset), (start, *at));
        Ok(())
    }
    let (start, end) = p.tree_docs[doc];
    let mut out = HashMap::new();
    let mut at = 0;
    let mut offset = 0;
    walk(p, &p.tree[start..end], &mut at, &mut offset, &mut out, 0)?;
    if at != end - start || offset != p.docs[doc].size {
        return Err("tree span coverage".into());
    }
    Ok(out)
}
impl Builder<'_> {
    fn plan(&mut self, shape: Vec<PlanOp>) -> usize {
        if let Some(id) = self.plan_ids.get(&shape) {
            return *id;
        }
        let id = self.j.plans.len();
        self.j.plans.push(shape.clone());
        self.plan_ids.insert(shape, id);
        id
    }
    fn field(&mut self, doc: usize, begin: usize, end: usize, raw: &[u8], role: u8) -> Res<usize> {
        self.j.stats.fields += 1;
        self.j.stats.raw_field_bytes += raw.len();
        if let Some((id, roles)) = self.field_ids.get_mut(raw) {
            if *roles != 3 && (*roles | role) == 3 {
                self.j.stats.cross_role_fields += 1;
            }
            *roles |= role;
            return Ok(*id);
        }
        let d = &self.prepared.docs[doc];
        let mut pos = 0;
        let mut shape = vec![];
        let mut values = vec![];
        let mut covered = 0;
        for &a in &self.prepared.atoms[d.start..d.end] {
            let n = atom_bytes(a);
            let l = pos.max(begin);
            let r = (pos + n).min(end);
            if l < r {
                if a.len != TX && a.len != KEY && a.len & FIXED != 0 {
                    let at = a.at as usize + l - pos;
                    shape.push(PlanOp::Fixed(self.prepared.pool[at..at + r - l].to_vec()));
                } else {
                    if l != pos || r != pos + n {
                        return Err("field crosses a scalar atom".into());
                    }
                    shape.push(PlanOp::Value);
                    values.push(a);
                }
                covered += r - l;
            }
            pos += n;
            if pos >= end {
                break;
            }
        }
        if covered != raw.len() {
            return Err("field span mismatch".into());
        }
        let template = self.plan(shape);
        let mut program = vec![Atom {
            at: template as u32,
            len: NODE,
        }];
        program.extend(values);
        let id = self.j.programs.len();
        self.j.programs.push(Program::Tree(program));
        self.field_ids.insert(raw.to_vec(), (id, role));
        self.j.stats.unique_fields += 1;
        self.j.stats.unique_raw_field_bytes += raw.len();
        Ok(id)
    }
    fn remember(&mut self, key: [u8; 32], view: usize) {
        let r = self.recent.entry(key).or_default();
        if r.back() != Some(&view) {
            r.push_back(view);
        }
        if r.len() > 8 {
            r.pop_front();
        }
    }
    fn view(
        &mut self,
        doc: usize,
        source: &[u8],
        begin: usize,
        end: usize,
        key: [u8; 32],
        role: u8,
    ) -> Res<usize> {
        let fs = stobject::fields(&source[begin..end]).map_err(er)?;
        if fs.is_empty() || fs.iter().map(|f| f.raw.len()).sum::<usize>() != end - begin {
            return Err("field coverage or empty view".into());
        }
        if fs.len() < self.min_fields {
            self.j.stats.skipped_small += 1;
            return Err("small view skipped".into());
        }
        let mut schema = vec![];
        let mut fields = vec![];
        let mut seen = HashSet::new();
        // Validate duplicate field IDs before mutating the auxiliary program set.
        for f in &fs {
            let key = (u32::from(f.id.type_code) << 16) | u32::from(f.id.field_code);
            if !seen.insert(key) {
                return Err("duplicate field id".into());
            }
        }
        for f in fs {
            let at = f.raw.as_ptr() as usize - source.as_ptr() as usize;
            schema.push((u32::from(f.id.type_code) << 16) | u32::from(f.id.field_code));
            fields.push(self.field(doc, at, at + f.raw.len(), f.raw, role)?);
        }
        if let Some(&v) = self.view_ids.get(&fields) {
            self.j.stats.exact_view_hits += 1;
            let id = self.views[v].doc;
            self.remember(key, v);
            return Ok(id);
        }
        let schema_id = if let Some(&id) = self.schema_ids.get(&schema) {
            id
        } else {
            let id = self.j.schemas.len();
            self.j.schemas.push(schema.clone());
            self.schema_ids.insert(schema.clone(), id);
            id
        };
        let mut base = None;
        let mut best = 0;
        let mut depth = 0;
        if let Some(recent) = self.recent.get(&key) {
            for &v in recent.iter().rev() {
                let s = &self.views[v];
                if s.depth >= self.j.depth_limit {
                    continue;
                }
                let matches = schema
                    .iter()
                    .zip(&fields)
                    .filter(|(key, value)| {
                        s.sorted
                            .binary_search_by_key(*key, |x| x.0)
                            .is_ok_and(|i| s.sorted[i].1 == **value)
                    })
                    .count();
                if matches > best {
                    best = matches;
                    base = Some(v);
                    depth = s.depth + 1;
                }
            }
        }
        let mut edits = vec![];
        for (pos, (&key, &value)) in schema.iter().zip(&fields).enumerate() {
            if base.is_some_and(|v| {
                self.views[v]
                    .sorted
                    .binary_search_by_key(&key, |x| x.0)
                    .is_ok_and(|i| self.views[v].sorted[i].1 == value)
            }) {
                continue;
            }
            edits.push((pos, value));
        }
        let id = self.j.programs.len();
        let v = self.views.len();
        let mut sorted: Vec<_> = schema.into_iter().zip(fields.iter().copied()).collect();
        sorted.sort_unstable();
        self.j.stats.inherited_fields += best;
        self.j.stats.edited_fields += edits.len();
        self.j.stats.views += 1;
        self.j.stats.max_depth = self.j.stats.max_depth.max(depth);
        if base.is_some() {
            self.j.stats.delta_views += 1;
        }
        self.j.programs.push(Program::View(View {
            schema: schema_id,
            base: base.map(|v| self.views[v].doc),
            edits,
        }));
        self.views.push(Saved {
            doc: id,
            sorted,
            depth,
        });
        self.view_ids.insert(fields, v);
        self.remember(key, v);
        Ok(id)
    }
    fn metadata(&mut self, doc: usize, meta: &[u8]) -> Res<()> {
        let fs = match stobject::fields(meta) {
            Ok(fs) => fs,
            Err(_) => return Ok(()),
        };
        let Some(nodes) = fs
            .iter()
            .find(|f| f.id.type_code == 15 && f.id.field_code == 8)
        else {
            return Ok(());
        };
        let spans = tree_spans(self.prepared, doc)?;
        let mut replacements = vec![];
        for node in stobject::children(nodes).map_err(er)? {
            let nf = stobject::children(&node).map_err(er)?;
            let Some(k) = nf
                .iter()
                .find(|f| f.id.type_code == 5 && f.id.field_code == 6 && f.value.len() == 32)
            else {
                continue;
            };
            let key: [u8; 32] = k.value.try_into().map_err(|_| "object key")?;
            // Visit old values before final/new values; source positions remain unchanged.
            for kind in [6, 7, 8] {
                let Some(group) = nf
                    .iter()
                    .find(|f| f.id.type_code == 14 && f.id.field_code == kind)
                else {
                    continue;
                };
                if group.value.is_empty() {
                    continue;
                }
                let begin = group.value.as_ptr() as usize - meta.as_ptr() as usize;
                let end = begin + group.value.len();
                if let Some(&(start, stop)) = spans.get(&(begin, end)) {
                    match self.view(doc, meta, begin, end, key, 1) {
                        Ok(id) => {
                            replacements.push((start, stop, id));
                            self.j.stats.groups += 1;
                        }
                        Err(_) => self.j.stats.fallback_groups += 1,
                    }
                } else {
                    self.j.stats.fallback_groups += 1;
                }
            }
        }
        replacements.sort_unstable_by_key(|x| x.0);
        let wrapper = self.plan(vec![PlanOp::Value]);
        let (begin, end) = self.prepared.tree_docs[doc];
        let old = &self.prepared.tree[begin..end];
        let mut out = vec![];
        let mut at = 0;
        for (start, stop, id) in replacements {
            if start < at {
                return Err("overlapping metadata projections".into());
            }
            out.extend_from_slice(&old[at..start]);
            out.push(Atom {
                at: wrapper as u32,
                len: NODE,
            });
            out.push(Atom {
                at: id as u32,
                len: SHARED,
            });
            at = stop;
        }
        out.extend_from_slice(&old[at..]);
        self.j.programs[doc] = Program::Tree(out);
        Ok(())
    }
}
pub(crate) fn build(p: &Prepared, rows: &[Row], depth_limit: usize) -> Res<Journal> {
    build_filtered(p, rows, depth_limit, 0)
}
pub(crate) fn build_filtered(
    p: &Prepared,
    rows: &[Row],
    depth_limit: usize,
    min_fields: usize,
) -> Res<Journal> {
    if depth_limit > 32 {
        return Err("shared version depth must be at most 32".into());
    }
    if rows.len() != p.layout.len() {
        return Err("shared row layout".into());
    }
    let plans = p.plans.clone();
    let plan_ids = plans
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, p)| (p, i))
        .collect();
    let programs = p
        .tree_docs
        .iter()
        .map(|&(a, b)| Program::Tree(p.tree[a..b].to_vec()))
        .collect();
    let mut b = Builder {
        prepared: p,
        min_fields,
        j: Journal {
            programs,
            plans,
            schemas: vec![],
            depth_limit,
            stats: Stats::default(),
        },
        field_ids: HashMap::new(),
        plan_ids,
        schema_ids: HashMap::new(),
        view_ids: HashMap::new(),
        views: vec![],
        recent: HashMap::new(),
    };
    for (row, layout) in rows.iter().zip(&p.layout) {
        let mut txs = vec![];
        for (storage, (_, meta)) in row.txs.iter().enumerate() {
            let rank = indexed::affected(meta)
                .map(|x| x.0)
                .unwrap_or(storage as u32);
            txs.push((rank, storage));
        }
        txs.sort_unstable();
        for (_, storage) in txs {
            b.metadata(layout.tx[storage].1, &row.txs[storage].1)?;
        }
        for ((key, value), &(_, doc)) in row.patches.iter().zip(&layout.patches) {
            if value.is_empty() {
                continue;
            }
            match b.view(doc, value, 0, value.len(), *key, 2) {
                Ok(id) => {
                    let wrapper = b.plan(vec![PlanOp::Value]);
                    b.j.programs[doc] = Program::Tree(vec![
                        Atom {
                            at: wrapper as u32,
                            len: NODE,
                        },
                        Atom {
                            at: id as u32,
                            len: SHARED,
                        },
                    ]);
                    b.j.stats.patches += 1;
                }
                Err(_) => b.j.stats.fallback_patches += 1,
            }
        }
    }
    Ok(b.j)
}

pub(crate) struct NumericPlan {
    pub atoms: Vec<Atom>,
    pub deltas: HashMap<(usize, usize), (usize, u64)>,
}
/// Plan exact modular deltas before building the literal pool, so unused values disappear.
pub(crate) fn numeric_plan(p: &Prepared, j: &Journal) -> Res<NumericPlan> {
    let mut atoms = vec![];
    let mut deltas = HashMap::new();
    for program in &j.programs[..p.docs.len()] {
        let Program::Tree(tree) = program else {
            return Err("original numeric document".into());
        };
        atoms.extend_from_slice(tree);
    }
    let mut states: HashMap<usize, Vec<(u32, usize)>> = HashMap::new();
    for (id, program) in j.programs.iter().enumerate() {
        let Program::View(v) = program else {
            continue;
        };
        let old: std::collections::BTreeMap<_, _> = if let Some(base) = v.base {
            states
                .get(&base)
                .ok_or("numeric base")?
                .iter()
                .copied()
                .collect()
        } else {
            std::collections::BTreeMap::new()
        };
        let schema = &j.schemas[v.schema];
        let mut fields: Vec<_> = schema.iter().map(|k| old.get(k).copied()).collect();
        for &(slot, field) in &v.edits {
            let Program::Tree(next) = &j.programs[field] else {
                return Err("numeric field tree".into());
            };
            let previous = old
                .get(&schema[slot])
                .and_then(|&id| match &j.programs[id] {
                    Program::Tree(v) => Some(v),
                    _ => None,
                });
            let mut selected = false;
            if let Some(previous) = previous
                && previous.len() == 2
                && next.len() == 2
                && previous[0].at == next[0].at
                && previous[1].len == next[1].len
            {
                let width = next[1].len as usize;
                let ty = schema[slot] >> 16;
                if (ty == 2 && width == 4) || ([3, 6].contains(&ty) && width == 8) {
                    let value = |a: Atom| -> u64 {
                        let mut b = [0u8; 8];
                        b[8 - width..]
                            .copy_from_slice(&p.pool[a.at as usize..a.at as usize + width]);
                        u64::from_be_bytes(b)
                    };
                    let a = value(previous[1]);
                    let b = value(next[1]);
                    let diff = if width == 4 {
                        (b as u32).wrapping_sub(a as u32) as i32 as i64
                    } else {
                        b.wrapping_sub(a) as i64
                    };
                    let zz = ((diff as u64) << 1) ^ ((diff >> 63) as u64);
                    if zz < 4096 {
                        deltas.insert((id, slot), (width, zz));
                        selected = true;
                    }
                }
            }
            if !selected {
                atoms.extend_from_slice(next);
            }
            fields[slot] = Some(field);
        }
        states.insert(
            id,
            schema
                .iter()
                .copied()
                .zip(fields)
                .map(|(key, field)| Ok((key, field.ok_or("numeric field missing")?)))
                .collect::<Res<_>>()?,
        );
    }
    Ok(NumericPlan { atoms, deltas })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn fields(n: u32, extra: bool) -> Vec<u8> {
        let mut b = vec![0x22];
        b.extend(7u32.to_be_bytes());
        b.push(0x24);
        b.extend(n.to_be_bytes());
        if extra {
            b.push(0x25);
            b.extend(9u32.to_be_bytes());
        }
        b
    }
    fn meta(rank: u32, old: u32, new: u32) -> Vec<u8> {
        let mut b = vec![0x20, 28];
        b.extend(rank.to_be_bytes());
        b.extend([0xf8, 0xe5, 0x11, 0, 97, 0x56]);
        b.extend([3; 32]);
        b.push(0xe6);
        b.extend(fields(old, false));
        b.push(0xe1);
        b.push(0xe7);
        b.extend(fields(new, true));
        b.extend([0xe1, 0xe1, 0xf1]);
        b
    }
    pub(crate) fn fixture() -> Vec<Row> {
        vec![
            Row {
                seq: 1,
                header: vec![0; 118],
                txs: vec![
                    (vec![0x81, 0], meta(1, 12, 13)),
                    (vec![0x81, 0], meta(0, 11, 12)),
                ],
                patches: vec![
                    ([3; 32], fields(13, true)),
                    ([8; 32], vec![]),
                    ([9; 32], vec![0xff, 1, 2, 3]),
                ],
            },
            Row {
                seq: 2,
                header: vec![0; 118],
                txs: vec![(vec![0x81, 0], meta(0, 13, 14))],
                patches: vec![([3; 32], fields(14, false))],
            },
        ]
    }
    #[test]
    fn shared_views_preserve_intermediate_values_absence_order_and_fallback() {
        let rows = fixture();
        let (frame, _) = encode_block(
            &rows,
            Options {
                split_shapes: true,
                context_delta: true,
                ..Options::default()
            },
        )
        .unwrap();
        let p = Prepared::parse(&frame).unwrap();
        for mode in 0..4 {
            for depth in [0, 1, 8] {
                let (archive, stats) = if mode == 3 {
                    seek::pack_shared_numeric(&p, &rows, 256, 3, depth, 0)
                } else if mode == 2 {
                    seek::pack_shared_compact(&p, &rows, 256, 3, depth, 0, true)
                } else if mode == 1 {
                    seek::pack_shared_inline(&p, &rows, 256, 3, depth)
                } else {
                    seek::pack_shared(&p, &rows, 256, 3, depth)
                }
                .unwrap();
                assert_eq!(stats.groups, 6);
                assert_eq!(stats.patches, 2);
                assert_eq!(stats.fallback_patches, 1);
                assert!(stats.cross_role_fields >= 2);
                assert!(stats.max_depth <= depth);
                if depth > 0 {
                    assert!(stats.inherited_fields > 0);
                }
                let path = std::env::temp_dir().join(format!(
                    "asts-shared-test-{}-{depth}-{mode}",
                    std::process::id()
                ));
                std::fs::write(&path, &archive).unwrap();
                let mut reader = seek::Reader::open(&path).unwrap();
                // Reverse/random access before full restoration, and clear all data caches.
                assert_eq!(reader.patch(3).unwrap(), rows[1].patches[0]);
                reader.clear_data_cache();
                assert_eq!(reader.tx(0).unwrap(), rows[0].txs[0]);
                reader.clear_data_cache();
                assert_eq!(reader.tx(1).unwrap(), rows[0].txs[1]);
                reader.clear_data_cache();
                assert_eq!(reader.all_rows().unwrap(), rows);
                for n in [0, 7, 63, 64, archive.len() / 2, archive.len() - 1] {
                    std::fs::write(&path, &archive[..n]).unwrap();
                    assert!(
                        seek::Reader::open(&path)
                            .and_then(|mut r| r.all_rows())
                            .is_err()
                    );
                }
                std::fs::remove_file(path).unwrap();
            }
        }
    }
    #[test]
    fn compact_large_schema_and_changing_numeric_values_roundtrip() {
        let mut rows = vec![];
        for step in 0..80u32 {
            let mut fields = vec![];
            for id in 1..=65u8 {
                if id < 16 {
                    fields.push(0x20 | id);
                } else {
                    fields.extend([0x20, id]);
                }
                let value = if id == 1 {
                    7
                } else if step % 3 == 0 {
                    u32::MAX.wrapping_sub(u32::from(id)).wrapping_add(step)
                } else {
                    1000 + u32::from(id) + step
                };
                fields.extend(value.to_be_bytes());
            }
            rows.push(Row {
                seq: step + 1,
                header: vec![0; 118],
                txs: vec![],
                patches: vec![([3; 32], fields)],
            });
        }
        let (frame, _) = encode_block(
            &rows,
            Options {
                split_shapes: true,
                context_delta: true,
                ..Options::default()
            },
        )
        .unwrap();
        let p = Prepared::parse(&frame).unwrap();
        let (archive, stats) = seek::pack_shared_numeric(&p, &rows, 256, 7, 4, 0).unwrap();
        assert_eq!(stats.patches, rows.len());
        assert!(stats.numeric4 > 0);
        let path = std::env::temp_dir().join(format!("asts7-wide-{}", std::process::id()));
        std::fs::write(&path, archive).unwrap();
        let mut reader = seek::Reader::open(&path).unwrap();
        for i in [79, 0, 53, 20, 41] {
            reader.clear_data_cache();
            assert_eq!(reader.patch(i).unwrap(), rows[i].patches[0]);
        }
        assert_eq!(reader.all_rows().unwrap(), rows);
        std::fs::remove_file(path).unwrap();
    }
}
