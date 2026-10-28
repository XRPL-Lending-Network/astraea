//! ASTS3: independently readable hierarchical programs and a shared fixed-width literal pool.
//! This is an experimental successor to the ASTJ2 representation, not a second payload copy.
use super::*;
#[path = "capsule.rs"]
mod capsule;
use fast::{FIXED, KEY, NODE, PlanOp, Prepared, TX};
use std::io::{Read as _, Seek as _};
#[derive(Clone, Hash, PartialEq, Eq)]
enum Shape {
    Fixed(Vec<u8>),
    Value,
    Child,
}
#[derive(Clone)]
struct Group {
    first: usize,
    count: usize,
    width: usize,
    der: bool,
    offset: usize,
}
#[derive(Clone)]
struct Key {
    domain: u8,
    args: Vec<usize>,
}
#[derive(Clone)]
struct Location {
    seq: u32,
    first_doc: usize,
    txs: usize,
    patches: usize,
    first_tx: usize,
    first_patch: usize,
}
#[derive(Clone)]
struct Chunk {
    offset: u64,
    length: usize,
    raw: usize,
    hash: [u8; 32],
}
fn value_key(v: &[u8]) -> (bool, Vec<u8>) {
    if (68..=72).contains(&v.len())
        && let Ok(sig) = k256::ecdsa::Signature::from_der(v)
        && sig.to_der().as_bytes() == v
    {
        return (true, sig.to_bytes().to_vec());
    }
    (false, v.to_vec())
}
#[derive(Clone, Copy)]
enum Packing<'a> {
    Plain,
    Columns,
    Shared,
    Inline,
    Compact,
    Numeric(&'a shared::NumericPlan),
}
const NUMERIC_VALUE: u64 = u64::MAX - 1;
/// Encode only the prepared programs/literals, not the original ASTJ archive.
pub fn pack(prepared: &Prepared, pool_chunk: usize, docs_per_chunk: usize) -> Res<Vec<u8>> {
    pack_inner(prepared, pool_chunk, docs_per_chunk, None, Packing::Plain)
}
pub fn pack_columns(prepared: &Prepared, pool_chunk: usize, docs_per_chunk: usize) -> Res<Vec<u8>> {
    pack_inner(prepared, pool_chunk, docs_per_chunk, None, Packing::Columns)
}
pub fn pack_shared(
    prepared: &Prepared,
    rows: &[Row],
    pool_chunk: usize,
    docs_per_chunk: usize,
    depth: usize,
) -> Res<(Vec<u8>, shared::Stats)> {
    let j = shared::build(prepared, rows, depth)?;
    let bytes = pack_inner(
        prepared,
        pool_chunk,
        docs_per_chunk,
        Some(&j),
        Packing::Shared,
    )?;
    Ok((bytes, j.stats))
}
pub fn pack_shared_inline(
    prepared: &Prepared,
    rows: &[Row],
    pool_chunk: usize,
    docs_per_chunk: usize,
    depth: usize,
) -> Res<(Vec<u8>, shared::Stats)> {
    pack_shared_filtered(prepared, rows, pool_chunk, docs_per_chunk, depth, 0)
}
pub fn pack_shared_filtered(
    prepared: &Prepared,
    rows: &[Row],
    pool_chunk: usize,
    docs_per_chunk: usize,
    depth: usize,
    min_fields: usize,
) -> Res<(Vec<u8>, shared::Stats)> {
    pack_shared_compact(
        prepared,
        rows,
        pool_chunk,
        docs_per_chunk,
        depth,
        min_fields,
        false,
    )
}
pub fn pack_shared_compact(
    prepared: &Prepared,
    rows: &[Row],
    pool_chunk: usize,
    docs_per_chunk: usize,
    depth: usize,
    min_fields: usize,
    compact: bool,
) -> Res<(Vec<u8>, shared::Stats)> {
    let j = shared::build_filtered(prepared, rows, depth, min_fields)?;
    let bytes = pack_inner(
        prepared,
        pool_chunk,
        docs_per_chunk,
        Some(&j),
        if compact {
            Packing::Compact
        } else {
            Packing::Inline
        },
    )?;
    Ok((bytes, j.stats))
}
pub fn pack_shared_numeric(
    prepared: &Prepared,
    rows: &[Row],
    pool_chunk: usize,
    docs_per_chunk: usize,
    depth: usize,
    min_fields: usize,
) -> Res<(Vec<u8>, shared::Stats)> {
    let mut j = shared::build_filtered(prepared, rows, depth, min_fields)?;
    let plan = shared::numeric_plan(prepared, &j)?;
    j.stats.numeric4 = plan.deltas.values().filter(|v| v.0 == 4).count();
    j.stats.numeric8 = plan.deltas.values().filter(|v| v.0 == 8).count();
    let bytes = pack_inner(
        prepared,
        pool_chunk,
        docs_per_chunk,
        Some(&j),
        Packing::Numeric(&plan),
    )?;
    Ok((bytes, j.stats))
}
fn pack_inner(
    prepared: &Prepared,
    pool_chunk: usize,
    docs_per_chunk: usize,
    journal: Option<&shared::Journal>,
    mode: Packing<'_>,
) -> Res<Vec<u8>> {
    let columns = matches!(mode, Packing::Columns);
    let inline = matches!(
        mode,
        Packing::Inline | Packing::Compact | Packing::Numeric(_)
    );
    let compact = matches!(mode, Packing::Compact | Packing::Numeric(_));
    let numeric = if let Packing::Numeric(plan) = mode {
        Some(plan)
    } else {
        None
    };
    if pool_chunk < 256 || docs_per_chunk == 0 {
        return Err("seek chunk size".into());
    }
    let mut unique = HashSet::new();
    for a in numeric.map_or(prepared.atoms.as_slice(), |p| p.atoms.as_slice()) {
        if ![TX, KEY, NODE, shared::SHARED].contains(&a.len) && a.len & FIXED == 0 {
            unique.insert(value_key(
                &prepared.pool[a.at as usize..a.at as usize + a.len as usize],
            ));
        }
    }
    for (_, args) in &prepared.keys {
        for a in args {
            unique.insert(value_key(
                &prepared.pool[a.at as usize..a.at as usize + a.len as usize],
            ));
        }
    }
    let mut values: Vec<_> = unique.into_iter().collect();
    values.sort_by(|a, b| (a.0, a.1.len(), &a.1).cmp(&(b.0, b.1.len(), &b.1)));
    let shapes: Vec<Vec<Shape>> = journal
        .map_or(&prepared.plans, |j| &j.plans)
        .iter()
        .map(|p| {
            p.iter()
                .map(|op| match op {
                    PlanOp::Fixed(b) => Shape::Fixed(b.clone()),
                    PlanOp::Value => Shape::Value,
                    PlanOp::Child => Shape::Child,
                })
                .collect()
        })
        .collect();
    let ids: HashMap<_, _> = values
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, v)| (v, i))
        .collect();
    let mut atom_ids = HashMap::new();
    let mut groups = vec![];
    let mut pool = vec![];
    for (id, (der, v)) in values.iter().enumerate() {
        if groups
            .last()
            .is_none_or(|g: &Group| g.der != *der || g.width != v.len())
        {
            groups.push(Group {
                first: id,
                count: 0,
                width: v.len(),
                der: *der,
                offset: pool.len(),
            });
        }
        groups.last_mut().ok_or("group")?.count += 1;
        pool.extend(v);
    }
    let mut atom_id = |at: u32, len: u32| -> Res<usize> {
        if let Some(id) = atom_ids.get(&(at, len)) {
            return Ok(*id);
        }
        let id = ids[&value_key(&prepared.pool[at as usize..at as usize + len as usize])];
        atom_ids.insert((at, len), id);
        Ok(id)
    };
    let old_count = journal.map_or(prepared.docs.len(), |j| j.programs.len());
    let mut doc_map = vec![usize::MAX; old_count];
    let mut retained = vec![];
    for (id, entry) in doc_map.iter_mut().enumerate() {
        if !inline
            || id < prepared.docs.len()
            || matches!(
                journal.ok_or("inline journal")?.programs[id],
                shared::Program::View(_)
            )
        {
            *entry = retained.len();
            retained.push(id);
        }
    }
    let mut inline_schemas: Vec<Vec<(u32, usize)>> = vec![];
    let mut inline_schema_ids = HashMap::new();
    let mut full_fields: HashMap<usize, Vec<(u32, usize)>> = HashMap::new();
    let mut meta = vec![];
    put(&mut meta, pool_chunk as u64);
    put(&mut meta, docs_per_chunk as u64);
    put(&mut meta, retained.len() as u64);
    put(&mut meta, groups.len() as u64);
    for g in &groups {
        meta.push(u8::from(g.der));
        put(&mut meta, g.width as u64);
        put(&mut meta, g.count as u64);
    }
    put(&mut meta, prepared.keys.len() as u64);
    for (domain, args) in &prepared.keys {
        meta.push(*domain);
        put(&mut meta, args.len() as u64);
        for a in args {
            put(&mut meta, atom_id(a.at, a.len)? as u64);
        }
    }
    put(&mut meta, prepared.layout.len() as u64);
    for l in &prepared.layout {
        put(&mut meta, u64::from(l.seq));
        put(&mut meta, l.tx.len() as u64);
        put(&mut meta, l.patches.len() as u64);
    }
    let mut raw_chunks = vec![];
    for p in pool.chunks(pool_chunk) {
        raw_chunks.push(p.to_vec());
    }
    let pool_count = raw_chunks.len();
    let mut programs = Vec::new();
    for &doc in &retained {
        let mut ops = vec![];
        let tree = if let Some(j) = journal {
            match &j.programs[doc] {
                shared::Program::Tree(tree) => Some(tree.as_slice()),
                shared::Program::View(v) => {
                    if inline {
                        let old: std::collections::BTreeMap<_, _> = if let Some(base) = v.base {
                            full_fields
                                .get(&base)
                                .ok_or("inline base")?
                                .iter()
                                .copied()
                                .collect()
                        } else {
                            std::collections::BTreeMap::new()
                        };
                        let schema = &j.schemas[v.schema];
                        let mut fields: Vec<_> =
                            schema.iter().map(|key| old.get(key).copied()).collect();
                        for &(slot, field) in &v.edits {
                            fields[slot] = Some(field);
                        }
                        let fields: Vec<_> = schema
                            .iter()
                            .copied()
                            .zip(fields)
                            .map(|(key, field)| Ok((key, field.ok_or("inline field")?)))
                            .collect::<Res<_>>()?;
                        let mut shape = vec![];
                        for &(key, field) in &fields {
                            let shared::Program::Tree(program) = &j.programs[field] else {
                                return Err("inline field not tree".into());
                            };
                            shape.push((key, program[0].at as usize));
                        }
                        let schema_id = if let Some(&id) = inline_schema_ids.get(&shape) {
                            id
                        } else {
                            let id = inline_schemas.len();
                            inline_schemas.push(shape.clone());
                            inline_schema_ids.insert(shape, id);
                            id
                        };
                        let base = v.base.map_or(0, |x| {
                            if compact {
                                doc_map[doc] - doc_map[x]
                            } else {
                                doc_map[x] + 1
                            }
                        });
                        ops.extend([shared::VIEW, schema_id as u64, base as u64]);
                        let mask = compact && fields.len() <= 63;
                        if compact {
                            if mask {
                                let bits =
                                    v.edits.iter().fold(0u64, |m, (slot, _)| m | (1u64 << slot));
                                ops.push(bits * 2 + 1);
                            } else {
                                ops.extend([0, v.edits.len() as u64]);
                            }
                        } else {
                            ops.push(v.edits.len() as u64);
                        }

                        for &(slot, field) in &v.edits {
                            if !mask {
                                ops.push(slot as u64);
                            }
                            let shared::Program::Tree(program) = &j.programs[field] else {
                                return Err("inline edit not tree".into());
                            };
                            if let Some(&(width, zz)) =
                                numeric.and_then(|p| p.deltas.get(&(doc, slot)))
                            {
                                ops.push((zz << 2) | if width == 4 { 1 } else { 3 });
                                continue;
                            }
                            let old_program = old.get(&schema[slot]).and_then(|&field| {
                                match &j.programs[field] {
                                    shared::Program::Tree(p) if p[0].at == program[0].at => Some(p),
                                    _ => None,
                                }
                            });
                            for (value_pos, a) in program[1..].iter().enumerate() {
                                let token = if a.len == TX {
                                    (a.at as u64) * 4 + 1
                                } else if a.len == KEY {
                                    (a.at as u64) * 4 + 2
                                } else {
                                    (atom_id(a.at, a.len)? as u64) * 4
                                };
                                let encoded = if numeric.is_some() {
                                    token.checked_mul(2).ok_or("numeric literal overflow")?
                                } else if compact {
                                    let absolute =
                                        token.checked_mul(2).ok_or("compact value overflow")?;
                                    if let Some(old) =
                                        old_program.and_then(|p| p.get(value_pos + 1))
                                    {
                                        let old_token = if old.len == TX {
                                            (old.at as u64) * 4 + 1
                                        } else if old.len == KEY {
                                            (old.at as u64) * 4 + 2
                                        } else {
                                            (atom_id(old.at, old.len)? as u64) * 4
                                        };
                                        let delta = token as i64 - old_token as i64;
                                        let zigzag = ((delta as u64) << 1) ^ ((delta >> 63) as u64);
                                        let relative = zigzag
                                            .checked_mul(2)
                                            .and_then(|x| x.checked_add(1))
                                            .ok_or("compact delta overflow")?;
                                        // Varint length, rather than integer size, determines a real byte saving.
                                        if (64 - relative.leading_zeros()).max(1).div_ceil(7)
                                            < (64 - absolute.leading_zeros()).max(1).div_ceil(7)
                                        {
                                            relative
                                        } else {
                                            absolute
                                        }
                                    } else {
                                        absolute
                                    }
                                } else {
                                    token
                                };
                                ops.push(encoded);
                            }
                        }
                        full_fields.insert(doc, fields);
                    } else {
                        ops.extend([
                            shared::VIEW,
                            v.schema as u64,
                            v.base.map_or(0, |x| x as u64 + 1),
                            v.edits.len() as u64,
                        ]);
                        for &(slot, field) in &v.edits {
                            ops.extend([slot as u64, field as u64]);
                        }
                    }
                    None
                }
            }
        } else {
            let (a, b) = prepared.tree_docs[doc];
            Some(&prepared.tree[a..b])
        };
        if let Some(tree) = tree {
            for a in tree {
                let id = if a.len == NODE {
                    a.at as u64
                } else if a.len == TX {
                    (a.at as u64) * 4 + 1
                } else if a.len == KEY {
                    (a.at as u64) * 4 + 2
                } else if a.len == shared::SHARED {
                    (doc_map[a.at as usize] as u64) * 4 + 3
                } else {
                    (atom_id(a.at, a.len)? as u64) * 4
                };
                ops.push(id);
            }
        }
        programs.push(ops);
    }
    for docs in programs.chunks(docs_per_chunk) {
        let mut p = vec![];
        put(&mut p, docs.len() as u64);
        for ops in docs {
            put(&mut p, ops.len() as u64);
            for &op in ops {
                put(&mut p, op);
            }
        }
        raw_chunks.push(if columns {
            capsule::encode(&p, &shapes)?
        } else {
            p
        });
    }
    // A stored program dictionary is trained on these exact programs; all its bytes count.
    let dict = if raw_chunks.len() - pool_count >= 8 {
        zstd::dict::from_samples(&raw_chunks[pool_count..], 16_384).unwrap_or_default()
    } else {
        vec![]
    };
    put(&mut meta, shapes.len() as u64);
    for shape in &shapes {
        put(&mut meta, shape.len() as u64);
        for op in shape {
            match op {
                Shape::Fixed(b) => {
                    meta.push(0);
                    blob(&mut meta, b)
                }
                Shape::Value => meta.push(1),
                Shape::Child => meta.push(2),
            }
        }
    }
    if let Some(j) = journal {
        put(&mut meta, j.depth_limit as u64);
        if inline {
            put(&mut meta, inline_schemas.len() as u64);
            for schema in &inline_schemas {
                put(&mut meta, schema.len() as u64);
                for &(key, shape) in schema {
                    put(&mut meta, key as u64);
                    put(&mut meta, shape as u64);
                }
            }
        } else {
            put(&mut meta, j.schemas.len() as u64);
            for schema in &j.schemas {
                put(&mut meta, schema.len() as u64);
                for &field in schema {
                    put(&mut meta, field as u64);
                }
            }
        }
    }
    blob(&mut meta, &dict);
    let mz = compress(&meta)?;
    let mut compressor = zstd::bulk::Compressor::with_dictionary(19, &dict).map_err(er)?;
    let mut chunks = vec![];
    for (i, raw) in raw_chunks.iter().enumerate() {
        let compressed = if i < pool_count {
            compress(raw)?
        } else {
            compressor.compress(raw).map_err(er)?
        };
        chunks.push((raw.len(), compressed));
    }
    let mut out = if numeric.is_some() {
        b"ASTS8\0\0\0"
    } else if compact {
        b"ASTS7\0\0\0"
    } else if inline {
        b"ASTS6\0\0\0"
    } else if journal.is_some() {
        b"ASTS5\0\0\0"
    } else if columns {
        b"ASTS4\0\0\0"
    } else {
        b"ASTS3\0\0\0"
    }
    .to_vec();
    out.extend((meta.len() as u64).to_le_bytes());
    out.extend((mz.len() as u64).to_le_bytes());
    out.extend((pool_count as u32).to_le_bytes());
    out.extend((chunks.len() as u32).to_le_bytes());
    out.extend(sha512_half(&mz));
    out.extend(&mz);
    let mut offset = out.len() + chunks.len() * 48;
    for (n, z) in &chunks {
        out.extend((offset as u64).to_le_bytes());
        out.extend((z.len() as u32).to_le_bytes());
        out.extend((*n as u32).to_le_bytes());
        out.extend(sha512_half(z));
        offset += z.len();
    }
    for (_, z) in chunks {
        out.extend(z);
    }
    Ok(out)
}
struct Cache {
    entries: std::collections::VecDeque<(usize, Vec<u8>)>,
    limit: usize,
}
impl Cache {
    fn new(limit: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            limit,
        }
    }
    fn clear(&mut self) {
        self.entries.clear()
    }
    fn bytes(&self) -> usize {
        self.entries.iter().map(|(_, v)| v.capacity()).sum()
    }
}
/// On-disk capsule reader. Metadata is resident; only touched pool/program chunks are decoded.
pub struct TransactionProof {
    pub header: Vec<u8>,
    pub tx: Vec<u8>,
    pub meta: Vec<u8>,
    pub path: shamap::Path,
}
type InlineFields = Vec<(u32, Vec<u64>)>;
type InlineView = (usize, InlineFields);
pub struct Reader {
    file: std::fs::File,
    groups: Vec<Group>,
    keys: Vec<Key>,
    layout: Vec<Location>,
    chunks: Vec<Chunk>,
    pool_count: usize,
    pool_chunk: usize,
    docs_per_chunk: usize,
    doc_count: usize,
    tree_programs: bool,
    column_programs: bool,
    shared_programs: bool,
    inline_fields: bool,
    compact_fields: bool,
    numeric_fields: bool,
    field_shapes: Vec<Vec<usize>>,
    inline_cache: HashMap<usize, InlineView>,
    schemas: Vec<Vec<u32>>,
    view_depth_limit: usize,
    view_cache: HashMap<usize, (usize, Vec<(u32, usize)>)>,
    document_depth: usize,
    shapes: Option<Vec<Vec<Shape>>>,
    dictionary: Vec<u8>,
    pool_cache: Cache,
    program_cache: Cache,
    program_offsets: std::collections::VecDeque<(usize, Vec<(usize, usize)>)>,
    key_hashes: HashMap<usize, [u8; 32]>,
    tx_hashes: HashMap<usize, [u8; 32]>,
    pub bytes_read: u64,
    pub chunks_read: u64,
}
impl Reader {
    pub fn open(path: impl AsRef<std::path::Path>) -> Res<Self> {
        let mut file = std::fs::File::open(path).map_err(er)?;
        let length = file.metadata().map_err(er)?.len();
        let mut head = [0u8; 64];
        file.read_exact(&mut head).map_err(er)?;
        let column_programs = &head[..8] == b"ASTS4\0\0\0";
        let numeric_fields = &head[..8] == b"ASTS8\0\0\0";
        let compact_fields = numeric_fields || &head[..8] == b"ASTS7\0\0\0";
        let inline_fields = compact_fields || &head[..8] == b"ASTS6\0\0\0";
        let shared_programs = inline_fields || &head[..8] == b"ASTS5\0\0\0";
        let tree_programs = shared_programs || column_programs || &head[..8] == b"ASTS3\0\0\0";
        let v2 = tree_programs || &head[..8] == b"ASTS2\0\0\0";
        if !v2 && &head[..8] != b"ASTS1\0\0\0" {
            return Err("seek magic".into());
        }
        let raw = u64::from_le_bytes(head[8..16].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(head[16..24].try_into().unwrap()) as usize;
        if raw > MAX || size > MAX {
            return Err("metadata limit".into());
        }
        let pool_count = u32::from_le_bytes(head[24..28].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(head[28..32].try_into().unwrap()) as usize;
        if count > 1_000_000 || pool_count > count {
            return Err("chunk count".into());
        }
        let mut z = vec![0; size];
        file.read_exact(&mut z).map_err(er)?;
        if sha512_half(&z) != head[32..64] {
            return Err("metadata checksum".into());
        }
        let meta = zstd::bulk::decompress(&z, raw).map_err(er)?;
        if meta.len() != raw {
            return Err("metadata size".into());
        }
        let mut r = Read::new(&meta);
        let pool_chunk = r.count()?;
        let docs_per_chunk = r.count()?;
        let doc_count = r.count()?;
        if pool_chunk < 256 || docs_per_chunk == 0 {
            return Err("chunk size".into());
        }
        let mut groups = vec![];
        let (mut first, mut offset) = (0, 0);
        for _ in 0..r.count()? {
            let der = match r.byte()? {
                0 => false,
                1 => true,
                _ => return Err("literal kind".into()),
            };
            let width = r.count()?;
            let n = r.count()?;
            if der && width != 64 {
                return Err("DER width".into());
            }
            groups.push(Group {
                first,
                count: n,
                width,
                der,
                offset,
            });
            first += n;
            offset += width.checked_mul(n).ok_or("pool extent")?;
        }
        let mut keys = vec![];
        for _ in 0..r.count()? {
            let domain = r.byte()?;
            let n = r.count()?;
            if n > 4 {
                return Err("recipe arguments".into());
            }
            let mut args = vec![];
            for _ in 0..n {
                let id = r.count()?;
                if id >= first {
                    return Err("recipe literal id".into());
                }
                args.push(id);
            }
            keys.push(Key { domain, args });
        }
        let mut layout = vec![];
        let (mut doc, mut tx, mut patch) = (0, 0, 0);
        for _ in 0..r.count()? {
            let seq = u32::try_from(r.var()?).map_err(er)?;
            let nt = r.count()?;
            let np = r.count()?;
            layout.push(Location {
                seq,
                first_doc: doc,
                txs: nt,
                patches: np,
                first_tx: tx,
                first_patch: patch,
            });
            doc += 1 + 2 * (nt + np);
            tx += nt;
            patch += np;
        }
        if (!shared_programs && doc != doc_count) || doc > doc_count {
            return Err("document count".into());
        }
        let shapes = if v2 {
            let mut ss = vec![];
            for _ in 0..r.count()? {
                let mut shape = vec![];
                for _ in 0..r.count()? {
                    shape.push(match r.byte()? {
                        0 => Shape::Fixed(r.blob()?.to_vec()),
                        1 => Shape::Value,
                        2 if tree_programs => Shape::Child,
                        _ => return Err("shape opcode".into()),
                    })
                }
                ss.push(shape);
            }
            Some(ss)
        } else {
            None
        };
        let mut schemas = vec![];
        let mut field_shapes = vec![];
        let mut view_depth_limit = 0;
        if shared_programs {
            view_depth_limit = r.count()?;
            if view_depth_limit > 32 {
                return Err("view depth limit".into());
            }
            for _ in 0..r.count()? {
                let n = r.count()?;
                if n > 65536 {
                    return Err("view schema limit".into());
                }
                let mut schema = vec![];
                let mut templates = vec![];
                let mut seen = HashSet::new();
                for _ in 0..n {
                    let id = u32::try_from(r.var()?).map_err(er)?;
                    if !seen.insert(id) {
                        return Err("duplicate schema field".into());
                    }
                    schema.push(id);
                    if inline_fields {
                        let shape = r.count()?;
                        let plan = shapes
                            .as_ref()
                            .and_then(|s| s.get(shape))
                            .ok_or("field shape id")?;
                        if plan.iter().any(|x| matches!(x, Shape::Child)) {
                            return Err("nested inline shape".into());
                        }
                        templates.push(shape);
                    }
                }
                schemas.push(schema);
                field_shapes.push(templates);
            }
        }
        let dictionary = r.blob()?.to_vec();
        r.end()?;
        if offset.div_ceil(pool_chunk) != pool_count
            || doc_count.div_ceil(docs_per_chunk) + pool_count != count
        {
            return Err("chunk layout".into());
        }
        let mut expected = 64 + size + 48 * count;
        let mut chunks = vec![];
        for _ in 0..count {
            let mut b = [0u8; 48];
            file.read_exact(&mut b).map_err(er)?;
            let offset = u64::from_le_bytes(b[..8].try_into().unwrap());
            let length = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
            let raw = u32::from_le_bytes(b[12..16].try_into().unwrap()) as usize;
            if offset != expected as u64 || length > MAX || raw > MAX {
                return Err("chunk directory".into());
            }
            expected += length;
            chunks.push(Chunk {
                offset,
                length,
                raw,
                hash: b[16..].try_into().unwrap(),
            });
        }
        if expected as u64 != length {
            return Err("file extent".into());
        }
        Ok(Self {
            file,
            groups,
            keys,
            layout,
            chunks,
            pool_count,
            pool_chunk,
            docs_per_chunk,
            doc_count,
            tree_programs,
            column_programs,
            shared_programs,
            inline_fields,
            compact_fields,
            numeric_fields,
            field_shapes,
            inline_cache: HashMap::new(),
            schemas,
            view_depth_limit,
            view_cache: HashMap::new(),
            document_depth: 0,
            shapes,
            dictionary,
            pool_cache: Cache::new(64),
            program_cache: Cache::new(16),
            program_offsets: std::collections::VecDeque::new(),
            key_hashes: HashMap::new(),
            tx_hashes: HashMap::new(),
            bytes_read: (64 + size + 48 * count) as u64,
            chunks_read: 0,
        })
    }
    pub fn format_name(&self) -> &'static str {
        if self.numeric_fields {
            "ASTS8"
        } else if self.compact_fields {
            "ASTS7"
        } else if self.inline_fields {
            "ASTS6"
        } else if self.shared_programs {
            "ASTS5"
        } else if self.column_programs {
            "ASTS4"
        } else if self.tree_programs {
            "ASTS3"
        } else if self.shapes.is_some() {
            "ASTS2"
        } else {
            "ASTS1"
        }
    }
    pub fn clear_data_cache(&mut self) {
        self.pool_cache.clear();
        self.program_cache.clear();
        self.program_offsets.clear();
        self.key_hashes.clear();
        self.tx_hashes.clear();
        self.view_cache.clear();
        self.inline_cache.clear();
    }
    fn chunk(&mut self, id: usize) -> Res<&[u8]> {
        let cache = if id < self.pool_count {
            &mut self.pool_cache
        } else {
            &mut self.program_cache
        };
        if let Some(pos) = cache.entries.iter().position(|(i, _)| *i == id) {
            let e = cache.entries.remove(pos).ok_or("cache")?;
            cache.entries.push_back(e);
        } else {
            let c = self.chunks.get(id).ok_or("chunk id")?;
            let mut z = vec![0; c.length];
            self.file
                .seek(std::io::SeekFrom::Start(c.offset))
                .map_err(er)?;
            self.file.read_exact(&mut z).map_err(er)?;
            self.bytes_read += z.len() as u64;
            self.chunks_read += 1;
            if sha512_half(&z) != c.hash {
                return Err("chunk checksum".into());
            }
            let raw = if id < self.pool_count {
                zstd::bulk::decompress(&z, c.raw).map_err(er)?
            } else {
                zstd::bulk::Decompressor::with_dictionary(&self.dictionary)
                    .map_err(er)?
                    .decompress(&z, c.raw)
                    .map_err(er)?
            };
            if raw.len() != c.raw {
                return Err("chunk length".into());
            }
            let raw = if id >= self.pool_count && self.column_programs {
                capsule::decode(&raw, self.shapes.as_ref().ok_or("column shapes")?)?
            } else {
                raw
            };
            if cache.entries.len() == cache.limit {
                cache.entries.pop_front();
            }
            cache.entries.push_back((id, raw));
        }
        Ok(&cache.entries.back().ok_or("cache empty")?.1)
    }
    fn literal(&mut self, id: usize) -> Res<Vec<u8>> {
        let i = self
            .groups
            .partition_point(|g| g.first <= id)
            .checked_sub(1)
            .ok_or("literal id")?;
        let g = &self.groups[i];
        if id >= g.first + g.count {
            return Err("literal extent".into());
        }
        let mut at = g.offset + (id - g.first) * g.width;
        let mut remain = g.width;
        let der = g.der;
        let mut out = Vec::with_capacity(remain);
        while remain > 0 {
            let chunk = at / self.pool_chunk;
            let off = at % self.pool_chunk;
            let n = remain.min(self.pool_chunk - off);
            let raw = self.chunk(chunk)?;
            out.extend(raw.get(off..off + n).ok_or("literal span")?);
            at += n;
            remain -= n;
        }
        if der {
            Ok(k256::ecdsa::Signature::from_slice(&out)
                .map_err(er)?
                .to_der()
                .as_bytes()
                .to_vec())
        } else {
            Ok(out)
        }
    }
    fn key(&mut self, id: usize) -> Res<[u8; 32]> {
        if let Some(h) = self.key_hashes.get(&id) {
            return Ok(*h);
        }
        let k = self.keys.get(id).ok_or("key id")?.clone();
        let mut pre = vec![0, k.domain];
        for arg in k.args {
            let b = self.literal(arg)?;
            if ![4, 20].contains(&b.len()) {
                return Err("key argument width".into());
            }
            pre.extend(b)
        }
        let hash = sha512_half(&pre);
        if self.key_hashes.len() >= 4096 {
            self.key_hashes.clear();
        }
        self.key_hashes.insert(id, hash);
        Ok(hash)
    }
    fn tx_doc(&self, ordinal: usize) -> Res<usize> {
        let i = self
            .layout
            .partition_point(|l| l.first_tx <= ordinal)
            .checked_sub(1)
            .ok_or("TX ordinal")?;
        let l = &self.layout[i];
        if ordinal >= l.first_tx + l.txs {
            return Err("TX extent".into());
        }
        Ok(l.first_doc + 1 + 2 * (ordinal - l.first_tx))
    }
    fn program(&mut self, id: usize) -> Res<Vec<u64>> {
        if id >= self.doc_count {
            return Err("document id".into());
        }
        let chunk = self.pool_count + id / self.docs_per_chunk;
        let nth = id % self.docs_per_chunk;
        let (start, count) =
            if let Some(pos) = self.program_offsets.iter().position(|(c, _)| *c == chunk) {
                let entry = self.program_offsets.remove(pos).ok_or("program offsets")?;
                let span = *entry.1.get(nth).ok_or("document extent")?;
                self.program_offsets.push_back(entry);
                span
            } else {
                let data = self.chunk(chunk)?;
                let mut r = Read::new(data);
                let n = r.count()?;
                let mut spans = Vec::new();
                for _ in 0..n {
                    let count = r.count()?;
                    spans.push((r.p, count));
                    for _ in 0..count {
                        r.var()?;
                    }
                }
                r.end()?;
                let span = *spans.get(nth).ok_or("document extent")?;
                if self.program_offsets.len() == 16 {
                    self.program_offsets.pop_front();
                }
                self.program_offsets.push_back((chunk, spans));
                span
            };
        let data = self.chunk(chunk)?;
        let mut r = Read::new(data.get(start..).ok_or("program offset")?);
        (0..count).map(|_| r.var()).collect()
    }
    /// Covered input window. This does not establish an initial state snapshot.
    pub fn coverage(&self) -> Res<(u32, u32)> {
        Ok((
            self.layout.first().ok_or("empty archive")?.seq,
            self.layout.last().ok_or("empty archive")?.seq,
        ))
    }
    pub fn ledger_count(&self) -> usize {
        self.layout.len()
    }
    fn emit(&mut self, op: u64, is_tx: bool, out: &mut Vec<u8>) -> Res<()> {
        let n = usize::try_from(op >> 2).map_err(er)?;
        match op & 3 {
            0 => out.extend(self.literal(n)?),
            1 => {
                if is_tx {
                    return Err("recursive TX reference".into());
                }
                let h = if let Some(h) = self.tx_hashes.get(&n) {
                    *h
                } else {
                    let d = self.tx_doc(n)?;
                    let b = self.document(d, true)?;
                    let h = shamap::tx_id(&b);
                    if self.tx_hashes.len() >= 4096 {
                        self.tx_hashes.clear();
                    }
                    self.tx_hashes.insert(n, h);
                    h
                };
                out.extend(h)
            }
            2 => out.extend(self.key(n)?),
            3 if self.shared_programs && !is_tx => out.extend(self.document(n, false)?),
            _ => return Err("opcode".into()),
        }
        if out.len() > MAX {
            return Err("expanded document limit".into());
        }
        Ok(())
    }
    fn render_tree(
        &mut self,
        ops: &[u64],
        at: &mut usize,
        is_tx: bool,
        out: &mut Vec<u8>,
        depth: usize,
    ) -> Res<()> {
        if depth > 64 {
            return Err("tree depth".into());
        }
        let id = *ops.get(*at).ok_or("tree template")? as usize;
        *at += 1;
        let shape = self
            .shapes
            .as_ref()
            .ok_or("templates")?
            .get(id)
            .ok_or("template id")?
            .clone();
        for step in shape {
            match step {
                Shape::Fixed(b) => {
                    if out.len().checked_add(b.len()).is_none_or(|n| n > MAX) {
                        return Err("fixed output limit".into());
                    }
                    out.extend(b);
                }
                Shape::Value => {
                    let op = *ops.get(*at).ok_or("tree value")?;
                    *at += 1;
                    if self.numeric_fields && op == NUMERIC_VALUE && !is_tx {
                        let width =
                            usize::try_from(*ops.get(*at).ok_or("numeric width")?).map_err(er)?;
                        let value = *ops.get(*at + 1).ok_or("numeric value")?;
                        *at += 2;
                        if ![4, 8].contains(&width) || (width == 4 && value > u32::MAX as u64) {
                            return Err("numeric width or value".into());
                        }
                        out.extend(&value.to_be_bytes()[8 - width..]);
                    } else {
                        self.emit(op, is_tx, out)?;
                    }
                }
                Shape::Child => self.render_tree(ops, at, is_tx, out, depth + 1)?,
            }
        }
        Ok(())
    }
    fn inline_view(&mut self, id: usize, depth: usize) -> Res<InlineView> {
        if depth > self.view_depth_limit {
            return Err("inline chain depth".into());
        }
        if let Some((height, fields)) = self.inline_cache.get(&id) {
            if depth + height > self.view_depth_limit {
                return Err("cached inline chain depth".into());
            }
            return Ok((*height, fields.clone()));
        }
        let ops = self.program(id)?;
        if ops.len() < 4 || ops[0] != shared::VIEW {
            return Err("inline view marker".into());
        }
        let schema_id = usize::try_from(ops[1]).map_err(er)?;
        let schema = self.schemas.get(schema_id).ok_or("inline schema")?.clone();
        let shapes = self.field_shapes[schema_id].clone();
        let stored_base = usize::try_from(ops[2]).map_err(er)?;
        let base = if self.compact_fields && stored_base != 0 {
            id.checked_sub(stored_base).ok_or("compact base gap")? + 1
        } else {
            stored_base
        };
        let mut at = 4;
        let mask = if self.compact_fields && ops[3] & 1 != 0 {
            Some(ops[3] >> 1)
        } else {
            None
        };
        if let Some(mask) = mask
            && schema.len() < 64
            && mask >> schema.len() != 0
        {
            return Err("compact edit mask".into());
        }
        let n = if self.compact_fields {
            if let Some(mask) = mask {
                mask.count_ones() as usize
            } else {
                if ops[3] != 0 {
                    return Err("compact escape".into());
                }
                at += 1;
                usize::try_from(*ops.get(4).ok_or("compact edit count")?).map_err(er)?
            }
        } else {
            usize::try_from(ops[3]).map_err(er)?
        };
        if n > schema.len() {
            return Err("inline edit count".into());
        }
        let (height, old) = if base != 0 {
            if base > id {
                return Err("inline base order".into());
            }
            let (height, fields) = self.inline_view(base - 1, depth + 1)?;
            (
                height + 1,
                fields
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
        } else {
            (0, std::collections::BTreeMap::new())
        };
        let mut fields: Vec<_> = schema.iter().map(|key| old.get(key).cloned()).collect();
        let mut previous = None;
        let mut bits = mask.unwrap_or(0);
        for _ in 0..n {
            let slot = if mask.is_some() {
                let slot = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                slot
            } else {
                let slot = usize::try_from(*ops.get(at).ok_or("inline slot")?).map_err(er)?;
                at += 1;
                slot
            };
            if slot >= schema.len() || previous.is_some_and(|p| p >= slot) {
                return Err("inline slot order".into());
            }
            previous = Some(slot);
            let shape = shapes[slot];
            let count = self.shapes.as_ref().ok_or("inline plans")?[shape]
                .iter()
                .filter(|x| matches!(x, Shape::Value))
                .count();
            let mut program = vec![shape as u64];
            let tokens = ops.get(at..at + count).ok_or("inline values")?;
            at += count;
            for (value_pos, &encoded) in tokens.iter().enumerate() {
                if self.numeric_fields && encoded & 1 != 0 {
                    if count != 1 {
                        return Err("numeric field arity".into());
                    }
                    let width = if encoded & 2 == 0 { 4 } else { 8 };
                    let ty = schema[slot] >> 16;
                    if !((ty == 2 && width == 4) || ([3, 6].contains(&ty) && width == 8)) {
                        return Err("numeric field type".into());
                    }
                    let previous = fields[slot]
                        .as_ref()
                        .filter(|p| p[0] == shape as u64)
                        .ok_or("numeric field base")?;
                    let old = if previous.len() == 4 && previous[1] == NUMERIC_VALUE {
                        if previous[2] != width as u64 {
                            return Err("numeric base width".into());
                        }
                        previous[3]
                    } else if previous.len() == 2 && previous[1] & 3 == 0 {
                        let token = previous[1];
                        let b = self.literal(usize::try_from(token >> 2).map_err(er)?)?;
                        if b.len() != width {
                            return Err("numeric literal width".into());
                        }
                        let mut v = [0u8; 8];
                        v[8 - width..].copy_from_slice(&b);
                        u64::from_be_bytes(v)
                    } else {
                        return Err("numeric base representation".into());
                    };
                    let zz = encoded >> 2;
                    let diff = ((zz >> 1) as i64) ^ (-((zz & 1) as i64));
                    let value = if width == 4 {
                        (old as u32).wrapping_add(diff as u32) as u64
                    } else {
                        old.wrapping_add(diff as u64)
                    };
                    program.extend([NUMERIC_VALUE, width as u64, value]);
                    continue;
                }
                let token = if !self.compact_fields {
                    encoded
                } else if encoded & 1 == 0 {
                    encoded >> 1
                } else {
                    let previous = fields[slot]
                        .as_ref()
                        .filter(|p| p[0] == shape as u64)
                        .and_then(|p| p.get(value_pos + 1))
                        .ok_or("compact delta base")?;
                    let zz = encoded >> 1;
                    let delta = ((zz >> 1) as i64) ^ (-((zz & 1) as i64));
                    let token = i128::from(*previous) + i128::from(delta);
                    u64::try_from(token).map_err(er)?
                };
                if token & 3 == 3 {
                    return Err("shared reference inside inline field".into());
                }
                program.push(token);
            }
            fields[slot] = Some(program);
        }
        if at != ops.len() {
            return Err("inline trailing values".into());
        }
        let fields = schema
            .into_iter()
            .zip(fields)
            .enumerate()
            .map(|(i, (key, value))| {
                let value = value.ok_or("missing inline field")?;
                if value.first() != Some(&(shapes[i] as u64)) {
                    return Err("inline inherited shape mismatch".into());
                }
                Ok((key, value))
            })
            .collect::<Res<Vec<_>>>()?;
        if self.inline_cache.len() >= 128 {
            self.inline_cache.clear();
        }
        self.inline_cache.insert(id, (height, fields.clone()));
        Ok((height, fields))
    }
    fn view_fields(&mut self, id: usize, depth: usize) -> Res<(usize, Vec<(u32, usize)>)> {
        if depth > self.view_depth_limit {
            return Err("view chain depth".into());
        }
        if let Some((height, v)) = self.view_cache.get(&id) {
            if depth + height > self.view_depth_limit {
                return Err("cached view chain depth".into());
            }
            return Ok((*height, v.clone()));
        }
        let ops = self.program(id)?;
        if ops.len() < 4 || ops[0] != shared::VIEW {
            return Err("expected view".into());
        }
        let schema = self
            .schemas
            .get(usize::try_from(ops[1]).map_err(er)?)
            .ok_or("view schema")?
            .clone();
        let base = usize::try_from(ops[2]).map_err(er)?;
        let n = usize::try_from(ops[3]).map_err(er)?;
        if n > schema.len() || ops.len() != 4 + 2 * n {
            return Err("view edit count".into());
        }
        let (height, old) = if base != 0 {
            if base > id {
                return Err("view base must precede view".into());
            }
            let (height, fields) = self.view_fields(base - 1, depth + 1)?;
            (
                height + 1,
                fields
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
        } else {
            (0, std::collections::BTreeMap::new())
        };
        let mut fields: Vec<_> = schema.iter().map(|key| old.get(key).copied()).collect();
        let mut previous = None;
        for edit in ops[4..].as_chunks::<2>().0 {
            let slot = usize::try_from(edit[0]).map_err(er)?;
            let field = usize::try_from(edit[1]).map_err(er)?;
            if slot >= fields.len() || previous.is_some_and(|p| p >= slot) || field >= id {
                return Err("view edit extent or order".into());
            }
            previous = Some(slot);
            fields[slot] = Some(field);
        }
        let fields = schema
            .into_iter()
            .zip(fields)
            .map(|(key, field)| Ok((key, field.ok_or("missing view field")?)))
            .collect::<Res<Vec<_>>>()?;
        if self.view_cache.len() >= 128 {
            self.view_cache.clear();
        }
        self.view_cache.insert(id, (height, fields.clone()));
        Ok((height, fields))
    }
    fn document(&mut self, id: usize, is_tx: bool) -> Res<Vec<u8>> {
        if self.document_depth >= 64 {
            return Err("document reference depth".into());
        }
        self.document_depth += 1;
        let result = self.document_inner(id, is_tx);
        self.document_depth -= 1;
        result
    }
    fn document_inner(&mut self, id: usize, is_tx: bool) -> Res<Vec<u8>> {
        let ops = self.program(id)?;
        let mut out = vec![];
        if self.shared_programs && ops.first() == Some(&shared::VIEW) {
            if is_tx {
                return Err("view in TX document".into());
            }
            if self.inline_fields {
                for (_, program) in self.inline_view(id, 0)?.1 {
                    let mut at = 0;
                    self.render_tree(&program, &mut at, false, &mut out, 0)?;
                    if at != program.len() || out.len() > MAX {
                        return Err("inline expanded program".into());
                    }
                }
            } else {
                for (_, field) in self.view_fields(id, 0)?.1 {
                    out.extend(self.document(field, false)?);
                    if out.len() > MAX {
                        return Err("view output limit".into());
                    }
                }
            }
        } else if self.tree_programs {
            let mut at = 0;
            self.render_tree(&ops, &mut at, is_tx, &mut out, 0)?;
            if at != ops.len() {
                return Err("extra tree tokens".into());
            }
        } else if let Some(shapes) = &self.shapes {
            let id = *ops.first().ok_or("shape id")? as usize;
            let shape = shapes.get(id).ok_or("shape id")?.clone();
            let mut i = 1;
            for step in shape {
                match step {
                    Shape::Fixed(b) => {
                        if out.len().checked_add(b.len()).is_none_or(|n| n > MAX) {
                            return Err("fixed output limit".into());
                        }
                        out.extend(b);
                    }
                    Shape::Value => {
                        self.emit(*ops.get(i).ok_or("missing value")?, is_tx, &mut out)?;
                        i += 1;
                    }
                    Shape::Child => return Err("child in flat shape".into()),
                }
            }
            if i != ops.len() {
                return Err("extra values".into());
            }
        } else {
            for op in ops {
                self.emit(op, is_tx, &mut out)?;
            }
        }
        Ok(out)
    }

    pub fn tx(&mut self, ordinal: usize) -> Res<(Vec<u8>, Vec<u8>)> {
        let d = self.tx_doc(ordinal)?;
        Ok((self.document(d, true)?, self.document(d + 1, false)?))
    }
    /// Fetches every TX leaf in the ledger, builds and verifies the proof against its stored header.
    /// Authenticating that header is the caller's responsibility.
    pub fn proof_tx(&mut self, ordinal: usize) -> Res<TransactionProof> {
        self.tx_doc(ordinal)?;
        let i = self.layout.partition_point(|l| l.first_tx <= ordinal) - 1;
        let l = self.layout[i].clone();
        let header = self.document(l.first_doc, false)?;
        let parsed = LedgerHeader::parse(&header).map_err(er)?;
        let mut leaves = vec![];
        let mut chosen = None;
        for j in 0..l.txs {
            let (tx, meta) = self.tx(l.first_tx + j)?;
            let id = shamap::tx_id(&tx);
            leaves.push((id, shamap::tx_leaf_hash(&tx, &meta, &id)));
            if l.first_tx + j == ordinal {
                chosen = Some((tx, meta, id));
            }
        }
        if shamap::has_duplicates(&leaves) || shamap::root(&leaves) != parsed.transaction_hash {
            return Err("proof ledger root".into());
        }
        let (tx, meta, id) = chosen.ok_or("proof TX")?;
        let path = shamap::prove(&leaves, &id).ok_or("proof path")?;
        if !shamap::verify(
            &path,
            &id,
            &shamap::tx_leaf_hash(&tx, &meta, &id),
            &parsed.transaction_hash,
        ) {
            return Err("proof verification".into());
        }
        Ok(TransactionProof {
            header,
            tx,
            meta,
            path,
        })
    }
    pub fn patch(&mut self, ordinal: usize) -> Res<([u8; 32], Vec<u8>)> {
        let i = self
            .layout
            .partition_point(|l| l.first_patch <= ordinal)
            .checked_sub(1)
            .ok_or("patch ordinal")?;
        let l = &self.layout[i];
        if ordinal >= l.first_patch + l.patches {
            return Err("patch extent".into());
        }
        let d = l.first_doc + 1 + 2 * l.txs + 2 * (ordinal - l.first_patch);
        Ok((
            self.document(d, false)?
                .try_into()
                .map_err(|_| "key width")?,
            self.document(d + 1, false)?,
        ))
    }
    pub fn row(&mut self, index: usize) -> Res<Row> {
        let l = self.layout.get(index).ok_or("ledger index")?.clone();
        let header = self.document(l.first_doc, false)?;
        let mut txs = vec![];
        let mut patches = vec![];
        for i in 0..l.txs {
            txs.push(self.tx(l.first_tx + i)?)
        }
        for i in 0..l.patches {
            patches.push(self.patch(l.first_patch + i)?)
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
    pub fn components(&self) -> std::collections::BTreeMap<&'static str, usize> {
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "pool_frames",
            self.chunks[..self.pool_count]
                .iter()
                .map(|c| c.length)
                .sum(),
        );
        m.insert(
            "program_frames",
            self.chunks[self.pool_count..]
                .iter()
                .map(|c| c.length)
                .sum(),
        );
        m.insert(
            "metadata_and_directory",
            self.chunks.first().map_or(0, |c| c.offset as usize),
        );
        m
    }
    pub fn memory_bytes(&self) -> usize {
        self.field_shapes.capacity() * 24
            + self
                .field_shapes
                .iter()
                .map(|v| v.capacity() * 8)
                .sum::<usize>()
            + self.inline_cache.capacity() * 40
            + self
                .inline_cache
                .values()
                .map(|(_, v)| {
                    v.capacity() * 32 + v.iter().map(|(_, p)| p.capacity() * 8).sum::<usize>()
                })
                .sum::<usize>()
            + self.schemas.capacity() * 24
            + self.schemas.iter().map(|s| s.capacity() * 4).sum::<usize>()
            + self.view_cache.capacity() * 40
            + self
                .view_cache
                .values()
                .map(|(_, v)| v.capacity() * std::mem::size_of::<(u32, usize)>())
                .sum::<usize>()
            + self.shapes.as_ref().map_or(0, |ss| {
                ss.capacity() * 24
                    + ss.iter()
                        .map(|s| {
                            s.capacity() * std::mem::size_of::<Shape>()
                                + s.iter()
                                    .map(|x| match x {
                                        Shape::Fixed(b) => b.capacity(),
                                        Shape::Value | Shape::Child => 0,
                                    })
                                    .sum::<usize>()
                        })
                        .sum::<usize>()
            })
            + self.groups.capacity() * std::mem::size_of::<Group>()
            + self.keys.capacity() * std::mem::size_of::<Key>()
            + self
                .keys
                .iter()
                .map(|k| k.args.capacity() * 8)
                .sum::<usize>()
            + self.layout.capacity() * std::mem::size_of::<Location>()
            + self.chunks.capacity() * std::mem::size_of::<Chunk>()
            + self.dictionary.capacity()
            + self.pool_cache.bytes()
            + self.program_cache.bytes()
            + self.program_offsets.capacity() * std::mem::size_of::<(usize, Vec<(usize, usize)>)>()
            + self
                .program_offsets
                .iter()
                .map(|(_, v)| v.capacity() * 2 * std::mem::size_of::<usize>())
                .sum::<usize>()
            + (self.key_hashes.capacity() + self.tx_hashes.capacity()) * 48
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_capsules_preserve_unknown_fields_tombstones_and_high_s() {
        let mut high_s = [0u8; 32];
        high_s[0] = 0x80;
        let der = k256::ecdsa::Signature::from_scalars([1; 32], high_s)
            .unwrap()
            .to_der()
            .as_bytes()
            .to_vec();
        let mut tx = vec![0x74, der.len() as u8];
        tx.extend(der);
        tx.extend([0x81, 0]);
        let row = Row {
            seq: 1,
            header: vec![0; 118],
            txs: vec![(tx, vec![0xff, 1, 2, 3])],
            patches: vec![([2; 32], vec![]), ([3; 32], vec![0x81, 0])],
        };
        let (frame, _) = encode_block(
            std::slice::from_ref(&row),
            Options {
                split_shapes: true,
                context_delta: true,
                ..Options::default()
            },
        )
        .unwrap();
        let prepared = Prepared::parse(&frame).unwrap();
        let mut archive = pack(&prepared, 256, 3).unwrap();
        let path = std::env::temp_dir().join(format!("asts-test-{}.asts", std::process::id()));
        std::fs::write(&path, &archive).unwrap();
        let mut reader = Reader::open(&path).unwrap();
        assert_eq!(reader.tx(0).unwrap(), row.txs[0]);
        reader.clear_data_cache();
        assert_eq!(reader.all_rows().unwrap(), vec![row]);
        let last = archive.len() - 1;
        archive[last] ^= 1;
        std::fs::write(&path, &archive).unwrap();
        assert!(Reader::open(&path).unwrap().all_rows().is_err());
        archive.truncate(40);
        std::fs::write(&path, &archive).unwrap();
        assert!(Reader::open(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod shared_corruption_tests {
    use super::*;
    #[test]
    fn invalid_view_graphs_and_cached_depth_are_rejected() {
        let rows = shared::tests::fixture();
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
        let path = std::env::temp_dir().join(format!("asts-shared-corrupt-{}", std::process::id()));
        for mode in 0..4 {
            let inline = mode != 0;
            let archive = if mode == 3 {
                pack_shared_numeric(&p, &rows, 256, 3, 8, 0)
            } else if mode == 2 {
                pack_shared_compact(&p, &rows, 256, 3, 8, 0, true)
            } else if inline {
                pack_shared_inline(&p, &rows, 256, 3, 8)
            } else {
                pack_shared(&p, &rows, 256, 3, 8)
            }
            .unwrap()
            .0;
            std::fs::write(&path, archive).unwrap();
            let mut r = Reader::open(&path).unwrap();
            let mut checked = false;
            for id in 0..r.doc_count {
                let ops = r.program(id).unwrap();
                if ops.first() == Some(&shared::VIEW) && ops[2] != 0 {
                    // Prime cache at a permissive limit, then ensure cache cannot bypass a stricter one.
                    if inline {
                        r.inline_view(id, 0).unwrap();
                    } else {
                        r.view_fields(id, 0).unwrap();
                    }
                    r.view_depth_limit = 0;
                    if inline {
                        assert!(r.inline_view(id, 0).is_err());
                    } else {
                        assert!(r.view_fields(id, 0).is_err());
                    }
                    checked = true;
                    break;
                }
            }
            assert!(checked);
        }
        let mut j = shared::build(&p, &rows, 8).unwrap();
        let id = j
            .programs
            .iter()
            .position(|x| matches!(x, shared::Program::View(_)))
            .unwrap();
        let shared::Program::View(view) = &mut j.programs[id] else {
            unreachable!()
        };
        view.base = Some(id);
        let archive = pack_inner(&p, 256, 3, Some(&j), Packing::Shared).unwrap();
        std::fs::write(&path, archive).unwrap();
        let mut r = Reader::open(&path).unwrap();
        assert!(r.document(id, false).is_err());
        // A valid-checksum archive containing an arbitrary document-reference cycle.
        let wrapper = j.plans.len();
        j.plans.push(vec![PlanOp::Value]);
        j.programs[0] = shared::Program::Tree(vec![
            fast::Atom {
                at: wrapper as u32,
                len: NODE,
            },
            fast::Atom {
                at: 0,
                len: shared::SHARED,
            },
        ]);
        std::fs::write(
            &path,
            pack_inner(&p, 256, 3, Some(&j), Packing::Shared).unwrap(),
        )
        .unwrap();
        let mut r = Reader::open(&path).unwrap();
        assert!(r.document(0, false).is_err());
        assert_eq!(r.document_depth, 0);
        std::fs::remove_file(path).unwrap();
    }
}
