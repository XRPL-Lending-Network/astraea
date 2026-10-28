//! astraea-deltabench: how much space state changes take if they are
//! stored not as full objects but as a diff against the previous version.
//!
//! Full objects are the baseline form;
//! a replacement is acceptable only if every object is restored byte for
//! byte. That is what is checked here: any variant that produces even one wrong
//! object stops the measurement.
//!
//! Variants (all in blocks of 128 ledgers, zstd-19, like the format 2 change
//! stream):
//! - the full object after the change (current layout);
//! - a per-field STObject diff against the previous version: changed and new fields
//!   in full, removed ones by field code;
//! - zstd patch-from: each object is compressed with the previous version as the
//!   reference, frames back to back;
//! - metadata and residual: the object is built from the previous version and the fields
//!   of the last transaction that touched it (NewFields for a created one,
//!   FinalFields for a modified one; LedgerEntryType; PreviousTxnID and
//!   PreviousTxnLgrSeq pointing to that transaction), and only the difference between
//!   the built object and the real one is stored. No protocol logic: whatever the
//!   metadata lacks goes into the residual.
//!
//! The previous version is taken from the state store (a copy while the loader
//! is running, since it holds the store open).

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use ledger_engine::history::HistoryReader;
use ledger_engine::ledger::{Change, Ledger};
use ledger_engine::state::StateStore;
use witness_core::stobject;
use zstd::zstd_safe;

#[derive(Debug, Parser)]
struct Args {
    /// Format 2 history directory.
    history: PathBuf,
    /// Copy of the state store.
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    from: u32,
    #[arg(long, default_value_t = 2048)]
    ledgers: u32,
}

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

fn put_u16(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u16).to_le_bytes());
}

/// Field diff: (count of changed and new fields, their raw fields back to back), (count
/// of removed fields, their type and field codes).
fn field_diff(prev: &[u8], new: &[u8]) -> Res<Vec<u8>> {
    let p = stobject::fields(prev).map_err(e)?;
    let n = stobject::fields(new).map_err(e)?;
    let mut changed = Vec::new();
    let mut count = 0;
    for f in &n {
        if !p.iter().any(|x| x.id == f.id && x.raw == f.raw) {
            changed.extend_from_slice(f.raw);
            count += 1;
        }
    }
    let removed: Vec<_> = p
        .iter()
        .filter(|x| !n.iter().any(|f| f.id == x.id))
        .collect();
    let mut out = Vec::with_capacity(changed.len() + 8);
    put_u16(&mut out, count);
    put_u16(&mut out, changed.len());
    out.extend_from_slice(&changed);
    put_u16(&mut out, removed.len());
    for r in removed {
        put_u16(&mut out, usize::from(r.id.type_code));
        put_u16(&mut out, usize::from(r.id.field_code));
    }
    Ok(out)
}

/// Object from the previous version and a diff: fields in canonical XRPL order
/// (type code, then field code).
fn apply_diff(prev: &[u8], diff: &[u8]) -> Res<Vec<u8>> {
    let u16_at = |at: usize| -> Res<usize> {
        Ok(usize::from(u16::from_le_bytes(
            diff.get(at..at + 2)
                .ok_or("diff truncated")?
                .try_into()
                .map_err(e)?,
        )))
    };
    let len = u16_at(2)?;
    let changed_raw = diff.get(4..4 + len).ok_or("diff truncated")?;
    let changed = stobject::fields(changed_raw).map_err(e)?;
    let mut at = 4 + len;
    let nrem = u16_at(at)?;
    at += 2;
    let mut removed = Vec::new();
    for _ in 0..nrem {
        removed.push((u16_at(at)? as u16, u16_at(at + 2)? as u16));
        at += 4;
    }
    let p = stobject::fields(prev).map_err(e)?;
    let mut all: Vec<(u16, u16, &[u8])> = p
        .iter()
        .filter(|x| {
            !removed.contains(&(x.id.type_code, x.id.field_code))
                && !changed.iter().any(|c| c.id == x.id)
        })
        .map(|x| (x.id.type_code, x.id.field_code, x.raw))
        .collect();
    all.extend(
        changed
            .iter()
            .map(|c| (c.id.type_code, c.id.field_code, c.raw)),
    );
    all.sort_by_key(|(t, f, _)| (*t, *f));
    Ok(all
        .into_iter()
        .flat_map(|(_, _, r)| r.iter().copied())
        .collect())
}

const AFFECTED_NODES: (u16, u16) = (15, 8);
const CREATED: (u16, u16) = (14, 3);
const FINAL_FIELDS: (u16, u16) = (14, 7);
const NEW_FIELDS: (u16, u16) = (14, 8);
const LEDGER_INDEX: (u16, u16) = (5, 6);
const LEDGER_ENTRY_TYPE: (u16, u16) = (1, 1);
const TX_INDEX: (u16, u16) = (2, 28);

fn id(f: &stobject::Field<'_>) -> (u16, u16) {
    (f.id.type_code, f.id.field_code)
}

/// For each object touched by the ledger's transactions, the last
/// transaction that touched it: its hash, fields (NewFields or FinalFields) and
/// LedgerEntryType.
type Touch = ([u8; 32], Vec<u8>, Vec<u8>);

fn touches(l: &Ledger) -> Res<std::collections::HashMap<[u8; 32], Touch>> {
    let mut order: Vec<(u32, &[u8], &[u8])> = Vec::new();
    for (tx, meta) in &l.transactions {
        let f = stobject::fields(meta).map_err(e)?;
        let idx = f
            .iter()
            .find(|x| id(x) == TX_INDEX)
            .and_then(|x| stobject::u32_of(x.value))
            .ok_or("no TransactionIndex")?;
        order.push((idx, tx, meta));
    }
    order.sort_by_key(|o| o.0);
    let mut out = std::collections::HashMap::new();
    for (_, tx, meta) in order {
        let txid = witness_core::shamap::tx_id(tx);
        let f = stobject::fields(meta).map_err(e)?;
        let Some(nodes) = f.iter().find(|x| id(x) == AFFECTED_NODES) else {
            continue;
        };
        for node in stobject::children(nodes).map_err(e)? {
            let inner = stobject::children(&node).map_err(e)?;
            let Some(key) = inner
                .iter()
                .find(|x| id(x) == LEDGER_INDEX)
                .and_then(|x| <[u8; 32]>::try_from(x.value).ok())
            else {
                continue;
            };
            let want = if id(&node) == CREATED {
                NEW_FIELDS
            } else {
                FINAL_FIELDS
            };
            let fields = inner
                .iter()
                .find(|x| id(x) == want)
                .map(|x| x.value.to_vec())
                .unwrap_or_default();
            let let_raw = inner
                .iter()
                .find(|x| id(x) == LEDGER_ENTRY_TYPE)
                .map(|x| x.raw.to_vec())
                .unwrap_or_default();
            out.insert(key, (txid, fields, let_raw));
        }
    }
    Ok(out)
}

/// Object built from the previous version and the transaction's fields.
fn candidate(prev: Option<&[u8]>, t: &Touch, seq: u32) -> Res<Vec<u8>> {
    let mut all: Vec<((u16, u16), Vec<u8>)> = match prev {
        Some(p) => stobject::fields(p)
            .map_err(e)?
            .iter()
            .map(|x| (id(x), x.raw.to_vec()))
            .collect(),
        None => Vec::new(),
    };
    let mut set = |k: (u16, u16), raw: Vec<u8>| {
        all.retain(|(i, _)| *i != k);
        all.push((k, raw));
    };
    for x in stobject::fields(&t.1).map_err(e)? {
        set(id(&x), x.raw.to_vec());
    }
    if !t.2.is_empty() {
        set(LEDGER_ENTRY_TYPE, t.2.clone());
    }
    let mut txid = vec![0x55];
    txid.extend_from_slice(&t.0);
    set((5, 5), txid);
    let mut lseq = vec![0x25];
    lseq.extend_from_slice(&seq.to_be_bytes());
    set((2, 5), lseq);
    // Flags is required on every state object; a zero value is not included
    // in NewFields.
    if !all.iter().any(|(k, _)| *k == (2, 2)) {
        all.push(((2, 2), vec![0x22, 0, 0, 0, 0]));
    }
    all.sort_by_key(|(k, _)| *k);
    Ok(all.into_iter().flat_map(|(_, r)| r).collect())
}

/// Field header: type and field codes in one to three bytes.
fn field_header(t: u16, f: u16) -> Vec<u8> {
    let mut h =
        vec![(if t < 16 { (t as u8) << 4 } else { 0 }) | (if f < 16 { f as u8 } else { 0 })];
    if t >= 16 {
        h.push(t as u8);
    }
    if f >= 16 {
        h.push(f as u8);
    }
    h
}

/// Edit of a list of 32-byte items: positions removed from the old list and
/// items added (position in the new list, item). `None` if the order changed some other way.
fn vector_patch(old: &[u8], new: &[u8]) -> Option<Vec<u8>> {
    let (o, n): (Vec<&[u8]>, Vec<&[u8]>) = (old.chunks(32).collect(), new.chunks(32).collect());
    let removed: Vec<usize> = (0..o.len()).filter(|i| !n.contains(&o[*i])).collect();
    let inserted: Vec<usize> = (0..n.len()).filter(|j| !o.contains(&n[*j])).collect();
    let kept_old: Vec<&[u8]> = (0..o.len())
        .filter(|i| !removed.contains(i))
        .map(|i| o[i])
        .collect();
    let kept_new: Vec<&[u8]> = (0..n.len())
        .filter(|j| !inserted.contains(j))
        .map(|j| n[j])
        .collect();
    if kept_old != kept_new {
        return None;
    }
    let mut out = Vec::new();
    put_u16(&mut out, removed.len());
    for i in removed {
        put_u16(&mut out, i);
    }
    put_u16(&mut out, inserted.len());
    for j in inserted {
        put_u16(&mut out, j);
        out.extend_from_slice(n[j]);
    }
    Some(out)
}

/// Diff v2: like `field_diff`, but changed Vector256 lists are stored as an edit against
/// the previous value when that is shorter.
fn field_diff2(prev: &[u8], new: &[u8]) -> Res<Vec<u8>> {
    let p = stobject::fields(prev).map_err(e)?;
    let n = stobject::fields(new).map_err(e)?;
    let (mut changed, mut count, mut patches, mut npatch) = (Vec::new(), 0, Vec::new(), 0);
    for f in &n {
        let old = p.iter().find(|x| x.id == f.id);
        if old.is_some_and(|x| x.raw == f.raw) {
            continue;
        }
        if f.id.type_code == stobject::types::VECTOR256
            && let Some(o) = old
            && let Some(vp) = vector_patch(o.value, f.value)
            && vp.len() + 2 < f.raw.len()
        {
            put_u16(&mut patches, usize::from(f.id.field_code));
            patches.extend_from_slice(&vp);
            npatch += 1;
            continue;
        }
        changed.extend_from_slice(f.raw);
        count += 1;
    }
    let removed: Vec<_> = p
        .iter()
        .filter(|x| !n.iter().any(|f| f.id == x.id))
        .collect();
    let mut out = Vec::with_capacity(changed.len() + patches.len() + 8);
    put_u16(&mut out, count);
    put_u16(&mut out, changed.len());
    out.extend_from_slice(&changed);
    put_u16(&mut out, npatch);
    out.extend_from_slice(&patches);
    put_u16(&mut out, removed.len());
    for r in removed {
        put_u16(&mut out, usize::from(r.id.type_code));
        put_u16(&mut out, usize::from(r.id.field_code));
    }
    Ok(out)
}

fn apply_diff2(prev: &[u8], diff: &[u8]) -> Res<Vec<u8>> {
    let u16_at = |at: usize| -> Res<usize> {
        Ok(usize::from(u16::from_le_bytes(
            diff.get(at..at + 2)
                .ok_or("diff truncated")?
                .try_into()
                .map_err(e)?,
        )))
    };
    let len = u16_at(2)?;
    let changed = stobject::fields(diff.get(4..4 + len).ok_or("diff truncated")?).map_err(e)?;
    let mut at = 4 + len;
    let p = stobject::fields(prev).map_err(e)?;
    let mut rebuilt: Vec<(u16, u16, Vec<u8>)> = Vec::new();
    let npatch = u16_at(at)?;
    at += 2;
    for _ in 0..npatch {
        let fcode = u16_at(at)? as u16;
        at += 2;
        let old = p
            .iter()
            .find(|x| x.id.type_code == stobject::types::VECTOR256 && x.id.field_code == fcode)
            .ok_or("list edit without a previous value")?;
        let mut items: Vec<Vec<u8>> = old.value.chunks(32).map(<[u8]>::to_vec).collect();
        let nrem = u16_at(at)?;
        at += 2;
        let mut rem = Vec::new();
        for _ in 0..nrem {
            rem.push(u16_at(at)?);
            at += 2;
        }
        items = items
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !rem.contains(i))
            .map(|(_, v)| v)
            .collect();
        let nins = u16_at(at)?;
        at += 2;
        for _ in 0..nins {
            let pos = u16_at(at)?;
            let h = diff.get(at + 2..at + 34).ok_or("diff truncated")?.to_vec();
            at += 34;
            items.insert(pos.min(items.len()), h);
        }
        let value: Vec<u8> = items.concat();
        let mut raw = field_header(stobject::types::VECTOR256, fcode);
        witness_core::shamap::encode_vl(value.len(), &mut raw);
        raw.extend_from_slice(&value);
        rebuilt.push((stobject::types::VECTOR256, fcode, raw));
    }
    let nrem = u16_at(at)?;
    at += 2;
    let mut removed = Vec::new();
    for _ in 0..nrem {
        removed.push((u16_at(at)? as u16, u16_at(at + 2)? as u16));
        at += 4;
    }
    let replaced = |t: u16, f: u16| {
        removed.contains(&(t, f))
            || changed
                .iter()
                .any(|c| c.id.type_code == t && c.id.field_code == f)
            || rebuilt.iter().any(|r| r.0 == t && r.1 == f)
    };
    let mut all: Vec<(u16, u16, Vec<u8>)> = p
        .iter()
        .filter(|x| !replaced(x.id.type_code, x.id.field_code))
        .map(|x| (x.id.type_code, x.id.field_code, x.raw.to_vec()))
        .collect();
    all.extend(
        changed
            .iter()
            .map(|c| (c.id.type_code, c.id.field_code, c.raw.to_vec())),
    );
    all.extend(rebuilt.iter().cloned());
    all.sort_by_key(|(t, f, _)| (*t, *f));
    Ok(all.into_iter().flat_map(|(_, _, r)| r).collect())
}

fn patch(prev: &[u8], new: &[u8]) -> Res<Vec<u8>> {
    let mut c = zstd_safe::CCtx::create();
    c.set_parameter(zstd_safe::CParameter::CompressionLevel(19))
        .map_err(|x| format!("zstd {x}"))?;
    c.ref_prefix(prev).map_err(|x| format!("zstd {x}"))?;
    let mut out = vec![0u8; zstd_safe::compress_bound(new.len())];
    let n = c
        .compress2(&mut out[..], new)
        .map_err(|x| format!("zstd {x}"))?;
    out.truncate(n);
    Ok(out)
}

fn unpatch(prev: &[u8], z: &[u8], size: usize) -> Res<Vec<u8>> {
    let mut d = zstd_safe::DCtx::create();
    d.ref_prefix(prev).map_err(|x| format!("zstd {x}"))?;
    let mut out = vec![0u8; size];
    let n = d
        .decompress(&mut out[..], z)
        .map_err(|x| format!("zstd {x}"))?;
    out.truncate(n);
    Ok(out)
}

fn main() -> Res<()> {
    let args = Args::parse();
    let h = HistoryReader::open(&args.history)?;
    let store = StateStore::open(&args.db)?;
    let (first, last) = (args.from, args.from + args.ledgers - 1);
    let (mut full_buf, mut diff_buf, mut meta_buf) = (Vec::new(), Vec::new(), Vec::new());
    let (mut meta2_buf, mut via_meta2) = (Vec::new(), 0u64);
    let (mut full, mut diff, mut patched, mut raw, mut via_meta) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut exact, mut residual, mut untouched) = (0u64, 0u64, 0u64);
    // What the residuals consist of: field → (count, bytes), plus removed fields.
    let mut what: std::collections::HashMap<((u16, u16), bool), (u64, u64)> =
        std::collections::HashMap::new();
    let (mut modified, mut created, mut deleted, mut no_prev) = (0u64, 0u64, 0u64, 0u64);
    let (mut t_diff, mut t_patch) = (0f64, 0f64);
    let flush = |buf: &mut Vec<u8>| -> Res<u64> {
        let n = zstd::bulk::compress(buf, 19).map_err(e)?.len() as u64;
        buf.clear();
        Ok(n)
    };
    let t = Instant::now();
    for seq in first..=last {
        let l = Ledger::decode(&h.get(seq)?.ok_or(format!("no ledger {seq}"))?)?;
        let touched = touches(&l)?;
        for c in &l.changes {
            // Metadata and residual.
            meta_buf.extend_from_slice(&c.key);
            meta_buf.push(c.change as u8);
            if c.change != Change::Deleted {
                let prev = if c.change == Change::Modified {
                    store.get(&c.key, seq - 1)?
                } else {
                    None
                };
                let base = match touched.get(&c.key) {
                    Some(t) => candidate(prev.as_deref(), t, seq)?,
                    None => {
                        untouched += 1;
                        prev.clone().unwrap_or_default()
                    }
                };
                let d2 = field_diff2(&base, &c.data)?;
                if apply_diff2(&base, &d2)? != c.data {
                    return Err(format!(
                        "residual v2: ledger {seq}, object {} restored incorrectly",
                        hex::encode_upper(c.key)
                    ));
                }
                meta2_buf.extend_from_slice(&c.key);
                meta2_buf.push(c.change as u8);
                meta2_buf.extend_from_slice(&(d2.len() as u32).to_le_bytes());
                meta2_buf.extend_from_slice(&d2);
                let d = field_diff(&base, &c.data)?;
                if apply_diff(&base, &d)? != c.data {
                    return Err(format!(
                        "metadata and residual: ledger {seq}, object {} restored incorrectly",
                        hex::encode_upper(c.key)
                    ));
                }
                // Empty residual: the whole object comes from metadata, 1 byte.
                if d == [0, 0, 0, 0, 0, 0] {
                    exact += 1;
                    meta_buf.push(0);
                } else {
                    let p = stobject::fields(&base).map_err(e)?;
                    let n = stobject::fields(&c.data).map_err(e)?;
                    for f in &n {
                        if !p.iter().any(|x| x.id == f.id && x.raw == f.raw) {
                            let w = what.entry((id(f), false)).or_default();
                            w.0 += 1;
                            w.1 += f.raw.len() as u64;
                        }
                    }
                    for x in &p {
                        if !n.iter().any(|f| f.id == x.id) {
                            what.entry((id(x), true)).or_default().0 += 1;
                        }
                    }
                    residual += 1;
                    meta_buf.push(1);
                    meta_buf.extend_from_slice(&(d.len() as u32).to_le_bytes());
                    meta_buf.extend_from_slice(&d);
                }
            }
            raw += c.data.len() as u64 + 37;
            full_buf.extend_from_slice(&c.key);
            full_buf.push(c.change as u8);
            full_buf.extend_from_slice(&(c.data.len() as u32).to_le_bytes());
            full_buf.extend_from_slice(&c.data);
            diff_buf.extend_from_slice(&c.key);
            diff_buf.push(c.change as u8);
            patched += 37;
            match c.change {
                Change::Deleted => deleted += 1,
                Change::Created => {
                    created += 1;
                    diff_buf.extend_from_slice(&(c.data.len() as u32).to_le_bytes());
                    diff_buf.extend_from_slice(&c.data);
                    patched += zstd::bulk::compress(&c.data, 19).map_err(e)?.len() as u64;
                }
                Change::Modified => {
                    modified += 1;
                    let Some(prev) = store.get(&c.key, seq - 1)? else {
                        no_prev += 1;
                        diff_buf.extend_from_slice(&(c.data.len() as u32).to_le_bytes());
                        diff_buf.extend_from_slice(&c.data);
                        continue;
                    };
                    let t0 = Instant::now();
                    let d = field_diff(&prev, &c.data)?;
                    if apply_diff(&prev, &d)? != c.data {
                        return Err(format!(
                            "field diff: ledger {seq}, object {} restored incorrectly",
                            hex::encode_upper(c.key)
                        ));
                    }
                    t_diff += t0.elapsed().as_secs_f64();
                    diff_buf.extend_from_slice(&(d.len() as u32).to_le_bytes());
                    diff_buf.extend_from_slice(&d);
                    let t0 = Instant::now();
                    let z = patch(&prev, &c.data)?;
                    if unpatch(&prev, &z, c.data.len())? != c.data {
                        return Err(format!("patch-from: ledger {seq} restored incorrectly"));
                    }
                    t_patch += t0.elapsed().as_secs_f64();
                    patched += z.len() as u64;
                }
            }
        }
        if (seq - first + 1).is_multiple_of(128) || seq == last {
            full += flush(&mut full_buf)?;
            diff += flush(&mut diff_buf)?;
            via_meta += flush(&mut meta_buf)?;
            via_meta2 += flush(&mut meta2_buf)?;
        }
    }
    let n = f64::from(args.ledgers);
    let kb = |b: u64| b as f64 / n / 1000.0;
    println!(
        "ledgers {first}…{last} ({} changes: {modified} modified, {created} created, {deleted} deleted; {no_prev} without a previous version), in {:.0} s",
        modified + created + deleted,
        t.elapsed().as_secs_f64()
    );
    println!("uncompressed: {:.1} KB/ledger", kb(raw));
    println!("| variant | KB/ledger | restored | parse and build, µs per object |");
    println!("|---|---:|---|---:|");
    println!(
        "| full object, blocks of 128, zstd-19 (current) | {:.1} | — | — |",
        kb(full)
    );
    println!(
        "| field diff, blocks of 128, zstd-19 | {:.1} | {modified} of {modified} | {:.1} |",
        kb(diff),
        t_diff / modified.max(1) as f64 * 1e6
    );
    println!(
        "| zstd patch-from, frame per object | {:.1} | {modified} of {modified} | {:.1} |",
        kb(patched),
        t_patch / modified.max(1) as f64 * 1e6
    );
    println!(
        "| metadata and residual, blocks of 128, zstd-19 | {:.1} | {} of {} | — |",
        kb(via_meta),
        modified + created,
        modified + created
    );
    println!(
        "| metadata and residual, list edits, Flags=0, blocks of 128, zstd-19 | {:.1} | {} of {} | — |",
        kb(via_meta2),
        modified + created,
        modified + created
    );
    println!(
        "  entirely from metadata: {exact}; with residual: {residual}; not touched by transactions (residual against previous version): {untouched}"
    );
    let mut top: Vec<_> = what.into_iter().collect();
    top.sort_by_key(|(_, (n, b))| std::cmp::Reverse(*b + *n));
    println!("residual breakdown (field: count, uncompressed bytes):");
    let d = ledger_engine::xrpl_json::definitions();
    for (((t, f), removed), (n, b)) in top.into_iter().take(15) {
        println!(
            "  {}{}: {n}, {b}",
            if removed { "removed: " } else { "" },
            d.field_name(t, f).unwrap_or("?")
        );
    }
    Ok(())
}
