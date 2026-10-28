//! A ledger's state changes, stored as a diff against what is already known:
//! the previous version of the object and the transaction metadata.
//!
//! Measured on 2048 mainnet ledgers (1.08 million objects, each one
//! restored byte for byte): full objects take 26.8 KB per ledger in zstd-19
//! blocks, this diff takes 8.8.
//!
//! For every created or modified object a "base" is built, with no
//! protocol logic, only from what is at hand:
//! - the object was touched by the ledger's transactions: the previous version
//!   (nothing for a created one), overlaid with the fields from the last
//!   touching transaction (NewFields for a created object, FinalFields for a
//!   modified one), LedgerEntryType, PreviousTxnID and PreviousTxnLgrSeq set to
//!   that transaction and this ledger, and Flags = 0 if the field is missing
//!   (every object has it, and a zero value never appears in NewFields);
//! - not touched (LedgerHashes and the like): the previous version.
//!
//! What gets stored is the remainder: changed and new fields in full, changed
//! Vector256 lists as a patch (removed positions, inserted items), deleted fields
//! by code. Whatever is missing from the metadata (directory Indexes, page
//! numbers) ends up in the remainder.
//!
//! Encoding checks itself: every object is rebuilt right away and compared
//! byte for byte. If it does not match, or the remainder is not shorter than
//! the object, the full object is stored.

use std::collections::HashMap;

use witness_core::shamap::{encode_vl, tx_id};
use witness_core::stobject::{self, Field, types};

use crate::ledger::{Change, Ledger, StateChange};

type Res<T> = Result<T, String>;
type FieldKey = (u16, u16);

const AFFECTED_NODES: FieldKey = (types::ARRAY, 8);
const CREATED_NODE: FieldKey = (types::OBJECT, 3);
const FINAL_FIELDS: FieldKey = (types::OBJECT, 7);
const NEW_FIELDS: FieldKey = (types::OBJECT, 8);
const LEDGER_INDEX: FieldKey = (types::HASH256, 6);
const LEDGER_ENTRY_TYPE: FieldKey = (types::UINT16, 1);
const TX_INDEX: FieldKey = (types::UINT32, 28);
const FLAGS: FieldKey = (types::UINT32, 2);
const PREVIOUS_TXN_ID: FieldKey = (types::HASH256, 5);
const PREVIOUS_TXN_LGR_SEQ: FieldKey = (types::UINT32, 5);

/// Kind of change record.
const DELETED: u8 = 0;
const FULL: u8 = 1;
const DIFF: u8 = 2;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

fn fid(f: &Field<'_>) -> FieldKey {
    (f.id.type_code, f.id.field_code)
}

fn put_u16(out: &mut Vec<u8>, v: usize) -> Res<()> {
    let v = u16::try_from(v).map_err(|_| "value does not fit in u16")?;
    out.extend_from_slice(&v.to_le_bytes());
    Ok(())
}

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

/// The last transaction in the ledger that touched the object: its hash, its
/// fields for the object and LedgerEntryType (raw field bytes).
#[derive(Debug, Clone)]
pub struct Touch {
    tx: [u8; 32],
    fields: Vec<u8>,
    entry_type: Vec<u8>,
}

/// Objects touched by the ledger's transactions, in order of application.
pub fn touches(l: &Ledger) -> Res<HashMap<[u8; 32], Touch>> {
    let mut order: Vec<(u32, &[u8], &[u8])> = Vec::with_capacity(l.transactions.len());
    for (tx, meta) in &l.transactions {
        let f = stobject::fields(meta).map_err(e)?;
        let idx = f
            .iter()
            .find(|x| fid(x) == TX_INDEX)
            .and_then(|x| stobject::u32_of(x.value))
            .ok_or("no TransactionIndex in metadata")?;
        order.push((idx, tx, meta));
    }
    order.sort_by_key(|o| o.0);
    let mut out = HashMap::new();
    for (_, tx, meta) in order {
        let id = tx_id(tx);
        let f = stobject::fields(meta).map_err(e)?;
        let Some(nodes) = f.iter().find(|x| fid(x) == AFFECTED_NODES) else {
            continue;
        };
        for node in stobject::children(nodes).map_err(e)? {
            let inner = stobject::children(&node).map_err(e)?;
            let Some(key) = inner
                .iter()
                .find(|x| fid(x) == LEDGER_INDEX)
                .and_then(|x| <[u8; 32]>::try_from(x.value).ok())
            else {
                continue;
            };
            let want = if fid(&node) == CREATED_NODE {
                NEW_FIELDS
            } else {
                FINAL_FIELDS
            };
            out.insert(
                key,
                Touch {
                    tx: id,
                    fields: inner
                        .iter()
                        .find(|x| fid(x) == want)
                        .map(|x| x.value.to_vec())
                        .unwrap_or_default(),
                    entry_type: inner
                        .iter()
                        .find(|x| fid(x) == LEDGER_ENTRY_TYPE)
                        .map(|x| x.raw.to_vec())
                        .unwrap_or_default(),
                },
            );
        }
    }
    Ok(out)
}

/// The object's base (see the module docs).
fn base(prev: Option<&[u8]>, touch: Option<&Touch>, seq: u32) -> Res<Vec<u8>> {
    let mut all: Vec<(FieldKey, Vec<u8>)> = match prev {
        Some(p) => stobject::fields(p)
            .map_err(e)?
            .iter()
            .map(|x| (fid(x), x.raw.to_vec()))
            .collect(),
        None => Vec::new(),
    };
    if let Some(t) = touch {
        let mut set = |k: FieldKey, raw: Vec<u8>| {
            all.retain(|(i, _)| *i != k);
            all.push((k, raw));
        };
        for x in stobject::fields(&t.fields).map_err(e)? {
            set(fid(&x), x.raw.to_vec());
        }
        if !t.entry_type.is_empty() {
            set(LEDGER_ENTRY_TYPE, t.entry_type.clone());
        }
        let mut txid = field_header(PREVIOUS_TXN_ID.0, PREVIOUS_TXN_ID.1);
        txid.extend_from_slice(&t.tx);
        set(PREVIOUS_TXN_ID, txid);
        let mut lseq = field_header(PREVIOUS_TXN_LGR_SEQ.0, PREVIOUS_TXN_LGR_SEQ.1);
        lseq.extend_from_slice(&seq.to_be_bytes());
        set(PREVIOUS_TXN_LGR_SEQ, lseq);
        if !all.iter().any(|(k, _)| *k == FLAGS) {
            all.push((FLAGS, vec![0x22, 0, 0, 0, 0]));
        }
    }
    all.sort_by_key(|(k, _)| *k);
    Ok(all.into_iter().flat_map(|(_, r)| r).collect())
}

/// A patch for a list of 32-byte items: removed positions and inserted (position,
/// item) pairs. `None` if the order of the remaining items changed.
fn vector_patch(old: &[u8], new: &[u8]) -> Res<Option<Vec<u8>>> {
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
        return Ok(None);
    }
    let mut out = Vec::new();
    put_u16(&mut out, removed.len())?;
    for i in removed {
        put_u16(&mut out, i)?;
    }
    put_u16(&mut out, inserted.len())?;
    for j in inserted {
        put_u16(&mut out, j)?;
        out.extend_from_slice(n[j]);
    }
    Ok(Some(out))
}

/// The remainder: what to change in the base to get the object.
fn diff(base: &[u8], new: &[u8]) -> Res<Vec<u8>> {
    let p = stobject::fields(base).map_err(e)?;
    let n = stobject::fields(new).map_err(e)?;
    let (mut changed, mut count, mut patches, mut npatch) = (Vec::new(), 0, Vec::new(), 0);
    for f in &n {
        let old = p.iter().find(|x| x.id == f.id);
        if old.is_some_and(|x| x.raw == f.raw) {
            continue;
        }
        if f.id.type_code == types::VECTOR256
            && let Some(o) = old
            && let Some(vp) = vector_patch(o.value, f.value)?
            && vp.len() + 2 < f.raw.len()
        {
            put_u16(&mut patches, usize::from(f.id.field_code))?;
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
    put_u16(&mut out, count)?;
    out.extend_from_slice(&(changed.len() as u32).to_le_bytes());
    out.extend_from_slice(&changed);
    put_u16(&mut out, npatch)?;
    out.extend_from_slice(&patches);
    put_u16(&mut out, removed.len())?;
    for r in removed {
        put_u16(&mut out, usize::from(r.id.type_code))?;
        put_u16(&mut out, usize::from(r.id.field_code))?;
    }
    Ok(out)
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let s = self
            .b
            .get(self.at..self.at + n)
            .ok_or("changes truncated")?;
        self.at += n;
        Ok(s)
    }
    fn u16(&mut self) -> Res<usize> {
        let s = self.take(2)?;
        Ok(usize::from(u16::from_le_bytes([s[0], s[1]])))
    }
    fn u32(&mut self) -> Res<usize> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
    }
}

/// An object from a base and a remainder.
fn apply(base: &[u8], c: &mut Cursor<'_>) -> Res<Vec<u8>> {
    let _count = c.u16()?;
    let len = c.u32()?;
    let changed = stobject::fields(c.take(len)?).map_err(e)?;
    let p = stobject::fields(base).map_err(e)?;
    let mut rebuilt: Vec<(FieldKey, Vec<u8>)> = Vec::new();
    for _ in 0..c.u16()? {
        let fcode = c.u16()? as u16;
        let old = p
            .iter()
            .find(|x| fid(x) == (types::VECTOR256, fcode))
            .ok_or("list patch without a previous value")?;
        let mut rem = Vec::new();
        for _ in 0..c.u16()? {
            rem.push(c.u16()?);
        }
        let mut items: Vec<&[u8]> = old
            .value
            .chunks(32)
            .enumerate()
            .filter(|(i, _)| !rem.contains(i))
            .map(|(_, v)| v)
            .collect();
        for _ in 0..c.u16()? {
            let pos = c.u16()?;
            let h = c.take(32)?;
            if pos > items.len() {
                return Err("list patch: position outside the list".into());
            }
            items.insert(pos, h);
        }
        let value = items.concat();
        let mut raw = field_header(types::VECTOR256, fcode);
        encode_vl(value.len(), &mut raw);
        raw.extend_from_slice(&value);
        rebuilt.push(((types::VECTOR256, fcode), raw));
    }
    let mut removed = Vec::new();
    for _ in 0..c.u16()? {
        removed.push((c.u16()? as u16, c.u16()? as u16));
    }
    let replaced = |k: FieldKey| {
        removed.contains(&k)
            || changed.iter().any(|x| fid(x) == k)
            || rebuilt.iter().any(|(r, _)| *r == k)
    };
    let mut all: Vec<(FieldKey, Vec<u8>)> = p
        .iter()
        .filter(|x| !replaced(fid(x)))
        .map(|x| (fid(x), x.raw.to_vec()))
        .collect();
    all.extend(changed.iter().map(|x| (fid(x), x.raw.to_vec())));
    all.extend(rebuilt);
    all.sort_by_key(|(k, _)| *k);
    Ok(all.into_iter().flat_map(|(_, r)| r).collect())
}

/// The previous version of the object, as of the ledger before this one; `None` if it did not exist.
pub type Prev<'a> = dyn Fn(&[u8; 32]) -> Res<Option<Vec<u8>>> + 'a;

/// Changes of ledger `seq` as a format 3 record. Returns the record and how many
/// objects had to be stored in full.
pub fn encode(l: &Ledger, seq: u32, prev: &Prev<'_>) -> Res<(Vec<u8>, usize)> {
    let touched = touches(l)?;
    let mut out = (l.changes.len() as u32).to_le_bytes().to_vec();
    let mut full = 0;
    for c in &l.changes {
        out.extend_from_slice(&c.key);
        if c.change == Change::Deleted {
            out.push(DELETED);
            continue;
        }
        let prior = if c.change == Change::Modified {
            prev(&c.key)?
        } else {
            None
        };
        let b = base(prior.as_deref(), touched.get(&c.key), seq)?;
        let d = diff(&b, &c.data)?;
        let ok = d.len() < c.data.len()
            && apply(&b, &mut Cursor { b: &d, at: 0 }).is_ok_and(|x| x == c.data);
        let kind = match c.change {
            Change::Created => 0x10,
            _ => 0x20,
        };
        if ok {
            out.push(kind | DIFF);
            out.extend_from_slice(&(d.len() as u32).to_le_bytes());
            out.extend_from_slice(&d);
        } else {
            full += 1;
            out.push(kind | FULL);
            out.extend_from_slice(&(c.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&c.data);
        }
    }
    Ok((out, full))
}

/// Changes of a ledger from a format 3 record; `l` is the ledger with its transactions.
pub fn decode(l: &Ledger, seq: u32, record: &[u8], prev: &Prev<'_>) -> Res<Vec<StateChange>> {
    let touched = touches(l)?;
    let mut c = Cursor { b: record, at: 0 };
    let n = c.u32()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let key: [u8; 32] = c.take(32)?.try_into().map_err(e)?;
        let tag = c.take(1)?[0];
        if tag == DELETED {
            out.push(StateChange {
                key,
                change: Change::Deleted,
                data: Vec::new(),
            });
            continue;
        }
        let change = match tag & 0xF0 {
            0x10 => Change::Created,
            0x20 => Change::Modified,
            _ => return Err(format!("unknown change record {tag:#04x}")),
        };
        let len = c.u32()?;
        let payload = c.take(len)?;
        let data = match tag & 0x0F {
            FULL => payload.to_vec(),
            DIFF => {
                let prior = if change == Change::Modified {
                    prev(&key)?
                } else {
                    None
                };
                let b = base(prior.as_deref(), touched.get(&key), seq)?;
                apply(&b, &mut Cursor { b: payload, at: 0 })?
            }
            _ => return Err(format!("unknown change record {tag:#04x}")),
        };
        out.push(StateChange { key, change, data });
    }
    if c.at != record.len() {
        return Err("trailing bytes after the changes".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        fields
            .iter()
            .flat_map(|(h, v)| h.iter().chain(v.iter()).copied())
            .collect()
    }

    #[test]
    fn vector_patches_roundtrip() {
        // Directory: Flags, Indexes (Vector256 field 1), one key removed, two added.
        let mut idx_old = vec![0x01, 0x13, 96];
        for i in 1..=3u8 {
            idx_old.extend([i; 32]);
        }
        let mut idx_new = vec![0x01, 0x13, 96];
        for i in [1u8, 9, 3] {
            idx_new.extend([i; 32]);
        }
        let a = obj(&[
            (&[0x11], &[0, 0x64]),
            (&[0x22], &[0, 0, 0, 0]),
            (&idx_old, &[]),
        ]);
        let b = obj(&[
            (&[0x11], &[0, 0x64]),
            (&[0x22], &[0, 0, 0, 1]),
            (&idx_new, &[]),
        ]);
        let d = diff(&a, &b).unwrap();
        assert!(
            d.len() < 60,
            "a list patch, not the whole list: {}",
            d.len()
        );
        assert_eq!(apply(&a, &mut Cursor { b: &d, at: 0 }).unwrap(), b);
    }

    #[test]
    fn encode_decode_without_transactions() {
        // A ledger with no transactions: the modified object is a diff against the
        // previous version, the created one is stored in full (no base), the deleted one by key.
        let mut header = vec![0u8; 118];
        header[..4].copy_from_slice(&5u32.to_be_bytes());
        let prev_obj = obj(&[
            (&[0x11], &[0, 0x68]),
            (&[0x22], &[0, 0, 0, 0]),
            (&[0x24], &[0, 0, 0, 7]),
            (&[0x51], &[7; 32]),
        ]);
        let new_obj = obj(&[
            (&[0x11], &[0, 0x68]),
            (&[0x22], &[0, 0, 0, 0]),
            (&[0x24], &[0, 0, 0, 8]),
            (&[0x51], &[7; 32]),
        ]);
        let l = Ledger {
            header,
            transactions: Vec::new(),
            changes: vec![
                StateChange {
                    key: [1; 32],
                    change: Change::Modified,
                    data: new_obj.clone(),
                },
                StateChange {
                    key: [2; 32],
                    change: Change::Created,
                    data: prev_obj.clone(),
                },
                StateChange {
                    key: [3; 32],
                    change: Change::Deleted,
                    data: Vec::new(),
                },
            ],
        };
        let prev = |k: &[u8; 32]| -> Res<Option<Vec<u8>>> {
            Ok((*k == [1; 32]).then(|| prev_obj.clone()))
        };
        let (rec, full) = encode(&l, 5, &prev).unwrap();
        assert_eq!(full, 1, "a created object without a base is stored in full");
        assert_eq!(decode(&l, 5, &rec, &prev).unwrap(), l.changes);
    }
}
