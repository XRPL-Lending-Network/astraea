//! State patches of a cold segment, stored only where the metadata doesn't give
//! them.
//!
//! A ledger's metadata names every object its transactions touched. The object
//! after the last of them follows from that node: `FinalFields` or `NewFields`,
//! `LedgerEntryType`, and this transaction as `PreviousTxnID` and
//! `PreviousTxnLgrSeq` if the object is threaded. What the node leaves out is
//! added by a few rules (`defaults`): xrpld doesn't list a field at its default
//! value when it creates an object, and it never lists a directory's `Indexes`,
//! though a new page usually holds just the object its transaction created. A
//! deleted object has no data, and one created and deleted in the same ledger has
//! no patch at all. Most of a ledger's patches come back exactly, and most of
//! the others up to a few fields.
//!
//! A stored ledger starts with an entry under the zero key that says how to read
//! the rest:
//! - `DERIVED` and the directory rule: an entry `(key, value)` follows only for what
//!   isn't restored. For a key the metadata doesn't name, `value` is the patch as it
//!   is. For a key it names, by `value`: empty, the object is deleted; `NO_PATCH`, the
//!   ledger has no patch for it; `WHOLE` and the data, the patch as it is; otherwise
//!   the fields that are missing or different, in canonical order. Patches come
//!   back sorted by key;
//! - `AS_IS`: every patch follows as it is. A ledger gets this when it doesn't
//!   come back exactly the other way (unsorted patches, metadata that can't be read).
//!
//! A row without that entry was written before this format and holds every patch. The
//! entry is in the row and not in the manifest so that a reader can't pair a
//! rule with the wrong archive while a segment is being rewritten under it. Object
//! keys are hashes, so none of them is zero.
//!
//! Only `Row::patches` changes, and only reading the patches needs this: transactions
//! are read as before.
//!
//! Directories were not threaded until the fixPreviousTxnID amendment, and nothing
//! in the metadata says which rule a ledger followed, so each ledger keeps the
//! rule that stores less.
//!
//! These rules are fixed: `DERIVED` names them. Changing them means a new
//! marker, with this one still read.

use std::collections::{BTreeMap, HashMap};

use astraea_journal_codec::Row;
use witness_core::shamap::tx_id;
use witness_core::stobject::{self, Field, FieldId, types};

type Res<T> = Result<T, String>;
type Key = [u8; 32];
type Patch = (Key, Vec<u8>);

const NO_PATCH: u8 = 0xFF;
const WHOLE: u8 = 0xFE;
const AS_IS: u8 = 0xFD;
const DERIVED: u8 = 0xFC;
const MARKER_KEY: Key = [0; 32];

const AFFECTED: FieldId = FieldId::new(types::ARRAY, 8);
const TX_INDEX: FieldId = FieldId::new(types::UINT32, 28);
const ENTRY_TYPE: FieldId = FieldId::new(types::UINT16, 1);
const LEDGER_INDEX: FieldId = FieldId::new(types::HASH256, 6);
const PREV_TXN_ID: FieldId = FieldId::new(types::HASH256, 5);
const PREV_TXN_SEQ: FieldId = FieldId::new(types::UINT32, 5);
const FINAL: FieldId = FieldId::new(types::OBJECT, 7);
const NEW: FieldId = FieldId::new(types::OBJECT, 8);
const CREATED: FieldId = FieldId::new(types::OBJECT, 3);
const DELETED: FieldId = FieldId::new(types::OBJECT, 4);
const FLAGS: FieldId = FieldId::new(types::UINT32, 2);
const EXCHANGE_RATE: FieldId = FieldId::new(types::UINT64, 6);
const DIRECTORY: u16 = 0x64;
/// `TakerPaysCurrency`, `TakerPaysIssuer`, `TakerGetsCurrency`, `TakerGetsIssuer`.
const BOOK: [FieldId; 4] = [
    FieldId::new(types::HASH160, 1),
    FieldId::new(types::HASH160, 2),
    FieldId::new(types::HASH160, 3),
    FieldId::new(types::HASH160, 4),
];
const BOOK_NODE: FieldId = FieldId::new(types::UINT64, 3);
const OWNER_NODE: FieldId = FieldId::new(types::UINT64, 4);
const LOW_NODE: FieldId = FieldId::new(types::UINT64, 7);
const HIGH_NODE: FieldId = FieldId::new(types::UINT64, 8);
const OFFER_NODE: FieldId = FieldId::new(types::UINT64, 12);
const OWNER_COUNT: FieldId = FieldId::new(types::UINT32, 13);
const INDEXES: FieldId = FieldId::new(types::VECTOR256, 1);

/// Required fields of an entry type that xrpld leaves out of `NewFields` when
/// they are zero.
fn defaults(entry_type: u16) -> &'static [FieldId] {
    match entry_type {
        // Offer.
        0x6F => &[BOOK_NODE, OWNER_NODE],
        // RippleState.
        0x72 => &[LOW_NODE, HIGH_NODE],
        // AccountRoot.
        0x61 => &[OWNER_COUNT],
        // Ticket.
        0x54 => &[OWNER_NODE],
        // NFTokenOffer.
        0x37 => &[OWNER_NODE, OFFER_NODE],
        _ => &[],
    }
}

/// A field with a zero value of a fixed width.
fn zero(id: FieldId) -> Vec<u8> {
    let width = match id.type_code {
        types::UINT32 => 4,
        types::UINT64 => 8,
        _ => 20,
    };
    let (t, f) = (id.type_code as u8, id.field_code as u8);
    let mut out = match (t < 16, f < 16) {
        (true, true) => vec![t << 4 | f],
        (true, false) => vec![t << 4, f],
        (false, true) => vec![f, t],
        (false, false) => vec![0, t, f],
    };
    out.resize(out.len() + width, 0);
    out
}

fn order(id: &FieldId) -> (u16, u16) {
    (id.type_code, id.field_code)
}

fn bad<E: std::fmt::Display>(e: E) -> String {
    format!("patches from metadata: {e}")
}

/// An object after the last node that touched it in the ledger.
struct Node {
    fields: Vec<(FieldId, Vec<u8>)>,
    /// The first node of this object in the ledger created it.
    born: bool,
    deleted: bool,
}

impl Node {
    /// The patch this node gives, if it gives one.
    fn patch(&self) -> Option<Vec<u8>> {
        if self.deleted && self.born {
            return None;
        }
        Some(self.fields.iter().flat_map(|(_, r)| r.clone()).collect())
    }
}

/// The object a node leaves behind, as fields in canonical order.
fn rebuild(
    node: &Field<'_>,
    inner: &[Field<'_>],
    tx: &Key,
    seq: u32,
    threaded_directories: bool,
    new_object: Option<&Key>,
) -> Res<Vec<(FieldId, Vec<u8>)>> {
    let created = node.id == CREATED;
    let body = if created { NEW } else { FINAL };
    let mut out: Vec<(FieldId, Vec<u8>)> = Vec::with_capacity(16);
    let mut threaded = false;
    let mut entry_type = 0;
    for f in inner {
        if f.id == ENTRY_TYPE {
            let [a, b] = <[u8; 2]>::try_from(f.value).map_err(bad)?;
            entry_type = u16::from_be_bytes([a, b]);
            out.push((f.id, f.raw.to_vec()));
        } else if f.id == PREV_TXN_ID {
            threaded = true;
        } else if f.id == body {
            for g in stobject::children(f).map_err(bad)? {
                threaded |= g.id == PREV_TXN_ID;
                out.push((g.id, g.raw.to_vec()));
            }
        }
    }
    let directory = entry_type == DIRECTORY;
    if threaded || (directory && threaded_directories) || (created && !directory) {
        out.retain(|(i, _)| *i != PREV_TXN_ID && *i != PREV_TXN_SEQ);
        let mut id = vec![0x55];
        id.extend_from_slice(tx);
        out.push((PREV_TXN_ID, id));
        let mut at = vec![0x25];
        at.extend_from_slice(&seq.to_be_bytes());
        out.push((PREV_TXN_SEQ, at));
    }
    if created {
        let has = |out: &[(FieldId, Vec<u8>)], id| out.iter().any(|(i, _)| *i == id);
        let book = directory && (has(&out, EXCHANGE_RATE) || BOOK.iter().any(|b| has(&out, *b)));
        let extra: &[FieldId] = if book { &BOOK } else { defaults(entry_type) };
        for id in std::iter::once(&FLAGS).chain(extra) {
            if !has(&out, *id) {
                out.push((*id, zero(*id)));
            }
        }
        if directory && let Some(k) = new_object {
            // VECTOR256 field 1: header, length 32, the key.
            let mut indexes = vec![0x01, 0x13, 0x20];
            indexes.extend_from_slice(k);
            out.push((INDEXES, indexes));
        }
    }
    out.sort_by_key(|(i, _)| order(i));
    Ok(out)
}

/// What the metadata of a ledger's transactions gives, by object.
fn derive(
    txs: &[(Vec<u8>, Vec<u8>)],
    seq: u32,
    threaded_directories: bool,
) -> Res<HashMap<Key, Node>> {
    let mut by_index = Vec::with_capacity(txs.len());
    for (i, (_, meta)) in txs.iter().enumerate() {
        let fs = stobject::fields(meta).map_err(bad)?;
        let index = stobject::find(&fs, TX_INDEX)
            .and_then(stobject::u32_of)
            .ok_or_else(|| bad("no TransactionIndex"))?;
        by_index.push((index, i));
    }
    by_index.sort_unstable();
    let mut out: HashMap<Key, Node> = HashMap::with_capacity(txs.len() * 4);
    for (_, i) in by_index {
        let (tx, meta) = &txs[i];
        let id = tx_id(tx);
        let fs = stobject::fields(meta).map_err(bad)?;
        let Some(nodes) = fs.iter().find(|f| f.id == AFFECTED) else {
            continue;
        };
        let mut parsed = Vec::new();
        for node in stobject::children(nodes).map_err(bad)? {
            let inner = stobject::children(&node).map_err(bad)?;
            let key = stobject::find(&inner, LEDGER_INDEX)
                .and_then(|v| Key::try_from(v).ok())
                .ok_or_else(|| bad("node without LedgerIndex"))?;
            parsed.push((node, inner, key));
        }
        // The one object this transaction created, directories aside.
        let mut created = parsed.iter().filter(|(node, inner, _)| {
            node.id == CREATED
                && stobject::find(inner, ENTRY_TYPE) != Some(&DIRECTORY.to_be_bytes()[..])
        });
        let new_object = match (created.next(), created.next()) {
            (Some((_, _, k)), None) => Some(*k),
            _ => None,
        };
        for (node, inner, key) in parsed {
            let deleted = node.id == DELETED;
            let fields = if deleted {
                Vec::new()
            } else {
                rebuild(
                    &node,
                    &inner,
                    &id,
                    seq,
                    threaded_directories,
                    new_object.as_ref(),
                )?
            };
            let born = out.get(&key).map_or(node.id == CREATED, |n| n.born);
            out.insert(
                key,
                Node {
                    fields,
                    born,
                    deleted,
                },
            );
        }
    }
    Ok(out)
}

/// A patch's data over the node's fields: the entry for this key, or none
/// if the node gives the patch exactly.
fn entry(node: &Node, data: &[u8]) -> Option<Vec<u8>> {
    if node.patch().as_deref() == Some(data) {
        return None;
    }
    if data.is_empty() {
        return Some(Vec::new());
    }
    let whole = || [&[WHOLE], data].concat();
    let Ok(fs) = stobject::fields(data) else {
        return Some(whole());
    };
    if node
        .fields
        .iter()
        .any(|(i, _)| !fs.iter().any(|f| f.id == *i))
    {
        return Some(whole());
    }
    let have: HashMap<FieldId, &[u8]> = node.fields.iter().map(|(i, r)| (*i, &r[..])).collect();
    let delta: Vec<u8> = fs
        .iter()
        .filter(|f| have.get(&f.id) != Some(&f.raw))
        .flat_map(|f| f.raw.iter().copied())
        .collect();
    Some(match delta.first() {
        Some(&b) if b != NO_PATCH && b != WHOLE => delta,
        _ => whole(),
    })
}

fn kept(row: &Row, threaded_directories: bool) -> Res<Vec<Patch>> {
    let nodes = derive(&row.txs, row.seq, threaded_directories)?;
    let mut out = Vec::new();
    for (key, data) in &row.patches {
        match nodes.get(key) {
            None => out.push((*key, data.clone())),
            Some(n) => {
                if let Some(e) = entry(n, data) {
                    out.push((*key, e));
                }
            }
        }
    }
    let mut named: Vec<&Key> = nodes
        .iter()
        .filter(|(_, n)| n.patch().is_some())
        .map(|(k, _)| k)
        .collect();
    named.retain(|k| row.patches.binary_search_by(|(p, _)| p.cmp(k)).is_err());
    out.extend(named.into_iter().map(|k| (*k, vec![NO_PATCH])));
    out.sort_by_key(|(k, _)| *k);
    Ok(out)
}

/// The entries to store for a row. Always restored exactly by `restore`.
pub fn compact(row: &Row) -> Vec<Patch> {
    let attempt = |threaded| {
        let mut out = vec![(MARKER_KEY, vec![DERIVED, u8::from(threaded)])];
        out.extend(kept(row, threaded).ok()?);
        restore(&row.txs, row.seq, &out)
            .is_ok_and(|r| r == row.patches)
            .then_some(out)
    };
    let cost = |k: &[Patch]| k.iter().map(|(_, v)| 32 + v.len()).sum::<usize>();
    match (attempt(false), attempt(true)) {
        (Some(a), Some(b)) => {
            if cost(&b) < cost(&a) {
                b
            } else {
                a
            }
        }
        (Some(k), None) | (None, Some(k)) => k,
        (None, None) => {
            let mut out = Vec::with_capacity(row.patches.len() + 1);
            out.push((MARKER_KEY, vec![AS_IS]));
            out.extend(row.patches.iter().cloned());
            out
        }
    }
}

/// The patches of a ledger from its transactions and stored entries.
pub fn restore(txs: &[(Vec<u8>, Vec<u8>)], seq: u32, stored: &[Patch]) -> Res<Vec<Patch>> {
    let threaded_directories = match stored.split_first() {
        Some(((k, v), rest)) if *k == MARKER_KEY && v.as_slice() == [AS_IS] => {
            return Ok(rest.to_vec());
        }
        Some(((k, v), _)) if *k == MARKER_KEY && v.first() == Some(&DERIVED) => match v.get(1) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(bad("directory rule")),
        },
        // Written before this format: every patch is here.
        _ => return Ok(stored.to_vec()),
    };
    let nodes = derive(txs, seq, threaded_directories)?;
    let mut out: BTreeMap<Key, Vec<u8>> = nodes
        .iter()
        .filter_map(|(k, n)| n.patch().map(|p| (*k, p)))
        .collect();
    for (key, value) in &stored[1..] {
        let Some(node) = nodes.get(key) else {
            out.insert(*key, value.clone());
            continue;
        };
        match value.first() {
            None => {
                out.insert(*key, Vec::new());
            }
            Some(&NO_PATCH) => {
                out.remove(key);
            }
            Some(&WHOLE) => {
                out.insert(*key, value[1..].to_vec());
            }
            Some(_) => {
                let mut fields: BTreeMap<(u16, u16), &[u8]> = node
                    .fields
                    .iter()
                    .map(|(i, r)| (order(i), &r[..]))
                    .collect();
                let delta = stobject::fields(value).map_err(bad)?;
                for f in &delta {
                    fields.insert(order(&f.id), f.raw);
                }
                out.insert(*key, fields.into_values().flatten().copied().collect());
            }
        }
    }
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEQ: u32 = 90_000_000;

    fn node(kind: u8, entry_type: u16, key: u8, top: &[u8], body: Option<(u8, &[u8])>) -> Vec<u8> {
        let mut n = vec![kind, 0x11];
        n.extend(entry_type.to_be_bytes());
        n.extend(top);
        n.push(0x56);
        n.extend([key; 32]);
        if let Some((id, fields)) = body {
            n.push(id);
            n.extend(fields);
            n.push(0xE1);
        }
        n.push(0xE1);
        n
    }

    fn tx(index: u32, nodes: &[Vec<u8>]) -> (Vec<u8>, Vec<u8>) {
        let mut meta = vec![0x20, 0x1C];
        meta.extend(index.to_be_bytes());
        meta.push(0xF8);
        for n in nodes {
            meta.extend(n);
        }
        meta.push(0xF1);
        (vec![0x12, 0, index as u8], meta)
    }

    fn prev_seq(seq: u32) -> Vec<u8> {
        let mut out = vec![0x25];
        out.extend(seq.to_be_bytes());
        out
    }

    fn prev_id(id: &Key) -> Vec<u8> {
        let mut out = vec![0x55];
        out.extend(id);
        out
    }

    fn entry_type(t: u16) -> Vec<u8> {
        let mut out = vec![0x11];
        out.extend(t.to_be_bytes());
        out
    }

    /// The entries stored for a ledger, after the marker.
    fn round_trip(txs: Vec<(Vec<u8>, Vec<u8>)>, patches: Vec<Patch>, threaded: bool) -> Vec<Patch> {
        let row = Row {
            seq: SEQ,
            header: Vec::new(),
            txs,
            patches,
        };
        let stored = compact(&row);
        assert_eq!(restore(&row.txs, SEQ, &stored).unwrap(), row.patches);
        assert_eq!(stored[0].0, MARKER_KEY);
        if stored[0].1[0] == DERIVED {
            assert_eq!(stored[0].1[1] == 1, threaded);
        }
        stored[1..].to_vec()
    }

    #[test]
    fn a_created_offer_comes_with_its_default_fields() {
        let new = [vec![0x24, 0, 0, 0, 7]].concat();
        let t = tx(0, &[node(0xE3, 0x6F, 9, &[], Some((0xE8, &new)))]);
        let id = tx_id(&t.0);
        let mut data = entry_type(0x6F);
        data.extend([0x22, 0, 0, 0, 0]);
        data.extend([0x24, 0, 0, 0, 7]);
        data.extend(prev_seq(SEQ));
        data.extend([0x33, 0, 0, 0, 0, 0, 0, 0, 0]);
        data.extend([0x34, 0, 0, 0, 0, 0, 0, 0, 0]);
        data.extend(prev_id(&id));
        assert!(round_trip(vec![t], vec![([9; 32], data)], false).is_empty());
    }

    #[test]
    fn only_what_the_metadata_lacks_is_kept() {
        let fin = vec![0x24, 0, 0, 0, 8];
        let top = {
            let mut p = vec![0x55];
            p.extend([0xAB; 32]);
            p.extend([0x25, 0, 0, 0, 1]);
            p
        };
        let t = tx(0, &[node(0xE5, 0x61, 1, &top, Some((0xE7, &fin)))]);
        let id = tx_id(&t.0);
        // The same object with one field the metadata doesn't have.
        let mut data = entry_type(0x61);
        data.extend([0x24, 0, 0, 0, 8]);
        data.extend(prev_seq(SEQ));
        data.extend([0x3A, 1, 2, 3, 4, 5, 6, 7, 8]);
        data.extend(prev_id(&id));
        let stored = round_trip(vec![t], vec![([1; 32], data)], false);
        assert_eq!(stored, vec![([1; 32], vec![0x3A, 1, 2, 3, 4, 5, 6, 7, 8])]);
    }

    #[test]
    fn deleted_objects_and_objects_born_and_deleted_in_the_ledger() {
        let a = tx(0, &[node(0xE3, 0x6F, 2, &[], Some((0xE8, &[])))]);
        let b = tx(
            1,
            &[
                node(0xE4, 0x6F, 2, &[], None),
                node(0xE4, 0x6F, 3, &[], None),
            ],
        );
        assert!(round_trip(vec![b, a], vec![([3; 32], vec![])], false).is_empty());
    }

    #[test]
    fn a_patch_missing_or_a_field_too_many_is_kept_whole() {
        let fin = vec![0x24, 0, 0, 0, 8];
        let a = tx(0, &[node(0xE5, 0x61, 4, &[], Some((0xE7, &fin)))]);
        let b = tx(1, &[node(0xE5, 0x61, 5, &[], Some((0xE7, &fin)))]);
        // Key 4 has no patch; key 5 has no Sequence, which the metadata gives.
        let data = entry_type(0x61);
        let stored = round_trip(vec![a, b], vec![([5; 32], data.clone())], false);
        assert_eq!(
            stored,
            vec![
                ([4; 32], vec![NO_PATCH]),
                ([5; 32], [&[WHOLE], &data[..]].concat())
            ]
        );
    }

    #[test]
    fn a_later_transaction_wins_whatever_the_order_of_the_rows() {
        let a = tx(
            0,
            &[node(0xE5, 0x61, 6, &[], Some((0xE7, &[0x24, 0, 0, 0, 1])))],
        );
        let b = tx(
            1,
            &[node(0xE5, 0x61, 6, &[], Some((0xE7, &[0x24, 0, 0, 0, 2])))],
        );
        let data = [entry_type(0x61), vec![0x24, 0, 0, 0, 2]].concat();
        assert!(round_trip(vec![b, a], vec![([6; 32], data)], false).is_empty());
    }

    #[test]
    fn each_ledger_keeps_the_directory_rule_that_stores_less() {
        let a = tx(
            0,
            &[node(
                0xE3,
                DIRECTORY,
                7,
                &[],
                Some((0xE8, &[0x24, 0, 0, 0, 1])),
            )],
        );
        let id = tx_id(&a.0);
        let base = [
            entry_type(DIRECTORY),
            vec![0x22, 0, 0, 0, 0],
            vec![0x24, 0, 0, 0, 1],
        ]
        .concat();
        let threaded = [base.clone(), prev_seq(SEQ), prev_id(&id)].concat();
        assert!(round_trip(vec![a.clone()], vec![([7; 32], base)], false).is_empty());
        assert!(round_trip(vec![a], vec![([7; 32], threaded)], true).is_empty());
    }

    #[test]
    fn rows_written_before_this_format_hold_every_patch() {
        let patches = vec![([1; 32], vec![0x11, 0, 0x61]), ([2; 32], vec![])];
        assert_eq!(restore(&[], SEQ, &patches).unwrap(), patches);
        assert_eq!(restore(&[], SEQ, &[]).unwrap(), vec![]);
    }

    #[test]
    fn an_unknown_directory_rule_is_refused() {
        let stored = vec![(MARKER_KEY, vec![DERIVED, 2])];
        assert!(restore(&[], SEQ, &stored).is_err());
    }

    #[test]
    fn a_new_directory_page_holds_the_object_the_transaction_created() {
        let t = tx(
            0,
            &[
                node(
                    0xE3,
                    DIRECTORY,
                    0x20,
                    &[],
                    Some((0xE8, &[0x24, 0, 0, 0, 1])),
                ),
                node(0xE3, 0x6F, 0x21, &[], Some((0xE8, &[0x24, 0, 0, 0, 2]))),
            ],
        );
        let id = tx_id(&t.0);
        let mut page = entry_type(DIRECTORY);
        page.extend([0x22, 0, 0, 0, 0]);
        page.extend([0x24, 0, 0, 0, 1]);
        page.extend([0x01, 0x13, 0x20]);
        page.extend([0x21; 32]);
        let mut offer = entry_type(0x6F);
        offer.extend([0x22, 0, 0, 0, 0]);
        offer.extend([0x24, 0, 0, 0, 2]);
        offer.extend(prev_seq(SEQ));
        offer.extend([0x33, 0, 0, 0, 0, 0, 0, 0, 0]);
        offer.extend([0x34, 0, 0, 0, 0, 0, 0, 0, 0]);
        offer.extend(prev_id(&id));
        let patches = vec![([0x20; 32], page), ([0x21; 32], offer)];
        assert!(round_trip(vec![t], patches, false).is_empty());
    }

    #[test]
    fn book_directories_get_zero_currencies_and_issuers() {
        let mut new = vec![0x36, 1, 2, 3, 4, 5, 6, 7, 8];
        new.extend([0x01, 0x11]);
        new.extend([9; 20]);
        let t = tx(0, &[node(0xE3, DIRECTORY, 8, &[], Some((0xE8, &new)))]);
        let mut data = entry_type(DIRECTORY);
        data.extend([0x22, 0, 0, 0, 0]);
        data.extend([0x36, 1, 2, 3, 4, 5, 6, 7, 8]);
        data.extend([0x01, 0x11]);
        data.extend([9; 20]);
        for f in [2u8, 3, 4] {
            data.extend([f, 0x11]);
            data.extend([0; 20]);
        }
        assert!(round_trip(vec![t], vec![([8; 32], data)], false).is_empty());
    }

    #[test]
    fn keys_the_metadata_does_not_name_are_kept_as_they_are() {
        let patches = vec![([1; 32], vec![0x11, 0, 0x68, 1]), ([2; 32], vec![])];
        assert_eq!(round_trip(vec![], patches.clone(), false), patches);
    }

    #[test]
    fn a_ledger_that_does_not_come_back_is_stored_as_it_is() {
        // Not sorted by key.
        let patches = vec![
            ([2; 32], vec![0x11, 0, 0x68]),
            ([1; 32], vec![0x11, 0, 0x69]),
        ];
        let row = Row {
            seq: SEQ,
            header: Vec::new(),
            txs: vec![],
            patches: patches.clone(),
        };
        let stored = compact(&row);
        assert_eq!(stored[0], (MARKER_KEY, vec![AS_IS]));
        assert_eq!(&stored[1..], &patches[..]);
        assert_eq!(restore(&[], SEQ, &stored).unwrap(), patches);
        // Metadata that can't be read.
        let row = Row {
            txs: vec![(vec![0x12], vec![0xFF, 0xFF])],
            patches: patches[1..].to_vec(),
            ..row
        };
        let stored = compact(&row);
        assert_eq!(stored[0], (MARKER_KEY, vec![AS_IS]));
        assert_eq!(restore(&row.txs, SEQ, &stored).unwrap(), row.patches);
    }
}
