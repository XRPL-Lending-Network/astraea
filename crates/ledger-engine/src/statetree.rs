//! State tree (SHAMap) with the root recomputed on every ledger.
//!
//! The XRPL tree rule: zero keys under a prefix is empty, one key is the hash
//! of its leaf SHA-512Half(`MLN\0`, object, key), two or more is an inner node
//! SHA-512Half(`MIN\0`, 16 children). The root is always an inner node. There is
//! no path compression: a chain of nodes with a single inner child is stored in full.
//!
//! Two fjall keyspaces:
//! - `live`: live state keys and their leaf hashes;
//! - `tree`: inner nodes by prefix, a bitmask of non-empty children
//!   (u16, big-endian) and their hashes. Of the 7.4 million nodes in the mainnet
//!   tree, most sit at depth 6 with two or three children, so 16 hashes in a row
//!   would take four times as much space. A 512-byte node without a mask is the
//!   older dense format and is still readable.
//!
//! On each ledger the changes are overlaid on `live` in memory, only the nodes on
//! the paths of changed keys are recomputed, and the root is checked against the
//! header's `AccountHash` before writing. If it does not match, the ledger is
//! rejected. New leaf hashes and nodes go into the same batch as the state changes.
//!
//! Only the latest version of the tree is stored. For proofs against earlier
//! ledgers each update also reports the subtrees at depth `LEVEL_DEPTH` it
//! changed (4096 of them, about 1700 keys each on mainnet): with those hashes
//! kept per ledger, the top of the tree at any ledger is a few thousand
//! hashes, and the subtree below is rebuilt from the object versions.

use std::collections::{BTreeMap, HashMap};

use fjall::{Keyspace, OwnedWriteBatch};
use witness_core::sha512_half;
use witness_core::shamap::state_leaf_hash;

type Hash = [u8; 32];
const ZERO: Hash = [0; 32];

/// Depth of the subtrees whose hashes are kept per ledger.
pub const LEVEL_DEPTH: usize = 3;
/// How many subtrees there are at that depth.
pub const LEVEL_SLOTS: usize = 1 << (4 * LEVEL_DEPTH);

/// The subtree at `LEVEL_DEPTH` a key belongs to: its first three nibbles.
pub fn level_slot(key: &Hash) -> u16 {
    (u16::from(key[0]) << 4) | u16::from(key[1] >> 4)
}

/// The key range of a subtree at `LEVEL_DEPTH`.
pub fn level_range(slot: u16) -> (Hash, Hash) {
    let mut k = ZERO;
    k[0] = (slot >> 4) as u8;
    k[1] = ((slot & 0x0F) as u8) << 4;
    range_of(&k, LEVEL_DEPTH)
}

/// SHA-512Half prefix for an inner node: `MIN\0`.
const INNER_PREFIX: [u8; 4] = [b'M', b'I', b'N', 0];

fn err(e: fjall::Error) -> String {
    e.to_string()
}

pub(crate) fn nibble(key: &Hash, depth: usize) -> u8 {
    let b = key[depth / 2];
    if depth.is_multiple_of(2) {
        b >> 4
    } else {
        b & 0x0F
    }
}

/// Key with nibble `n` at depth `depth` and the nibbles below zeroed:
/// the start of the key range under this prefix.
fn with_nibble(prefix: &Hash, depth: usize, n: u8) -> Hash {
    let mut k = *prefix;
    let i = depth / 2;
    if depth.is_multiple_of(2) {
        k[i] = n << 4;
    } else {
        k[i] = (k[i] & 0xF0) | n;
    }
    k
}

/// Key range under a prefix `depth` nibbles long.
pub(crate) fn range_of(prefix: &Hash, depth: usize) -> (Hash, Hash) {
    let (mut lo, mut hi) = (*prefix, *prefix);
    for d in depth..64 {
        let i = d / 2;
        if d.is_multiple_of(2) {
            lo[i] &= 0x0F;
            hi[i] |= 0xF0;
        } else {
            lo[i] &= 0xF0;
            hi[i] |= 0x0F;
        }
    }
    (lo, hi)
}

/// Node record key: depth and the significant nibbles of the prefix.
pub(crate) fn node_key(prefix: &Hash, depth: usize) -> Vec<u8> {
    let (lo, _) = range_of(prefix, depth);
    let mut k = Vec::with_capacity(1 + depth.div_ceil(2));
    k.push(depth as u8);
    k.extend_from_slice(&lo[..depth.div_ceil(2)]);
    k
}

pub fn inner_hash(children: &[Hash; 16]) -> Hash {
    if children.iter().all(|c| *c == ZERO) {
        return ZERO;
    }
    let mut data = Vec::with_capacity(4 + 16 * 32);
    data.extend_from_slice(&INNER_PREFIX);
    for c in children {
        data.extend_from_slice(c);
    }
    sha512_half(&data)
}

pub(crate) fn decode_node(v: &[u8]) -> Option<[Hash; 16]> {
    let mut out = [ZERO; 16];
    if v.len() == 16 * 32 {
        for (i, c) in out.iter_mut().enumerate() {
            c.copy_from_slice(&v[i * 32..(i + 1) * 32]);
        }
        return Some(out);
    }
    let mask = u16::from_be_bytes([*v.first()?, *v.get(1)?]);
    if v.len() != 2 + 32 * mask.count_ones() as usize {
        return None;
    }
    let mut at = 2;
    for (i, c) in out.iter_mut().enumerate() {
        if mask & (0x8000 >> i) != 0 {
            c.copy_from_slice(&v[at..at + 32]);
            at += 32;
        }
    }
    Some(out)
}

fn encode_node(children: &[Hash; 16]) -> Vec<u8> {
    let mut mask = 0u16;
    let mut out = vec![0, 0];
    for (i, c) in children.iter().enumerate() {
        if *c != ZERO {
            mask |= 0x8000 >> i;
            out.extend_from_slice(c);
        }
    }
    out[..2].copy_from_slice(&mask.to_be_bytes());
    out
}

/// Leaf changes for a ledger: key → new leaf hash, `None` if deleted.
pub type LeafChanges = BTreeMap<Hash, Option<Hash>>;

/// Leaf hash of an object version; `None` for a deletion (an empty version).
pub fn state_leaf_hash_of(data: &[u8], key: &Hash) -> Option<Hash> {
    (!data.is_empty()).then(|| state_leaf_hash(data, key))
}

/// Leaf hashes from state changes.
pub fn leaf_changes(changes: &[crate::ledger::StateChange]) -> LeafChanges {
    changes
        .iter()
        .map(|c| match c.change {
            crate::ledger::Change::Deleted => (c.key, None),
            _ => (c.key, Some(state_leaf_hash(&c.data, &c.key))),
        })
        .collect()
}

#[derive(Clone)]
pub struct StateTree {
    pub live: Keyspace,
    pub tree: Keyspace,
}

impl std::fmt::Debug for StateTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateTree").finish_non_exhaustive()
    }
}

/// One recomputation: changes on top of `live`, plus the nodes already read or
/// written during it.
struct Round<'a> {
    t: &'a StateTree,
    changes: &'a LeafChanges,
    written: HashMap<Vec<u8>, Option<[Hash; 16]>>,
    /// Recomputed subtrees at `LEVEL_DEPTH`: slot → hash.
    level: BTreeMap<u16, Hash>,
}

impl Round<'_> {
    /// How many live keys are under the prefix (0, 1 or "2 or more"), and
    /// the single leaf if there is exactly one.
    fn count(&self, prefix: &Hash, depth: usize) -> Result<(usize, Option<Hash>), String> {
        let (lo, hi) = range_of(prefix, depth);
        let mut found: Vec<Hash> = Vec::with_capacity(2);
        let mut single: Option<Hash> = None;
        // Keys added or changed in this ledger.
        for (k, v) in self.changes.range(lo..=hi) {
            if let Some(h) = v {
                found.push(*k);
                single = Some(*h);
                if found.len() >= 2 {
                    return Ok((2, None));
                }
            }
        }
        // The remaining live keys, skipping deleted and already counted ones.
        for g in self.t.live.range(lo..=hi) {
            let (k, v) = g.into_inner().map_err(err)?;
            let key: Hash = k[..].try_into().map_err(|_| "live key")?;
            if self.changes.contains_key(&key) {
                continue;
            }
            found.push(key);
            single = <Hash>::try_from(&v[..]).ok();
            if found.len() >= 2 {
                return Ok((2, None));
            }
        }
        Ok((found.len(), if found.len() == 1 { single } else { None }))
    }

    fn node(&mut self, key: &[u8]) -> Result<Option<[Hash; 16]>, String> {
        if let Some(n) = self.written.get(key) {
            return Ok(*n);
        }
        Ok(self
            .t
            .tree
            .get(key)
            .map_err(err)?
            .and_then(|v| decode_node(&v)))
    }

    /// Removes the records of a node and its descendants on the paths of changed
    /// keys: only there could the prefix have held two or more keys.
    fn purge(&mut self, prefix: &Hash, depth: usize) -> Result<(), String> {
        let nk = node_key(prefix, depth);
        if self.node(&nk)?.is_none() {
            return Ok(());
        }
        self.written.insert(nk, None);
        for c in 0..16u8 {
            let sub = with_nibble(prefix, depth, c);
            let (lo, hi) = range_of(&sub, depth + 1);
            if self.changes.range(lo..=hi).next().is_some() {
                self.purge(&sub, depth + 1)?;
            }
        }
        Ok(())
    }

    /// Hash of the subtree under the prefix; `touched` says whether it has changes.
    fn subtree(&mut self, prefix: &Hash, depth: usize, touched: bool) -> Result<Hash, String> {
        let h = self.subtree_at(prefix, depth, touched)?;
        if depth == LEVEL_DEPTH && touched {
            self.level.insert(level_slot(prefix), h);
        }
        Ok(h)
    }

    fn subtree_at(&mut self, prefix: &Hash, depth: usize, touched: bool) -> Result<Hash, String> {
        let nk = node_key(prefix, depth);
        if depth > 0 {
            let (n, single) = self.count(prefix, depth)?;
            if n < 2 {
                // There is no node here any more (or never was), and none of its
                // descendants either: their records would go stale and resurface
                // once the prefix holds more than one key again.
                if touched {
                    self.purge(prefix, depth)?;
                }
                return Ok(if n == 0 { ZERO } else { single.unwrap_or(ZERO) });
            }
        }
        let old = self.node(&nk)?;
        if !touched && let Some(o) = old {
            return Ok(inner_hash(&o));
        }
        let (lo, hi) = range_of(prefix, depth);
        let mut children = [ZERO; 16];
        for (c, child) in children.iter_mut().enumerate() {
            let sub = with_nibble(prefix, depth, c as u8);
            let (slo, shi) = range_of(&sub, depth + 1);
            let sub_touched = self
                .changes
                .range(slo.max(lo)..=shi.min(hi))
                .next()
                .is_some();
            *child = match old {
                Some(o) if !sub_touched => o[c],
                _ => self.subtree(&sub, depth + 1, sub_touched)?,
            };
        }
        self.written.insert(nk, Some(children));
        Ok(inner_hash(&children))
    }
}

impl StateTree {
    /// Root after the changes; nodes and leaf hashes go into the batch.
    pub fn update(
        &self,
        changes: &LeafChanges,
        batch: &mut OwnedWriteBatch,
    ) -> Result<Hash, String> {
        Ok(self.update_levels(changes, batch, false)?.0)
    }

    /// Like `update`, plus the subtrees at `LEVEL_DEPTH` the changes touched,
    /// or with `full` all `LEVEL_SLOTS` of them. A full set read from a tree
    /// so sparse that a node above that depth collapsed into a leaf comes out
    /// short, and the caller can tell by its length.
    pub fn update_levels(
        &self,
        changes: &LeafChanges,
        batch: &mut OwnedWriteBatch,
        full: bool,
    ) -> Result<(Hash, BTreeMap<u16, Hash>), String> {
        let mut r = Round {
            t: self,
            changes,
            written: HashMap::new(),
            level: BTreeMap::new(),
        };
        let root = r.subtree(&ZERO, 0, !changes.is_empty())?;
        let mut level = std::mem::take(&mut r.level);
        if full {
            for top in 0..=u8::MAX {
                let mut prefix = ZERO;
                prefix[0] = top;
                if let Some(children) = r.node(&node_key(&prefix, LEVEL_DEPTH - 1))? {
                    for (c, h) in children.iter().enumerate() {
                        level.insert((u16::from(top) << 4) | c as u16, *h);
                    }
                }
            }
        }
        for (k, v) in r.written {
            match v {
                Some(children) => batch.insert(&self.tree, k, encode_node(&children)),
                None => batch.remove(&self.tree, k),
            }
        }
        for (k, v) in changes {
            match v {
                Some(h) => batch.insert(&self.live, *k, *h),
                None => batch.remove(&self.live, *k),
            }
        }
        Ok((root, level))
    }

    /// All subtrees at `LEVEL_DEPTH` as the tree stands; short if a node above
    /// that depth collapsed into a leaf, as in `update_levels`.
    pub fn levels(&self) -> Result<BTreeMap<u16, Hash>, String> {
        let mut level = BTreeMap::new();
        for top in 0..=u8::MAX {
            let mut prefix = ZERO;
            prefix[0] = top;
            if let Some(children) = self
                .tree
                .get(node_key(&prefix, LEVEL_DEPTH - 1))
                .map_err(err)?
                .and_then(|v| decode_node(&v))
            {
                for (c, h) in children.iter().enumerate() {
                    level.insert((u16::from(top) << 4) | c as u16, *h);
                }
            }
        }
        Ok(level)
    }

    /// Current root, without changes.
    pub fn root(&self) -> Result<Hash, String> {
        Ok(self
            .tree
            .get(node_key(&ZERO, 0))
            .map_err(err)?
            .and_then(|v| decode_node(&v))
            .map_or(ZERO, |c| inner_hash(&c)))
    }

    /// Builds the tree from scratch from all leaves (in ascending key order) and
    /// writes the nodes; the caller writes the leaf hashes. Returns the root.
    pub fn build(
        &self,
        leaves: &[(Hash, Hash)],
        mut emit: impl FnMut(Vec<u8>, Vec<u8>) -> Result<(), String>,
    ) -> Result<Hash, String> {
        fn go(
            leaves: &[(Hash, Hash)],
            prefix: &Hash,
            depth: usize,
            emit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<(), String>,
        ) -> Result<Hash, String> {
            if depth > 0 {
                match leaves {
                    [] => return Ok(ZERO),
                    [(_, h)] => return Ok(*h),
                    _ => {}
                }
            }
            let mut children = [ZERO; 16];
            let mut start = 0;
            while start < leaves.len() {
                let n = nibble(&leaves[start].0, depth);
                let mut end = start + 1;
                while end < leaves.len() && nibble(&leaves[end].0, depth) == n {
                    end += 1;
                }
                let sub = with_nibble(prefix, depth, n);
                children[n as usize] = go(&leaves[start..end], &sub, depth + 1, emit)?;
                start = end;
            }
            emit(node_key(prefix, depth), encode_node(&children))?;
            Ok(inner_hash(&children))
        }
        go(leaves, &ZERO, 0, &mut emit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fjall::{Database, KeyspaceCreateOptions};
    use witness_core::shamap::root;

    fn key(i: u32) -> Hash {
        // Keys with shared prefixes of different lengths: both node chains and siblings.
        let mut k = sha512_half(&i.to_be_bytes());
        if i.is_multiple_of(7) {
            k[..3].copy_from_slice(&[0xAB, 0xCD, 0xEF]);
        }
        k
    }

    #[test]
    fn node_formats_roundtrip() {
        let mut c = [ZERO; 16];
        c[0] = [1; 32];
        c[15] = [2; 32];
        let sparse = encode_node(&c);
        assert_eq!(sparse.len(), 2 + 64);
        assert_eq!(decode_node(&sparse), Some(c));
        let dense: Vec<u8> = c.iter().flat_map(|h| h.iter().copied()).collect();
        assert_eq!(decode_node(&dense), Some(c));
        assert_eq!(decode_node(&sparse[..10]), None);
    }

    #[test]
    fn incremental_root_matches_full_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::builder(dir.path()).open().unwrap();
        let t = StateTree {
            live: db.keyspace("live", KeyspaceCreateOptions::default).unwrap(),
            tree: db.keyspace("tree", KeyspaceCreateOptions::default).unwrap(),
        };
        // Initial state: 300 keys, built in one go.
        let mut state: BTreeMap<Hash, Hash> = (0..300)
            .map(|i| (key(i), sha512_half(&[i as u8, 1])))
            .collect();
        let leaves: Vec<_> = state.iter().map(|(k, v)| (*k, *v)).collect();
        let mut b = db.batch();
        for (k, v) in &leaves {
            b.insert(&t.live, *k, *v);
        }
        let built = t
            .build(&leaves, |k, v| {
                b.insert(&t.tree, k, v);
                Ok(())
            })
            .unwrap();
        b.commit().unwrap();
        assert_eq!(built, root(&leaves));
        assert_eq!(t.root().unwrap(), built);

        // Ledgers: modifications, creations, deletions, including down to one key.
        for round in 0..40u32 {
            let mut changes = LeafChanges::new();
            for j in 0..15u32 {
                let i = (round * 37 + j * 11) % 400;
                let k = key(i);
                let v = if (round + j) % 4 == 0 {
                    None
                } else {
                    Some(sha512_half(&[i as u8, round as u8, 2]))
                };
                changes.insert(k, v);
            }
            for (k, v) in &changes {
                match v {
                    Some(h) => {
                        state.insert(*k, *h);
                    }
                    None => {
                        state.remove(k);
                    }
                }
            }
            let mut b = db.batch();
            let got = t.update(&changes, &mut b).unwrap();
            b.commit().unwrap();
            let want = root(&state.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>());
            assert_eq!(got, want, "ledger {round}");
            assert_eq!(t.root().unwrap(), want);
        }

        // Delete everything except one key, then that one too.
        let keys: Vec<Hash> = state.keys().copied().collect();
        let mut changes: LeafChanges = keys[1..].iter().map(|k| (*k, None)).collect();
        let mut b = db.batch();
        let got = t.update(&changes, &mut b).unwrap();
        b.commit().unwrap();
        assert_eq!(got, root(&[(keys[0], state[&keys[0]])]));
        // Fill it up again: stale nodes must not resurface.
        let refill: LeafChanges = keys[1..]
            .iter()
            .map(|k| (*k, Some(sha512_half(k))))
            .collect();
        let mut b = db.batch();
        let got = t.update(&refill, &mut b).unwrap();
        b.commit().unwrap();
        let mut want: Vec<(Hash, Hash)> = keys[1..].iter().map(|k| (*k, sha512_half(k))).collect();
        want.push((keys[0], state[&keys[0]]));
        assert_eq!(got, root(&want));

        changes = keys.iter().map(|k| (*k, None)).collect();
        let mut b = db.batch();
        assert_eq!(t.update(&changes, &mut b).unwrap(), ZERO);
    }
}
