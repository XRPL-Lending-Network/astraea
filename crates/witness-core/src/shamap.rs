//! The ledger transaction tree (SHAMap) and inclusion proofs.
//!
//! A SHAMap is a tree with fan-out 16 over a 256-bit key: at depth d the
//! branch is chosen by the d-th nibble of the key. A leaf sits at the depth
//! where it becomes the only one in its subtree. The root is always an inner node.
//!
//! Hashes, as in xrpld:
//! - transaction-with-metadata leaf: SHA-512Half(`SND\0`, VL(tx), VL(meta), key);
//! - inner node: SHA-512Half(`MIN\0`, 16 child hashes; zeros for an empty one);
//! - transaction key: its hash, SHA-512Half(`TXN\0`, tx);
//! - state object leaf: SHA-512Half(`MLN\0`, object, key); the state tree
//!   is built the same way, and its root is the header's `AccountHash`.
//!
//! The transaction tree root is stored in the ledger header (`TransactionHash`),
//! and the header hash is the ledger hash that validators sign. So the path
//! from a leaf to the root ties the transaction to the network's signatures.

use crate::{HashPrefix, sha512_half};

pub type Hash = [u8; 32];

const ZERO: Hash = [0; 32];

/// XRPL length prefix (VL) for `len` bytes.
pub fn encode_vl(len: usize, out: &mut Vec<u8>) {
    match len {
        0..=192 => out.push(len as u8),
        193..=12_480 => {
            let l = len - 193;
            out.push(193 + (l >> 8) as u8);
            out.push((l & 0xFF) as u8);
        }
        _ => {
            let l = len - 12_481;
            out.push(241 + (l >> 16) as u8);
            out.push(((l >> 8) & 0xFF) as u8);
            out.push((l & 0xFF) as u8);
        }
    }
}

/// Transaction hash: its identifier and its key in the tree.
pub fn tx_id(tx: &[u8]) -> Hash {
    let mut data = HashPrefix::TransactionId.to_bytes().to_vec();
    data.extend_from_slice(tx);
    sha512_half(&data)
}

/// Hash of a "transaction with metadata" leaf.
pub fn tx_leaf_hash(tx: &[u8], meta: &[u8], key: &Hash) -> Hash {
    let mut data = HashPrefix::TxNode.to_bytes().to_vec();
    encode_vl(tx.len(), &mut data);
    data.extend_from_slice(tx);
    encode_vl(meta.len(), &mut data);
    data.extend_from_slice(meta);
    data.extend_from_slice(key);
    sha512_half(&data)
}

/// Hash of a state object leaf: SHA-512Half(`MLN\0`, object, key).
/// The root of a tree of such leaves is the ledger header's `AccountHash`.
pub fn state_leaf_hash(data: &[u8], key: &Hash) -> Hash {
    let mut d = HashPrefix::LeafNode.to_bytes().to_vec();
    d.extend_from_slice(data);
    d.extend_from_slice(key);
    sha512_half(&d)
}

fn inner_hash(children: &[Hash; 16]) -> Hash {
    if children.iter().all(|c| *c == ZERO) {
        return ZERO;
    }
    let mut data = HashPrefix::InnerNode.to_bytes().to_vec();
    for c in children {
        data.extend_from_slice(c);
    }
    sha512_half(&data)
}

fn nibble(key: &Hash, depth: usize) -> usize {
    let b = key[depth / 2];
    usize::from(if depth.is_multiple_of(2) {
        b >> 4
    } else {
        b & 0x0F
    })
}

/// Children of the inner node at depth `depth` for sorted leaves.
fn children(items: &[(Hash, Hash)], depth: usize) -> [Hash; 16] {
    let mut out = [ZERO; 16];
    let mut start = 0;
    while start < items.len() {
        let branch = nibble(&items[start].0, depth);
        let mut end = start + 1;
        while end < items.len() && nibble(&items[end].0, depth) == branch {
            end += 1;
        }
        out[branch] = subtree(&items[start..end], depth + 1);
        start = end;
    }
    out
}

fn subtree(items: &[(Hash, Hash)], depth: usize) -> Hash {
    match items {
        [] => ZERO,
        [(_, leaf)] => *leaf,
        // The key ran out but there are several leaves: a duplicate key. Such
        // a set has no real tree; the caller rejects duplicates up front
        // (`has_duplicates`), and here we only make sure not to run past the
        // key. Zeros will not match any real root.
        _ if depth >= 64 => ZERO,
        _ => inner_hash(&children(items, depth)),
    }
}

/// Whether the leaves contain a duplicate key: such a set has no tree.
pub fn has_duplicates(items: &[(Hash, Hash)]) -> bool {
    let mut keys: Vec<&Hash> = items.iter().map(|(k, _)| k).collect();
    keys.sort_unstable();
    keys.windows(2).any(|w| w[0] == w[1])
}

fn sorted(items: &[(Hash, Hash)]) -> Vec<(Hash, Hash)> {
    let mut v = items.to_vec();
    v.sort_unstable_by_key(|a| a.0);
    v
}

/// Hash of the subtree at `depth` for sorted leaves that share their first
/// `depth` nibbles: zeros if empty, the leaf itself if alone, else an inner node.
pub fn subtree_hash(items: &[(Hash, Hash)], depth: usize) -> Hash {
    subtree(items, depth)
}

/// Inner nodes from `depth` down to the slot of `key`, for sorted leaves that
/// share the key's first `depth` nibbles, and the leaf in that slot: the key's
/// own, another key's (which proves the key absent), or none.
pub fn walk_from(
    items: &[(Hash, Hash)],
    key: &Hash,
    depth: usize,
) -> (Vec<[Hash; 16]>, Option<(Hash, Hash)>) {
    let mut slice = items;
    let mut levels = Vec::new();
    for depth in depth..64 {
        levels.push(children(slice, depth));
        let branch = nibble(key, depth);
        let start = slice.partition_point(|(k, _)| nibble(k, depth) < branch);
        let len = slice[start..]
            .iter()
            .take_while(|(k, _)| nibble(k, depth) == branch)
            .count();
        slice = &slice[start..start + len];
        match slice {
            [] => return (levels, None),
            [leaf] => return (levels, Some(*leaf)),
            _ => {}
        }
    }
    (levels, None)
}

/// Tree root from leaves (key, leaf hash). An empty tree is zeros.
pub fn root(items: &[(Hash, Hash)]) -> Hash {
    let v = sorted(items);
    if v.is_empty() {
        return ZERO;
    }
    inner_hash(&children(&v, 0))
}

/// Path from the root to a leaf: the children of each inner node on the way,
/// top down. The slot of the branch taken holds the hash of the node below, or of the leaf itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub levels: Vec<[Hash; 16]>,
}

/// Path to the leaf with key `key`, if there is such a leaf.
pub fn prove(items: &[(Hash, Hash)], key: &Hash) -> Option<Path> {
    let v = sorted(items);
    let mut slice: &[(Hash, Hash)] = &v;
    let mut levels = Vec::new();
    for depth in 0..64 {
        levels.push(children(slice, depth));
        let branch = nibble(key, depth);
        let start = slice.iter().position(|(k, _)| nibble(k, depth) == branch)?;
        let len = slice[start..]
            .iter()
            .take_while(|(k, _)| nibble(k, depth) == branch)
            .count();
        slice = &slice[start..start + len];
        if let [(k, _)] = slice {
            return (k == key).then_some(Path { levels });
        }
    }
    None
}

/// The path checks out: leaf `leaf` with key `key` is in the tree with root `root`.
pub fn verify(path: &Path, key: &Hash, leaf: &Hash, root: &Hash) -> bool {
    let mut below = *leaf;
    for (depth, level) in path.levels.iter().enumerate().rev() {
        if level[nibble(key, depth)] != below {
            return false;
        }
        below = inner_hash(level);
    }
    !path.levels.is_empty() && below == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(first: u8, second: u8) -> Hash {
        let mut k = [0u8; 32];
        k[0] = first;
        k[1] = second;
        k[31] = first ^ second;
        k
    }

    #[test]
    fn vl_prefixes_match_the_decoder() {
        for len in [0, 1, 192, 193, 300, 12_480, 12_481, 20_000] {
            let mut out = Vec::new();
            encode_vl(len, &mut out);
            let mut buf = out.clone();
            buf.extend(std::iter::repeat_n(0u8, len));
            // A Blob field with this prefix parses into a value of the expected length.
            let mut field = vec![0x77];
            field.extend_from_slice(&buf);
            let f = crate::stobject::fields(&field).unwrap();
            assert_eq!(f[0].value.len(), len, "length {len}");
        }
    }

    #[test]
    fn every_leaf_has_a_path_and_forgeries_fail() {
        // Keys with shared prefixes, so there are chains of inner nodes.
        let items: Vec<(Hash, Hash)> = (0..40u8)
            .map(|i| {
                (
                    key(i % 3 * 0x10, i),
                    [i.wrapping_mul(7).wrapping_add(1); 32],
                )
            })
            .collect();
        let r = root(&items);
        for (k, leaf) in &items {
            let p = prove(&items, k).unwrap();
            assert!(verify(&p, k, leaf, &r));
            let mut wrong = *leaf;
            wrong[0] ^= 1;
            assert!(!verify(&p, k, &wrong, &r));
        }
        assert!(prove(&items, &key(0xFF, 0xFF)).is_none());
    }

    #[test]
    fn single_item_tree_still_has_an_inner_root() {
        let items = [(key(1, 2), [9; 32])];
        let r = root(&items);
        assert_ne!(r, [9; 32]);
        let p = prove(&items, &items[0].0).unwrap();
        assert_eq!(p.levels.len(), 1);
        assert!(verify(&p, &items[0].0, &items[0].1, &r));
        assert_eq!(root(&[]), ZERO);
    }
}
