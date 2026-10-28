//! A state object proof: whether the object is in the ledger or not.
//!
//! A path in the state tree (SHAMap) from the header's `AccountHash` root to
//! the key's slot. Three outcomes:
//! - the object is present: the key's slot holds the leaf SHA-512Half(`MLN\0`, object, key);
//! - the object is absent and the slot is empty: the last node on the path has zeros in the key's slot;
//! - the object is absent and the slot is taken by another leaf: the bundle then
//!   carries that leaf in full (key and object). It shows the key is different,
//!   and since that leaf is alone in the slot, our key is not under this prefix.
//!
//! Whether the network confirmed the header itself is decided by the evidence
//! bundle (`evidence`): by quorum or by a hash chain to a confirmed ledger.

use serde::{Deserialize, Serialize};

use crate::ledger::LedgerHeader;
use crate::shamap::{Hash, Path, state_leaf_hash, verify};

pub const FORMAT: &str = "xrpl-witness/state-proof/1";

/// A different leaf in the key's slot, used to prove absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtherLeaf {
    pub key: String,
    pub object: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    pub format: String,
    /// Ledger header, 118 bytes in hex.
    pub ledger_header: String,
    pub key: String,
    /// The object byte for byte; `None` means absence is being proved.
    pub object: Option<String>,
    /// Another leaf in the key's slot, if the object is absent but the slot is taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_leaf: Option<OtherLeaf>,
    /// Inner nodes from the root down: 16 child hashes each, in hex.
    pub path: Vec<Vec<String>>,
}

/// What the proof establishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvenState {
    pub key: String,
    pub present: bool,
    pub ledger_index: u32,
    /// Ledger hash; whether it is confirmed is checked separately.
    pub ledger_hash: String,
}

fn nibble(key: &Hash, depth: usize) -> u8 {
    let b = key[depth / 2];
    if depth.is_multiple_of(2) {
        b >> 4
    } else {
        b & 0x0F
    }
}

fn hash32(s: &str, what: &str) -> Result<Hash, String> {
    hex::decode(s)
        .map_err(|_| format!("{what} is not hex"))?
        .try_into()
        .map_err(|_| format!("{what} is not 32 bytes"))
}

impl StateProof {
    pub fn new(
        header: &[u8],
        key: &Hash,
        object: Option<&[u8]>,
        other: Option<(&Hash, &[u8])>,
        path: &Path,
    ) -> StateProof {
        StateProof {
            format: FORMAT.into(),
            ledger_header: hex::encode_upper(header),
            key: hex::encode_upper(key),
            object: object.map(hex::encode_upper),
            other_leaf: other.map(|(k, o)| OtherLeaf {
                key: hex::encode_upper(k),
                object: hex::encode_upper(o),
            }),
            path: path
                .levels
                .iter()
                .map(|l| l.iter().map(hex::encode_upper).collect())
                .collect(),
        }
    }

    pub fn verify(&self) -> Result<ProvenState, String> {
        if self.format != FORMAT {
            return Err(format!("format {}, expected {FORMAT}", self.format));
        }
        let header = LedgerHeader::parse(
            &hex::decode(&self.ledger_header).map_err(|_| "header is not hex")?,
        )
        .map_err(|e| e.to_string())?;
        let key = hash32(&self.key, "key")?;
        let mut levels = Vec::with_capacity(self.path.len());
        for level in &self.path {
            if level.len() != 16 {
                return Err("path node is not 16 hashes".into());
            }
            let mut node = [[0u8; 32]; 16];
            for (slot, h) in node.iter_mut().zip(level) {
                *slot = hash32(h, "node hash")?;
            }
            levels.push(node);
        }
        if levels.is_empty() || levels.len() > 64 {
            return Err("path is empty or longer than the key".into());
        }
        let path = Path { levels };
        let root = header.account_hash;
        let present = match (&self.object, &self.other_leaf) {
            (Some(o), None) => {
                let object = hex::decode(o).map_err(|_| "object is not hex")?;
                if !verify(&path, &key, &state_leaf_hash(&object, &key), &root) {
                    return Err("path does not match the header state root".into());
                }
                true
            }
            (None, None) => {
                // The key's slot in the last node is empty.
                if !verify(&path, &key, &[0u8; 32], &root) {
                    return Err("empty slot does not match the state root".into());
                }
                false
            }
            (None, Some(other)) => {
                let okey = hash32(&other.key, "other leaf key")?;
                if okey == key {
                    return Err("\"other\" leaf has the same key".into());
                }
                // The other leaf sits in the same slot: the keys share the
                // prefix down to the last node on the path.
                let depth = path.levels.len();
                if (0..depth).any(|d| nibble(&okey, d) != nibble(&key, d)) {
                    return Err("other leaf is not in the key's slot".into());
                }
                let object =
                    hex::decode(&other.object).map_err(|_| "other leaf object is not hex")?;
                if !verify(&path, &key, &state_leaf_hash(&object, &okey), &root) {
                    return Err("other leaf does not match the state root".into());
                }
                false
            }
            (Some(_), Some(_)) => {
                return Err("both an object and another leaf, expected one or the other".into());
            }
        };
        Ok(ProvenState {
            key: hex::encode_upper(key),
            present,
            ledger_index: header.sequence,
            ledger_hash: hex::encode_upper(header.hash()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamap::{prove, root};

    fn header_with(account_hash: Hash) -> Vec<u8> {
        let mut h = vec![0u8; 118];
        h[76..108].copy_from_slice(&account_hash);
        h
    }

    fn key(a: u8, b: u8) -> Hash {
        let mut k = [0u8; 32];
        k[0] = a;
        k[1] = b;
        k
    }

    #[test]
    fn presence_and_both_kinds_of_absence() {
        let objs: Vec<(Hash, Vec<u8>)> = vec![
            (key(0x10, 1), vec![1]),
            (key(0x10, 2), vec![2]),
            (key(0x20, 0), vec![3]),
        ];
        let leaves: Vec<(Hash, Hash)> = objs
            .iter()
            .map(|(k, o)| (*k, state_leaf_hash(o, k)))
            .collect();
        let h = header_with(root(&leaves));

        // Present.
        let p = prove(&leaves, &objs[0].0).unwrap();
        let ok = StateProof::new(&h, &objs[0].0, Some(&objs[0].1), None, &p)
            .verify()
            .unwrap();
        assert!(ok.present);
        // A tampered object does not match.
        assert!(
            StateProof::new(&h, &objs[0].0, Some(&[9]), None, &p)
                .verify()
                .is_err()
        );

        // Absent, empty slot: key 0x30…, branch 3 at the root is empty.
        let p_root = Path {
            levels: vec![prove(&leaves, &objs[0].0).unwrap().levels[0]],
        };
        let absent = StateProof::new(&h, &key(0x30, 0), None, None, &p_root)
            .verify()
            .unwrap();
        assert!(!absent.present);

        // Absent, slot taken: key 0x20 0x07, branch 2 at the root holds leaf 0x20 0x00.
        let other = StateProof::new(
            &h,
            &key(0x20, 7),
            None,
            Some((&objs[2].0, &objs[2].1)),
            &p_root,
        );
        assert!(!other.verify().unwrap().present);
        // The slot cannot be passed off as empty: branch 2 is not empty.
        assert!(
            StateProof::new(&h, &key(0x20, 7), None, None, &p_root)
                .verify()
                .is_err()
        );
        // Another leaf from the wrong slot is rejected.
        assert!(
            StateProof::new(
                &h,
                &key(0x20, 7),
                None,
                Some((&objs[0].0, &objs[0].1)),
                &p_root
            )
            .verify()
            .is_err()
        );
    }
}
