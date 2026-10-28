//! XRPL hashing.
//!
//! Almost every identifier in XRPL (the hash of a ledger, a transaction, a
//! tree node, the signed data of a validation) is SHA-512Half: the first 32
//! bytes of SHA-512 over the data preceded by a four-byte domain prefix.
//! The prefix separates the spaces: the same bytes hashed as a transaction
//! and as a tree node give different hashes.

use sha2::{Digest, Sha512};

/// Hashing domain prefixes.
///
/// Each value is three ASCII letters and a zero byte, as in the reference
/// implementation (`HashPrefix.h` in xrpld). Only the ones needed so far are
/// here; others get added together with the code that uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HashPrefix {
    /// Transaction ID: `TXN\0`.
    TransactionId = 0x5458_4E00,
    /// Leaf of the transaction tree (a transaction with its metadata): `SND\0`.
    TxNode = 0x534E_4400,
    /// Leaf of the state tree: `MLN\0`.
    LeafNode = 0x4D4C_4E00,
    /// Inner node of either tree: `MIN\0`.
    InnerNode = 0x4D49_4E00,
    /// Ledger header: `LWR\0`.
    LedgerMaster = 0x4C57_5200,
    /// Signed part of a validation: `VAL\0`.
    Validation = 0x5641_4C00,
    /// Signed part of a consensus proposal: `PRP\0`.
    Proposal = 0x5052_5000,
    /// Signed part of a validator manifest: `MAN\0`.
    Manifest = 0x4D41_4E00,
}

impl HashPrefix {
    /// The four prefix bytes, in the order they precede the data.
    pub const fn to_bytes(self) -> [u8; 4] {
        (self as u32).to_be_bytes()
    }
}

/// SHA-512Half: the first 32 bytes of SHA-512 over the data.
pub fn sha512_half(data: &[u8]) -> [u8; 32] {
    first_half(Sha512::digest(data).as_slice())
}

/// SHA-512Half over the data with a domain prefix. This is how XRPL computes hashes.
pub fn sha512_half_prefixed(prefix: HashPrefix, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(prefix.to_bytes());
    hasher.update(data);
    first_half(hasher.finalize().as_slice())
}

fn first_half(digest: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-512 of the empty string is a well-known reference value (FIPS 180-4);
    /// SHA-512Half is its first 32 bytes.
    #[test]
    fn sha512_half_of_empty_input_matches_reference() {
        assert_eq!(
            hex::encode_upper(sha512_half(b"")),
            "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE"
        );
    }

    /// A prefix is exactly the ASCII bytes visible in its name.
    #[test]
    fn prefixes_spell_their_names() {
        assert_eq!(&HashPrefix::Validation.to_bytes(), b"VAL\0");
        assert_eq!(&HashPrefix::LedgerMaster.to_bytes(), b"LWR\0");
        assert_eq!(&HashPrefix::TransactionId.to_bytes(), b"TXN\0");
        assert_eq!(&HashPrefix::Manifest.to_bytes(), b"MAN\0");
    }

    /// A prefixed hash equals the hash of the prefix concatenated with the data.
    #[test]
    fn prefixed_hash_is_hash_of_concatenation() {
        let data = b"xrpl-witness";
        let mut joined = HashPrefix::Validation.to_bytes().to_vec();
        joined.extend_from_slice(data);
        assert_eq!(
            sha512_half_prefixed(HashPrefix::Validation, data),
            sha512_half(&joined)
        );
    }
}
