//! XRPL keys and signatures.
//!
//! Two algorithms. An ed25519 key is 33 bytes, the first one `0xED`; the
//! message itself is signed. A secp256k1 key is a 33-byte compressed point,
//! first byte `0x02` or `0x03`; the SHA-512Half of the message is signed, and
//! the signature is DER. This is what xrpld does (`ripple::verify`), and this
//! is how we check.
//!
//! secp256k1 canonicality: a validator that sets the "fully canonical
//! signature" flag must produce a signature with low S. Without the flag
//! xrpld also accepts high S, and so do we, normalizing it to low S: it is
//! mathematically the same signature.

use std::fmt;

use ed25519_dalek::Verifier as _;
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::{Digest, Sha256};

use crate::sha512_half;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Secp256k1,
    Ed25519,
}

pub fn key_type(pk: &[u8]) -> Option<KeyType> {
    match (pk.len(), pk.first()) {
        (33, Some(0xED)) => Some(KeyType::Ed25519),
        (33, Some(0x02 | 0x03)) => Some(KeyType::Secp256k1),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    BadKey,
    BadSignatureEncoding,
    /// A high-S signature where a canonical one was required.
    NotCanonical,
    /// The signature does not match the key and message.
    Mismatch,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VerifyError::BadKey => "cannot parse key",
            VerifyError::BadSignatureEncoding => "cannot parse signature",
            VerifyError::NotCanonical => "signature is not canonical",
            VerifyError::Mismatch => "signature does not match",
        })
    }
}

impl std::error::Error for VerifyError {}

/// Checks signature `sig` over `message` with key `pk`.
pub fn verify(
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
    require_canonical: bool,
) -> Result<(), VerifyError> {
    match key_type(pk).ok_or(VerifyError::BadKey)? {
        KeyType::Ed25519 => {
            let key: [u8; 32] = pk[1..].try_into().map_err(|_| VerifyError::BadKey)?;
            let vk =
                ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| VerifyError::BadKey)?;
            let s = ed25519_dalek::Signature::from_slice(sig)
                .map_err(|_| VerifyError::BadSignatureEncoding)?;
            vk.verify(message, &s).map_err(|_| VerifyError::Mismatch)
        }
        KeyType::Secp256k1 => {
            let vk =
                k256::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| VerifyError::BadKey)?;
            let mut s = k256::ecdsa::Signature::from_der(sig)
                .map_err(|_| VerifyError::BadSignatureEncoding)?;
            // A high S is the malleable twin of a low one; `require_canonical` refuses it.
            let low = s.normalize_s();
            if low != s {
                if require_canonical {
                    return Err(VerifyError::NotCanonical);
                }
                s = low;
            }
            vk.verify_prehash(&sha512_half(message), &s)
                .map_err(|_| VerifyError::Mismatch)
        }
    }
}

const ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// Version prefix for node and validator public keys: strings like `n9…`.
pub const NODE_PUBLIC: u8 = 28;

fn checksum(data: &[u8]) -> [u8; 4] {
    let h = Sha256::digest(Sha256::digest(data));
    [h[0], h[1], h[2], h[3]]
}

/// Base58Check in the XRPL alphabet.
pub fn encode_base58(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(payload.len() + 5);
    data.push(version);
    data.extend_from_slice(payload);
    let sum = checksum(&data);
    data.extend_from_slice(&sum);

    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &data {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n(ALPHABET[0] as char, zeros));
    out.extend(
        digits
            .iter()
            .rev()
            .map(|&d| ALPHABET[usize::from(d)] as char),
    );
    out
}

/// Base58Check decoding: version and payload, if the checksum matches.
pub fn decode_base58(s: &str) -> Option<(u8, Vec<u8>)> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == ALPHABET[0]).count();
    bytes.extend(std::iter::repeat_n(0, zeros));
    bytes.reverse();
    if bytes.len() < 5 {
        return None;
    }
    let (data, sum) = bytes.split_at(bytes.len() - 4);
    (checksum(data) == sum).then(|| (data[0], data[1..].to_vec()))
}

/// A validator public key as `n9…`.
pub fn node_public(pk: &[u8]) -> String {
    encode_base58(NODE_PUBLIC, pk)
}

/// A key from an `n9…` string.
pub fn parse_node_public(s: &str) -> Option<Vec<u8>> {
    match decode_base58(s)? {
        (NODE_PUBLIC, pk) if key_type(&pk).is_some() => Some(pk),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_roundtrip_and_checksum() {
        let pk = hex::decode("0371ED125A7B4EA88D33EB92A12783D27A287FD7FEB95294C9183044624DC0D0A2")
            .unwrap();
        let s = node_public(&pk);
        assert!(s.starts_with('n'), "{s}");
        assert_eq!(parse_node_public(&s).unwrap(), pk);
        // A corrupted character breaks the checksum.
        let mut bad = s.into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'r' { b'p' } else { b'r' };
        assert!(parse_node_public(std::str::from_utf8(&bad).unwrap()).is_none());
    }

    #[test]
    fn known_publisher_key_decodes() {
        // Master key of the vl.ripple.com publisher, from its site's response.
        let pk = hex::decode("ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734")
            .unwrap();
        assert_eq!(key_type(&pk), Some(KeyType::Ed25519));
        assert_eq!(parse_node_public(&node_public(&pk)).unwrap(), pk);
    }

    #[test]
    fn key_types() {
        assert_eq!(key_type(&[0x02; 33]), Some(KeyType::Secp256k1));
        assert_eq!(key_type(&[0xED; 33]), Some(KeyType::Ed25519));
        assert_eq!(key_type(&[0x04; 33]), None);
        assert_eq!(key_type(&[0x02; 32]), None);
    }
}
