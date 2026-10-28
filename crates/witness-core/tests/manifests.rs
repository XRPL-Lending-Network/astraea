//! Manifest key rotation and revocation: only the latest manifest of each
//! master key is in effect.

// Test code: a panic on unexpected data is exactly a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};
use witness_core::evidence::signing_to_master;
use witness_core::manifest::{Manifest, REVOKED};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(k: &SigningKey) -> Vec<u8> {
    let mut p = vec![0xED];
    p.extend(k.verifying_key().to_bytes());
    p
}

fn blob(code: u8, v: &[u8]) -> Vec<u8> {
    let mut out = if code < 16 {
        vec![0x70 | code]
    } else {
        vec![0x70, code]
    };
    out.push(v.len() as u8);
    out.extend(v);
    out
}

/// A manifest: the master key signs "my signing key is such-and-such, sequence N".
fn manifest(master: &SigningKey, seq: u32, signing: Option<&SigningKey>) -> Manifest {
    let mut fields = vec![0x24];
    fields.extend(seq.to_be_bytes());
    fields.extend(blob(1, &public(master)));
    if let Some(s) = signing {
        fields.extend(blob(3, &public(s)));
    }
    let mut data = b"MAN\x00".to_vec();
    data.extend(&fields);
    let mut raw = fields.clone();
    if let Some(s) = signing {
        raw.extend(blob(6, &s.sign(&data).to_bytes()));
    }
    raw.extend(blob(18, &master.sign(&data).to_bytes()));
    let m = Manifest::parse(&raw).unwrap();
    m.verify().unwrap();
    m
}

#[test]
fn rotated_key_no_longer_belongs_to_master() {
    let (a, s1, s2) = (key(1), key(2), key(3));
    let ms = vec![manifest(&a, 2, Some(&s2)), manifest(&a, 1, Some(&s1))];
    let (map, rejected) = signing_to_master(&ms);
    assert_eq!(rejected, 0);
    assert_eq!(map.get(&public(&s2)), Some(&public(&a)));
    assert!(
        !map.contains_key(&public(&s1)),
        "a rotated signing key does not count"
    );
}

#[test]
fn revoked_master_has_no_signing_key() {
    let (b, s) = (key(4), key(5));
    let ms = vec![manifest(&b, 1, Some(&s)), manifest(&b, REVOKED, None)];
    assert!(signing_to_master(&ms).0.is_empty());
}

#[test]
fn contested_signing_key_counts_for_nobody() {
    let (c, d, s) = (key(6), key(7), key(8));
    let ms = vec![manifest(&c, 1, Some(&s)), manifest(&d, 1, Some(&s))];
    assert!(!signing_to_master(&ms).0.contains_key(&public(&s)));
}

#[test]
fn forged_manifest_is_rejected() {
    let (e, s, mallory) = (key(9), key(10), key(11));
    let good = manifest(&e, 1, Some(&s));
    // Someone else's master key claim, signed with the wrong key.
    let mut fields = vec![0x24];
    fields.extend(5u32.to_be_bytes());
    fields.extend(blob(1, &public(&e)));
    fields.extend(blob(3, &public(&mallory)));
    let mut data = b"MAN\x00".to_vec();
    data.extend(&fields);
    let mut raw = fields;
    raw.extend(blob(6, &mallory.sign(&data).to_bytes()));
    raw.extend(blob(18, &mallory.sign(&data).to_bytes()));
    let forged = Manifest::parse(&raw).unwrap();
    let (map, rejected) = signing_to_master(&[good, forged]);
    assert_eq!(rejected, 1);
    assert_eq!(map.get(&public(&s)), Some(&public(&e)));
}
