//! UNL publisher key lifecycle: a `blobs_v2` element with its own manifest,
//! and rotation and revocation of the publisher key.

// Test code: a panic on unexpected data is exactly a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use witness_core::evidence::{current_lists, lists_from_response};
use witness_core::manifest::REVOKED;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(k: &SigningKey) -> Vec<u8> {
    let mut p = vec![0xED];
    p.extend(k.verifying_key().to_bytes());
    p
}

fn vl(code: u8, v: &[u8]) -> Vec<u8> {
    let mut out = if code < 16 {
        vec![0x70 | code]
    } else {
        vec![0x70, code]
    };
    out.push(v.len() as u8);
    out.extend(v);
    out
}

/// A raw manifest: the master key signs "my signing key is such-and-such,
/// sequence N"; without a signing key it is a revocation.
fn manifest(master: &SigningKey, seq: u32, signing: Option<&SigningKey>) -> Vec<u8> {
    let mut fields = vec![0x24];
    fields.extend(seq.to_be_bytes());
    fields.extend(vl(1, &public(master)));
    if let Some(s) = signing {
        fields.extend(vl(3, &public(s)));
    }
    let mut data = b"MAN\x00".to_vec();
    data.extend(&fields);
    let mut raw = fields.clone();
    if let Some(s) = signing {
        raw.extend(vl(6, &s.sign(&data).to_bytes()));
    }
    raw.extend(vl(18, &master.sign(&data).to_bytes()));
    raw
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// A validator list signed with key `signing`.
fn signed_list(seq: u64, signing: &SigningKey) -> (String, String) {
    let blob = format!(
        r#"{{"sequence":{seq},"expiration":2000000000,"validators":[{{"validation_public_key":"{}"}}]}}"#,
        hex::encode_upper(public(&key(99)))
    );
    let sig = signing.sign(blob.as_bytes()).to_bytes();
    (b64(blob.as_bytes()), hex::encode_upper(sig))
}

#[test]
fn per_blob_manifest_is_used() {
    let (p, s1, s2) = (key(20), key(21), key(22));
    let (blob, sig) = signed_list(7, &s2);
    // The shared manifest has the old key, the element's has the new one, which
    // the list is signed with. Such a list used to be rejected.
    let body = serde_json::json!({
        "version": 2,
        "manifest": b64(&manifest(&p, 1, Some(&s1))),
        "blobs_v2": [{ "blob": blob, "signature": sig, "manifest": b64(&manifest(&p, 2, Some(&s2))) }],
    });
    let got = lists_from_response(body.to_string().as_bytes(), &[public(&p)]).unwrap();
    assert_eq!(got.untrusted, 0);
    assert_eq!(got.lists.len(), 1);
    assert_eq!(got.lists[0].manifest_sequence, 2);
    assert_eq!(got.publisher_manifests.len(), 2);
}

#[test]
fn rotation_and_revocation_of_the_publisher_key() {
    let (p, s1, s2) = (key(23), key(24), key(25));
    let pk = public(&p);
    let (blob, sig) = signed_list(3, &s1);
    let old = serde_json::json!({ "manifest": b64(&manifest(&p, 1, Some(&s1))), "blob": blob, "signature": sig });
    let got = lists_from_response(old.to_string().as_bytes(), std::slice::from_ref(&pk)).unwrap();
    assert_eq!(got.lists.len(), 1);

    // Rotation: manifest 2 is known, so the list from key 1 no longer counts.
    let rotated = witness_core::manifest::Manifest::parse(&manifest(&p, 2, Some(&s2))).unwrap();
    let mut lists = got.lists.clone();
    let mut problems = Vec::new();
    let mut known = got.publisher_manifests.clone();
    known.push(rotated);
    current_lists(&mut lists, &known, &mut problems);
    assert!(lists.is_empty());
    assert!(problems.is_empty());

    // Revocation: no lists left, the reason is given; manifest order does not matter.
    let revoked = witness_core::manifest::Manifest::parse(&manifest(&p, REVOKED, None)).unwrap();
    for order in [true, false] {
        let mut lists = got.lists.clone();
        let mut problems = Vec::new();
        let mut known = got.publisher_manifests.clone();
        if order {
            known.push(revoked.clone());
        } else {
            known.insert(0, revoked.clone());
        }
        current_lists(&mut lists, &known, &mut problems);
        assert!(lists.is_empty());
        assert!(problems.iter().any(|p| p.contains("revoked")));
    }

    // Without newer manifests the list stays.
    let mut lists = got.lists.clone();
    current_lists(&mut lists, &got.publisher_manifests, &mut Vec::new());
    assert_eq!(lists.len(), 1);
}
