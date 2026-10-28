//! Checks the core against real data saved from the network on
//! 2026-10-23: the responses of both UNL publishers and the validator
//! manifests they list.
//!
//! The publisher keys are not taken from the responses themselves (that
//! would be a circular check) but from xrpld's default configuration
//! (`[validator_list_keys]`).

// Test code: a panic on unexpected data is exactly a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use serde_json::Value;
use witness_core::Manifest;
use witness_core::keys::node_public;
use witness_core::unl::{ListError, verify_list};

const RIPPLE: &str = "ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734";
const XRPLF: &str = "ED42AEC58B701EEBB77356FFFEC26F83C1F0407263530F068C7C73D392C7E06FD1";

struct Response {
    manifest: Vec<u8>,
    blob: Vec<u8>,
    signature: Vec<u8>,
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn load(json: &str) -> Response {
    let v: Value = serde_json::from_str(json).unwrap();
    Response {
        manifest: b64(v["manifest"].as_str().unwrap()),
        blob: b64(v["blob"].as_str().unwrap()),
        signature: hex::decode(v["signature"].as_str().unwrap()).unwrap(),
    }
}

fn check_list(json: &str, publisher: &str) -> Value {
    let r = load(json);
    let key = hex::decode(publisher).unwrap();
    let m = verify_list(&key, &r.manifest, &r.blob, &r.signature).unwrap();
    assert!(!m.is_revoked());
    serde_json::from_slice(&r.blob).unwrap()
}

/// Every validator in the list: its manifest is signed, and the master key in
/// it is the one given in the list.
fn check_validators(list: &Value) -> usize {
    let validators = list["validators"].as_array().unwrap();
    for v in validators {
        let listed = hex::decode(v["validation_public_key"].as_str().unwrap()).unwrap();
        let m = Manifest::parse(&b64(v["manifest"].as_str().unwrap())).unwrap();
        m.verify()
            .unwrap_or_else(|e| panic!("{}: {e}", node_public(&listed)));
        assert_eq!(m.master_key, listed);
    }
    validators.len()
}

#[test]
fn ripple_list_85_is_authentic() {
    let list = check_list(include_str!("fixtures/vl.ripple.com-85.json"), RIPPLE);
    assert_eq!(list["sequence"], 85);
    assert_eq!(check_validators(&list), 35);
}

#[test]
fn xrplf_list_is_authentic() {
    let list = check_list(
        include_str!("fixtures/unl.xrplf.org-2026070302.json"),
        XRPLF,
    );
    assert_eq!(list["sequence"], 2_026_070_302u64);
    assert_eq!(check_validators(&list), 35);
}

#[test]
fn list_from_the_other_publisher_is_refused() {
    let r = load(include_str!("fixtures/vl.ripple.com-85.json"));
    let xrplf = hex::decode(XRPLF).unwrap();
    assert_eq!(
        verify_list(&xrplf, &r.manifest, &r.blob, &r.signature),
        Err(ListError::WrongPublisher)
    );
}

#[test]
fn tampered_list_is_refused() {
    let r = load(include_str!("fixtures/vl.ripple.com-85.json"));
    let key = hex::decode(RIPPLE).unwrap();
    // One digit in the list sequence.
    let text = String::from_utf8(r.blob.clone()).unwrap();
    let forged = text.replacen("\"sequence\":85", "\"sequence\":86", 1);
    assert_ne!(forged, text);
    assert!(matches!(
        verify_list(&key, &r.manifest, forged.as_bytes(), &r.signature),
        Err(ListError::ListSignature(_))
    ));
}

#[test]
fn validator_manifest_from_the_list_is_authentic() {
    let r = load(include_str!("fixtures/vl.ripple.com-85.json"));
    let list: Value = serde_json::from_slice(&r.blob).unwrap();
    let v = &list["validators"][0];
    let mut raw = b64(v["manifest"].as_str().unwrap());
    let m = Manifest::parse(&raw).unwrap();
    m.verify().unwrap();
    // The list names the validator by its master key; the signature confirms
    // the manifest really belongs to that key.
    let listed = hex::decode(v["validation_public_key"].as_str().unwrap()).unwrap();
    assert_eq!(node_public(&m.master_key), node_public(&listed));
    let last = raw.len() - 1;
    raw[last] ^= 1;
    assert!(Manifest::parse(&raw).unwrap().verify().is_err());
}
