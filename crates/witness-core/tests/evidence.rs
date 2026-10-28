//! An evidence bundle on real data: mainnet ledger 107 855 813, exported from
//! an archive on 2026-10-24 with `witness-verify export`.

// Test code: a panic on unexpected data is exactly a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use witness_core::evidence::{
    Bundle, FORMAT_V2, NegativeUnlEvidence, Trust, ValidationEvidence, lists_from_response,
    signing_to_master, verify,
};
use witness_core::ledger::HEADER_LEN;
use witness_core::manifest::Manifest;
use witness_core::shamap::{prove, tx_id, tx_leaf_hash};
use witness_core::txproof::TxProof;
use witness_core::validation::Validation;

const RIPPLE: &str = "ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734";
const XRPLF: &str = "ED42AEC58B701EEBB77356FFFEC26F83C1F0407263530F068C7C73D392C7E06FD1";

fn bundle() -> Bundle {
    serde_json::from_str(include_str!("fixtures/evidence-107855813.json")).unwrap()
}

fn trust(publishers: &[&str]) -> Trust {
    Trust {
        publishers: publishers.iter().map(|h| hex::decode(h).unwrap()).collect(),
        threshold: 0,
        trusted_directly: BTreeSet::new(),
    }
}

#[test]
fn real_ledger_is_confirmed_offline() {
    let b = bundle();
    let r = verify(&b, &trust(&[RIPPLE, XRPLF]));
    assert_eq!(r.confirmed_hash.as_deref(), Some(b.ledger_hash.as_str()));
    assert!(r.matches_claim);
    assert_eq!((r.unl_size, r.quorum), (35, 28));
    assert!(r.signers >= r.quorum);
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert!(!r.policy_differs);
    // The lists are chosen by the ledger time taken from signed validations
    // and are in effect at that time.
    let (from, to) = r.policy_window.unwrap();
    assert!(from <= to);
    assert!(r.missing_publishers.is_empty());
    assert_eq!(r.policies.len(), 1);
    let seqs: Vec<u64> = r.policies[0].lists.iter().map(|l| l.sequence).collect();
    assert_eq!(seqs, vec![85, 2_026_070_302]);
    assert!(
        r.policies[0]
            .lists
            .iter()
            .all(|l| l.expiration.is_some_and(|x| from < x))
    );
}

#[test]
fn tampering_is_reported() {
    let mut b = bundle();
    let d = &mut b.validations[0].data;
    let flipped = if d.as_bytes()[60] == b'0' { "1" } else { "0" };
    d.replace_range(60..61, flipped);
    let r = verify(&b, &trust(&[RIPPLE, XRPLF]));
    assert!(
        r.problems.iter().any(|p| p.contains("signature")),
        "{:?}",
        r.problems
    );

    let mut b = bundle();
    b.ledger_hash = "00".repeat(32);
    assert!(!verify(&b, &trust(&[RIPPLE, XRPLF])).matches_claim);
}

#[test]
fn trust_comes_from_the_verifier() {
    // Trusting one publisher: the second list is ignored, but that is not corruption.
    let r = verify(&bundle(), &trust(&[RIPPLE]));
    assert!(r.policy_differs);
    assert_eq!(r.untrusted_publishers, vec!["unl.xrplf.org".to_string()]);
    assert!(r.problems.is_empty());
    assert!(r.confirmed_hash.is_some());

    // A key that signed none of the lists: nobody is trusted, no quorum.
    let stranger = format!("ED{}", "11".repeat(32));
    let r = verify(&bundle(), &trust(&[stranger.as_str()]));
    assert_eq!(r.unl_size, 0);
    assert!(r.confirmed_hash.is_none());
}

/// Without the response of one of two trusted publishers the policy is
/// incomplete: not "a smaller UNL" but a refusal with a reason.
#[test]
fn missing_trusted_publisher_does_not_confirm() {
    let mut b = bundle();
    b.publisher_responses.retain(|r| r.site != "unl.xrplf.org");
    let r = verify(&b, &trust(&[RIPPLE, XRPLF]));
    assert!(r.confirmed_hash.is_none());
    assert_eq!(r.missing_publishers, vec![XRPLF.to_string()]);
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("policy is incomplete"))
    );
}

/// Duplicates and the order of validations change neither the time window
/// nor the verdict.
#[test]
fn duplicated_and_reordered_validations_change_nothing() {
    let b = bundle();
    let base = verify(&b, &trust(&[RIPPLE, XRPLF]));
    let mut d = b.clone();
    let first = d.validations[0].clone();
    d.validations.extend(std::iter::repeat_n(first, 30));
    d.validations.reverse();
    let r = verify(&d, &trust(&[RIPPLE, XRPLF]));
    assert_eq!(r.policy_window, base.policy_window);
    assert_eq!(r.confirmed_hash, base.confirmed_hash);
    assert_eq!((r.quorum, r.signers), (base.quorum, base.signers));
}

#[test]
fn too_few_validations_do_not_confirm() {
    let mut b = bundle();
    b.validations.truncate(20);
    assert!(
        verify(&b, &trust(&[RIPPLE, XRPLF]))
            .confirmed_hash
            .is_none()
    );
}

/// A version 2 bundle: the same ledger plus proofs for two of its transactions,
/// from the ledger sample `ledger-107855813.xwtl.zst`.
fn bundle_v2() -> Bundle {
    let raw = zstd::decode_all(&include_bytes!("fixtures/ledger-107855813.xwtl.zst")[..]).unwrap();
    let mut b = &raw[6..];
    let header = b[..HEADER_LEN].to_vec();
    b = &b[HEADER_LEN + 64..];
    let n = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
    b = &b[4..];
    let mut txs = Vec::new();
    for _ in 0..n {
        b = &b[32..];
        let l = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
        let tx = b[4..4 + l].to_vec();
        b = &b[4 + l..];
        let l = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
        let meta = b[4..4 + l].to_vec();
        b = &b[4 + l..];
        txs.push((tx, meta));
    }
    let items: Vec<_> = txs
        .iter()
        .map(|(tx, meta)| {
            let id = tx_id(tx);
            (id, tx_leaf_hash(tx, meta, &id))
        })
        .collect();
    let mut bundle = bundle();
    bundle.format = FORMAT_V2.into();
    for i in [0, 300] {
        let path = prove(&items, &items[i].0).unwrap();
        bundle
            .transactions
            .push(TxProof::new(&header, &txs[i].0, &txs[i].1, &path));
    }
    bundle
}

#[test]
fn v2_bundle_proves_transactions_in_the_confirmed_ledger() {
    let b = bundle_v2();
    let json = serde_json::to_string(&b).unwrap();
    let back: Bundle = serde_json::from_str(&json).unwrap();
    let r = verify(&back, &trust(&[RIPPLE, XRPLF]));
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert!(r.confirmed_hash.is_some());
    assert_eq!(r.transactions.len(), 2);
    assert!(
        r.transactions
            .iter()
            .all(|t| t.included && t.in_confirmed_ledger)
    );
}

#[test]
fn v1_bundles_still_verify_and_carry_no_transactions() {
    let r = verify(&bundle(), &trust(&[RIPPLE, XRPLF]));
    assert!(r.transactions.is_empty());
    assert!(
        serde_json::to_string(&bundle())
            .unwrap()
            .find("\"transactions\"")
            .is_none()
    );
}

#[test]
fn transaction_from_another_ledger_is_not_in_the_confirmed_one() {
    // The proof is genuine but the header is from another ledger: change the
    // sequence in the header, and the path matches a different "ledger".
    let mut b = bundle_v2();
    let h = &mut b.transactions[0].ledger_header;
    let flipped = if h.as_bytes()[7] == b'0' { "1" } else { "0" };
    h.replace_range(7..8, flipped);
    let r = verify(&b, &trust(&[RIPPLE, XRPLF]));
    assert!(r.transactions[0].included);
    assert!(!r.transactions[0].in_confirmed_ledger);
    assert!(r.transactions[1].in_confirmed_ledger);
}

/// A NegativeUNL object disabling these master keys.
fn negative_unl(keys: &[Vec<u8>], since: u32) -> String {
    let mut v = vec![0x11, 0x00, 0x4E]; // LedgerEntryType = NegativeUNL
    v.extend([0xF0, 0x11]); // DisabledValidators
    for k in keys {
        v.extend([0xE0, 0x13]); // DisabledValidator
        v.extend([0x20, 0x1A]); // FirstLedgerSequence
        v.extend(since.to_be_bytes());
        v.push(0x71); // PublicKey
        v.push(k.len() as u8);
        v.extend(k);
        v.push(0xE1);
    }
    v.push(0xF1);
    hex::encode_upper(v)
}

/// A Negative UNL from the bundle without an inclusion proof used to lower the
/// threshold, so 27 signatures against a quorum of 28 became a confirmation.
/// No signatures are forged here; only the unproven object is substituted.
#[test]
fn claimed_negative_unl_does_not_lower_the_quorum() {
    let mut b = bundle();
    // Master keys and the UNL come from the manifests and lists in the bundle,
    // as in the verification itself.
    let publishers: Vec<Vec<u8>> = [RIPPLE, XRPLF]
        .iter()
        .map(|h| hex::decode(h).unwrap())
        .collect();
    let mut manifests: Vec<Manifest> = b
        .manifests
        .iter()
        .map(|m| Manifest::parse(&hex::decode(m).unwrap()).unwrap())
        .collect();
    let mut unl = BTreeSet::new();
    for r in &b.publisher_responses {
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD
            .decode(&r.body)
            .unwrap();
        let got = lists_from_response(&body, &publishers).unwrap();
        manifests.extend(got.manifests);
        for l in got.lists {
            unl.extend(l.validators);
        }
    }
    let (to_master, _) = signing_to_master(&manifests);
    let master_of = |v: &ValidationEvidence| {
        let val = Validation::parse(&hex::decode(&v.data).unwrap()).unwrap();
        to_master.get(&val.signing_pub_key).cloned()
    };
    // 27 distinct trusted signers.
    let mut kept = Vec::new();
    let mut signers = BTreeSet::new();
    for v in &b.validations {
        if let Some(m) = master_of(v)
            && unl.contains(&m)
            && signers.len() < 27
            && signers.insert(m)
        {
            kept.push(v.clone());
        }
    }
    assert_eq!(signers.len(), 27);
    let others: Vec<Vec<u8>> = unl.difference(&signers).take(2).cloned().collect();
    assert_eq!(others.len(), 2);
    b.validations = kept;
    b.negative_unl = None;
    let r = verify(&b, &trust(&[RIPPLE, XRPLF]));
    assert_eq!(r.quorum, 28);
    assert!(r.confirmed_hash.is_none());

    // A made-up Negative UNL disables two other trusted validators, the flag
    // ledger hash is zeros, and there is no inclusion proof.
    b.negative_unl = Some(NegativeUnlEvidence {
        flag_ledger: (b.ledger_index - 1) / 256 * 256,
        flag_ledger_hash: Some("00".repeat(32)),
        node_binary: Some(negative_unl(&others, 1)),
    });
    let r = verify(&b, &trust(&[RIPPLE, XRPLF]));
    assert!(
        r.confirmed_hash.is_none(),
        "an unproven Negative UNL must not lower the threshold"
    );
    assert_eq!(
        (r.rule, r.quorum, r.negative_unl.len()),
        ("full-unl", 28, 2)
    );
    // The reference section shows what would happen with the claimed object:
    // this is exactly the path that used to produce a confirmation.
    let c = r.with_claimed_negative_unl.unwrap();
    assert_eq!((c.effective_size, c.quorum, c.signers), (33, 27, 27));
    assert!(c.confirmed_hash.is_some());
}
