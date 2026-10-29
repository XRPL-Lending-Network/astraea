//! Evidence bundle: everything needed to check one ledger without us.
//!
//! It contains only originals, bytes that others signed:
//! - UNL publisher responses byte for byte (with the publishers' signatures inside);
//! - validator manifests (signed by their master keys);
//! - the Negative UNL object from the nearest flag ledger;
//! - every validation of this ledger that we saw.
//!
//! The root of trust (publisher keys, threshold, direct trust) is set by
//! whoever verifies, not by the bundle. The policy inside the bundle only
//! records which policy it was built with; if it differs from yours, the
//! check will say so.
//!
//! Version 2 adds transaction inclusion proofs (`transactions`): for each one,
//! a path in this ledger's transaction tree. The bundle then answers two
//! questions: "the ledger is confirmed by quorum" and "the transaction is
//! recorded in this ledger". Version 1 is the same without transactions and
//! is verified the same way.
//!
//! What the bundle does not prove. That the Negative UNL object is in the
//! state tree of the confirmed ledger, and when we first saw a list, are our
//! word only; an inclusion proof is the next step. A validation missing from
//! the bundle means "we did not see it", not "the validator was silent".

use std::collections::{BTreeSet, HashMap};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::keys::node_public;
use crate::manifest::Manifest;
use crate::negative_unl::NegativeUnl;
use crate::quorum::{
    Decision, Key, Observed, Policy, PublishedList, assess, decide, default_threshold,
};
use crate::skiplist;
use crate::stateproof::StateProof;
use crate::txproof::TxProof;
use crate::unl::verify_list;
use crate::validation::Validation;

pub const FORMAT: &str = "xrpl-witness/evidence/1";
/// Bundle with transaction inclusion proofs.
pub const FORMAT_V2: &str = "xrpl-witness/evidence/2";
/// Bundle with a header chain up to the confirmed ledger and state object
/// proofs.
pub const FORMAT_V3: &str = "xrpl-witness/evidence/3";
/// Bundle that reaches older ledgers through skip lists (`skips`).
pub const FORMAT_V4: &str = "xrpl-witness/evidence/4";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub ledger_index: u32,
    /// The hash that, according to whoever built the bundle, reached quorum.
    pub ledger_hash: String,
    /// The policy the bundle was built with.
    pub policy: PolicySpec,
    pub publisher_responses: Vec<PublisherResponse>,
    /// Validator manifests in hex, beyond those inside the lists.
    pub manifests: Vec<String>,
    pub negative_unl: Option<NegativeUnlEvidence>,
    pub validations: Vec<ValidationEvidence>,
    pub provenance: Provenance,
    /// Inclusion proofs for transactions in this ledger (version 2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transactions: Vec<TxProof>,
    /// Headers (hex) from the target ledger up to and including the one confirmed
    /// by quorum (`ledger_index`), in order: each one references the hash of the
    /// previous one (version 3). Empty means the target is the confirmed ledger.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
    /// State object proofs (version 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<StateProof>,
    /// Hops to older ledgers through skip lists, in order (version 4). Each
    /// starts from a ledger the bundle already proves, and the last one ends
    /// at the target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skips: Vec<SkipHop>,
}

/// A hop back through a skip list: the list proven in the state of a ledger
/// the bundle already proves, and headers from an older ledger up to one whose
/// hash is in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipHop {
    /// The `LedgerHashes` object, present, in `xrpl-witness/state-proof/1` format.
    pub list: StateProof,
    /// Headers (hex) in order, each referencing the hash of the previous one;
    /// the hash of the last one is in the list.
    pub headers: Vec<String>,
}

/// Result for one state object in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectCheck {
    pub key: Option<String>,
    /// Whether the object is in the ledger or its absence is proved.
    pub present: Option<bool>,
    pub ledger_index: Option<u32>,
    /// The path checks out, and the ledger is confirmed by quorum or linked to
    /// a confirmed one by a hash chain.
    pub proven: bool,
    /// The ledger is linked to a confirmed one by hashes rather than confirmed itself.
    pub via_chain: bool,
    pub error: Option<String>,
}

/// Result for one transaction in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TxCheck {
    pub tx_hash: Option<String>,
    /// The tree path matches the header's transaction root.
    pub included: bool,
    /// The header is the ledger that reached quorum, or one linked to it by a
    /// hash chain.
    pub in_confirmed_ledger: bool,
    /// The ledger is linked to a confirmed one by hashes rather than confirmed itself.
    #[serde(default)]
    pub via_chain: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySpec {
    /// Publisher master keys, hex.
    pub publishers: Vec<String>,
    /// How many lists must contain a key; 0 means the xrpld default.
    pub threshold: usize,
    /// Directly trusted keys, hex.
    pub trusted_directly: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherResponse {
    pub site: String,
    /// The publisher response body byte for byte, base64.
    pub body: String,
    /// When the bundle builder first saw this response, Unix ms.
    pub first_seen_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegativeUnlEvidence {
    pub flag_ledger: u32,
    pub flag_ledger_hash: Option<String>,
    /// The NegativeUNL object in hex; `None` if there was no object.
    pub node_binary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationEvidence {
    /// The raw signed validation, hex.
    pub data: String,
    pub received_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Which collector observed the validations.
    pub source: String,
    pub exported_ms: u64,
    /// Seals of the archive segments that hold these validations.
    pub seals: Vec<String>,
}

/// What the verifier trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    pub publishers: Vec<Key>,
    pub threshold: usize,
    pub trusted_directly: BTreeSet<Key>,
}

/// What one publisher response yielded.
#[derive(Debug, Default)]
pub struct FromResponse {
    /// Lists whose signature matched one of the trusted publishers.
    pub lists: Vec<PublishedList>,
    /// Validator manifests from these lists.
    pub manifests: Vec<Manifest>,
    /// Number of lists signed by an untrusted publisher. This is not corruption,
    /// just someone else's policy: such lists simply don't count toward quorum.
    pub untrusted: usize,
    /// Trusted publisher manifests from the response (the shared one and those of
    /// `blobs_v2` elements), with verified signatures, revocations included.
    pub publisher_manifests: Vec<Manifest>,
}

/// Lists from one publisher response, verified against one of the `publishers` keys.
/// Handles v1 and v2 responses. Returns an error only if the response cannot be parsed.
pub fn lists_from_response(body: &[u8], publishers: &[Key]) -> Result<FromResponse, String> {
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).ok();
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("response is not json: {e}"))?;
    let manifest = v.get("manifest").and_then(Value::as_str).and_then(b64);
    // The list, the publisher manifest it is signed under, and the signature. A
    // `blobs_v2` element may carry its own manifest; if so it is used, otherwise the shared one.
    let item = |o: &Value, fallback: Option<&Vec<u8>>| -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let own = o.get("manifest").and_then(Value::as_str).and_then(b64);
        Some((
            b64(o.get("blob")?.as_str()?)?,
            own.or_else(|| fallback.cloned())?,
            hex::decode(o.get("signature")?.as_str()?).ok()?,
        ))
    };
    let mut blobs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> =
        item(&v, manifest.as_ref()).into_iter().collect();
    for o in v
        .get("blobs_v2")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        blobs.extend(item(o, manifest.as_ref()));
    }
    if blobs.is_empty() && manifest.is_none() {
        return Err("response has no publisher manifest".into());
    }
    let mut out = FromResponse::default();
    let mut seen_manifests: Vec<&Vec<u8>> = manifest.iter().collect();
    seen_manifests.extend(blobs.iter().map(|(_, m, _)| m));
    for raw in seen_manifests {
        if let Ok(m) = Manifest::parse(raw)
            && m.verify().is_ok()
            && publishers.contains(&m.master_key)
            && !out
                .publisher_manifests
                .iter()
                .any(|x| x.master_key == m.master_key && x.sequence == m.sequence)
        {
            out.publisher_manifests.push(m);
        }
    }
    for (blob, manifest, sig) in blobs {
        let Some((publisher, pm)) = publishers
            .iter()
            .find_map(|p| verify_list(p, &manifest, &blob, &sig).ok().map(|m| (p, m)))
        else {
            out.untrusted += 1;
            continue;
        };
        let list: Value =
            serde_json::from_slice(&blob).map_err(|e| format!("list is not json: {e}"))?;
        let mut validators = BTreeSet::new();
        for e in list
            .get("validators")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(k) = e
                .get("validation_public_key")
                .and_then(Value::as_str)
                .and_then(|h| hex::decode(h).ok())
            {
                validators.insert(k);
            }
            if let Some(m) = e
                .get("manifest")
                .and_then(Value::as_str)
                .and_then(b64)
                .and_then(|raw| Manifest::parse(&raw).ok())
            {
                out.manifests.push(m);
            }
        }
        let secs = |k: &str| {
            list.get(k)
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
        };
        out.lists.push(PublishedList {
            publisher: publisher.clone(),
            sequence: list.get("sequence").and_then(Value::as_u64).unwrap_or(0),
            validators,
            effective: secs("effective"),
            expiration: secs("expiration"),
            manifest_sequence: pm.sequence,
        });
    }
    Ok(out)
}

/// Keeps only lists signed by the publisher's current key: for each publisher,
/// the manifest with the highest sequence among all those presented (from
/// publisher responses and from the bundle) is taken. If it is revoked, the
/// publisher keeps no lists at all; if the key was rotated, lists signed with
/// the previous key are dropped. A publisher left without a list makes the
/// policy incomplete further on.
///
/// This is how a live xrpld behaves: after a key rotation old lists are not
/// accepted even for old ledgers, so checking such bundles fails outright
/// instead of guessing when the old key was still good.
pub fn current_lists(
    lists: &mut Vec<PublishedList>,
    publisher_manifests: &[Manifest],
    problems: &mut Vec<String>,
) {
    let mut latest: HashMap<&Key, &Manifest> = HashMap::new();
    for m in publisher_manifests {
        if m.verify().is_err() {
            continue;
        }
        let e = latest.entry(&m.master_key).or_insert(m);
        if m.sequence > e.sequence {
            *e = m;
        }
    }
    let mut revoked = BTreeSet::new();
    for (p, m) in &latest {
        if m.is_revoked() {
            revoked.insert((*p).clone());
            problems.push(format!(
                "publisher {}: key revoked, its lists are ignored",
                hex::encode_upper(p)
            ));
        }
    }
    lists.retain(|l| match latest.get(&l.publisher) {
        _ if revoked.contains(&l.publisher) => false,
        Some(m) => l.manifest_sequence >= m.sequence,
        None => true,
    });
}

/// Signing key → master key, from manifests whose signatures check out.
/// The second value is how many manifests were rejected.
///
/// As in xrpld: for each master key only the manifest with the highest
/// sequence is in effect. A rotated signing key no longer belongs to it; a
/// revocation (sequence 0xFFFFFFFF) leaves the master key with no signing key
/// at all. A signing key claimed by two master keys is credited to neither.
pub fn signing_to_master(manifests: &[Manifest]) -> (HashMap<Key, Key>, usize) {
    let mut latest: HashMap<Key, &Manifest> = HashMap::new();
    let mut rejected = 0;
    for m in manifests {
        if m.verify().is_err() {
            rejected += 1;
            continue;
        }
        let e = latest.entry(m.master_key.clone()).or_insert(m);
        if m.sequence > e.sequence {
            *e = m;
        }
    }
    let mut out: HashMap<Key, Key> = HashMap::new();
    let mut contested = BTreeSet::new();
    for (master, m) in &latest {
        if m.is_revoked() {
            continue;
        }
        let Some(sk) = &m.signing_key else { continue };
        match out.get(sk) {
            Some(other) if other != master => {
                contested.insert(sk.clone());
            }
            _ => {
                out.insert(sk.clone(), master.clone());
            }
        }
    }
    for sk in contested {
        out.remove(&sk);
    }
    (out, rejected)
}

/// The result of verifying a bundle.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub ledger_index: u32,
    /// The hash that reached quorum under the verifier's policy.
    pub confirmed_hash: Option<String>,
    /// Whether it matches the one claimed in the bundle.
    pub matches_claim: bool,
    pub unl_size: usize,
    pub effective_size: usize,
    pub quorum: usize,
    pub signers: usize,
    /// The bundle's policy differs from the verifier's.
    pub policy_differs: bool,
    /// The bundle builder saw the lists later than the ledger's first validation.
    pub policy_observed_after: bool,
    /// The rule used to compute the quorum. Currently always `full-unl`: 80% of
    /// the whole UNL, Negative UNL not applied, since the bundle has no proof of
    /// its inclusion in the flag ledger state. This is our own policy, not a
    /// reproduction of the historical xrpld quorum.
    pub rule: &'static str,
    /// The time window used to pick lists: from the earliest to the latest
    /// signing time of full votes for the hash from known validators,
    /// seconds since the XRPL epoch.
    pub policy_window: Option<(u32, u32)>,
    /// Configured publishers with no list in effect in the window. If not empty,
    /// the policy is incomplete and there is no confirmation.
    pub missing_publishers: Vec<String>,
    /// Every policy that could have been in effect in the window, and the result for each.
    /// The report's `confirmed_hash` is set only if they all agree and the policy is complete.
    pub policies: Vec<PolicyUsed>,
    /// The Negative UNL claimed by the bundle: the builder's word only, not part of the verdict.
    pub negative_unl: Vec<String>,
    /// What the result would be with the claimed Negative UNL, for diagnostics only.
    pub with_claimed_negative_unl: Option<ClaimedNegativeUnl>,
    pub not_seen: Vec<String>,
    pub conflicting: Vec<String>,
    pub unattributed: usize,
    /// Responses from publishers the verifier does not trust: not counted toward quorum.
    pub untrusted_publishers: Vec<String>,
    /// What in the bundle failed checks: signatures, sequences, formats.
    pub problems: Vec<String>,
    /// Per transaction in the bundle (version 2).
    pub transactions: Vec<TxCheck>,
    /// The header chain checks out (or there is none).
    pub chain_ok: bool,
    /// The bundle's target ledger: the first header of the last skip hop, the
    /// first in the chain, otherwise the confirmed one.
    pub target_ledger: Option<u32>,
    pub target_hash: Option<String>,
    /// Per state object in the bundle (version 3).
    pub objects: Vec<ObjectCheck>,
    /// Skip hops that check out (version 4); with `chain_ok`, all of them did.
    pub skip_hops: usize,
}

/// Quorum with the Negative UNL from the bundle. There is no inclusion proof,
/// so this is for reference, not a verdict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClaimedNegativeUnl {
    pub effective_size: usize,
    pub quorum: usize,
    pub confirmed_hash: Option<String>,
    pub signers: usize,
}

/// A publisher list in a policy.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListUsed {
    pub publisher: String,
    pub sequence: u64,
    pub effective: Option<u32>,
    pub expiration: Option<u32>,
}

/// One of the possible policies and its result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyUsed {
    pub lists: Vec<ListUsed>,
    pub unl_size: usize,
    pub quorum: usize,
    pub confirmed_hash: Option<String>,
}

/// The quorum counting rule in the report.
pub const RULE_FULL_UNL: &str = "full-unl";

/// Verifies a bundle against the verifier's policy.
pub fn verify(bundle: &Bundle, trust: &Trust) -> Report {
    let mut problems = Vec::new();
    if ![FORMAT, FORMAT_V2, FORMAT_V3, FORMAT_V4].contains(&bundle.format.as_str()) {
        problems.push(format!(
            "format {}, expected {FORMAT}, {FORMAT_V2}, {FORMAT_V3} or {FORMAT_V4}",
            bundle.format
        ));
    }
    let hex_set =
        |v: &[String]| -> BTreeSet<Key> { v.iter().filter_map(|h| hex::decode(h).ok()).collect() };
    let policy_differs = hex_set(&bundle.policy.publishers)
        != trust.publishers.iter().cloned().collect()
        || hex_set(&bundle.policy.trusted_directly) != trust.trusted_directly
        || bundle.policy.threshold != trust.threshold;

    let mut lists: Vec<PublishedList> = Vec::new();
    let mut manifests: Vec<Manifest> = Vec::new();
    let mut publisher_manifests: Vec<Manifest> = Vec::new();
    let mut first_seen = u64::MAX;
    let mut untrusted = Vec::new();
    for r in &bundle.publisher_responses {
        let Ok(body) = base64::engine::general_purpose::STANDARD.decode(&r.body) else {
            problems.push(format!("{}: body is not base64", r.site));
            continue;
        };
        match lists_from_response(&body, &trust.publishers) {
            Ok(got) => {
                if got.untrusted > 0 {
                    untrusted.push(r.site.clone());
                }
                if !got.lists.is_empty() {
                    first_seen = first_seen.min(r.first_seen_ms.unwrap_or(u64::MAX));
                }
                lists.extend(got.lists);
                manifests.extend(got.manifests);
                publisher_manifests.extend(got.publisher_manifests);
            }
            Err(e) => problems.push(format!("{}: {e}", r.site)),
        }
    }
    for m in &bundle.manifests {
        match hex::decode(m)
            .ok()
            .and_then(|raw| Manifest::parse(&raw).ok())
        {
            Some(m) => {
                if trust.publishers.contains(&m.master_key) {
                    publisher_manifests.push(m.clone());
                }
                manifests.push(m);
            }
            None => problems.push("cannot parse manifest".into()),
        }
    }
    current_lists(&mut lists, &publisher_manifests, &mut problems);
    let (to_master, rejected) = signing_to_master(&manifests);
    if rejected > 0 {
        problems.push(format!("manifests with an invalid signature: {rejected}"));
    }

    let negative: BTreeSet<Key> = match &bundle.negative_unl {
        None => BTreeSet::new(),
        Some(n) => {
            if n.flag_ledger >= bundle.ledger_index {
                problems.push("Negative UNL is not from the previous flag ledger".into());
            }
            match n.node_binary.as_deref().map(hex::decode) {
                None => BTreeSet::new(),
                Some(Ok(raw)) => match NegativeUnl::parse(&raw) {
                    Ok(x) => x.disabled.into_iter().map(|d| d.master_key).collect(),
                    Err(e) => {
                        problems.push(format!("Negative UNL: {e}"));
                        BTreeSet::new()
                    }
                },
                Some(Err(_)) => {
                    problems.push("Negative UNL is not hex".into());
                    BTreeSet::new()
                }
            }
        }
    };

    let mut observed = Vec::new();
    let mut first_validation = u64::MAX;
    for (i, v) in bundle.validations.iter().enumerate() {
        let parsed = hex::decode(&v.data)
            .map_err(|_| "not hex".to_string())
            .and_then(|raw| Validation::parse(&raw).map_err(|e| e.to_string()));
        let val = match parsed {
            Ok(x) => x,
            Err(e) => {
                problems.push(format!("validation {i}: {e}"));
                continue;
            }
        };
        if let Err(e) = val.verify() {
            problems.push(format!("validation {i}: {e}"));
            continue;
        }
        if val.ledger_sequence != bundle.ledger_index {
            problems.push(format!("validation {i}: ledger {}", val.ledger_sequence));
            continue;
        }
        first_validation = first_validation.min(v.received_ms);
        observed.push(Observed {
            master_key: to_master.get(&val.signing_pub_key).cloned(),
            full: val.is_full(),
            ledger_hash: val.ledger_hash,
            signing_key: val.signing_pub_key,
            signing_time: val.signing_time,
        });
    }

    // A decision for each hash with full votes, using the same rule as
    // confirmation at load time (`quorum::decide`): the time is the window of
    // signed vote times for that hash, the policies are all lists in effect in
    // the window, and a publisher with no list in effect means no confirmation.
    // The Negative UNL only lowers the threshold; until the bundle proves its
    // inclusion in the flag ledger state, it is not part of the verdict.
    let hashes: BTreeSet<[u8; 32]> = observed
        .iter()
        .filter(|o| o.full)
        .map(|o| o.ledger_hash)
        .collect();
    let decisions: Vec<([u8; 32], Decision)> = hashes
        .iter()
        .map(|h| {
            let d = decide(
                &lists,
                &trust.publishers,
                trust.threshold,
                &trust.trusted_directly,
                &observed,
                h,
            );
            (*h, d)
        })
        .collect();
    let confirmed_all: Vec<[u8; 32]> = decisions
        .iter()
        .filter(|(_, d)| d.confirmed)
        .map(|(h, _)| *h)
        .collect();
    let agreed = (confirmed_all.len() == 1).then(|| confirmed_all[0]);
    // The report gets the decision for the confirmed hash, otherwise for the
    // claimed one, otherwise for the hash with the most full votes.
    let claimed = hex::decode(&bundle.ledger_hash)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .filter(|h| hashes.contains(h));
    let most_voted = hashes.iter().copied().max_by_key(|h| {
        observed
            .iter()
            .filter(|o| o.full && o.ledger_hash == *h)
            .count()
    });
    let decision = agreed
        .or(claimed)
        .or(most_voted)
        .and_then(|h| decisions.iter().find(|(x, _)| *x == h))
        .map(|(_, d)| d.clone());
    let (policy_window, policies, assessed, missing) = match decision {
        Some(d) => (d.window, d.set.policies, d.assessed, d.set.missing),
        None => (None, Vec::new(), Vec::new(), Vec::new()),
    };
    for m in &missing {
        problems.push(format!(
            "publisher {}: no list in effect at the ledger's time, policy is incomplete",
            hex::encode_upper(m)
        ));
    }
    let empty = Policy {
        lists: Vec::new(),
        threshold: default_threshold(trust.publishers.len()),
        local: trust.trusted_directly.clone(),
        negative_unl: BTreeSet::new(),
    };
    let base = policies.first().cloned().unwrap_or(empty);
    let a = assessed
        .iter()
        .max_by_key(|a| a.quorum)
        .cloned()
        .unwrap_or_else(|| assess(&base, &observed));
    let with_claimed_negative_unl = (!negative.is_empty()).then(|| {
        let claimed = Policy {
            negative_unl: negative.clone(),
            ..base.clone()
        };
        let c = assess(&claimed, &observed);
        ClaimedNegativeUnl {
            effective_size: c.effective_size,
            quorum: c.quorum,
            confirmed_hash: c.confirmed.map(hex::encode_upper),
            signers: c.confirmed.map_or(0, |h| c.by_hash[&h].len()),
        }
    });
    let policies_used: Vec<PolicyUsed> = policies
        .iter()
        .zip(&assessed)
        .map(|(p, a)| PolicyUsed {
            lists: p
                .lists
                .iter()
                .map(|l| ListUsed {
                    publisher: hex::encode_upper(&l.publisher),
                    sequence: l.sequence,
                    effective: l.effective,
                    expiration: l.expiration,
                })
                .collect(),
            unl_size: a.unl_size,
            quorum: a.quorum,
            confirmed_hash: a.confirmed.map(hex::encode_upper),
        })
        .collect();
    let confirmed_hash = agreed.map(hex::encode_upper);
    let signers = agreed.map_or(0, |h| {
        assessed
            .iter()
            .map(|a| a.by_hash.get(&h).map_or(0, BTreeSet::len))
            .min()
            .unwrap_or(0)
    });
    // Header chain: from the target to the confirmed ledger, each one references
    // the hash of the previous one, and the last is the one confirmed by quorum.
    let (chain_ok, linked, target) = check_chain(bundle, confirmed_hash.as_deref(), &mut problems);
    let (chain_ok, linked, target, skip_hops) = if chain_ok {
        check_skips(bundle, linked, target, &mut problems)
    } else {
        (false, linked, target, 0)
    };
    let in_linked = |hash: &str| {
        linked
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(hash))
            .map(|(_, s)| *s)
    };
    let transactions = bundle
        .transactions
        .iter()
        .map(|p| match p.verify() {
            Ok(proven) => {
                let at = in_linked(&proven.ledger_hash).filter(|s| *s == proven.ledger_index);
                TxCheck {
                    in_confirmed_ledger: at.is_some(),
                    via_chain: at.is_some_and(|s| s != bundle.ledger_index),
                    tx_hash: Some(proven.tx_hash),
                    included: true,
                    error: None,
                }
            }
            Err(e) => TxCheck {
                tx_hash: None,
                included: false,
                in_confirmed_ledger: false,
                via_chain: false,
                error: Some(e),
            },
        })
        .collect();
    let objects = bundle
        .objects
        .iter()
        .map(|p| match p.verify() {
            Ok(proven) => {
                let at = in_linked(&proven.ledger_hash).filter(|s| *s == proven.ledger_index);
                ObjectCheck {
                    key: Some(proven.key),
                    present: Some(proven.present),
                    ledger_index: Some(proven.ledger_index),
                    proven: at.is_some(),
                    via_chain: at.is_some_and(|s| s != bundle.ledger_index),
                    error: None,
                }
            }
            Err(e) => ObjectCheck {
                key: None,
                present: None,
                ledger_index: None,
                proven: false,
                via_chain: false,
                error: Some(e),
            },
        })
        .collect();
    Report {
        ledger_index: bundle.ledger_index,
        matches_claim: confirmed_hash
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case(&bundle.ledger_hash)),
        confirmed_hash,
        unl_size: a.unl_size,
        effective_size: a.effective_size,
        quorum: a.quorum,
        signers,
        policy_differs,
        policy_observed_after: first_seen > first_validation,
        rule: RULE_FULL_UNL,
        policy_window,
        missing_publishers: missing.iter().map(hex::encode_upper).collect(),
        policies: policies_used,
        negative_unl: negative.iter().map(|k| node_public(k)).collect(),
        with_claimed_negative_unl,
        not_seen: a.not_seen.iter().map(|k| node_public(k)).collect(),
        conflicting: a.conflicting.iter().map(|k| node_public(k)).collect(),
        unattributed: a.unattributed.len(),
        untrusted_publishers: untrusted,
        problems,
        transactions,
        chain_ok,
        target_ledger: target.as_ref().map(|t| t.0),
        target_hash: target.map(|t| t.1),
        objects,
        skip_hops,
    }
}

/// Hashes of the ledgers the bundle proves (the confirmed one and those linked
/// to it by the chain), and the target (the first header of the chain or the confirmed ledger itself).
type Linked = (bool, Vec<(String, u32)>, Option<(u32, String)>);
/// `Linked` and the number of skip hops that checked out.
type LinkedSkips = (bool, Vec<(String, u32)>, Option<(u32, String)>, usize);

fn check_chain(bundle: &Bundle, confirmed: Option<&str>, problems: &mut Vec<String>) -> Linked {
    let Some(confirmed) = confirmed else {
        return (false, Vec::new(), None);
    };
    let anchor = (confirmed.to_owned(), bundle.ledger_index);
    if bundle.chain.is_empty() {
        return (
            true,
            vec![anchor],
            Some((bundle.ledger_index, confirmed.to_owned())),
        );
    }
    let Some(headers) = parse_headers(&bundle.chain, "chain", problems) else {
        return (false, vec![anchor], None);
    };
    let last = &headers[headers.len() - 1];
    if last.sequence != bundle.ledger_index
        || !hex::encode_upper(last.hash()).eq_ignore_ascii_case(confirmed)
    {
        problems.push("chain does not end at the confirmed ledger".into());
        return (false, vec![anchor], None);
    }
    let linked = headers
        .iter()
        .map(|h| (hex::encode_upper(h.hash()), h.sequence))
        .collect();
    let first = &headers[0];
    (
        true,
        linked,
        Some((first.sequence, hex::encode_upper(first.hash()))),
    )
}

fn parse_headers(
    hex_headers: &[String],
    what: &str,
    problems: &mut Vec<String>,
) -> Option<Vec<crate::ledger::LedgerHeader>> {
    let mut headers = Vec::with_capacity(hex_headers.len());
    for (i, h) in hex_headers.iter().enumerate() {
        match hex::decode(h)
            .ok()
            .and_then(|b| crate::ledger::LedgerHeader::parse(&b).ok())
        {
            Some(x) => headers.push(x),
            None => {
                problems.push(format!("{what}: cannot parse header {i}"));
                return None;
            }
        }
    }
    for w in headers.windows(2) {
        if w[1].sequence != w[0].sequence + 1 || w[1].parent_hash != w[0].hash() {
            problems.push(format!("{what} breaks at ledger {}", w[1].sequence));
            return None;
        }
    }
    Some(headers)
}

/// Skip hops, in order: each list must be proven present in a ledger already
/// linked, its key must be a skip list key, and the last of its headers must
/// have a hash from the list. The headers of a hop then join the linked
/// ledgers, and the first header of the last hop is the target.
fn check_skips(
    bundle: &Bundle,
    mut linked: Vec<(String, u32)>,
    mut target: Option<(u32, String)>,
    problems: &mut Vec<String>,
) -> LinkedSkips {
    for (i, hop) in bundle.skips.iter().enumerate() {
        let what = format!("skip hop {i}");
        let fail = |problems: &mut Vec<String>, m: String| {
            problems.push(format!("{what}: {m}"));
        };
        let proven = match hop.list.verify() {
            Ok(p) => p,
            Err(e) => {
                fail(problems, format!("list proof: {e}"));
                return (false, linked, target, i);
            }
        };
        let in_linked = linked
            .iter()
            .any(|(h, s)| *s == proven.ledger_index && h.eq_ignore_ascii_case(&proven.ledger_hash));
        if !proven.present || !in_linked {
            fail(
                problems,
                "the list is not proven present in a ledger the bundle proves".into(),
            );
            return (false, linked, target, i);
        }
        let Some(headers) = parse_headers(&hop.headers, &what, problems) else {
            return (false, linked, target, i);
        };
        let Some(last) = headers.last() else {
            fail(problems, "no headers".into());
            return (false, linked, target, i);
        };
        let is_key = |k: [u8; 32]| proven.key.eq_ignore_ascii_case(&hex::encode(k));
        let long = last.sequence.is_multiple_of(256) && is_key(skiplist::long_key(last.sequence));
        if !long && !is_key(skiplist::short_key()) {
            fail(
                problems,
                "the object is not the skip list for this ledger".into(),
            );
            return (false, linked, target, i);
        }
        let object = hop
            .list
            .object
            .as_deref()
            .and_then(|o| hex::decode(o).ok())
            .unwrap_or_default();
        match skiplist::hashes(&object) {
            Ok(hs) if hs.contains(&last.hash()) => {}
            Ok(_) => {
                fail(
                    problems,
                    format!("ledger {} is not in the skip list", last.sequence),
                );
                return (false, linked, target, i);
            }
            Err(e) => {
                fail(problems, e);
                return (false, linked, target, i);
            }
        }
        linked.extend(
            headers
                .iter()
                .map(|h| (hex::encode_upper(h.hash()), h.sequence)),
        );
        let first = &headers[0];
        target = Some((first.sequence, hex::encode_upper(first.hash())));
    }
    (true, linked, target, bundle.skips.len())
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::ledger::LedgerHeader;

    fn header(seq: u32, parent: [u8; 32]) -> Vec<u8> {
        let mut h = vec![0u8; 118];
        h[..4].copy_from_slice(&seq.to_be_bytes());
        h[12..44].copy_from_slice(&parent);
        h
    }

    fn bundle(anchor: u32, chain: Vec<String>) -> Bundle {
        Bundle {
            format: FORMAT_V3.into(),
            ledger_index: anchor,
            ledger_hash: String::new(),
            policy: PolicySpec {
                publishers: Vec::new(),
                threshold: 0,
                trusted_directly: Vec::new(),
            },
            publisher_responses: Vec::new(),
            manifests: Vec::new(),
            negative_unl: None,
            validations: Vec::new(),
            provenance: Provenance {
                source: String::new(),
                exported_ms: 0,
                seals: Vec::new(),
            },
            transactions: Vec::new(),
            chain,
            objects: Vec::new(),
            skips: Vec::new(),
        }
    }

    #[test]
    fn header_chain_links_target_to_confirmed() {
        let h0 = header(10, [7; 32]);
        let h1 = header(11, LedgerHeader::parse(&h0).unwrap().hash());
        let h2 = header(12, LedgerHeader::parse(&h1).unwrap().hash());
        let anchor = hex::encode_upper(LedgerHeader::parse(&h2).unwrap().hash());
        let chain: Vec<String> = [&h0, &h1, &h2].iter().map(hex::encode_upper).collect();

        let mut problems = Vec::new();
        let (ok, linked, target) =
            check_chain(&bundle(12, chain.clone()), Some(&anchor), &mut problems);
        assert!(ok && problems.is_empty(), "{problems:?}");
        assert_eq!(linked.len(), 3);
        assert_eq!(target.unwrap().0, 10);

        // Not confirmed by quorum: nothing is proved.
        let (ok, linked, _) = check_chain(&bundle(12, chain.clone()), None, &mut problems);
        assert!(!ok && linked.is_empty());

        // A break: the middle header is swapped.
        let mut broken = chain.clone();
        broken[1] = hex::encode_upper(header(11, [9; 32]));
        let mut problems = Vec::new();
        assert!(!check_chain(&bundle(12, broken), Some(&anchor), &mut problems).0);
        assert!(problems.iter().any(|p| p.contains("breaks")));

        // The chain does not end at the confirmed ledger.
        let mut problems = Vec::new();
        assert!(
            !check_chain(
                &bundle(12, chain[..2].to_vec()),
                Some(&anchor),
                &mut problems
            )
            .0
        );
    }

    #[test]
    fn skip_hop_links_an_older_ledger() {
        use crate::shamap::{prove, root, state_leaf_hash};
        // Ledgers 1000..=1024 of an old chain; 1024 is a multiple of 256.
        let mut old = vec![header(1000, [5; 32])];
        for seq in 1001..=1024 {
            let parent = LedgerHeader::parse(old.last().unwrap()).unwrap().hash();
            old.push(header(seq, parent));
        }
        let m = LedgerHeader::parse(old.last().unwrap()).unwrap().hash();
        // The long list holding the hash of 1024, in the state of a confirmed ledger.
        let key = skiplist::long_key(1024);
        let mut list = vec![0x11, 0x00, 0x68, 0x02, 0x13, 64];
        list.extend([3u8; 32]);
        list.extend(m);
        let other = ([0xAB; 32], vec![1u8, 2, 3]);
        let leaves = vec![
            (key, state_leaf_hash(&list, &key)),
            (other.0, state_leaf_hash(&other.1, &other.0)),
        ];
        let mut confirmed = header(90_000, [8; 32]);
        confirmed[76..108].copy_from_slice(&root(&leaves));
        let anchor = hex::encode_upper(LedgerHeader::parse(&confirmed).unwrap().hash());
        let mut b = bundle(90_000, vec![hex::encode_upper(&confirmed)]);
        let proof = StateProof::new(
            &confirmed,
            &key,
            Some(&list),
            None,
            &prove(&leaves, &key).unwrap(),
        );
        b.skips = vec![SkipHop {
            list: proof,
            headers: old.iter().map(hex::encode_upper).collect(),
        }];
        let check = |b: &Bundle| {
            let mut problems = Vec::new();
            let (ok, linked, target) = check_chain(b, Some(&anchor), &mut problems);
            let r = check_skips(b, linked, target, &mut problems);
            (ok && r.0, r.2.map(|t| t.0), r.1.len(), problems)
        };
        let (ok, target, linked, problems) = check(&b);
        assert!(ok, "{problems:?}");
        assert_eq!((target, linked), (Some(1000), 26));

        // The headers stop short of the ledger in the list.
        let mut short = b.clone();
        short.skips[0].headers.pop();
        let (ok, _, _, problems) = check(&short);
        assert!(
            !ok && problems.iter().any(|p| p.contains("skip list")),
            "{problems:?}"
        );

        // A hop from a ledger the bundle does not prove.
        let mut stray = b.clone();
        stray.chain = vec![hex::encode_upper(header(90_000, [9; 32]))];
        let stray_anchor = hex::encode_upper(
            LedgerHeader::parse(&hex::decode(&stray.chain[0]).unwrap())
                .unwrap()
                .hash(),
        );
        let mut problems = Vec::new();
        let (_, linked, target) = check_chain(&stray, Some(&stray_anchor), &mut problems);
        assert!(!check_skips(&stray, linked, target, &mut problems).0);
    }
}
