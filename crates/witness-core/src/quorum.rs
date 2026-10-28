//! Quorum check: whether a ledger is confirmed by the validators that a given
//! policy trusts.
//!
//! This is a separate claim from "the signature is valid". It is always
//! relative to a trust policy (which UNL publishers we accept, how many lists
//! must contain a key, who is temporarily disabled via the Negative UNL) and
//! means nothing without that policy being stated.
//!
//! The calculation follows xrpld (`ValidatorList::calculateQuorum`): 80% of
//! the effective validators (the UNL minus those disabled by the Negative UNL),
//! but no less than 60% of the full UNL. It is computed in `float`, as there:
//! rounding at the boundaries depends on it.
//!
//! What the check does not claim. If a trusted validator is not found among
//! the signers, that means "we did not see its validation", not "it did not
//! vote": a collector can miss validations.

use std::collections::{BTreeMap, BTreeSet};

/// A key: the raw 33 bytes of a public key.
pub type Key = Vec<u8>;

/// How many lists must contain a key if no threshold is set. As in xrpld:
/// with one or two publishers one list is enough, otherwise a majority.
pub fn default_threshold(publishers: usize) -> usize {
    if publishers < 3 {
        1
    } else {
        publishers / 2 + 1
    }
}

/// The xrpld quorum for a UNL of size `unl` with `effective` effective validators.
pub fn quorum(unl: usize, effective: usize) -> usize {
    let by_effective = (effective as f32 * 0.8f32).ceil();
    let floor = (unl as f32 * 0.6f32).ceil();
    by_effective.max(floor) as usize
}

/// One publisher list, with its signature already verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedList {
    pub publisher: Key,
    pub sequence: u64,
    /// Master keys of the validators in the list.
    pub validators: BTreeSet<Key>,
    /// When it takes effect (v2 lists only), seconds since the XRPL epoch.
    pub effective: Option<u32>,
    /// When it expires, seconds since the XRPL epoch.
    pub expiration: Option<u32>,
    /// Sequence of the publisher manifest the list is signed under: lists
    /// signed with a rotated publisher key are not counted.
    pub manifest_sequence: u32,
}

impl PublishedList {
    /// Whether the list is in effect at time `t` (seconds since the XRPL epoch).
    pub fn valid_at(&self, t: u32) -> bool {
        self.valid_between(t, t)
    }

    /// Whether the list is in effect at any moment of the window `[from, to]`.
    pub fn valid_between(&self, from: u32, to: u32) -> bool {
        self.effective.is_none_or(|e| e <= to) && self.expiration.is_none_or(|x| from < x)
    }
}

/// The trust policy for a specific ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub lists: Vec<PublishedList>,
    pub threshold: usize,
    /// Keys trusted directly, without a publisher: the `[validators]` section
    /// of the xrpld config. The list threshold does not apply to them.
    pub local: BTreeSet<Key>,
    /// Master keys disabled by the Negative UNL on this ledger.
    pub negative_unl: BTreeSet<Key>,
}

impl Policy {
    /// Trusted: keys present in at least `threshold` lists, plus those
    /// trusted directly.
    pub fn trusted(&self) -> BTreeSet<Key> {
        let mut count: BTreeMap<&Key, usize> = BTreeMap::new();
        for l in &self.lists {
            for k in &l.validators {
                *count.entry(k).or_default() += 1;
            }
        }
        count
            .into_iter()
            .filter(|&(_, n)| n >= self.threshold)
            .map(|(k, _)| k.clone())
            .chain(self.local.iter().cloned())
            .collect()
    }

    /// Effective: trusted minus those disabled by the Negative UNL.
    pub fn effective(&self) -> BTreeSet<Key> {
        self.trusted()
            .difference(&self.negative_unl)
            .cloned()
            .collect()
    }
}

/// A validation for one ledger, with its signature already verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub signing_key: Key,
    /// Master key from the manifest; `None` means there is no manifest and the
    /// validator is not identified.
    pub master_key: Option<Key>,
    pub ledger_hash: [u8; 32],
    pub full: bool,
    /// Signing time from the validation itself, seconds since the XRPL epoch.
    pub signing_time: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub unl_size: usize,
    pub effective_size: usize,
    pub quorum: usize,
    /// For each hash, the effective validators that signed it with a full
    /// validation.
    pub by_hash: BTreeMap<[u8; 32], BTreeSet<Key>>,
    /// The hash that reached quorum, if any.
    pub confirmed: Option<[u8; 32]>,
    /// Effective validators whose validation we did not see.
    pub not_seen: BTreeSet<Key>,
    /// Effective validators that signed more than one hash.
    pub conflicting: BTreeSet<Key>,
    /// Signing keys without a manifest: we do not know whose they are.
    pub unattributed: BTreeSet<Key>,
    /// Signatures from validators disabled by the Negative UNL: not counted toward quorum.
    pub from_negative_unl: BTreeSet<Key>,
}

/// The policies that could have been in effect, and the publishers that have
/// no list in effect for that time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    pub policies: Vec<Policy>,
    /// Configured publishers without a list in effect. If this is not empty the
    /// policy is incomplete and nothing can be confirmed: without a publisher's
    /// list the UNL is smaller, and the quorum would be computed from a smaller number.
    pub missing: Vec<Key>,
}

/// All policies that could have been in effect at any moment of the window
/// `[from, to]` (seconds since the XRPL epoch): for each publisher, the lists
/// signed under its latest manifest and in effect within the window. Which of
/// them the network used cannot be known without a signed publication time, so
/// every combination is returned, and confirmation must hold for each one.
pub fn policies_between(
    lists: &[PublishedList],
    publishers: &[Key],
    from: u32,
    to: u32,
    threshold: usize,
    local: &BTreeSet<Key>,
) -> PolicySet {
    let threshold = if threshold == 0 {
        default_threshold(publishers.len())
    } else {
        threshold
    };
    let mut combos: Vec<Vec<PublishedList>> = vec![Vec::new()];
    let mut missing = Vec::new();
    for p in publishers {
        let mine: Vec<&PublishedList> = lists.iter().filter(|l| &l.publisher == p).collect();
        let top = mine.iter().map(|l| l.manifest_sequence).max();
        let mut candidates: Vec<PublishedList> = Vec::new();
        for l in mine {
            if Some(l.manifest_sequence) == top
                && l.valid_between(from, to)
                && !candidates.iter().any(|c| c.sequence == l.sequence)
            {
                candidates.push(l.clone());
            }
        }
        if candidates.is_empty() {
            missing.push(p.clone());
            continue;
        }
        combos = combos
            .into_iter()
            .flat_map(|c| {
                candidates.iter().map(move |l| {
                    let mut c = c.clone();
                    c.push(l.clone());
                    c
                })
            })
            .collect();
    }
    PolicySet {
        policies: combos
            .into_iter()
            .map(|lists| Policy {
                lists,
                threshold,
                local: local.clone(),
                negative_unl: BTreeSet::new(),
            })
            .collect(),
        missing,
    }
}

/// The decision for a ledger hash: the time window, the policies and the outcome for each.
#[derive(Debug, Clone)]
pub struct Decision {
    /// The vote time window: from the earliest to the latest signing time of full
    /// validations for this hash from known validators. `None` if there are none.
    pub window: Option<(u32, u32)>,
    pub set: PolicySet,
    pub assessed: Vec<Assessment>,
    /// The hash reached quorum under every policy of the window, and the policy is complete.
    pub confirmed: bool,
}

/// Whether `hash` is confirmed under the verifier's policy. One rule shared by
/// offline bundle verification and confirmation at load time.
///
/// The time used to pick lists is the window of signed vote times for this
/// hash, not the median: duplicates and the order of validations do not change
/// the window, and every list in effect at any moment of the window must give
/// the same answer. A publisher with no list in effect in the window makes the
/// policy incomplete, and there is no confirmation.
pub fn decide(
    lists: &[PublishedList],
    publishers: &[Key],
    threshold: usize,
    local: &BTreeSet<Key>,
    observed: &[Observed],
    hash: &[u8; 32],
) -> Decision {
    let known: BTreeSet<&Key> = lists
        .iter()
        .flat_map(|l| l.validators.iter())
        .chain(local.iter())
        .collect();
    let times = observed
        .iter()
        .filter(|o| o.full && o.ledger_hash == *hash)
        .filter(|o| o.master_key.as_ref().is_some_and(|m| known.contains(m)))
        .map(|o| o.signing_time);
    let window = times.fold(None, |w: Option<(u32, u32)>, t| {
        Some(w.map_or((t, t), |(a, b)| (a.min(t), b.max(t))))
    });
    let Some((from, to)) = window else {
        return Decision {
            window,
            set: PolicySet {
                policies: Vec::new(),
                missing: Vec::new(),
            },
            assessed: Vec::new(),
            confirmed: false,
        };
    };
    let set = policies_between(lists, publishers, from, to, threshold, local);
    let assessed: Vec<Assessment> = set.policies.iter().map(|p| assess(p, observed)).collect();
    let confirmed = set.missing.is_empty()
        && !assessed.is_empty()
        && assessed.iter().all(|a| a.confirmed == Some(*hash));
    Decision {
        window,
        set,
        assessed,
        confirmed,
    }
}

pub fn assess(policy: &Policy, observed: &[Observed]) -> Assessment {
    let trusted = policy.trusted();
    let effective = policy.effective();
    let mut by_hash: BTreeMap<[u8; 32], BTreeSet<Key>> = BTreeMap::new();
    let mut hashes_of: BTreeMap<Key, BTreeSet<[u8; 32]>> = BTreeMap::new();
    let mut unattributed = BTreeSet::new();
    let mut from_negative_unl = BTreeSet::new();
    for o in observed {
        let Some(master) = &o.master_key else {
            unattributed.insert(o.signing_key.clone());
            continue;
        };
        if policy.negative_unl.contains(master) {
            from_negative_unl.insert(master.clone());
            continue;
        }
        if !effective.contains(master) {
            continue;
        }
        hashes_of
            .entry(master.clone())
            .or_default()
            .insert(o.ledger_hash);
        // Only full validations count toward quorum: a partial one means "I saw
        // this ledger", not "I accept it".
        if o.full {
            by_hash
                .entry(o.ledger_hash)
                .or_default()
                .insert(master.clone());
        }
    }
    let q = quorum(trusted.len(), effective.len());
    let confirmed = by_hash
        .iter()
        .find(|(_, signers)| signers.len() >= q)
        .map(|(h, _)| *h);
    let not_seen = effective
        .iter()
        .filter(|k| !hashes_of.contains_key(*k))
        .cloned()
        .collect();
    let conflicting = hashes_of
        .into_iter()
        .filter(|(_, hs)| hs.len() > 1)
        .map(|(k, _)| k)
        .collect();
    Assessment {
        unl_size: trusted.len(),
        effective_size: effective.len(),
        quorum: q,
        by_hash,
        confirmed,
        not_seen,
        conflicting,
        unattributed,
        from_negative_unl,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(
        publisher: u8,
        seq: u64,
        keys: &[u8],
        effective: Option<u32>,
        expiration: Option<u32>,
        manifest: u32,
    ) -> PublishedList {
        PublishedList {
            publisher: vec![publisher],
            sequence: seq,
            validators: keys.iter().map(|k| vec![*k]).collect(),
            effective,
            expiration,
            manifest_sequence: manifest,
        }
    }

    #[test]
    fn lists_are_chosen_by_ledger_time() {
        let lists = vec![
            list(1, 10, &[1, 2], None, Some(100), 1), // expired by 150
            list(1, 11, &[1, 2, 3], None, Some(200), 1), // in effect
            list(1, 12, &[1, 4], Some(180), Some(300), 1), // takes effect later
            list(1, 13, &[9], None, Some(500), 0),    // old publisher key
            list(2, 5, &[5], None, Some(400), 2),
            list(2, 6, &[5, 6], None, Some(400), 2), // also in effect
        ];
        let ps = policies_between(&lists, &[vec![1], vec![2]], 150, 150, 0, &BTreeSet::new());
        assert!(ps.missing.is_empty());
        let got: Vec<Vec<u64>> = ps
            .policies
            .iter()
            .map(|p| p.lists.iter().map(|l| l.sequence).collect())
            .collect();
        assert_eq!(got, vec![vec![11, 5], vec![11, 6]]);
        // Once all lists of the first publisher expire, the policy is incomplete.
        let ps = policies_between(&lists, &[vec![1], vec![2]], 350, 350, 0, &BTreeSet::new());
        assert_eq!(ps.missing, vec![vec![1]]);
        // The 150..190 window also covers list 12, which takes effect at 180.
        let ps = policies_between(&lists, &[vec![1], vec![2]], 150, 190, 0, &BTreeSet::new());
        assert_eq!(ps.policies.len(), 4);
    }

    #[test]
    fn quorum_matches_xrpld() {
        // 2026-10-23: two lists of 35 give 36 trusted validators, and the node
        // reports validation_quorum 29.
        assert_eq!(quorum(36, 36), 29);
        assert_eq!(quorum(35, 35), 28);
        // The Negative UNL disabled two: 80% of 33.
        assert_eq!(quorum(35, 33), 27);
        // Too many disabled: the 60%-of-UNL floor kicks in.
        assert_eq!(quorum(35, 20), 21);
        assert_eq!(default_threshold(1), 1);
        assert_eq!(default_threshold(2), 1);
        assert_eq!(default_threshold(3), 2);
        assert_eq!(default_threshold(4), 3);
    }

    fn key(i: u8) -> Key {
        vec![i; 33]
    }

    fn policy(n: u8, negative: &[u8]) -> Policy {
        Policy {
            lists: vec![PublishedList {
                publisher: key(200),
                sequence: 1,
                validators: (0..n).map(key).collect(),
                effective: None,
                expiration: None,
                manifest_sequence: 1,
            }],
            threshold: 1,
            local: BTreeSet::new(),
            negative_unl: negative.iter().map(|&i| key(i)).collect(),
        }
    }

    fn signed(i: u8, hash: u8, full: bool) -> Observed {
        signed_at(i, hash, full, 100)
    }

    fn signed_at(i: u8, hash: u8, full: bool, signing_time: u32) -> Observed {
        Observed {
            signing_key: key(100 + i),
            master_key: Some(key(i)),
            ledger_hash: [hash; 32],
            full,
            signing_time,
        }
    }

    fn listed(
        publisher: u8,
        seq: u64,
        n: u8,
        effective: Option<u32>,
        exp: Option<u32>,
    ) -> PublishedList {
        PublishedList {
            publisher: key(publisher),
            sequence: seq,
            validators: (0..n).map(key).collect(),
            effective,
            expiration: exp,
            manifest_sequence: 1,
        }
    }

    /// The first publisher has 5 validators, the second 10, and there are
    /// four signatures. With both lists it is not confirmed; without the second
    /// publisher's response it used to come out "confirmed" with quorum 4.
    #[test]
    fn missing_publisher_is_not_a_smaller_unl() {
        let (a, b) = (
            listed(200, 1, 5, None, None),
            listed(201, 1, 10, None, None),
        );
        let pubs = [key(200), key(201)];
        let obs: Vec<_> = (0..4).map(|i| signed(i, 1, true)).collect();
        let both = decide(&[a.clone(), b], &pubs, 0, &BTreeSet::new(), &obs, &[1; 32]);
        assert!(!both.confirmed);
        assert_eq!(both.assessed[0].quorum, 8);
        let one = decide(&[a], &pubs, 0, &BTreeSet::new(), &obs, &[1; 32]);
        assert!(!one.confirmed);
        assert_eq!(one.set.missing, vec![key(201)]);
    }

    /// An old list of 5 expires at 150, a new list of 10 is in effect from 150;
    /// signatures at 149, 150, 150, 150. Duplicates of one validation no longer
    /// shift the time toward the old list.
    #[test]
    fn duplicates_do_not_move_policy_time() {
        let lists = [
            listed(200, 1, 5, None, Some(150)),
            listed(200, 2, 10, Some(150), None),
        ];
        let pubs = [key(200)];
        let mut obs = vec![
            signed_at(0, 1, true, 149),
            signed_at(1, 1, true, 150),
            signed_at(2, 1, true, 150),
            signed_at(3, 1, true, 150),
        ];
        let base = decide(&lists, &pubs, 0, &BTreeSet::new(), &obs, &[1; 32]);
        assert!(!base.confirmed);
        assert_eq!(base.window, Some((149, 150)));
        for _ in 0..4 {
            obs.push(obs[0].clone());
        }
        let dup = decide(&lists, &pubs, 0, &BTreeSet::new(), &obs, &[1; 32]);
        assert!(!dup.confirmed);
        assert_eq!(dup.window, base.window);
        obs.reverse();
        assert!(!decide(&lists, &pubs, 0, &BTreeSet::new(), &obs, &[1; 32]).confirmed);
        // The window touches both lists: confirmation only if both agree.
        let all: Vec<_> = (0..10)
            .map(|i| signed_at(i, 1, true, 149 + u32::from(i % 2)))
            .collect();
        let ok = decide(&lists, &pubs, 0, &BTreeSet::new(), &all, &[1; 32]);
        assert!(ok.confirmed);
        assert_eq!(ok.set.policies.len(), 2);
    }

    #[test]
    fn ledger_is_confirmed_at_quorum_and_not_below() {
        let p = policy(10, &[]);
        assert_eq!(quorum(10, 10), 8);
        let eight: Vec<_> = (0..8).map(|i| signed(i, 1, true)).collect();
        let a = assess(&p, &eight);
        assert_eq!(a.confirmed, Some([1; 32]));
        assert_eq!(a.not_seen.len(), 2);
        let seven = &eight[..7];
        assert_eq!(assess(&p, seven).confirmed, None);
    }

    #[test]
    fn partial_validations_do_not_count_but_are_seen() {
        let p = policy(10, &[]);
        let mut obs: Vec<_> = (0..7).map(|i| signed(i, 1, true)).collect();
        obs.push(signed(7, 1, false));
        let a = assess(&p, &obs);
        assert_eq!(a.confirmed, None);
        assert_eq!(a.not_seen.len(), 2);
    }

    #[test]
    fn negative_unl_lowers_quorum_and_its_votes_do_not_count() {
        // Two are disabled: the quorum, 80% of 8, is 7.
        let p = policy(10, &[8, 9]);
        let mut obs: Vec<_> = (0..7).map(|i| signed(i, 1, true)).collect();
        obs.push(signed(9, 1, true));
        let a = assess(&p, &obs);
        assert_eq!(a.quorum, 7);
        assert_eq!(a.effective_size, 8);
        assert_eq!(a.confirmed, Some([1; 32]));
        assert!(a.from_negative_unl.contains(&key(9)));
        assert_eq!(a.by_hash[&[1; 32]].len(), 7);
    }

    #[test]
    fn conflicts_and_unknown_keys_are_reported() {
        let p = policy(10, &[]);
        let mut obs: Vec<_> = (0..8).map(|i| signed(i, 1, true)).collect();
        obs.push(signed(0, 2, true));
        obs.push(Observed {
            signing_key: key(150),
            master_key: None,
            ledger_hash: [1; 32],
            full: true,
            signing_time: 100,
        });
        let a = assess(&p, &obs);
        assert_eq!(a.confirmed, Some([1; 32]));
        assert!(a.conflicting.contains(&key(0)));
        assert!(a.unattributed.contains(&key(150)));
    }

    #[test]
    fn threshold_two_of_three_lists() {
        let mk = |ks: &[u8]| PublishedList {
            publisher: key(200),
            sequence: 1,
            validators: ks.iter().map(|&i| key(i)).collect(),
            effective: None,
            expiration: None,
            manifest_sequence: 1,
        };
        let p = Policy {
            lists: vec![mk(&[1, 2, 3]), mk(&[2, 3, 4]), mk(&[3, 4, 5])],
            threshold: 2,
            local: [9].iter().map(|&i| key(i)).collect(),
            negative_unl: BTreeSet::new(),
        };
        // Key 9 is trusted directly, so the list threshold does not apply to it.
        assert_eq!(
            p.trusted(),
            [2, 3, 4, 9]
                .iter()
                .map(|&i| key(i))
                .collect::<BTreeSet<_>>()
        );
    }
}
