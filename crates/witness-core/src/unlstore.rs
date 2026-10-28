//! The UNL archive written by the `witness-unl` collector: verified lists and
//! choosing the policy as of a given ledger.
//!
//! Directory layout: one subdirectory per publisher with raw responses, plus
//! `observations.jsonl`, the poll log: when each response (by body hash) was
//! first seen. Responses are re-verified on every load: the publisher's
//! signature and its manifest, against the verifier's pinned keys.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::evidence::{current_lists, lists_from_response};
use crate::manifest::Manifest;
use crate::quorum::{Key, Policy, PublishedList, default_threshold};
use crate::sha512_half;

type Res<T> = Result<T, String>;

/// A verified list, the publisher response it came from, and when we first
/// saw that response.
#[derive(Debug, Clone)]
pub struct Seen {
    pub list: PublishedList,
    pub site: String,
    pub body: Vec<u8>,
    pub first_seen_ms: u64,
}

/// Lists from the collector archive; the validator manifests from them go into `manifests`.
pub fn load_lists(
    unl_dir: &Path,
    publishers: &[Key],
    manifests: &mut Vec<Manifest>,
    problems: &mut Vec<String>,
) -> Res<Vec<Seen>> {
    // When each response was first seen, by body hash in the poll log.
    let mut first_seen: HashMap<String, u64> = HashMap::new();
    if let Ok(log) = fs::read_to_string(unl_dir.join("observations.jsonl")) {
        for line in log.lines() {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if let (Some(h), Some(at)) = (
                v.get("body_hash").and_then(Value::as_str),
                v.get("at_ms").and_then(Value::as_u64),
            ) {
                let e = first_seen.entry(h.to_owned()).or_insert(at);
                *e = (*e).min(at);
            }
        }
    }
    let mut out = Vec::new();
    let mut publisher_manifests = Vec::new();
    for site in fs::read_dir(unl_dir).map_err(|e| e.to_string())? {
        let site = site.map_err(|e| e.to_string())?.path();
        if !site.is_dir() {
            continue;
        }
        let site_name = site
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for file in fs::read_dir(&site).map_err(|e| e.to_string())? {
            let path = file.map_err(|e| e.to_string())?.path();
            let body = fs::read(&path).map_err(|e| e.to_string())?;
            let hash = hex::encode_upper(sha512_half(&body));
            match lists_from_response(&body, publishers) {
                Ok(got) => {
                    if got.untrusted > 0 {
                        problems.push(format!(
                            "{}: list is not from a trusted publisher, ignored",
                            path.display()
                        ));
                    }
                    manifests.extend(got.manifests);
                    publisher_manifests.extend(got.publisher_manifests);
                    for list in got.lists {
                        out.push(Seen {
                            list,
                            site: site_name.clone(),
                            body: body.clone(),
                            first_seen_ms: first_seen.get(&hash).copied().unwrap_or(u64::MAX),
                        });
                    }
                }
                Err(e) => problems.push(format!("{}: {e}", path.display())),
            }
        }
    }
    // Same as when verifying a bundle: only lists from the publisher's current key.
    let mut current: Vec<PublishedList> = out.iter().map(|s| s.list.clone()).collect();
    current_lists(&mut current, &publisher_manifests, problems);
    out.retain(|s| current.contains(&s.list));
    Ok(out)
}

/// The policy as of `at_ms`: for each publisher, the list with the highest
/// sequence among those seen by that time. If none had been seen by then,
/// the earliest one seen, flagged as such.
pub fn policy_at(
    lists: &[Seen],
    publishers: &[Key],
    at_ms: u64,
    threshold: usize,
    local: &BTreeSet<Key>,
    nunl: &BTreeSet<Key>,
) -> (Policy, bool) {
    let mut chosen = Vec::new();
    let mut observed_before = true;
    for p in publishers {
        let mine: Vec<&Seen> = lists.iter().filter(|s| &s.list.publisher == p).collect();
        let pick = mine
            .iter()
            .filter(|s| s.first_seen_ms <= at_ms)
            .max_by_key(|s| s.list.sequence)
            .or_else(|| {
                observed_before = false;
                mine.iter().min_by_key(|s| s.first_seen_ms)
            });
        if let Some(s) = pick {
            chosen.push(s.list.clone());
        }
    }
    let threshold = if threshold == 0 {
        default_threshold(publishers.len())
    } else {
        threshold
    };
    (
        Policy {
            lists: chosen,
            threshold,
            local: local.clone(),
            negative_unl: nunl.clone(),
        },
        observed_before,
    )
}
