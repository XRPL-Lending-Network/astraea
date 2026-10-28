//! Quorum check over the archive: whether each ledger in a range is
//! confirmed by the validators the policy trusts.
//!
//! Everything comes from the archive and is checked again; the node is not
//! trusted for anything:
//! - UNL lists are the publishers' raw responses, and their signatures are
//!   checked with the publisher keys from the policy (by default, the keys
//!   from xrpld's default configuration);
//! - when a list was in effect comes from the collector's poll log: a list
//!   applies to ledgers after the moment we first saw it;
//! - which validator is whose comes from verified manifests, both from the
//!   lists and from the node;
//! - every validation signature is checked.
//!
//! If we did not observe the policy as of the ledger (the list was seen
//! later), the result is flagged: the check then uses the list we know, not
//! the one that was certainly in effect.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use clap::Args;
use serde_json::{Value, json};
use witness_core::evidence::signing_to_master;
use witness_core::keys::node_public;
use witness_core::negative_unl::NegativeUnl;
use witness_core::quorum::{Key, Observed, assess};
use witness_core::{Manifest, Validation};
use witness_store::segment::read_segment;

use crate::archive::seals;
pub use witness_core::unlstore::{load_lists, policy_at};

/// Publisher keys from xrpld's default `[validator_list_keys]`: vl.ripple.com and
/// unl.xrplf.org.
pub const DEFAULT_PUBLISHERS: [&str; 2] = [
    "ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734",
    "ED42AEC58B701EEBB77356FFFEC26F83C1F0407263530F068C7C73D392C7E06FD1",
];

#[derive(Debug, Args)]
pub struct QuorumArgs {
    /// Archive root: segments/, manifests/, unl/.
    data_dir: PathBuf,
    /// First ledger of the range. Defaults to 1000 ledgers ending one
    /// late-arrival window before the edge of the archive: validations for the
    /// latest ledgers are still in the open segment.
    #[arg(long)]
    from: Option<u32>,
    #[arg(long)]
    to: Option<u32>,
    /// List publisher keys in hex. Defaults to xrpld's default publishers.
    #[arg(long = "publisher")]
    publishers: Vec<String>,
    /// How many lists must contain a key. 0 means the xrpld default.
    #[arg(long, default_value_t = 0)]
    threshold: usize,
    /// Keys trusted directly, like the `[validators]` section of the xrpld
    /// config. Either `n9...` form or hex.
    #[arg(long = "trust")]
    local: Vec<String>,
    /// Master keys disabled by the Negative UNL, in hex, for ledgers the archive
    /// has no observation for (`negative_unl/observations.jsonl`).
    #[arg(long = "negative-unl")]
    negative_unl: Vec<String>,
    /// Show a breakdown of every unconfirmed ledger.
    #[arg(long)]
    details: bool,
}

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Negative UNL per flag ledger, from the archiver's log. An "object not
/// found" answer means an empty list; other errors are skipped, since we know
/// nothing about such a flag ledger.
fn load_negative_unl(dir: &Path) -> Res<BTreeMap<u32, BTreeSet<Key>>> {
    let mut out = BTreeMap::new();
    let Ok(log) = fs::read_to_string(dir.join("observations.jsonl")) else {
        return Ok(out);
    };
    for line in log.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(flag) = v
            .get("flag_ledger")
            .and_then(Value::as_u64)
            .and_then(|f| u32::try_from(f).ok())
        else {
            continue;
        };
        if let Some(bin) = v.get("node_binary").and_then(Value::as_str) {
            let parsed = NegativeUnl::parse(&hex::decode(bin)?)
                .map_err(|e| format!("Negative UNL at flag ledger {flag}: {e}"))?;
            out.insert(
                flag,
                parsed.disabled.into_iter().map(|d| d.master_key).collect(),
            );
        } else if v.get("error").and_then(Value::as_str) == Some("entryNotFound") {
            out.insert(flag, BTreeSet::new());
        }
    }
    Ok(out)
}

pub fn run(args: &QuorumArgs) -> Res<bool> {
    let publishers: Vec<Key> = if args.publishers.is_empty() {
        DEFAULT_PUBLISHERS
            .iter()
            .map(hex::decode)
            .collect::<Result<_, _>>()?
    } else {
        args.publishers
            .iter()
            .map(hex::decode)
            .collect::<Result<_, _>>()?
    };
    let local: BTreeSet<Key> = args
        .local
        .iter()
        .map(|s| {
            witness_core::keys::parse_node_public(s)
                .or_else(|| hex::decode(s).ok())
                .ok_or_else(|| format!("could not parse key {s}"))
        })
        .collect::<Result<_, _>>()?;
    let nunl: BTreeSet<Key> = args
        .negative_unl
        .iter()
        .map(hex::decode)
        .collect::<Result<_, _>>()?;

    let mut manifests = Vec::new();
    let mut list_problems = Vec::new();
    let lists = load_lists(
        &args.data_dir.join("unl"),
        &publishers,
        &mut manifests,
        &mut list_problems,
    )?;
    for p in &list_problems {
        eprintln!("{p}");
    }
    if lists.is_empty() {
        return Err("the archive has no verified UNL list".into());
    }
    if let Ok(dir) = fs::read_dir(args.data_dir.join("manifests")) {
        for e in dir.flatten() {
            if e.path().extension().is_some_and(|x| x == "bin")
                && let Ok(m) = Manifest::parse(&fs::read(e.path())?)
            {
                manifests.push(m);
            }
        }
    }
    let manifest_count = manifests.len();
    let (to_master, manifests_rejected) = signing_to_master(&manifests);

    // Default range: the archive's last 1000 ledgers.
    let all_seals = seals(&args.data_dir.join("segments"))?;
    let last = all_seals
        .iter()
        .map(|(_, s)| s.coverage_last)
        .max()
        .ok_or("the archive has no seals")?;
    // Back off by the late-arrival window plus a margin for the median.
    let to = args.to.unwrap_or(last.saturating_sub(64));
    let from = args.from.unwrap_or(to.saturating_sub(999));

    // Validations in the range: signature verified, inner ledger index matches.
    let mut per_ledger: BTreeMap<u32, Vec<Observed>> = BTreeMap::new();
    let mut first_ms: BTreeMap<u32, u64> = BTreeMap::new();
    let mut bad_signatures = 0u64;
    for (seal_path, seal) in &all_seals {
        let reach = seal.nominal_last.saturating_add(512);
        if seal.nominal_first > to.saturating_add(512) || reach < from {
            continue;
        }
        let seg = PathBuf::from(
            seal_path
                .to_string_lossy()
                .replace(".seal.json", ".xwv.zst"),
        );
        for rec in read_segment(&seg)? {
            if !(from..=to).contains(&rec.ledger_index) {
                continue;
            }
            let Ok(v) = Validation::parse(&rec.data) else {
                bad_signatures += 1;
                continue;
            };
            if v.verify().is_err() || v.ledger_sequence != rec.ledger_index {
                bad_signatures += 1;
                continue;
            }
            let e = first_ms.entry(v.ledger_sequence).or_insert(rec.received_ms);
            *e = (*e).min(rec.received_ms);
            per_ledger
                .entry(v.ledger_sequence)
                .or_default()
                .push(Observed {
                    master_key: to_master.get(&v.signing_pub_key).cloned(),
                    signing_key: v.signing_pub_key.clone(),
                    ledger_hash: v.ledger_hash,
                    full: v.is_full(),
                    signing_time: v.signing_time,
                });
        }
    }

    let mut confirmed = 0u64;
    let mut unconfirmed = Vec::new();
    let mut not_seen_count: BTreeMap<Key, u64> = BTreeMap::new();
    let mut conflicts = Vec::new();
    let mut unattributed: BTreeSet<Key> = BTreeSet::new();
    let mut policy_gaps = 0u64;
    let mut signers_min = usize::MAX;
    let mut signers_sum = 0usize;
    let mut summary_policy = None;
    let ledgers_without_data: Vec<u32> = (from..=to)
        .filter(|l| !per_ledger.contains_key(l))
        .collect();
    let observed_nunl = load_negative_unl(&args.data_dir.join("negative_unl"))?;
    let mut nunl_unknown = 0u64;
    let mut nunl_nonempty = 0u64;
    for (ledger, obs) in &per_ledger {
        // State as of the last flag ledger before this one: changes recorded
        // in a flag ledger apply to the ledgers after it.
        let ledger_nunl = match observed_nunl.range(..*ledger).next_back() {
            Some((_, set)) => set,
            None => {
                nunl_unknown += 1;
                &nunl
            }
        };
        if !ledger_nunl.is_empty() {
            nunl_nonempty += 1;
        }
        let (policy, observed_before) = policy_at(
            &lists,
            &publishers,
            first_ms[ledger],
            args.threshold,
            &local,
            ledger_nunl,
        );
        if !observed_before {
            policy_gaps += 1;
        }
        let a = assess(&policy, obs);
        summary_policy.get_or_insert_with(|| {
            json!({
                "publishers": publishers.iter().map(hex::encode_upper).collect::<Vec<_>>(),
                "lists": policy.lists.iter().map(|l| json!({
                    "publisher": hex::encode_upper(&l.publisher),
                    "sequence": l.sequence,
                    "validators": l.validators.len(),
                })).collect::<Vec<_>>(),
                "threshold": policy.threshold,
                "trusted_directly": local.iter().map(|k| node_public(k)).collect::<Vec<_>>(),
                "unl_size": a.unl_size,
                "negative_unl": policy.negative_unl.iter().map(|k| node_public(k)).collect::<Vec<_>>(),
                "quorum": a.quorum,
            })
        });
        for k in &a.not_seen {
            *not_seen_count.entry(k.clone()).or_default() += 1;
        }
        for k in &a.conflicting {
            conflicts.push(json!({"ledger": ledger, "validator": node_public(k)}));
        }
        unattributed.extend(a.unattributed.iter().cloned());
        match a.confirmed {
            Some(h) => {
                confirmed += 1;
                let n = a.by_hash[&h].len();
                signers_min = signers_min.min(n);
                signers_sum += n;
            }
            None => {
                let best = a.by_hash.values().map(BTreeSet::len).max().unwrap_or(0);
                let mut entry = json!({"ledger": ledger, "best_signers": best, "quorum": a.quorum});
                if args.details {
                    entry["by_hash"] = a
                        .by_hash
                        .iter()
                        .map(|(h, s)| (hex::encode_upper(h), json!(s.len())))
                        .collect::<serde_json::Map<_, _>>()
                        .into();
                    entry["not_seen"] = a
                        .not_seen
                        .iter()
                        .map(|k| node_public(k))
                        .collect::<Vec<_>>()
                        .into();
                }
                unconfirmed.push(entry);
            }
        }
    }
    let mut often_not_seen: Vec<(Key, u64)> = not_seen_count.into_iter().collect();
    often_not_seen.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let report = json!({
        "range": [from, to],
        "policy": summary_policy,
        "policy_not_observed_before_ledger": policy_gaps,
        "negative_unl": {
            "flag_ledgers_observed": observed_nunl.len(),
            "ledgers_without_observation": nunl_unknown,
            "ledgers_with_disabled_validators": nunl_nonempty,
        },
        "manifests": {"total": manifest_count, "rejected": manifests_rejected, "signing_keys_mapped": to_master.len()},
        "ledgers_with_validations": per_ledger.len(),
        "ledgers_without_validations": ledgers_without_data.len(),
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
        "signers_on_confirmed": {
            "min": if confirmed > 0 { signers_min } else { 0 },
            "avg": if confirmed > 0 { signers_sum as f64 / confirmed as f64 } else { 0.0 },
        },
        "conflicting_signatures": conflicts,
        "invalid_validations_skipped": bad_signatures,
        "unattributed_signing_keys": unattributed.len(),
        "trusted_not_seen_most": often_not_seen.iter().take(5).map(|(k, n)| json!({"validator": node_public(k), "ledgers": n})).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(unconfirmed.is_empty() && ledgers_without_data.is_empty())
}
