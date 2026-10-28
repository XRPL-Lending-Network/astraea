//! Archive verification: seals, chain, signatures.
//!
//! Takes the segments directory and checks everything that can be checked
//! without us:
//! - every segment matches its seal (content hash);
//! - the seals form a chain and the coverage spans are contiguous;
//! - every validation parses, its signature matches its key, and the ledger
//!   index inside it matches the one it was recorded under.
//!
//! The result is JSON on stdout: how much of what was checked and what failed.
//! The exit code is non-zero if anything at all did not match.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use clap::Args;
use serde_json::json;
use witness_core::Validation;
use witness_core::keys::node_public;
use witness_store::Seal;
use witness_store::segment::{read_segment, verify_segment};

#[derive(Debug, Args)]
pub struct ArchiveArgs {
    /// The archive's segments directory.
    segments: PathBuf,
    /// How many failure examples to show for each reason.
    #[arg(long, default_value_t = 3)]
    examples: usize,
}

#[derive(Default)]
struct Tally {
    segments: u64,
    seals_broken: Vec<String>,
    chain_breaks: Vec<String>,
    /// Switches between numberings: not an error, but they should be visible.
    lineage_switches: Vec<String>,
    missing_total: u64,
    /// Gaps longer than a thousand ledgers are almost certainly not downtime
    /// but an accounting error; shown separately.
    missing_suspicious: Vec<String>,
    records: u64,
    valid: u64,
    /// Reason -> count and examples.
    failures: BTreeMap<String, (u64, Vec<String>)>,
    index_mismatch: u64,
    keys: HashSet<Vec<u8>>,
    full: u64,
    partial: u64,
}

impl Tally {
    fn fail(&mut self, reason: String, example: String, keep: usize) {
        let e = self.failures.entry(reason).or_default();
        e.0 += 1;
        if e.1.len() < keep {
            e.1.push(example);
        }
    }
}

pub fn seals(dir: &Path) -> Result<Vec<(PathBuf, Seal)>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.to_string_lossy().ends_with(".seal.json") {
            let seal: Seal = serde_json::from_slice(&fs::read(&path)?)?;
            out.push((path, seal));
        }
    }
    out.sort_by_key(|(_, s)| s.sealed_ms);
    Ok(out)
}

pub fn run(args: &ArchiveArgs) -> Result<bool, Box<dyn std::error::Error>> {
    let mut t = Tally::default();
    let mut prev: Option<Seal> = None;
    for (seal_path, seal) in seals(&args.segments)? {
        t.segments += 1;
        let name = seal_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let seg_path = PathBuf::from(
            seal_path
                .to_string_lossy()
                .replace(".seal.json", ".xwv.zst"),
        );
        if !verify_segment(&seg_path, &seal)? {
            t.seals_broken.push(name.clone());
        }
        if let Some(p) = &prev {
            if seal.prev_seal_hash.as_deref() != Some(p.seal_hash.as_str()) {
                t.chain_breaks
                    .push(format!("{name}: link to previous seal"));
            }
            // An empty span (a segment with no ledgers of its own) does not affect contiguity.
            let empty =
                seal.coverage_first > seal.coverage_last || p.coverage_first > p.coverage_last;
            let tiles = seal.coverage_first == p.coverage_last.saturating_add(1);
            // The span started far from the end of the previous one: the
            // archive switched to a different numbering (a foreign network in
            // the stream) and started or resumed a separate coverage lineage.
            let switch = seal.coverage_first.abs_diff(p.coverage_last) > 256;
            if !empty && !tiles {
                let what = format!(
                    "{name}: span {}.. after {}",
                    seal.coverage_first, p.coverage_last
                );
                if switch {
                    t.lineage_switches.push(what);
                } else {
                    t.chain_breaks.push(what);
                }
            }
        }
        for [a, b] in &seal.missing_ledgers {
            let n = u64::from(b.saturating_sub(*a)) + 1;
            t.missing_total += n;
            if n > 1000 {
                t.missing_suspicious.push(format!("{name}: {a}..{b} ({n})"));
            }
        }
        for rec in read_segment(&seg_path)? {
            t.records += 1;
            match Validation::parse(&rec.data) {
                Err(e) => t.fail(
                    format!("does not parse: {e}"),
                    hex::encode_upper(&rec.data),
                    args.examples,
                ),
                Ok(v) => {
                    if v.ledger_sequence != rec.ledger_index {
                        t.index_mismatch += 1;
                    }
                    match v.verify() {
                        Ok(()) => {
                            t.valid += 1;
                            if v.is_full() {
                                t.full += 1;
                            } else {
                                t.partial += 1;
                            }
                            t.keys.insert(v.signing_pub_key);
                        }
                        Err(e) => t.fail(
                            format!("signature: {e}"),
                            format!(
                                "{} ledger {}",
                                node_public(&v.signing_pub_key),
                                v.ledger_sequence
                            ),
                            args.examples,
                        ),
                    }
                }
            }
        }
        prev = Some(seal);
    }
    let failed: u64 = t.failures.values().map(|(n, _)| n).sum();
    let ok = t.seals_broken.is_empty()
        && t.chain_breaks.is_empty()
        && failed == 0
        && t.index_mismatch == 0;
    let failures: BTreeMap<_, _> = t
        .failures
        .iter()
        .map(|(k, (n, ex))| (k.clone(), json!({"count": n, "examples": ex})))
        .collect();
    let report = json!({
        "ok": ok,
        "segments": t.segments,
        "seals_broken": t.seals_broken,
        "chain_breaks": t.chain_breaks,
        "lineage_switches": t.lineage_switches,
        "missing_ledgers_total": t.missing_total,
        "missing_suspicious": t.missing_suspicious,
        "records": t.records,
        "signatures_valid": t.valid,
        "full_validations": t.full,
        "partial_validations": t.partial,
        "signing_keys": t.keys.len(),
        "ledger_index_mismatch": t.index_mismatch,
        "failures": failures,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(ok)
}
