//! Evidence package: export from the archive and verification without it.
//!
//! `export` gathers everything needed to check a single ledger, using
//! originals only (see `witness_core::evidence`). `evidence` checks such a
//! package against your own trust policy without contacting us or a node.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use clap::Args;
use serde_json::Value;
use witness_core::evidence::{
    Bundle, FORMAT, FORMAT_V2, NegativeUnlEvidence, PolicySpec, Provenance, PublisherResponse,
    Trust, ValidationEvidence, signing_to_master, verify,
};
use witness_core::quorum::{Key, PublishedList, policies_between};
use witness_core::shamap::{prove, tx_id, tx_leaf_hash};
use witness_core::txproof::TxProof;
use witness_core::util::now_ms;
use witness_core::{Manifest, Validation};
use witness_store::segment::read_segment;

use crate::archive::seals;
use crate::quorum::{DEFAULT_PUBLISHERS, load_lists};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// The verifier's trust policy, shared by export and check.
#[derive(Debug, Args)]
pub struct TrustArgs {
    /// List publisher keys in hex. Defaults to xrpld's default publishers.
    #[arg(long = "publisher")]
    publishers: Vec<String>,
    /// How many lists must contain a key. 0 means the xrpld default.
    #[arg(long, default_value_t = 0)]
    threshold: usize,
    /// Directly trusted keys, `n9...` or hex.
    #[arg(long = "trust")]
    trusted_directly: Vec<String>,
}

impl TrustArgs {
    fn trust(&self) -> Res<Trust> {
        let publishers: Vec<Key> = if self.publishers.is_empty() {
            DEFAULT_PUBLISHERS
                .iter()
                .map(hex::decode)
                .collect::<Result<_, _>>()?
        } else {
            self.publishers
                .iter()
                .map(hex::decode)
                .collect::<Result<_, _>>()?
        };
        let trusted_directly = self
            .trusted_directly
            .iter()
            .map(|s| {
                witness_core::keys::parse_node_public(s)
                    .or_else(|| hex::decode(s).ok())
                    .ok_or_else(|| format!("could not parse key {s}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Trust {
            publishers,
            threshold: self.threshold,
            trusted_directly,
        })
    }
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Archive root: segments/, manifests/, unl/, negative_unl/.
    data_dir: PathBuf,
    /// The ledger to build the package for.
    #[arg(long)]
    ledger: u32,
    /// Transactions of this ledger to add inclusion proofs for (version 2
    /// package). Hash in hex; may be given more than once.
    #[arg(long = "tx")]
    txs: Vec<String>,
    /// JSON-RPC of a node or Clio server that has this ledger's transactions.
    /// Only needed together with --tx. It is not trusted: the header is
    /// checked against the hash confirmed by quorum.
    #[arg(long)]
    rpc: Option<String>,
    #[command(flatten)]
    trust: TrustArgs,
}

/// The ledger header and all its transactions with metadata.
type LedgerTxs = (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>);

/// Fetches the ledger header and all transactions with metadata from the node.
fn fetch_ledger(rpc: &str, ledger: u32) -> Res<LedgerTxs> {
    let body = serde_json::json!({"method": "ledger", "params": [{
        "ledger_index": ledger, "transactions": true, "expand": true, "binary": true}]});
    let mut resp = ureq::post(rpc)
        .header("Content-Type", "application/json")
        .send(body.to_string())?;
    let text = resp
        .body_mut()
        .with_config()
        .limit(256 << 20)
        .read_to_string()?;
    let v: Value = serde_json::from_str(&text)?;
    let lg = &v["result"]["ledger"];
    let header = hex::decode(
        lg["ledger_data"]
            .as_str()
            .ok_or("node did not return the ledger header")?,
    )?;
    let mut txs = Vec::new();
    for t in lg["transactions"]
        .as_array()
        .ok_or("node did not return the transactions")?
    {
        let tx = t["tx_blob"].as_str().ok_or("no tx_blob")?;
        // xrpld returns metadata as meta, Clio as meta_blob.
        let meta = t["meta_blob"]
            .as_str()
            .or_else(|| t["meta"].as_str())
            .ok_or("no metadata")?;
        txs.push((hex::decode(tx)?, hex::decode(meta)?));
    }
    Ok((header, txs))
}

/// Inclusion proofs for the selected transactions.
fn tx_proofs(rpc: &str, ledger: u32, wanted: &[String]) -> Res<Vec<TxProof>> {
    let (header, txs) = fetch_ledger(rpc, ledger)?;
    let items: Vec<_> = txs
        .iter()
        .map(|(tx, meta)| {
            let id = tx_id(tx);
            (id, tx_leaf_hash(tx, meta, &id))
        })
        .collect();
    let mut out = Vec::new();
    for w in wanted {
        let key: [u8; 32] = hex::decode(w)?
            .try_into()
            .map_err(|_| format!("hash {w} is not 32 bytes"))?;
        let i = items
            .iter()
            .position(|(k, _)| *k == key)
            .ok_or_else(|| format!("transaction {w} is not in ledger {ledger}"))?;
        let path = prove(&items, &key).ok_or("could not build the proof path")?;
        out.push(TxProof::new(&header, &txs[i].0, &txs[i].1, &path));
    }
    Ok(out)
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Evidence package file.
    bundle: PathBuf,
    #[command(flatten)]
    trust: TrustArgs,
}

pub fn export(args: &ExportArgs) -> Res<bool> {
    let trust = args.trust.trust()?;
    let ledger = args.ledger;

    // The ledger's validations, from every segment they may be in: late
    // ones land in the next segment.
    let mut validations = Vec::new();
    let mut seal_hashes = BTreeSet::new();
    let mut source = String::new();
    for (path, seal) in seals(&args.data_dir.join("segments"))? {
        let reach = seal.nominal_last.saturating_add(512);
        if seal.nominal_first > ledger.saturating_add(512) || reach < ledger {
            continue;
        }
        let seg = PathBuf::from(path.to_string_lossy().replace(".seal.json", ".xwv.zst"));
        let mut found = false;
        for rec in read_segment(&seg)? {
            if rec.ledger_index == ledger {
                found = true;
                validations.push(ValidationEvidence {
                    data: hex::encode_upper(&rec.data),
                    received_ms: rec.received_ms,
                });
            }
        }
        if found {
            seal_hashes.insert(seal.seal_hash.clone());
            source.clone_from(&seal.source);
        }
    }
    if validations.is_empty() {
        return Err(format!("sealed segments have no validations for ledger {ledger}").into());
    }

    // Lists in effect for this ledger, as whole publisher responses.
    let mut list_manifests = Vec::new();
    let mut list_problems = Vec::new();
    let lists = load_lists(
        &args.data_dir.join("unl"),
        &trust.publishers,
        &mut list_manifests,
        &mut list_problems,
    )?;
    for p in &list_problems {
        eprintln!("{p}");
    }
    // The time window runs from the earliest to the latest signing time of
    // full validations by known validators; the package gets every list that
    // was in effect at any moment of the window. An extra list does no harm:
    // the verifier picks the ones in effect during the window of votes for
    // the hash being confirmed.
    let to_master = signing_to_master(&list_manifests).0;
    let known: BTreeSet<&Key> = lists
        .iter()
        .flat_map(|s| s.list.validators.iter())
        .collect();
    let times: Vec<u32> = validations
        .iter()
        .filter_map(|v| hex::decode(&v.data).ok())
        .filter_map(|raw| Validation::parse(&raw).ok())
        .filter(|v| {
            v.is_full()
                && to_master
                    .get(&v.signing_pub_key)
                    .is_some_and(|m| known.contains(m))
        })
        .map(|v| v.signing_time)
        .collect();
    let (from, to) = times
        .iter()
        .min()
        .zip(times.iter().max())
        .map(|(a, b)| (*a, *b))
        .ok_or("no full validations from known validators: cannot determine the ledger time")?;
    let all: Vec<PublishedList> = lists.iter().map(|s| s.list.clone()).collect();
    let set = policies_between(
        &all,
        &trust.publishers,
        from,
        to,
        trust.threshold,
        &trust.trusted_directly,
    );
    for m in &set.missing {
        eprintln!(
            "publisher {}: no list in effect at the ledger time, the package will not confirm",
            hex::encode_upper(m)
        );
    }
    let policies = set.policies;
    let mut responses: Vec<PublisherResponse> = Vec::new();
    for chosen in policies.iter().flat_map(|p| p.lists.iter()) {
        let Some(seen) = lists
            .iter()
            .find(|s| s.list.publisher == chosen.publisher && s.list.sequence == chosen.sequence)
        else {
            continue;
        };
        let body = base64::engine::general_purpose::STANDARD.encode(&seen.body);
        if !responses.iter().any(|r| r.body == body) {
            responses.push(PublisherResponse {
                site: seen.site.clone(),
                body,
                first_seen_ms: (seen.first_seen_ms != u64::MAX).then_some(seen.first_seen_ms),
            });
        }
    }

    // Manifests from the node, only for keys that signed this ledger.
    let signers: BTreeSet<Vec<u8>> = validations
        .iter()
        .filter_map(|v| hex::decode(&v.data).ok())
        .filter_map(|raw| Validation::parse(&raw).ok())
        .map(|v| v.signing_pub_key)
        .collect();
    let mut manifests = Vec::new();
    if let Ok(dir) = fs::read_dir(args.data_dir.join("manifests")) {
        for e in dir.flatten() {
            if e.path().extension().is_none_or(|x| x != "bin") {
                continue;
            }
            let raw = fs::read(e.path())?;
            if let Ok(m) = Manifest::parse(&raw)
                && m.signing_key.as_ref().is_some_and(|k| signers.contains(k))
            {
                manifests.push(hex::encode_upper(&raw));
            }
        }
    }

    // Negative UNL, from the last flag ledger before this one.
    let mut negative_unl = None;
    if let Ok(log) = fs::read_to_string(args.data_dir.join("negative_unl/observations.jsonl")) {
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
            let binary = v.get("node_binary").and_then(Value::as_str);
            let known =
                binary.is_some() || v.get("error").and_then(Value::as_str) == Some("entryNotFound");
            if !known || flag >= ledger {
                continue;
            }
            if negative_unl
                .as_ref()
                .is_none_or(|n: &NegativeUnlEvidence| n.flag_ledger < flag)
            {
                negative_unl = Some(NegativeUnlEvidence {
                    flag_ledger: flag,
                    flag_ledger_hash: v
                        .get("ledger_hash")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    node_binary: binary.map(str::to_owned),
                });
            }
        }
    }

    let transactions = match (&args.rpc, args.txs.is_empty()) {
        (_, true) => Vec::new(),
        (Some(rpc), false) => tx_proofs(rpc, ledger, &args.txs)?,
        (None, false) => return Err("--tx requires --rpc".into()),
    };
    let mut bundle = Bundle {
        format: if transactions.is_empty() {
            FORMAT
        } else {
            FORMAT_V2
        }
        .into(),
        ledger_index: ledger,
        ledger_hash: String::new(),
        policy: PolicySpec {
            publishers: trust.publishers.iter().map(hex::encode_upper).collect(),
            threshold: trust.threshold,
            trusted_directly: trust
                .trusted_directly
                .iter()
                .map(hex::encode_upper)
                .collect(),
        },
        publisher_responses: responses,
        manifests,
        negative_unl,
        validations,
        provenance: Provenance {
            source,
            exported_ms: now_ms(),
            seals: seal_hashes.into_iter().collect(),
        },
        transactions,
        chain: Vec::new(),
        objects: Vec::new(),
        skips: Vec::new(),
    };
    // The claimed hash is the one that reached quorum under this same policy.
    let report = verify(&bundle, &trust);
    let Some(hash) = report.confirmed_hash.clone() else {
        eprintln!("{}", serde_json::to_string_pretty(&report)?);
        return Err(
            format!("ledger {ledger} is not confirmed by quorum, package not built").into(),
        );
    };
    // The node is not trusted: its header must be the confirmed ledger.
    if let Some(bad) = report.transactions.iter().find(|t| !t.in_confirmed_ledger) {
        return Err(format!(
            "transaction proof does not match the confirmed ledger: {:?}",
            bad.error
        )
        .into());
    }
    bundle.ledger_hash = hash;
    println!("{}", serde_json::to_string_pretty(&bundle)?);
    Ok(true)
}

pub fn check(args: &CheckArgs) -> Res<bool> {
    let trust = args.trust.trust()?;
    let bundle: Bundle = serde_json::from_slice(&fs::read(&args.bundle)?)?;
    let report = verify(&bundle, &trust);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(report.confirmed_hash.is_some()
        && report.matches_claim
        && report.problems.is_empty()
        && report.transactions.iter().all(|t| t.in_confirmed_ledger)
        && report.objects.iter().all(|o| o.proven))
}
