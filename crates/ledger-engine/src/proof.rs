//! Proof API: evidence bundles that can be verified without trusting us
//! (`witness-verify evidence`).
//!
//! A bundle uses the `xrpl-witness/evidence/3` format: quorum validations for the anchor
//! ledger, the UNL lists and manifests that show who is in the quorum, the chain
//! of headers from the target ledger to the anchor, and proofs of a transaction
//! (path in the transaction tree) or a state object (path in the state
//! tree, including proof that an object is absent).
//!
//! The anchor ledger is the nearest one after the target that has validations.
//! The confirmation module keeps recent ones in memory; every 256 ledgers the ingester
//! saves them to storage. The chain is at most `MAX_CHAIN` headers long.
//!
//! The response states plainly what is proven and how: whether the target ledger
//! was itself validated by a quorum or is linked by hashes to a validated one, and what
//! the bundle does not prove, for example that an account's history is complete.

use serde_json::{Map, Value, json};
use witness_core::evidence::{
    Bundle, FORMAT_V3, PolicySpec, Provenance, PublisherResponse, Trust, ValidationEvidence, verify,
};
use witness_core::ledger::LedgerHeader;
use witness_core::shamap::{prove, tx_id, tx_leaf_hash};
use witness_core::stateproof::StateProof;
use witness_core::txproof::TxProof;

use crate::api::{Engine, RpcError};
use crate::state::Leaf;

/// If the chain would be longer, no bundle is built; wait for the next anchor.
pub const MAX_CHAIN: u32 = 512;

/// How long `proof_entry` waits for the latest tree ledger to be validated.
const CONFIRM_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

type Res<T> = Result<T, RpcError>;

fn err(error: &'static str, code: i32, message: impl Into<String>) -> RpcError {
    RpcError {
        error,
        code,
        message: message.into(),
    }
}

fn internal(e: String) -> RpcError {
    err("internal", 73, e)
}

/// Anchor ledger, its hash, its validations, and the vote time window used
/// to pick the UNL lists.
struct Anchor {
    sequence: u32,
    hash: [u8; 32],
    validations: Vec<ValidationEvidence>,
    window: (u32, u32),
}

impl Engine {
    fn hash_of(&self, seq: u32) -> Res<[u8; 32]> {
        let raw = self
            .state
            .header(seq)
            .map_err(internal)?
            .ok_or_else(|| err("lgrNotFound", 21, "ledgerNotFound"))?;
        Ok(LedgerHeader::parse(&raw)
            .map_err(|e| internal(e.to_string()))?
            .hash())
    }

    /// Nearest validated ledger with validations after `target`.
    fn anchor(&self, target: u32) -> Res<Anchor> {
        let confirmed = self.state.confirmed().map_err(internal)?.ok_or_else(|| {
            err(
                "notReady",
                13,
                "No ledger has been validated by a quorum yet.",
            )
        })?;
        if target > confirmed {
            return Err(err(
                "lgrNotConfirmed",
                22,
                "Ledger has not been validated by a quorum yet.",
            ));
        }
        let top = confirmed.min(target.saturating_add(MAX_CHAIN));
        let c = self
            .confirmer
            .as_ref()
            .ok_or_else(|| err("notImpl", 74, "Quorum confirmation is not enabled."))?;
        // Recent ones from in-memory validations: the nearest to the target that reached quorum.
        for seq in target..=top {
            let hash = self.hash_of(seq)?;
            let vals = c.validations_for(seq, &hash);
            if vals.is_empty() {
                continue;
            }
            let v = c.check(seq, &hash);
            if let (true, Some(window)) = (v.confirmed, v.window) {
                return Ok(Anchor {
                    sequence: seq,
                    hash,
                    validations: vals
                        .into_iter()
                        .map(|(raw, at)| ValidationEvidence {
                            data: hex::encode_upper(raw),
                            received_ms: at,
                        })
                        .collect(),
                    window,
                });
            }
        }
        // The rest from anchor evidence in storage, by the same rule.
        if let Some((seq, validations)) = self.state.evidence_from(target).map_err(internal)?
            && seq <= top
        {
            let hash = self.hash_of(seq)?;
            let raws: Vec<Vec<u8>> = validations
                .iter()
                .filter_map(|v| hex::decode(&v.data).ok())
                .collect();
            let v = c.check_raw(seq, &raws, &hash);
            if let (true, Some(window)) = (v.confirmed, v.window) {
                return Ok(Anchor {
                    sequence: seq,
                    hash,
                    validations,
                    window,
                });
            }
        }
        Err(err(
            "noEvidence",
            5002,
            format!(
                "No validated ledger with validations within {MAX_CHAIN} after the target; the bundle cannot be built yet."
            ),
        ))
    }

    /// The state tree is at the latest loaded ledger, and quorum validation
    /// arrives slightly later (the ingester checks for it once a second):
    /// we wait for it; the path is already taken from the tree snapshot.
    fn wait_confirmed(&self, seq: u32) -> Res<()> {
        let until = std::time::Instant::now() + CONFIRM_WAIT;
        while self.state.confirmed().map_err(internal)?.unwrap_or(0) < seq {
            if std::time::Instant::now() >= until {
                return Err(err(
                    "lgrNotConfirmed",
                    22,
                    "Ledger has not been validated by a quorum yet.",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(())
    }

    /// Bundle: anchor ledger, chain from `target`, proofs.
    fn bundle(
        &self,
        target: u32,
        transactions: Vec<TxProof>,
        objects: Vec<StateProof>,
    ) -> Res<(Bundle, u32)> {
        let a = self.anchor(target)?;
        // The chain runs from the target to the anchor inclusive, even if it is a single
        // ledger: the header is always in the bundle and its hash is checked.
        let mut chain = Vec::new();
        for seq in target..=a.sequence {
            let raw = self
                .state
                .header(seq)
                .map_err(internal)?
                .ok_or_else(|| internal(format!("no header for {seq}")))?;
            chain.push(hex::encode_upper(raw));
        }
        let c = self
            .confirmer
            .as_ref()
            .ok_or_else(|| err("notImpl", 74, "Quorum confirmation is not enabled."))?;
        // Publisher responses use the same time window the decision was made with;
        // otherwise the bundle might not reproduce it.
        let responses = c
            .publisher_responses(a.window.0, a.window.1)
            .into_iter()
            .map(|(site, body, seen)| PublisherResponse {
                site,
                body: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, body),
                first_seen_ms: (seen != u64::MAX).then_some(seen),
            })
            .collect();
        let bundle = Bundle {
            format: FORMAT_V3.into(),
            ledger_index: a.sequence,
            ledger_hash: hex::encode_upper(a.hash),
            policy: PolicySpec {
                publishers: c.publishers().iter().map(hex::encode_upper).collect(),
                threshold: 0,
                trusted_directly: Vec::new(),
            },
            publisher_responses: responses,
            manifests: c.node_manifests().iter().map(hex::encode_upper).collect(),
            negative_unl: None,
            validations: a.validations,
            provenance: Provenance {
                source: "astraea".into(),
                exported_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                seals: Vec::new(),
            },
            transactions,
            chain,
            objects,
        };
        // The bundle is checked by the same offline verifier the recipient uses, and
        // returned only if it reproduces our decision in full.
        let trust = Trust {
            publishers: c.publishers(),
            threshold: 0,
            trusted_directly: Default::default(),
        };
        let r = verify(&bundle, &trust);
        let ok = r.confirmed_hash.as_deref() == Some(bundle.ledger_hash.as_str())
            && r.chain_ok
            && r.target_ledger == Some(target)
            && r.transactions.iter().all(|t| t.in_confirmed_ledger)
            && r.objects.iter().all(|o| o.proven);
        if !ok {
            return Err(err(
                "evidenceInvalid",
                5003,
                format!(
                    "The built bundle failed its own verification: {}",
                    r.problems.join("; ")
                ),
            ));
        }
        Ok((bundle, a.sequence))
    }

    fn answer(
        &self,
        bundle: Bundle,
        anchor: u32,
        target: u32,
        proves: &[&str],
        not: &[&str],
    ) -> Res<Map<String, Value>> {
        let mut m = Map::new();
        m.insert(
            "guarantee".into(),
            json!({
                "target_ledger": target,
                "anchor_ledger": anchor,
                "target_confirmed_by": if anchor == target { "quorum" } else { "hash-chain" },
                "anchor_confirmed_by": "quorum",
                "quorum_rule": "full-unl; UNL lists valid at ledger time; every possible policy must agree",
                "proves": proves,
                "does_not_prove": not,
                "verify_with": "witness-verify evidence <bundle.json>",
            }),
        );
        m.insert(
            "proof".into(),
            serde_json::to_value(bundle).map_err(|e| internal(e.to_string()))?,
        );
        Ok(m)
    }

    /// Ledger bundle: proves that the header with this hash was validated by the network.
    pub fn proof_ledger(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let target = self.resolve_ledger(p)?;
        let (b, anchor) = self.bundle(target, Vec::new(), Vec::new())?;
        self.answer(
            b,
            anchor,
            target,
            &["ledger header and hash"],
            &["contents beyond the header"],
        )
    }

    /// Transaction bundle: proves that it was recorded with this metadata in a
    /// validated ledger.
    pub fn proof_tx(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let id = p
            .get("transaction")
            .and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| {
                err(
                    "invalidParams",
                    31,
                    "transaction must be a transaction hash",
                )
            })?;
        let (seq, pos) = self
            .state
            .tx_location(&id)
            .map_err(internal)?
            .ok_or_else(|| err("txnNotFound", 29, "Transaction not found."))?;
        let l = self.ledger_txs(seq)?;
        let leaves: Vec<([u8; 32], [u8; 32])> = l
            .transactions
            .iter()
            .map(|(t, m)| {
                let k = tx_id(t);
                (k, tx_leaf_hash(t, m, &k))
            })
            .collect();
        let path = prove(&leaves, &id)
            .ok_or_else(|| internal("could not build the transaction path".into()))?;
        let (tx, meta) = &l.transactions[pos as usize];
        let proof = TxProof::new(&l.header, tx, meta, &path);
        let (b, anchor) = self.bundle(seq, vec![proof], Vec::new())?;
        self.answer(
            b,
            anchor,
            seq,
            &["transaction with metadata included in the ledger"],
            &["delivered_amount and other fields derived by servers"],
        )
    }

    /// Bundle for a state object (present or absent) at the latest ledger
    /// of the state tree. Older ledgers are the next step: that needs
    /// historical tree nodes.
    pub fn proof_entry(&self, p: &Map<String, Value>) -> Res<Map<String, Value>> {
        let key = self.entry_key_of(p)?;
        if p.get("ledger_index")
            .is_some_and(|v| v.as_str() != Some("validated"))
            || p.contains_key("ledger_hash")
        {
            return Err(err(
                "notImpl",
                74,
                "Object proofs are only available for the latest state ledger for now.",
            ));
        }
        let t = self.state.tree_path(&key).map_err(internal)?;
        let (object, other) = match &t.leaf {
            Leaf::Present(o) => (Some(&o[..]), None),
            Leaf::Empty => (None, None),
            Leaf::Other(k, o) => (None, Some((k, &o[..]))),
        };
        let proof = StateProof::new(&t.header, &key, object, other, &t.path);
        let present = object.is_some();
        self.wait_confirmed(t.ledger)?;
        let (b, anchor) = self.bundle(t.ledger, Vec::new(), vec![proof])?;
        self.answer(
            b,
            anchor,
            t.ledger,
            &[if present {
                "object present in ledger state, byte for byte"
            } else {
                "object absent from ledger state"
            }],
            &["object state at other ledgers"],
        )
    }
}
