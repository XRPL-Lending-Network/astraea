//! Confirmation of ledgers by a validator quorum, independent of the ledger
//! source.
//!
//! Whether a ledger is validated by the network is decided not by the node but by
//! the signatures of UNL validators. Validations come from the nodes' `validations`
//! stream, and each signature is checked on arrival. UNL membership comes from the
//! publisher lists in the `witness-unl` collector archive; responses are checked
//! against pinned publisher keys on every load. A signing key is mapped to its
//! master key using the manifests from the same lists, and for validators that
//! rotated keys after the list was published, using a manifest fetched from the node
//! (it is signed by the master key and checked the same way).
//!
//! The rule is the same as in evidence bundle verification (`full-unl`): 80% of
//! the whole UNL, full validations only, Negative UNL not taken into account. The lists
//! are those in effect at the ledger's time according to the signed validations, and the quorum must
//! hold for every combination of lists in effect. The source can
//! delay or hide validations (then the ledger simply won't be confirmed),
//! but it can't forge a signature.
//!
//! If ledger N is confirmed, so are all ledgers loaded before it: the ingester
//! has already checked that each one's parent hash is the hash of the previous ledger.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};
use witness_core::evidence::signing_to_master;
use witness_core::keys::node_public;
use witness_core::manifest::Manifest;
#[cfg(test)]
use witness_core::quorum::Policy;
use witness_core::quorum::{Key, Observed, decide, policies_between};
use witness_core::unlstore::{Seen, load_lists};
use witness_core::validation::Validation;

/// Validations older than this many ledgers behind the newest one are forgotten.
const KEEP_LEDGERS: u32 = 4096;
/// Raw validations (for evidence bundles) are kept for this many recent
/// ledgers; beyond that, ledgers are proven by anchor evidence
/// saved in storage and a chain of headers.
const RAW_LEDGERS: u32 = 512;
/// How far ahead of the latest ledger of known validators validations are
/// stored: anything further is not our stream or a different network.
const AHEAD: u32 = 64;
/// Maximum validations per ledger: the network has dozens of validators.
const PER_LEDGER: usize = 1024;
/// How often to reread the list archive.
const RELOAD_LISTS: Duration = Duration::from_secs(600);
/// Minimum interval between asking the node about an unknown signing key.
const MANIFEST_RETRY: Duration = Duration::from_secs(3600);
const FIRST_MANIFEST_ID: u64 = 1000;

/// Result of checking a ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub confirmed: bool,
    pub signers: usize,
    pub quorum: usize,
    pub unl_size: usize,
    /// Vote time window used to pick the lists: the evidence bundle
    /// takes publisher responses from the same window so that bundle verification
    /// reproduces this decision.
    pub window: Option<(u32, u32)>,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub connected: bool,
    pub validations: u64,
    pub rejected: u64,
    pub manifests: u64,
}

#[derive(Debug)]
struct Lists {
    seen: Vec<Seen>,
    manifests: Vec<Manifest>,
    loaded: Option<Instant>,
}

/// Verified validation: signing key, hash, full flag, signing time.
type Checked = (Key, [u8; 32], bool, u32);
/// Raw validation: bytes, when received (Unix ms), ledger hash, signing key.
type RawValidation = (Vec<u8>, u64, [u8; 32], Key);

#[derive(Debug)]
struct Inner {
    lists: Lists,
    /// Manifests from the node for keys that are not in the lists.
    node_manifests: Vec<Manifest>,
    /// The same manifests as bytes, for evidence bundles.
    node_manifests_raw: Vec<Vec<u8>>,
    /// Ledger → raw validations: (bytes, when received, ledger hash).
    raw: BTreeMap<u32, Vec<RawValidation>>,
    to_master: HashMap<Key, Key>,
    /// Validator master keys from the lists: their validations move the retention window.
    known: BTreeSet<Key>,
    /// Highest ledger sequence seen in validations from known validators.
    top: u32,
    /// Ledger → verified validations: (signing key, hash, full flag, signing time).
    validations: BTreeMap<u32, Vec<Checked>>,
    asked: HashMap<Key, Instant>,
    stats: Stats,
}

#[derive(Debug, Clone)]
pub struct Confirmer {
    publishers: Vec<Key>,
    unl_dir: PathBuf,
    inner: Arc<Mutex<Inner>>,
}

impl Confirmer {
    pub fn new(publishers: Vec<Key>, unl_dir: PathBuf) -> Confirmer {
        Confirmer {
            publishers,
            unl_dir,
            inner: Arc::new(Mutex::new(Inner {
                lists: Lists {
                    seen: Vec::new(),
                    manifests: Vec::new(),
                    loaded: None,
                },
                node_manifests: Vec::new(),
                node_manifests_raw: Vec::new(),
                raw: BTreeMap::new(),
                to_master: HashMap::new(),
                known: BTreeSet::new(),
                top: 0,
                validations: BTreeMap::new(),
                asked: HashMap::new(),
                stats: Stats::default(),
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Rereads the list archive when due; rebuilds the key mapping.
    fn refresh_lists(&self, g: &mut Inner) {
        if g.lists.loaded.is_some_and(|t| t.elapsed() < RELOAD_LISTS) {
            return;
        }
        let mut manifests = Vec::new();
        let mut problems = Vec::new();
        match load_lists(
            &self.unl_dir,
            &self.publishers,
            &mut manifests,
            &mut problems,
        ) {
            Ok(seen) => {
                for p in problems {
                    warn!("UNL lists: {p}");
                }
                g.lists = Lists {
                    seen,
                    manifests,
                    loaded: Some(Instant::now()),
                };
                rebuild_masters(g);
            }
            Err(e) => {
                warn!("UNL lists not read: {e}");
                g.lists.loaded = Some(Instant::now());
            }
        }
    }

    /// Each configured publisher's latest list: publisher, sequence, number of
    /// validators, expiration (seconds since the XRPL epoch).
    pub fn latest_lists(&self) -> Vec<(Key, u64, usize, Option<u32>)> {
        let mut g = self.lock();
        self.refresh_lists(&mut g);
        let mut latest: BTreeMap<Key, (u64, usize, Option<u32>)> = BTreeMap::new();
        for s in &g.lists.seen {
            let l = &s.list;
            if latest
                .get(&l.publisher)
                .is_none_or(|(seq, _, _)| *seq < l.sequence)
            {
                latest.insert(
                    l.publisher.clone(),
                    (l.sequence, l.validators.len(), l.expiration),
                );
            }
        }
        latest
            .into_iter()
            .map(|(p, (seq, n, exp))| (p, seq, n, exp))
            .collect()
    }

    pub fn stats(&self) -> (bool, u64, u64, u64) {
        let g = self.lock();
        (
            g.stats.connected,
            g.stats.validations,
            g.stats.rejected,
            g.stats.manifests,
        )
    }

    /// Accepts a raw validation: the signature must check out.
    ///
    /// Only validations from known validators move the retention window;
    /// otherwise a stranger's valid signature with a distant sequence could
    /// wipe the buffers and the quorum of the current ledger. Sequences beyond the window, ahead or behind, are not
    /// stored, and a ledger gets at most `PER_LEDGER` entries. A full
    /// validation replaces a partial one from the same key for the same hash.
    pub fn add_validation(&self, raw: &[u8]) -> Result<Key, String> {
        let v = Validation::parse(raw).map_err(|e| e.to_string());
        let mut g = self.lock();
        let v = match v.and_then(|v| v.verify().map(|()| v).map_err(|e| e.to_string())) {
            Ok(v) => v,
            Err(e) => {
                g.stats.rejected += 1;
                return Err(e);
            }
        };
        g.stats.validations += 1;
        self.refresh_lists(&mut g);
        let seq = v.ledger_sequence;
        let trusted = g
            .to_master
            .get(&v.signing_pub_key)
            .is_some_and(|m| g.known.contains(m));
        if trusted && seq > g.top {
            g.top = seq;
        }
        if g.top > 0
            && (seq.saturating_add(KEEP_LEDGERS) < g.top || seq > g.top.saturating_add(AHEAD))
        {
            return Ok(v.signing_pub_key);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let entry: Checked = (
            v.signing_pub_key.clone(),
            v.ledger_hash,
            v.is_full(),
            v.signing_time,
        );
        let list = g.validations.entry(seq).or_default();
        match list
            .iter()
            .position(|(k, h, ..)| *k == v.signing_pub_key && *h == v.ledger_hash)
        {
            // A repeat does nothing; a full one after a partial one replaces it.
            Some(i) if list[i].2 || !v.is_full() => {}
            Some(i) => {
                list[i] = entry;
                if let Some(r) = g.raw.get_mut(&seq).and_then(|rs| {
                    rs.iter_mut()
                        .find(|r| r.3 == v.signing_pub_key && r.2 == v.ledger_hash)
                }) {
                    *r = (raw.to_vec(), now, v.ledger_hash, v.signing_pub_key.clone());
                }
            }
            None if list.len() >= PER_LEDGER => {}
            None => {
                list.push(entry);
                g.raw.entry(seq).or_default().push((
                    raw.to_vec(),
                    now,
                    v.ledger_hash,
                    v.signing_pub_key.clone(),
                ));
            }
        }
        // Without known validators (lists not read yet) there is no window:
        // keep the latest sequences, however many arrive.
        let newest = if g.top > 0 {
            g.top
        } else {
            g.validations.keys().next_back().copied().unwrap_or(0)
        };
        let keep = newest.saturating_sub(RAW_LEDGERS);
        g.raw = g.raw.split_off(&keep);
        let keep = newest.saturating_sub(KEEP_LEDGERS);
        g.validations = g.validations.split_off(&keep);
        Ok(v.signing_pub_key)
    }

    /// Whether to ask the node for this signing key's manifest.
    fn should_ask(&self, signing_key: &Key) -> bool {
        let mut g = self.lock();
        self.refresh_lists(&mut g);
        if g.to_master.contains_key(signing_key) {
            return false;
        }
        match g.asked.get(signing_key) {
            Some(t) if t.elapsed() < MANIFEST_RETRY => false,
            _ => {
                g.asked.insert(signing_key.clone(), Instant::now());
                true
            }
        }
    }

    /// Manifest from the node: it enters the mapping only if the signatures check out.
    pub fn add_manifest(&self, raw: &[u8]) {
        if let Ok(m) = Manifest::parse(raw) {
            let mut g = self.lock();
            // The node sends the same manifest on every request.
            if g.node_manifests_raw.iter().any(|r| r == raw) {
                return;
            }
            g.node_manifests.push(m);
            g.node_manifests_raw.push(raw.to_vec());
            g.stats.manifests += 1;
            rebuild_masters(&mut g);
        }
    }

    /// Raw validations of the ledger for this hash: (bytes, when received).
    pub fn validations_for(&self, sequence: u32, hash: &[u8; 32]) -> Vec<(Vec<u8>, u64)> {
        self.lock()
            .raw
            .get(&sequence)
            .into_iter()
            .flatten()
            .filter(|(_, _, h, _)| h == hash)
            .map(|(r, t, ..)| (r.clone(), *t))
            .collect()
    }

    /// Publisher responses whose lists were in effect at any moment of the window
    /// `[from, to]` (seconds since the XRPL epoch): (site, body, when first
    /// seen).
    pub fn publisher_responses(&self, from: u32, to: u32) -> Vec<(String, Vec<u8>, u64)> {
        let mut g = self.lock();
        self.refresh_lists(&mut g);
        let lists: Vec<_> = g.lists.seen.iter().map(|s| s.list.clone()).collect();
        let mut out: Vec<(String, Vec<u8>, u64)> = Vec::new();
        let set = policies_between(&lists, &self.publishers, from, to, 0, &BTreeSet::new());
        for p in set.policies {
            for l in p.lists {
                if let Some(seen) = g
                    .lists
                    .seen
                    .iter()
                    .find(|s| s.list.publisher == l.publisher && s.list.sequence == l.sequence)
                    && !out.iter().any(|(_, b, _)| *b == seen.body)
                {
                    out.push((seen.site.clone(), seen.body.clone(), seen.first_seen_ms));
                }
            }
        }
        out
    }

    /// Manifests from the node as bytes, for validators that rotated keys after the list was published.
    pub fn node_manifests(&self) -> Vec<Vec<u8>> {
        self.lock().node_manifests_raw.clone()
    }

    pub fn publishers(&self) -> Vec<Key> {
        self.publishers.clone()
    }

    /// Whether the ledger hash reached a full-UNL quorum under every policy that
    /// could have been in effect during its vote time window, by the same rule
    /// as evidence bundle verification (`quorum::decide`).
    pub fn check(&self, sequence: u32, hash: &[u8; 32]) -> Verdict {
        let mut g = self.lock();
        self.refresh_lists(&mut g);
        let lists: Vec<_> = g.lists.seen.iter().map(|s| s.list.clone()).collect();
        let vals = g
            .validations
            .get(&sequence)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let observed: Vec<Observed> = vals
            .iter()
            .map(|(k, h, full, t)| Observed {
                signing_key: k.clone(),
                master_key: g.to_master.get(k).cloned(),
                ledger_hash: *h,
                full: *full,
                signing_time: *t,
            })
            .collect();
        Self::verdict_of(&lists, &self.publishers, &observed, hash)
    }

    /// The same decision from raw validations, for anchor evidence from
    /// storage: unparseable ones and ones with bad signatures are not counted.
    pub fn check_raw(&self, sequence: u32, raws: &[Vec<u8>], hash: &[u8; 32]) -> Verdict {
        let mut g = self.lock();
        self.refresh_lists(&mut g);
        let lists: Vec<_> = g.lists.seen.iter().map(|s| s.list.clone()).collect();
        let observed: Vec<Observed> = raws
            .iter()
            .filter_map(|r| Validation::parse(r).ok())
            .filter(|v| v.verify().is_ok() && v.ledger_sequence == sequence)
            .map(|v| Observed {
                master_key: g.to_master.get(&v.signing_pub_key).cloned(),
                full: v.is_full(),
                ledger_hash: v.ledger_hash,
                signing_time: v.signing_time,
                signing_key: v.signing_pub_key,
            })
            .collect();
        Self::verdict_of(&lists, &self.publishers, &observed, hash)
    }

    fn verdict_of(
        lists: &[witness_core::quorum::PublishedList],
        publishers: &[Key],
        observed: &[Observed],
        hash: &[u8; 32],
    ) -> Verdict {
        let d = decide(lists, publishers, 0, &BTreeSet::new(), observed, hash);
        Verdict {
            confirmed: d.confirmed,
            signers: d
                .assessed
                .iter()
                .map(|a| a.by_hash.get(hash).map_or(0, BTreeSet::len))
                .min()
                .unwrap_or(0),
            quorum: d.assessed.iter().map(|a| a.quorum).max().unwrap_or(0),
            unl_size: d.assessed.iter().map(|a| a.unl_size).max().unwrap_or(0),
            window: d.window,
        }
    }
}

#[cfg(test)]
fn verdict(policy: &Policy, observed: &[Observed], hash: &[u8; 32]) -> Verdict {
    let a = witness_core::quorum::assess(policy, observed);
    Verdict {
        confirmed: a.confirmed.as_ref() == Some(hash),
        signers: a.by_hash.get(hash).map_or(0, BTreeSet::len),
        quorum: a.quorum,
        unl_size: a.unl_size,
        window: None,
    }
}

fn rebuild_masters(g: &mut Inner) {
    let mut all = g.lists.manifests.clone();
    all.extend(g.node_manifests.iter().cloned());
    g.to_master = signing_to_master(&all).0;
    g.known = g
        .lists
        .seen
        .iter()
        .flat_map(|s| s.list.validators.iter().cloned())
        .collect();
}

/// Listens to the node's validation stream for the life of the process; reconnects on drop.
pub async fn listen(url: String, confirmer: Confirmer) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match session(&url, &confirmer).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(e) => warn!("validations {url}: {e}"),
        }
        confirmer.lock().stats.connected = false;
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

async fn session(url: &str, c: &Confirmer) -> Result<(), String> {
    let (mut ws, _) = connect_async(url).await.map_err(|e| e.to_string())?;
    let subscribe = json!({"id": 1, "command": "subscribe", "streams": ["validations"]});
    ws.send(Message::text(subscribe.to_string()))
        .await
        .map_err(|e| e.to_string())?;
    info!("validations: connected to {url}");
    c.lock().stats.connected = true;
    let mut next_id = FIRST_MANIFEST_ID;
    let mut last = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            msg = ws.next() => {
                let text = match msg {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Close(_))) | None => return Err("connection closed".into()),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(e.to_string()),
                };
                let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                if v.get("type").and_then(Value::as_str) == Some("validationReceived") {
                    last = Instant::now();
                    let Some(raw) = v.get("data").and_then(Value::as_str).and_then(|d| hex::decode(d).ok()) else {
                        continue;
                    };
                    if let Ok(key) = c.add_validation(&raw)
                        && c.should_ask(&key)
                    {
                        let req = json!({"id": next_id, "command": "manifest", "public_key": node_public(&key)});
                        next_id += 1;
                        ws.send(Message::text(req.to_string())).await.map_err(|e| e.to_string())?;
                    }
                } else if v.get("id").and_then(Value::as_u64).is_some_and(|id| id >= FIRST_MANIFEST_ID)
                    && let Some(raw) = v
                        .get("result")
                        .and_then(|r| r.get("manifest"))
                        .and_then(Value::as_str)
                        .and_then(|m| base64::engine::general_purpose::STANDARD.decode(m).ok())
                {
                    c.add_manifest(&raw);
                }
            }
            _ = tick.tick() => {
                // Validations arrive several times a second: a minute of silence
                // means the stream died silently.
                if last.elapsed() > Duration::from_secs(60) {
                    return Err("no validations for a minute".into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use witness_core::quorum::PublishedList;

    #[test]
    fn verdict_needs_quorum_of_full_unl() {
        let unl: BTreeSet<Key> = (0..10u8).map(|i| vec![i]).collect();
        let policy = Policy {
            lists: vec![PublishedList {
                publisher: vec![0xED],
                sequence: 1,
                validators: unl,
                effective: None,
                expiration: None,
                manifest_sequence: 1,
            }],
            threshold: 1,
            local: BTreeSet::new(),
            negative_unl: BTreeSet::new(),
        };
        let hash = [7u8; 32];
        let obs = |n: u8| -> Vec<Observed> {
            (0..n)
                .map(|i| Observed {
                    signing_key: vec![i],
                    master_key: Some(vec![i]),
                    ledger_hash: hash,
                    full: true,
                    signing_time: 100,
                })
                .collect()
        };
        let v = verdict(&policy, &obs(7), &hash);
        assert_eq!((v.confirmed, v.quorum, v.signers), (false, 8, 7));
        assert!(verdict(&policy, &obs(8), &hash).confirmed);
        // A quorum for a different hash does not confirm ours.
        assert!(!verdict(&policy, &obs(8), &[1u8; 32]).confirmed);
    }

    /// A real mainnet ledger, 107 855 813: validations and publisher responses
    /// from a witness-core evidence bundle.
    #[test]
    fn real_ledger_is_confirmed_and_a_forged_hash_is_not() {
        let b: Value = serde_json::from_str(include_str!(
            "../../witness-core/tests/fixtures/evidence-107855813.json"
        ))
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        for (i, r) in b["publisher_responses"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let site = dir.path().join(r["site"].as_str().unwrap());
            std::fs::create_dir_all(&site).unwrap();
            let body = base64::engine::general_purpose::STANDARD
                .decode(r["body"].as_str().unwrap())
                .unwrap();
            std::fs::write(site.join(format!("{i}.json")), body).unwrap();
        }
        let publishers: Vec<Key> = [
            "ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734",
            "ED42AEC58B701EEBB77356FFFEC26F83C1F0407263530F068C7C73D392C7E06FD1",
        ]
        .iter()
        .map(|h| hex::decode(h).unwrap())
        .collect();
        let c = Confirmer::new(publishers, dir.path().to_path_buf());
        let seq = u32::try_from(b["ledger_index"].as_u64().unwrap()).unwrap();
        let hash: [u8; 32] = hex::decode(b["ledger_hash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        // Without validations there is nothing to confirm with.
        assert!(!c.check(seq, &hash).confirmed);
        for v in b["validations"].as_array().unwrap() {
            let _ = c.add_validation(&hex::decode(v["data"].as_str().unwrap()).unwrap());
        }
        let v = c.check(seq, &hash);
        assert!(v.confirmed, "{v:?}");
        assert_eq!((v.unl_size, v.quorum), (35, 28));
        // A chain the source built itself won't reach quorum.
        assert!(!c.check(seq, &[0x42; 32]).confirmed);
        // A corrupted signature is rejected.
        let mut bad = hex::decode(b["validations"][0]["data"].as_str().unwrap()).unwrap();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(c.add_validation(&bad).is_err());

        // A genuine signature from a stranger's key with a distant sequence
        // does not move the retention window or wipe the quorum.
        let raw_before = c.validations_for(seq, &hash).len();
        for far in [seq + 1_000_000, seq.saturating_sub(100_000), u32::MAX] {
            assert!(
                c.add_validation(&foreign(far, true, 77, [9; 32], 1))
                    .is_ok()
            );
        }
        assert!(c.check(seq, &hash).confirmed);
        assert_eq!(c.validations_for(seq, &hash).len(), raw_before);
        assert!(
            c.lock()
                .validations
                .keys()
                .all(|k| k.abs_diff(seq) <= KEEP_LEDGERS)
        );
    }

    /// Signed validation from the test key `seed`.
    fn foreign(seq: u32, full: bool, seed: u8, hash: [u8; 32], time: u32) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};
        let k = SigningKey::from_bytes(&[seed; 32]);
        let mut pk = vec![0xED];
        pk.extend(k.verifying_key().to_bytes());
        let mut fields = vec![0x22];
        fields.extend(u32::from(full).to_be_bytes());
        fields.push(0x26);
        fields.extend(seq.to_be_bytes());
        fields.push(0x29);
        fields.extend(time.to_be_bytes());
        fields.push(0x51);
        fields.extend(hash);
        fields.push(0x73);
        fields.push(pk.len() as u8);
        fields.extend(&pk);
        let mut data = b"VAL\x00".to_vec();
        data.extend(&fields);
        let sig = k.sign(&data).to_bytes();
        fields.push(0x76);
        fields.push(sig.len() as u8);
        fields.extend(sig);
        fields
    }

    /// A full validation after a partial one from the same key for the same
    /// hash replaces it, and a partial one after a full one breaks nothing.
    #[test]
    fn full_validation_replaces_partial() {
        let dir = tempfile::tempdir().unwrap();
        let c = Confirmer::new(Vec::new(), dir.path().to_path_buf());
        let full_of = |c: &Confirmer| -> Vec<bool> {
            c.lock().validations[&100].iter().map(|v| v.2).collect()
        };
        c.add_validation(&foreign(100, false, 5, [1; 32], 10))
            .unwrap();
        assert_eq!(full_of(&c), vec![false]);
        let full = foreign(100, true, 5, [1; 32], 11);
        c.add_validation(&full).unwrap();
        assert_eq!(full_of(&c), vec![true]);
        assert_eq!(c.validations_for(100, &[1; 32]).len(), 1);
        assert_eq!(c.validations_for(100, &[1; 32])[0].0, full);
        c.add_validation(&foreign(100, false, 5, [1; 32], 12))
            .unwrap();
        assert_eq!(full_of(&c), vec![true]);
        assert_eq!(c.validations_for(100, &[1; 32])[0].0, full);
    }
}
