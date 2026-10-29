//! Ledger state over time: a snapshot plus object versions (fjall).
//!
//! Every object version is a separate record: the key is the object key (32 bytes)
//! and the ledger sequence (4 bytes, big-endian), the value is the object after the
//! change; an empty value means deletion. The object as of ledger N is the last
//! version with a sequence no greater than N: one reverse step over the key's range.
//!
//! The starting point is a snapshot of the whole state at one ledger, then the
//! changes of each following ledger, strictly in order and atomically. Headers of
//! applied ledgers are stored here too; they are used to check the state
//! root.
//!
//! The loader also puts the ledger itself into the same batch, as "pending", until
//! its block is written to block storage. That gives loading a single recovery
//! point: everything applied to the state is either already in blocks or
//! waiting here.
//!
//! The same batch carries the indexes (module `index`): transaction by hash
//! (`tx`: hash → ledger, position in the ledger), ledger by hash (`ledger_hash`) and
//! account history (`account_tx`: account, ledger, TransactionIndex → position).
//! History keys are big-endian, so a range scan follows the order in which
//! transactions were applied, forward or backward.
//!
//! The same batch also carries the state tree (module `statetree`): the root after
//! the ledger's changes is checked against its header's `AccountHash` before writing.
//! If it does not match, the ledger is rejected and the state stays at the previous one.
//!
//! And the tree's history (`levels`): ledger → the subtrees at depth 3 that the
//! ledger changed, as (slot u16, hash) pairs, all 4096 of them every 256
//! ledgers. A path at an earlier ledger takes the top of the tree from there
//! and rebuilds the subtree below from the object versions (`state_path_at`).

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};

use crate::index::{AccountId, entries};
use crate::ledger::{Change, Ledger, StateChange};
use crate::statetree::{LEVEL_DEPTH, LEVEL_SLOTS, StateTree, leaf_changes};
use witness_core::evidence::ValidationEvidence;

const BASE: &[u8] = b"base_ledger";
const LAST: &[u8] = b"last_ledger";
/// Last ledger included in the indexes.
const INDEXED: &[u8] = b"indexed_ledger";
/// Ledger the state tree corresponds to.
const TREE: &[u8] = b"tree_ledger";
/// First ledger with a full set of tree levels: paths at earlier ledgers
/// cannot be rebuilt.
const LEVELS_FROM: &[u8] = b"levels_from";
/// A full set of tree levels is written every this many ledgers, so a path
/// reads at most this many ledgers of them.
const LEVELS_EVERY: u32 = 256;
/// Last ledger confirmed by a validator quorum (`confirm`); every ledger
/// before it is confirmed by the chain of parent hashes.
const CONFIRMED: &[u8] = b"confirmed_ledger";
/// The MPT holder index has been built over all object versions (`mpt_holders`).
const MPT_INDEXED: &[u8] = b"mpt_holders_indexed";
/// LedgerEntryType of an MPToken object.
const LT_MPTOKEN: u16 = 0x007F;

/// Transaction position: the ledger and the order within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxPosition {
    pub ledger: u32,
    /// TransactionIndex from the metadata.
    pub index: u32,
}

/// A transaction in an account's history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountTx {
    pub at: TxPosition,
    /// Position in the ledger's transaction list, as stored in the block.
    pub pos: u32,
}

/// A page of account history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountTxPage {
    pub transactions: Vec<AccountTx>,
    /// Where to resume: the first transaction not returned; `None` if everything was returned.
    pub marker: Option<TxPosition>,
}

fn account_key(account: &AccountId, at: TxPosition) -> [u8; 28] {
    let mut k = [0u8; 28];
    k[..20].copy_from_slice(account);
    k[20..24].copy_from_slice(&at.ledger.to_be_bytes());
    k[24..].copy_from_slice(&at.index.to_be_bytes());
    k
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn err(e: fjall::Error) -> String {
    e.to_string()
}

/// MPT issuance and holder account.
type Holder = ([u8; 24], [u8; 20]);
/// MPT holder: the account and the key of its MPToken object.
pub type MptHolder = ([u8; 20], [u8; 32]);

/// Key of an MPT holder version: issuance, account, ledger.
fn holder_key(id: &[u8; 24], acc: &[u8; 20], sequence: u32) -> [u8; 48] {
    let mut k = [0u8; 48];
    k[..24].copy_from_slice(id);
    k[24..44].copy_from_slice(acc);
    k[44..].copy_from_slice(&sequence.to_be_bytes());
    k
}

/// Issuance and holder of an MPToken object; `None` for any other object.
/// LedgerEntryType is the first field of an object in canonical order.
fn mptoken_holder(data: &[u8]) -> Option<Holder> {
    use witness_core::stobject::{self, FieldId, types};
    if data.len() < 3 || data[0] != 0x11 || u16::from_be_bytes([data[1], data[2]]) != LT_MPTOKEN {
        return None;
    }
    let fs = stobject::fields(data).ok()?;
    let id = stobject::find(&fs, FieldId::new(types::HASH192, 1))?
        .try_into()
        .ok()?;
    let acc = stobject::find(&fs, FieldId::new(types::ACCOUNT, 1))?
        .try_into()
        .ok()?;
    Some((id, acc))
}

fn version_key(key: &[u8; 32], sequence: u32) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(key);
    k[32..].copy_from_slice(&sequence.to_be_bytes());
    k
}

/// A `levels` record: (slot u16, hash) pairs in slot order.
fn encode_levels(level: &std::collections::BTreeMap<u16, [u8; 32]>) -> Vec<u8> {
    let mut v = Vec::with_capacity(level.len() * 34);
    for (slot, h) in level {
        v.extend_from_slice(&slot.to_be_bytes());
        v.extend_from_slice(h);
    }
    v
}

fn header_key(sequence: u32) -> [u8; 5] {
    let mut k = [b'h'; 5];
    k[1..].copy_from_slice(&sequence.to_be_bytes());
    k
}

pub struct StateStore {
    db: Database,
    objects: Keyspace,
    meta: Keyspace,
    pending: Keyspace,
    tx: Keyspace,
    ledger_hash: Keyspace,
    account_tx: Keyspace,
    /// MPT holders: issuance (24) + account (20) + ledger → MPToken key or
    /// empty (deleted), versioned like `objects`. Holders are ordered by
    /// account, as in the Clio table.
    mpt_holders: Keyspace,
    /// MPToken key → issuance and account: used to recognize a deleted MPToken.
    mpt_keys: Keyspace,
    tree: StateTree,
    /// Tree history: ledger → changed subtrees at depth 3.
    levels: Keyspace,
    /// Anchor evidence: ledger → quorum validations (JSON).
    evidence: Keyspace,
}

/// What the tree holds at a key's position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Leaf {
    Present(Vec<u8>),
    Empty,
    /// A different leaf: key and object.
    Other([u8; 32], Vec<u8>),
}

/// Path in the state tree to a key, as of the tree's ledger.
#[derive(Debug, Clone)]
pub struct TreePath {
    pub ledger: u32,
    pub header: Vec<u8>,
    pub path: witness_core::shamap::Path,
    pub leaf: Leaf,
}

impl std::fmt::Debug for StateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateStore").finish_non_exhaustive()
    }
}

impl StateStore {
    pub fn open(dir: &std::path::Path) -> Result<StateStore, String> {
        let db = Database::builder(dir).open().map_err(err)?;
        let objects = db
            .keyspace("objects", KeyspaceCreateOptions::default)
            .map_err(err)?;
        let meta = db
            .keyspace("meta", KeyspaceCreateOptions::default)
            .map_err(err)?;
        let ks = |name: &str| {
            db.keyspace(name, KeyspaceCreateOptions::default)
                .map_err(err)
        };
        let (pending, tx, ledger_hash, account_tx) = (
            ks("pending")?,
            ks("tx")?,
            ks("ledger_hash")?,
            ks("account_tx")?,
        );
        let tree = StateTree {
            live: ks("live")?,
            tree: ks("tree")?,
        };
        let evidence = ks("evidence")?;
        let levels = ks("levels")?;
        let (mpt_holders, mpt_keys) = (ks("mpt_holders")?, ks("mpt_keys")?);
        Ok(StateStore {
            db,
            objects,
            meta,
            pending,
            tx,
            ledger_hash,
            account_tx,
            mpt_holders,
            mpt_keys,
            tree,
            levels,
            evidence,
        })
    }

    fn meta_u32(&self, k: &[u8]) -> Result<Option<u32>, String> {
        Ok(self
            .meta
            .get(k)
            .map_err(err)?
            .and_then(|v| <[u8; 4]>::try_from(&v[..]).ok())
            .map(u32::from_be_bytes))
    }

    /// The snapshot ledger; there is no state before it.
    pub fn base(&self) -> Result<Option<u32>, String> {
        self.meta_u32(BASE)
    }

    /// Last applied ledger.
    pub fn last(&self) -> Result<Option<u32>, String> {
        self.meta_u32(LAST)
    }

    /// Header of an applied ledger.
    pub fn header(&self, sequence: u32) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .meta
            .get(header_key(sequence))
            .map_err(err)?
            .map(|v| v.to_vec()))
    }

    /// Loads a snapshot into an empty store. Objects must be in ascending key order.
    pub fn load_snapshot(
        &self,
        sequence: u32,
        header: &[u8],
        objects: impl Iterator<Item = Result<([u8; 32], Vec<u8>), String>>,
    ) -> Result<u64, String> {
        if self.base()?.is_some() {
            return Err("snapshot already loaded".into());
        }
        let mut ing = self.objects.start_ingestion().map_err(err)?;
        let mut n = 0u64;
        let mut prev: Option<[u8; 32]> = None;
        for item in objects {
            let (key, data) = item?;
            if prev.is_some_and(|p| p >= key) {
                return Err("snapshot objects are not in ascending key order".into());
            }
            ing.write(version_key(&key, sequence), data).map_err(err)?;
            prev = Some(key);
            n += 1;
        }
        ing.finish().map_err(err)?;
        let mut b = self.db.batch();
        b.insert(&self.meta, BASE, sequence.to_be_bytes());
        b.insert(&self.meta, LAST, sequence.to_be_bytes());
        b.insert(&self.meta, header_key(sequence), header);
        b.commit().map_err(err)?;
        self.db.persist(PersistMode::SyncAll).map_err(err)?;
        Ok(n)
    }

    /// Applies the changes of ledger `sequence`; it must be the next one in order.
    pub fn apply(
        &self,
        sequence: u32,
        header: &[u8],
        changes: &[StateChange],
    ) -> Result<(), String> {
        let ledger = Ledger {
            header: header.to_vec(),
            transactions: Vec::new(),
            changes: changes.to_vec(),
        };
        self.apply_batch(sequence, &ledger, None)
    }

    /// Applies a whole ledger: changes, indexes and the ledger itself (`body` is
    /// its serialization) into the pending-block set, in one batch.
    pub fn apply_ledger(&self, sequence: u32, ledger: &Ledger, body: &[u8]) -> Result<(), String> {
        if self.indexed()? != self.last()? {
            return Err("indexes lag behind the state: catch them up first".into());
        }
        self.apply_batch(sequence, ledger, Some(body))
    }

    /// Stores a ledger's anchor evidence (quorum validations).
    pub fn put_evidence(
        &self,
        sequence: u32,
        validations: &[ValidationEvidence],
    ) -> Result<(), String> {
        let v = serde_json::to_vec(validations).map_err(|e| e.to_string())?;
        self.evidence.insert(sequence.to_be_bytes(), v).map_err(err)
    }

    /// Last ledger with anchor evidence.
    pub fn last_evidence(&self) -> Result<Option<u32>, String> {
        match self.evidence.last_key_value() {
            Some(g) => {
                let k = g.key().map_err(err)?;
                Ok(<[u8; 4]>::try_from(&k[..]).ok().map(u32::from_be_bytes))
            }
            None => Ok(None),
        }
    }

    /// The nearest anchor evidence at ledger `sequence` or later.
    pub fn evidence_from(
        &self,
        sequence: u32,
    ) -> Result<Option<(u32, Vec<ValidationEvidence>)>, String> {
        let Some(g) = self.evidence.range(sequence.to_be_bytes()..).next() else {
            return Ok(None);
        };
        let (k, v) = g.into_inner().map_err(err)?;
        let seq = u32::from_be_bytes(<[u8; 4]>::try_from(&k[..]).map_err(|_| "evidence key")?);
        Ok(Some((
            seq,
            serde_json::from_slice(&v).map_err(|e| e.to_string())?,
        )))
    }

    /// Path in the state tree to a key, as of the ledger the tree corresponds
    /// to. Everything is read from one snapshot, so a loader writing at the
    /// same time cannot break consistency.
    pub fn tree_path(&self, key: &[u8; 32]) -> Result<TreePath, String> {
        use crate::statetree::{decode_node, nibble, node_key, range_of};
        use fjall::Readable as _;
        let snap = self.db.snapshot();
        let u32_of = |v: Option<fjall::UserValue>| {
            v.and_then(|v| <[u8; 4]>::try_from(&v[..]).ok())
                .map(u32::from_be_bytes)
        };
        let ledger = u32_of(snap.get(&self.meta, TREE).map_err(err)?).ok_or("no state tree")?;
        let header = snap
            .get(&self.meta, header_key(ledger))
            .map_err(err)?
            .ok_or("no header for the tree's ledger")?
            .to_vec();
        let object_at = |k: &[u8; 32]| -> Result<Vec<u8>, String> {
            let g = snap
                .range(&self.objects, version_key(k, 0)..=version_key(k, ledger))
                .next_back()
                .ok_or("live object missing from versions")?;
            let (_, v) = g.into_inner().map_err(err)?;
            Ok(v.to_vec())
        };
        let mut levels = Vec::new();
        for depth in 0..64 {
            let node = snap
                .get(&self.tree.tree, node_key(key, depth))
                .map_err(err)?
                .and_then(|v| decode_node(&v))
                .ok_or("tree node missing on the path")?;
            levels.push(node);
            let child = node[usize::from(nibble(key, depth))];
            if child == [0u8; 32] {
                return Ok(TreePath {
                    ledger,
                    header,
                    path: witness_core::shamap::Path { levels },
                    leaf: Leaf::Empty,
                });
            }
            if snap
                .contains_key(&self.tree.tree, node_key(key, depth + 1))
                .map_err(err)?
            {
                continue;
            }
            // Below is a leaf: the only live key under this prefix.
            let (lo, hi) = range_of(key, depth + 1);
            let g = snap
                .range(&self.tree.live, lo..=hi)
                .next()
                .ok_or("no leaf under the prefix")?;
            let (k, h) = g.into_inner().map_err(err)?;
            let k: [u8; 32] = k[..].try_into().map_err(|_| "leaf key")?;
            if h[..] != child {
                return Err("leaf hash does not match the node".into());
            }
            let object = object_at(&k)?;
            let leaf = if k == *key {
                Leaf::Present(object)
            } else {
                Leaf::Other(k, object)
            };
            return Ok(TreePath {
                ledger,
                header,
                path: witness_core::shamap::Path { levels },
                leaf,
            });
        }
        Err("path longer than the key".into())
    }

    /// First ledger a path can be rebuilt at (`state_path_at`).
    pub fn levels_from(&self) -> Result<Option<u32>, String> {
        self.meta_u32(LEVELS_FROM)
    }

    /// Rebuilds the tree history from the snapshot up to `levels_from`, for a
    /// store that kept it only from a later ledger. The object versions are
    /// read in one pass per `window` ledgers; the snapshot's tree is built in
    /// `scratch` and every ledger's changes are replayed on it in order, with
    /// the root checked against the ledger's `AccountHash` each time. The
    /// records are written below the existing ones, and `levels_from` moves
    /// down to the snapshot only once all of them are in. Returns the range
    /// rebuilt, `None` if there was nothing to do.
    ///
    /// The scratch tree survives a stop: each ledger's nodes go into one batch
    /// with its records and the number of the ledger, and a later call goes on
    /// from there once the scratch root matches that ledger's `AccountHash`.
    pub fn backfill_levels(
        &self,
        scratch: &std::path::Path,
        window: u32,
        progress: impl Fn(u32, u32),
    ) -> Result<Option<(u32, u32)>, String> {
        use crate::statetree::{LeafChanges, state_leaf_hash_of};
        use fjall::Readable as _;
        let (Some(base), Some(to)) = (self.base()?, self.levels_from()?) else {
            return Ok(None);
        };
        if to <= base {
            return Ok(None);
        }
        let account_hash = |seq: u32| -> Result<[u8; 32], String> {
            Ok(Ledger {
                header: self.header(seq)?.ok_or(format!("no header for {seq}"))?,
                transactions: Vec::new(),
                changes: Vec::new(),
            }
            .header()?
            .account_hash)
        };
        // The replay walks the whole tree; with the default cache it rereads
        // the same blocks from the page cache for every ledger.
        let open = || -> Result<_, String> {
            let db = Database::builder(scratch)
                .cache_size(1 << 30)
                .open()
                .map_err(err)?;
            let ks = |name: &str| {
                db.keyspace(name, KeyspaceCreateOptions::default)
                    .map_err(err)
            };
            let t = StateTree {
                live: ks("live")?,
                tree: ks("tree")?,
            };
            let (meta, pending) = (ks("meta")?, ks("records")?);
            Ok((db, t, meta, pending))
        };
        // The scratch tree is for this snapshot and this end, at ledger `done`.
        let mut job = [0u8; 8];
        job[..4].copy_from_slice(&base.to_be_bytes());
        job[4..].copy_from_slice(&to.to_be_bytes());
        let mut resumed = None;
        if scratch.exists() {
            let (db, t, meta, pending) = open()?;
            let done = meta
                .get(b"done")
                .map_err(err)?
                .and_then(|v| <[u8; 4]>::try_from(&v[..]).ok())
                .map(u32::from_be_bytes);
            let same = meta.get(b"job").map_err(err)?.is_some_and(|v| v[..] == job);
            if let Some(d) = done
                && same
                && d >= base
                && d < to
                && t.root()? == account_hash(d)?
            {
                resumed = Some((db, t, meta, pending, d));
            }
        }
        let (db, t, meta, pending, mut next) = match resumed {
            Some((db, t, meta, pending, d)) => (db, t, meta, pending, d + 1),
            None => {
                let _ = std::fs::remove_dir_all(scratch);
                let (db, t, meta, pending) = open()?;
                (db, t, meta, pending, base)
            }
        };
        let snap = self.db.snapshot();
        // Records wait in the scratch store, in the batch of their ledger, and
        // move to the tree history in groups; a stop between the two steps
        // only moves some of them twice.
        let flush = || -> Result<(), String> {
            let mut moved = Vec::new();
            let mut b = self.db.batch();
            for g in pending.iter() {
                let (k, v) = g.into_inner().map_err(err)?;
                b.insert(&self.levels, k.clone(), v);
                moved.push(k);
            }
            if moved.is_empty() {
                return Ok(());
            }
            b.commit().map_err(err)?;
            self.persist()?;
            let mut b = db.batch();
            for k in moved {
                b.remove(&pending, k);
            }
            b.commit().map_err(err)
        };
        flush()?;
        while next < to {
            // Replays ledgers [next, end): the first window starts with the snapshot.
            let end = next.saturating_add(window).min(to);
            let first = next == base;
            let mut snapshot: Vec<([u8; 32], [u8; 32])> = Vec::new();
            let mut changes: Vec<(u32, [u8; 32], Option<[u8; 32]>)> = Vec::new();
            let mut at_base: Option<([u8; 32], Option<[u8; 32]>)> = None;
            for g in snap.iter(&self.objects) {
                let (k, v) = g.into_inner().map_err(err)?;
                let key: [u8; 32] = k[..32].try_into().map_err(|_| "object key")?;
                let seq = u32::from_be_bytes(k[32..].try_into().map_err(|_| "object version")?);
                if first {
                    if at_base.as_ref().is_some_and(|(ck, _)| *ck != key)
                        && let Some((ck, Some(h))) = at_base.take()
                    {
                        snapshot.push((ck, h));
                    }
                    if seq <= base {
                        at_base = Some((key, state_leaf_hash_of(&v, &key)));
                    }
                }
                if seq > base && seq >= next && seq < end {
                    changes.push((seq, key, state_leaf_hash_of(&v, &key)));
                }
            }
            if first {
                if let Some((ck, Some(h))) = at_base {
                    snapshot.push((ck, h));
                }
                let mut nodes = Vec::new();
                let root = t.build(&snapshot, |k, v| {
                    nodes.push((k, v));
                    Ok(())
                })?;
                if root != account_hash(base)? {
                    return Err(format!(
                        "objects at the snapshot do not give the state root of ledger {base}"
                    ));
                }
                for chunk in nodes.chunks(50_000) {
                    let mut b = db.batch();
                    for (k, v) in chunk {
                        b.insert(&t.tree, k.clone(), v.clone());
                    }
                    b.commit().map_err(err)?;
                }
                let mut ing = t.live.start_ingestion().map_err(err)?;
                for (k, h) in &snapshot {
                    ing.write(*k, *h).map_err(err)?;
                }
                ing.finish().map_err(err)?;
                let level = t.levels()?;
                if level.len() != LEVEL_SLOTS {
                    return Err("the snapshot's tree is too sparse for tree history".into());
                }
                let mut b = db.batch();
                b.insert(&pending, base.to_be_bytes(), encode_levels(&level));
                b.insert(&meta, "job", job);
                b.insert(&meta, "done", base.to_be_bytes());
                b.commit().map_err(err)?;
                next = base + 1;
            }
            changes.sort_by_key(|c| c.0);
            let mut i = 0;
            for seq in next..end {
                let mut lc = LeafChanges::new();
                while i < changes.len() && changes[i].0 == seq {
                    lc.insert(changes[i].1, changes[i].2);
                    i += 1;
                }
                let mut b = db.batch();
                let (root, level) =
                    t.update_levels(&lc, &mut b, seq.is_multiple_of(LEVELS_EVERY))?;
                if root != account_hash(seq)? {
                    return Err(format!(
                        "replay does not give the state root of ledger {seq}"
                    ));
                }
                if !level.is_empty() {
                    b.insert(&pending, seq.to_be_bytes(), encode_levels(&level));
                }
                b.insert(&meta, "done", seq.to_be_bytes());
                b.commit().map_err(err)?;
                if seq.is_multiple_of(1024) {
                    flush()?;
                }
                if seq.is_multiple_of(4096) {
                    progress(seq, to);
                }
            }
            flush()?;
            progress(end, to);
            next = end;
        }
        let mut b = self.db.batch();
        b.insert(&self.meta, LEVELS_FROM, base.to_be_bytes());
        b.commit().map_err(err)?;
        self.persist()?;
        drop((t, meta, pending, db));
        let _ = std::fs::remove_dir_all(scratch);
        Ok(Some((base, to - 1)))
    }

    /// Path in the state tree to a key as of an earlier ledger `at`. The top
    /// of the tree comes from the tree history: for each subtree at depth 3,
    /// the last hash recorded at or before `at`, back to the nearest full set.
    /// The key's own subtree is rebuilt from the object versions as of `at` and
    /// must give the recorded hash, and the root must be the header's
    /// `AccountHash`: a gap or a fault in the history is an error, never a
    /// wrong path.
    pub fn state_path_at(&self, key: &[u8; 32], at: u32) -> Result<TreePath, String> {
        use crate::statetree::{inner_hash, level_range, level_slot};
        use fjall::Readable as _;
        use std::ops::Bound;
        use witness_core::shamap::{state_leaf_hash, subtree_hash, walk_from};
        let snap = self.db.snapshot();
        let u32_of = |v: Option<fjall::UserValue>| {
            v.and_then(|v| <[u8; 4]>::try_from(&v[..]).ok())
                .map(u32::from_be_bytes)
        };
        let from = u32_of(snap.get(&self.meta, LEVELS_FROM).map_err(err)?);
        let tree = u32_of(snap.get(&self.meta, TREE).map_err(err)?);
        match (from, tree) {
            (Some(f), Some(t)) if f <= at && at <= t => {}
            (Some(f), _) if at < f => {
                return Err(format!(
                    "state paths start at ledger {f}: the tree history begins there"
                ));
            }
            _ => return Err(format!("no tree history for ledger {at}")),
        }
        let header = snap
            .get(&self.meta, header_key(at))
            .map_err(err)?
            .ok_or("no header for the ledger")?
            .to_vec();
        let want = Ledger {
            header: header.clone(),
            transactions: Vec::new(),
            changes: Vec::new(),
        }
        .header()?
        .account_hash;

        // The subtrees at depth 3 as of `at`.
        let mut slots: Vec<Option<[u8; 32]>> = vec![None; LEVEL_SLOTS];
        let mut missing = LEVEL_SLOTS;
        for g in snap.range(&self.levels, ..=at.to_be_bytes()).rev() {
            let (_, v) = g.into_inner().map_err(err)?;
            for e in v.as_chunks::<34>().0 {
                let slot = usize::from(u16::from_be_bytes([e[0], e[1]]));
                if slots[slot].is_none() {
                    slots[slot] = Some(e[2..].try_into().map_err(|_| "level hash")?);
                    missing -= 1;
                }
            }
            if missing == 0 || v.len() == LEVEL_SLOTS * 34 {
                break;
            }
        }
        if missing > 0 {
            return Err(format!("tree history has a gap before ledger {at}"));
        }
        let slots: Vec<[u8; 32]> = slots.into_iter().flatten().collect();
        // 256 nodes at depth 2, 16 at depth 1, the root.
        let nodes2 = slots.as_chunks::<16>().0;
        let hashes2: Vec<[u8; 32]> = nodes2.iter().map(inner_hash).collect();
        let nodes1 = hashes2.as_chunks::<16>().0;
        let hashes1: Vec<[u8; 32]> = nodes1.iter().map(inner_hash).collect();
        let root: [[u8; 32]; 16] = hashes1.try_into().map_err(|_| "tree top")?;
        if inner_hash(&root) != want {
            return Err(format!(
                "tree history does not give the state root of ledger {at}"
            ));
        }

        // The key's subtree, from the object versions as of `at`. Versions are
        // read in order; a key with many of them (LedgerHashes and busy
        // accounts change almost every ledger) costs two seeks instead: its
        // version as of `at`, and the next key.
        const SEEK_AFTER: usize = 32;
        let slot = level_slot(key);
        let (lo, hi) = level_range(slot);
        let end = Bound::Included(version_key(&hi, u32::MAX));
        let mut leaves = Vec::new();
        let mut objects = std::collections::HashMap::new();
        let mut keep = |k: [u8; 32], v: &[u8]| {
            if !v.is_empty() {
                leaves.push((k, state_leaf_hash(v, &k)));
                objects.insert(k, v.to_vec());
            }
        };
        let mut from = Bound::Included(version_key(&lo, 0));
        'scan: loop {
            // The key being read, its version as of `at` so far, versions seen.
            let mut cur: Option<([u8; 32], Option<fjall::UserValue>, usize)> = None;
            for g in snap.range(&self.objects, (from, end)) {
                let (k, v) = g.into_inner().map_err(err)?;
                let (k, seq): ([u8; 32], [u8; 4]) = (
                    k[..32].try_into().map_err(|_| "object key")?,
                    k[32..].try_into().map_err(|_| "object version")?,
                );
                let seq = u32::from_be_bytes(seq);
                match &mut cur {
                    Some((ck, best, n)) if *ck == k => {
                        *n += 1;
                        if seq <= at {
                            *best = Some(v);
                        }
                        if *n >= SEEK_AFTER {
                            if let Some(g) = snap
                                .range(&self.objects, version_key(&k, 0)..=version_key(&k, at))
                                .next_back()
                            {
                                keep(k, &g.into_inner().map_err(err)?.1);
                            }
                            from = Bound::Excluded(version_key(&k, u32::MAX));
                            continue 'scan;
                        }
                    }
                    _ => {
                        if let Some((ck, Some(b), _)) = cur.take() {
                            keep(ck, &b);
                        }
                        cur = Some((k, (seq <= at).then_some(v), 1));
                    }
                }
            }
            if let Some((ck, Some(b), _)) = cur {
                keep(ck, &b);
            }
            break;
        }
        if subtree_hash(&leaves, LEVEL_DEPTH) != slots[usize::from(slot)] {
            return Err(format!(
                "objects as of ledger {at} do not give the recorded subtree"
            ));
        }
        let n1 = usize::from(key[0] >> 4);
        let n0 = usize::from(key[0]);
        let mut levels = vec![root, nodes1[n1], nodes2[n0]];
        let leaf = match leaves.as_slice() {
            [] => None,
            [only] => Some(*only),
            _ => {
                let (below, leaf) = walk_from(&leaves, key, LEVEL_DEPTH);
                levels.extend(below);
                leaf
            }
        };
        let leaf = match leaf {
            None => Leaf::Empty,
            Some((k, _)) => {
                let object = objects.remove(&k).ok_or("leaf object")?;
                if k == *key {
                    Leaf::Present(object)
                } else {
                    Leaf::Other(k, object)
                }
            }
        };
        Ok(TreePath {
            ledger: at,
            header,
            path: witness_core::shamap::Path { levels },
            leaf,
        })
    }

    /// Last ledger confirmed by a quorum; `None` if none yet.
    pub fn confirmed(&self) -> Result<Option<u32>, String> {
        self.meta_u32(CONFIRMED)
    }

    /// Marks a ledger as confirmed. Only forward, and only up to the applied
    /// ledger: confirmation applies to an already verified chain.
    pub fn set_confirmed(&self, sequence: u32) -> Result<(), String> {
        if self.confirmed()?.is_some_and(|c| c >= sequence) {
            return Ok(());
        }
        if self.last()?.is_none_or(|l| l < sequence) {
            return Err(format!("ledger {sequence} not applied yet"));
        }
        let mut b = self.db.batch();
        b.insert(&self.meta, CONFIRMED, sequence.to_be_bytes());
        b.commit().map_err(err)
    }

    /// Ledger the state tree corresponds to; `None` if there is no tree.
    pub fn tree_ledger(&self) -> Result<Option<u32>, String> {
        self.meta_u32(TREE)
    }

    /// Deletes the whole state tree (for a rebuild). The store must be reopened
    /// afterwards.
    pub fn drop_tree(self) -> Result<(), String> {
        let mut b = self.db.batch();
        b.remove(&self.meta, TREE);
        b.commit().map_err(err)?;
        self.persist()?;
        self.db
            .delete_keyspace(self.tree.live.clone())
            .map_err(err)?;
        self.db
            .delete_keyspace(self.tree.tree.clone())
            .map_err(err)?;
        Ok(())
    }

    /// Root of the state tree.
    pub fn tree_root(&self) -> Result<[u8; 32], String> {
        self.tree.root()
    }

    /// Builds the state tree from scratch for the last applied ledger and
    /// checks the root against its AccountHash. Returns the ledger and the leaf count.
    pub fn build_tree(&self) -> Result<(u32, usize), String> {
        let last = self.last()?.ok_or("store is empty")?;
        if !self.tree.live.is_empty().map_err(err)? || !self.tree.tree.is_empty().map_err(err)? {
            return Err("tree already exists: it can only be built into an empty one".into());
        }
        let mut leaves = Vec::new();
        for item in self.objects_at(last) {
            let (key, data) = item?;
            leaves.push((key, witness_core::shamap::state_leaf_hash(&data, &key)));
        }
        let want = Ledger {
            header: self.header(last)?.ok_or("no header")?,
            transactions: Vec::new(),
            changes: Vec::new(),
        }
        .header()?
        .account_hash;
        let mut nodes = Vec::new();
        let root = self.tree.build(&leaves, |k, v| {
            nodes.push((k, v));
            Ok(())
        })?;
        if root != want {
            return Err(format!(
                "root {} does not match AccountHash {} of ledger {last}",
                hex::encode_upper(root),
                hex::encode_upper(want)
            ));
        }
        for chunk in nodes.chunks(50_000) {
            let mut b = self.db.batch();
            for (k, v) in chunk {
                b.insert(&self.tree.tree, k.clone(), v.clone());
            }
            b.commit().map_err(err)?;
        }
        let mut ing = self.tree.live.start_ingestion().map_err(err)?;
        for (k, h) in &leaves {
            ing.write(*k, *h).map_err(err)?;
        }
        ing.finish().map_err(err)?;
        let mut b = self.db.batch();
        b.insert(&self.meta, TREE, last.to_be_bytes());
        b.commit().map_err(err)?;
        self.persist()?;
        Ok((last, leaves.len()))
    }

    /// Last ledger in the indexes.
    pub fn indexed(&self) -> Result<Option<u32>, String> {
        Ok(self.meta_u32(INDEXED)?.or(self.base()?))
    }

    /// Catches up the indexes for a ledger already applied to the state; it must
    /// be the one right after the last indexed ledger.
    pub fn index_ledger(&self, sequence: u32, ledger: &Ledger) -> Result<(), String> {
        match self.indexed()? {
            Some(i) if i + 1 == sequence && Some(sequence) <= self.last()? => {}
            other => {
                return Err(format!(
                    "indexes are at {other:?}, got {sequence}: only in order"
                ));
            }
        }
        let mut b = self.db.batch();
        self.index_into(&mut b, sequence, ledger)?;
        b.commit().map_err(err)
    }

    fn index_into(
        &self,
        b: &mut fjall::OwnedWriteBatch,
        sequence: u32,
        ledger: &Ledger,
    ) -> Result<(), String> {
        let hash = ledger.header()?.hash();
        b.insert(&self.ledger_hash, hash, sequence.to_be_bytes());
        for e in entries(ledger)? {
            let mut loc = [0u8; 8];
            loc[..4].copy_from_slice(&sequence.to_be_bytes());
            loc[4..].copy_from_slice(&e.pos.to_be_bytes());
            b.insert(&self.tx, e.id, loc);
            let at = TxPosition {
                ledger: sequence,
                index: e.index,
            };
            for a in &e.accounts {
                b.insert(&self.account_tx, account_key(a, at), e.pos.to_be_bytes());
            }
        }
        b.insert(&self.meta, INDEXED, sequence.to_be_bytes());
        Ok(())
    }

    /// On-disk size and approximate record count of each index. Fresh
    /// records not yet flushed from memory are not counted in the on-disk size.
    pub fn index_sizes(&self) -> Vec<(&'static str, u64, usize)> {
        [
            ("tx", &self.tx),
            ("ledger_hash", &self.ledger_hash),
            ("account_tx", &self.account_tx),
            ("levels", &self.levels),
        ]
        .into_iter()
        .map(|(n, k)| (n, k.disk_space(), k.approximate_len()))
        .collect()
    }

    /// The ledger and position of the transaction with this hash.
    pub fn tx_location(&self, id: &[u8; 32]) -> Result<Option<(u32, u32)>, String> {
        Ok(self
            .tx
            .get(id)
            .map_err(err)?
            .filter(|v| v.len() == 8)
            .map(|v| (be32(&v[..4]), be32(&v[4..]))))
    }

    /// Ledger sequence by its hash.
    pub fn ledger_by_hash(&self, hash: &[u8; 32]) -> Result<Option<u32>, String> {
        Ok(self
            .ledger_hash
            .get(hash)
            .map_err(err)?
            .filter(|v| v.len() == 4)
            .map(|v| be32(&v)))
    }

    /// Account history in ledgers `min..=max`: ascending (`forward`) or
    /// descending, at most `limit`, starting at `marker` inclusive.
    pub fn account_tx(
        &self,
        account: &AccountId,
        min: u32,
        max: u32,
        forward: bool,
        limit: usize,
        marker: Option<TxPosition>,
    ) -> Result<AccountTxPage, String> {
        let mut lo = TxPosition {
            ledger: min,
            index: 0,
        };
        let mut hi = TxPosition {
            ledger: max,
            index: u32::MAX,
        };
        if let Some(m) = marker {
            if forward {
                lo = lo.max(m);
            } else {
                hi = hi.min(m);
            }
        }
        let mut page = AccountTxPage {
            transactions: Vec::new(),
            marker: None,
        };
        if lo > hi {
            return Ok(page);
        }
        let range = self
            .account_tx
            .range(account_key(account, lo)..=account_key(account, hi));
        let items: Box<dyn Iterator<Item = fjall::Guard>> = if forward {
            Box::new(range)
        } else {
            Box::new(range.rev())
        };
        for g in items {
            let (k, v) = g.into_inner().map_err(err)?;
            let at = TxPosition {
                ledger: be32(&k[20..24]),
                index: be32(&k[24..28]),
            };
            if page.transactions.len() == limit {
                page.marker = Some(at);
                break;
            }
            page.transactions.push(AccountTx { at, pos: be32(&v) });
        }
        Ok(page)
    }

    fn apply_batch(
        &self,
        sequence: u32,
        ledger: &Ledger,
        body: Option<&[u8]>,
    ) -> Result<(), String> {
        let (header, changes) = (&ledger.header[..], &ledger.changes[..]);
        match self.last()? {
            Some(last) if last + 1 == sequence => {}
            Some(last) => {
                return Err(format!(
                    "applied {last}, got {sequence}: changes only in order"
                ));
            }
            None => return Err("load a state snapshot first".into()),
        }
        let mut b = self.db.batch();
        // State root is checked before writing: if it does not match, the ledger is rejected.
        let tree_current = self.tree_ledger()? == Some(sequence - 1);
        if tree_current {
            let levels_from = self.levels_from()?;
            let full = levels_from.is_none() || sequence.is_multiple_of(LEVELS_EVERY);
            let (root, level) = self
                .tree
                .update_levels(&leaf_changes(changes), &mut b, full)?;
            let want = ledger.header()?.account_hash;
            if root != want {
                return Err(format!(
                    "ledger {sequence}: state root {} does not match AccountHash {}, changes rejected",
                    hex::encode_upper(root),
                    hex::encode_upper(want)
                ));
            }
            b.insert(&self.meta, TREE, sequence.to_be_bytes());
            if !level.is_empty() {
                b.insert(&self.levels, sequence.to_be_bytes(), encode_levels(&level));
            }
            if levels_from.is_none() && level.len() == LEVEL_SLOTS {
                b.insert(&self.meta, LEVELS_FROM, sequence.to_be_bytes());
            }
        }
        for c in changes {
            let value: &[u8] = match c.change {
                Change::Deleted => &[],
                Change::Created | Change::Modified => &c.data,
            };
            b.insert(&self.objects, version_key(&c.key, sequence), value);
            self.index_mpt(&mut b, sequence, c)?;
        }
        if let Some(l) = body {
            b.insert(&self.pending, sequence.to_be_bytes(), l);
            self.index_into(&mut b, sequence, ledger)?;
        }
        b.insert(&self.meta, LAST, sequence.to_be_bytes());
        b.insert(&self.meta, header_key(sequence), header);
        b.commit().map_err(err)
    }

    /// An MPT holder appeared or disappeared: a version in `mpt_holders`. An
    /// MPToken's issuance and account never change, so modifications are ignored.
    fn index_mpt(
        &self,
        b: &mut fjall::OwnedWriteBatch,
        sequence: u32,
        c: &StateChange,
    ) -> Result<(), String> {
        match c.change {
            Change::Created => {
                if let Some((id, acc)) = mptoken_holder(&c.data) {
                    b.insert(&self.mpt_holders, holder_key(&id, &acc, sequence), c.key);
                    b.insert(&self.mpt_keys, c.key, [&id[..], &acc[..]].concat());
                }
            }
            Change::Deleted => {
                if let Some(v) = self.mpt_keys.get(c.key).map_err(err)?
                    && v.len() == 44
                {
                    let (id, acc) = v.split_at(24);
                    let id: &[u8; 24] = id.try_into().map_err(|_| "mpt_keys record")?;
                    let acc: &[u8; 20] = acc.try_into().map_err(|_| "mpt_keys record")?;
                    b.insert(&self.mpt_holders, holder_key(id, acc, sequence), []);
                }
            }
            Change::Modified => {}
        }
        Ok(())
    }

    /// Builds the MPT holder index over all object versions if it does not
    /// exist yet: a single pass on first start. After that `apply` maintains it.
    /// Returns the number of holder versions found, or `None` if the index
    /// already existed.
    pub fn ensure_mpt_index(&self) -> Result<Option<usize>, String> {
        if self.meta.get(MPT_INDEXED).map_err(err)?.is_some() {
            return Ok(None);
        }
        let mut b = self.db.batch();
        let (mut n, mut pending) = (0usize, 0usize);
        // The key and its holder at the latest version (if it is an MPToken).
        let mut cur: Option<([u8; 32], Option<Holder>)> = None;
        for g in self.objects.iter() {
            let (k, v) = g.into_inner().map_err(err)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&k[..32]);
            let seq = u32::from_be_bytes([k[32], k[33], k[34], k[35]]);
            let was = match &cur {
                Some((ck, h)) if *ck == key => *h,
                _ => None,
            };
            let now = mptoken_holder(&v);
            match (was, now) {
                (None, Some((id, acc))) => {
                    b.insert(&self.mpt_holders, holder_key(&id, &acc, seq), key);
                    b.insert(&self.mpt_keys, key, [&id[..], &acc[..]].concat());
                    n += 1;
                    pending += 1;
                }
                (Some((id, acc)), None) => {
                    b.insert(&self.mpt_holders, holder_key(&id, &acc, seq), []);
                    n += 1;
                    pending += 1;
                }
                _ => {}
            }
            cur = Some((key, now));
            if pending >= 10_000 {
                std::mem::replace(&mut b, self.db.batch())
                    .commit()
                    .map_err(err)?;
                pending = 0;
            }
        }
        b.insert(&self.meta, MPT_INDEXED, [1u8]);
        b.commit().map_err(err)?;
        Ok(Some(n))
    }

    /// Holders of issuance `id` as of ledger `at` in ascending account order, strictly
    /// after `after`: the account and MPToken key, at most `limit`.
    pub fn mpt_holders(
        &self,
        id: &[u8; 24],
        at: u32,
        after: Option<&[u8; 20]>,
        limit: usize,
    ) -> Result<Vec<MptHolder>, String> {
        use std::ops::Bound;
        let start = match after {
            Some(a) => Bound::Excluded(holder_key(id, a, u32::MAX).to_vec()),
            None => Bound::Included(holder_key(id, &[0; 20], 0).to_vec()),
        };
        let end = Bound::Included(holder_key(id, &[0xFF; 20], u32::MAX).to_vec());
        let mut out = Vec::new();
        // The account and the key of its latest version no later than `at` (empty if deleted).
        let mut cur: Option<([u8; 20], Vec<u8>)> = None;
        let flush = |c: Option<([u8; 20], Vec<u8>)>, out: &mut Vec<_>| {
            if let Some((a, v)) = c
                && let Ok(k) = <[u8; 32]>::try_from(&v[..])
            {
                out.push((a, k));
            }
        };
        for g in self.mpt_holders.range::<Vec<u8>, _>((start, end)) {
            let (k, v) = g.into_inner().map_err(err)?;
            let mut acc = [0u8; 20];
            acc.copy_from_slice(&k[24..44]);
            let seq = u32::from_be_bytes([k[44], k[45], k[46], k[47]]);
            if cur.as_ref().is_some_and(|(a, _)| *a != acc) {
                flush(cur.take(), &mut out);
                if out.len() >= limit {
                    return Ok(out);
                }
            }
            if seq <= at {
                cur = Some((acc, v.to_vec()));
            } else if cur.is_none() {
                // The holder appeared after the requested ledger: skip it by
                // keeping an empty version so it is not returned.
                cur = Some((acc, Vec::new()));
            }
        }
        flush(cur, &mut out);
        out.truncate(limit);
        Ok(out)
    }

    /// Ledgers waiting for their block, in order.
    pub fn pending(&self) -> Result<Vec<(u32, Vec<u8>)>, String> {
        self.pending
            .iter()
            .map(|g| {
                let (k, v) = g.into_inner().map_err(err)?;
                let k = <[u8; 4]>::try_from(&k[..]).map_err(|_| "pending key")?;
                Ok((u32::from_be_bytes(k), v.to_vec()))
            })
            .collect()
    }

    /// A single ledger waiting for its block.
    pub fn pending_ledger(&self, sequence: u32) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .pending
            .get(sequence.to_be_bytes())
            .map_err(err)?
            .map(|v| v.to_vec()))
    }

    /// Removes pending ledgers up to `upto` inclusive; their block is already written.
    pub fn drop_pending(&self, upto: u32) -> Result<(), String> {
        let mut b = self.db.batch();
        for g in self.pending.range(..=upto.to_be_bytes()) {
            let k = g.key().map_err(err)?;
            b.remove(&self.pending, k);
        }
        b.commit().map_err(err)
    }

    pub fn persist(&self) -> Result<(), String> {
        self.db.persist(PersistMode::SyncAll).map_err(err)
    }

    /// Object `key` as of ledger `at`; `None` if it does not exist (not created or deleted).
    pub fn get(&self, key: &[u8; 32], at: u32) -> Result<Option<Vec<u8>>, String> {
        match self.base()? {
            Some(b) if at >= b => {}
            _ => {
                return Err(format!(
                    "no state for ledger {at}: it is before the snapshot"
                ));
            }
        }
        let Some(guard) = self
            .objects
            .range(version_key(key, 0)..=version_key(key, at))
            .next_back()
        else {
            return Ok(None);
        };
        let (_, v) = guard.into_inner().map_err(err)?;
        Ok((!v.is_empty()).then(|| v.to_vec()))
    }

    /// Objects `keys` as of ledger `at`, in the same order. Each version read is a
    /// range seek across all LSM levels (about 0.2 ms), so large sets are read
    /// on several threads.
    pub fn get_many(&self, keys: &[[u8; 32]], at: u32) -> Result<Vec<Option<Vec<u8>>>, String> {
        const PER_THREAD: usize = 32;
        const THREADS: usize = 6;
        if keys.len() <= PER_THREAD {
            return keys.iter().map(|k| self.get(k, at)).collect();
        }
        let chunk = keys.len().div_ceil(THREADS).max(PER_THREAD);
        std::thread::scope(|s| {
            let parts: Vec<_> = keys
                .chunks(chunk)
                .map(|c| s.spawn(move || c.iter().map(|k| self.get(k, at)).collect::<Vec<_>>()))
                .collect();
            let mut out = Vec::with_capacity(keys.len());
            for p in parts {
                for r in p.join().map_err(|_| "reader thread panicked".to_string())? {
                    out.push(r?);
                }
            }
            Ok(out)
        })
    }

    /// All objects as of ledger `at`, in ascending key order.
    pub fn objects_at(
        &self,
        at: u32,
    ) -> impl Iterator<Item = Result<([u8; 32], Vec<u8>), String>> + '_ {
        self.objects_after(at, None)
    }

    /// Like `objects_after`, but for `ledger_data` pages: it jumps from key to key
    /// and finds the version at `at` with a seek. The cost of a page depends on its
    /// size, not on how many versions the keys along the way have piled up
    /// (LedgerHashes and busy accounts change almost every ledger).
    pub fn objects_page(
        &self,
        at: u32,
        after: Option<&[u8; 32]>,
    ) -> impl Iterator<Item = Result<([u8; 32], Vec<u8>), String>> + '_ {
        use std::ops::Bound;
        let mut from = match after {
            Some(k) => Bound::Excluded(version_key(k, u32::MAX).to_vec()),
            None => Bound::Unbounded,
        };
        let mut done = false;
        std::iter::from_fn(move || {
            while !done {
                let next = self
                    .objects
                    .range::<Vec<u8>, _>((from.clone(), Bound::Unbounded))
                    .next();
                let k = match next.map(|g| g.key()) {
                    None => {
                        done = true;
                        return None;
                    }
                    Some(Err(e)) => {
                        done = true;
                        return Some(Err(err(e)));
                    }
                    Some(Ok(k)) => k,
                };
                let mut key = [0u8; 32];
                key.copy_from_slice(&k[..32]);
                from = Bound::Excluded(version_key(&key, u32::MAX).to_vec());
                match self.get(&key, at) {
                    Ok(Some(d)) => return Some(Ok((key, d))),
                    Ok(None) => {}
                    Err(e) => {
                        done = true;
                        return Some(Err(e));
                    }
                }
            }
            None
        })
    }

    /// Objects as of ledger `at` with keys strictly greater than `after`, in
    /// ascending key order.
    pub fn objects_after(
        &self,
        at: u32,
        after: Option<&[u8; 32]>,
    ) -> impl Iterator<Item = Result<([u8; 32], Vec<u8>), String>> + '_ {
        use std::ops::Bound;
        let start = match after {
            Some(k) => Bound::Excluded(version_key(k, u32::MAX).to_vec()),
            None => Bound::Unbounded,
        };
        let mut it = self.objects.range::<Vec<u8>, _>((start, Bound::Unbounded));
        let mut current: Option<([u8; 32], Vec<u8>)> = None;
        let mut done = false;
        std::iter::from_fn(move || {
            loop {
                if done {
                    return None;
                }
                let next = match it.next() {
                    Some(g) => match g.into_inner() {
                        Ok(kv) => Some(kv),
                        Err(e) => return Some(Err(err(e))),
                    },
                    None => None,
                };
                let Some((k, v)) = next else {
                    done = true;
                    return current.take().filter(|(_, d)| !d.is_empty()).map(Ok);
                };
                let mut key = [0u8; 32];
                key.copy_from_slice(&k[..32]);
                let seq = u32::from_be_bytes([k[32], k[33], k[34], k[35]]);
                let emitted = match &current {
                    Some((ck, _)) if *ck != key => current.take(),
                    _ => None,
                };
                if seq <= at {
                    current = Some((key, v.to_vec()));
                } else if current.as_ref().is_none_or(|(ck, _)| *ck != key) {
                    // A version later than the requested ledger, and the key has no earlier one.
                    current = None;
                }
                if let Some((ek, ed)) = emitted
                    && !ed.is_empty()
                {
                    return Some(Ok((ek, ed)));
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(key: u8, change: Change, data: &[u8]) -> StateChange {
        StateChange {
            key: [key; 32],
            change,
            data: data.to_vec(),
        }
    }

    /// MPToken: issuance `id`, holder `acc`, MPTAmount 7.
    fn mptoken(id: u8, acc: u8) -> Vec<u8> {
        let mut d = vec![0x11, 0x00, 0x7F, 0x22, 0, 0, 0, 0, 0x30, 0x1A];
        d.extend(7u64.to_be_bytes());
        d.extend([0x81, 0x14]);
        d.extend([acc; 20]);
        d.extend([0x01, 0x15]);
        d.extend([id; 24]);
        d
    }

    #[test]
    fn mpt_holders_follow_creation_and_deletion() {
        let holders = |s: &StateStore, at, after: Option<[u8; 20]>, limit| {
            s.mpt_holders(&[9; 24], at, after.as_ref(), limit)
                .unwrap()
                .into_iter()
                .map(|(a, k)| (a[0], k[0]))
                .collect::<Vec<_>>()
        };
        for ensure_after_apply in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let s = StateStore::open(dir.path()).unwrap();
            let snap = vec![
                ([5u8; 32], mptoken(9, 0x20)),
                ([6u8; 32], b"not an mptoken".to_vec()),
                ([7u8; 32], mptoken(8, 0x01)),
            ];
            s.load_snapshot(100, &[0; 118], snap.into_iter().map(Ok))
                .unwrap();
            if !ensure_after_apply {
                assert_eq!(s.ensure_mpt_index().unwrap(), Some(2));
            }
            s.apply(101, &[1; 118], &[ch(4, Change::Created, &mptoken(9, 0x10))])
                .unwrap();
            s.apply(
                102,
                &[2; 118],
                &[ch(5, Change::Deleted, b""), ch(6, Change::Deleted, b"")],
            )
            .unwrap();
            if ensure_after_apply {
                assert!(s.ensure_mpt_index().unwrap().is_some());
            }
            assert_eq!(s.ensure_mpt_index().unwrap(), None);
            assert_eq!(holders(&s, 100, None, 10), vec![(0x20, 5)]);
            assert_eq!(holders(&s, 101, None, 10), vec![(0x10, 4), (0x20, 5)]);
            assert_eq!(holders(&s, 101, None, 1), vec![(0x10, 4)]);
            assert_eq!(holders(&s, 101, Some([0x10; 20]), 10), vec![(0x20, 5)]);
            assert_eq!(holders(&s, 102, None, 10), vec![(0x10, 4)]);
        }
    }

    #[test]
    fn versions_answer_by_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let s = StateStore::open(dir.path()).unwrap();
        let snap = vec![([1u8; 32], b"a1".to_vec()), ([2u8; 32], b"b1".to_vec())];
        assert_eq!(
            s.load_snapshot(100, &[0; 118], snap.into_iter().map(Ok))
                .unwrap(),
            2
        );
        s.apply(
            101,
            &[1; 118],
            &[
                ch(1, Change::Modified, b"a2"),
                ch(3, Change::Created, b"c1"),
            ],
        )
        .unwrap();
        s.apply(102, &[2; 118], &[ch(2, Change::Deleted, b"")])
            .unwrap();
        assert!(s.apply(104, &[4; 118], &[]).is_err(), "only in order");

        assert_eq!(s.get(&[1; 32], 100).unwrap().unwrap(), b"a1");
        assert_eq!(s.get(&[1; 32], 101).unwrap().unwrap(), b"a2");
        assert_eq!(s.get(&[1; 32], 500).unwrap().unwrap(), b"a2");
        assert_eq!(s.get(&[2; 32], 101).unwrap().unwrap(), b"b1");
        assert_eq!(s.get(&[2; 32], 102).unwrap(), None);
        assert_eq!(s.get(&[3; 32], 100).unwrap(), None);
        assert_eq!(s.get(&[3; 32], 101).unwrap().unwrap(), b"c1");
        assert!(s.get(&[1; 32], 99).is_err());

        // A batch read matches reading one by one, in the same order, and runs
        // on several threads.
        let many: Vec<[u8; 32]> = (0..100).map(|i| [[1u8, 2, 3, 9][i % 4]; 32]).collect();
        for at in [100, 101, 102] {
            let one: Vec<_> = many.iter().map(|k| s.get(k, at).unwrap()).collect();
            assert_eq!(s.get_many(&many, at).unwrap(), one);
        }
        assert!(s.get_many(&many, 99).is_err());

        let at = |n| -> Vec<(u8, Vec<u8>)> {
            s.objects_at(n)
                .map(|r| r.map(|(k, v)| (k[0], v)).unwrap())
                .collect()
        };
        assert_eq!(at(100), vec![(1, b"a1".to_vec()), (2, b"b1".to_vec())]);
        assert_eq!(
            at(101),
            vec![
                (1, b"a2".to_vec()),
                (2, b"b1".to_vec()),
                (3, b"c1".to_vec())
            ]
        );
        assert_eq!(at(102), vec![(1, b"a2".to_vec()), (3, b"c1".to_vec())]);
        assert_eq!(s.header(101).unwrap().unwrap(), vec![1; 118]);
        assert_eq!(s.last().unwrap(), Some(102));
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = StateStore::open(dir.path()).unwrap();
            s.load_snapshot(
                7,
                &[0; 118],
                std::iter::once(Ok(([9u8; 32], b"x".to_vec()))),
            )
            .unwrap();
            s.apply(8, &[0; 118], &[ch(9, Change::Modified, b"y")])
                .unwrap();
            s.persist().unwrap();
        }
        let s = StateStore::open(dir.path()).unwrap();
        assert_eq!((s.base().unwrap(), s.last().unwrap()), (Some(7), Some(8)));
        assert_eq!(s.get(&[9; 32], 8).unwrap().unwrap(), b"y");
    }

    fn empty(n: u32) -> Ledger {
        Ledger {
            header: header(n),
            transactions: Vec::new(),
            changes: Vec::new(),
        }
    }

    fn header(n: u32) -> Vec<u8> {
        let mut h = vec![0u8; 118];
        h[..4].copy_from_slice(&n.to_be_bytes());
        h
    }

    /// Metadata: TransactionIndex and one modified object with an account.
    fn meta(index: u32, account: u8) -> Vec<u8> {
        let mut m = vec![0x20, 0x1C];
        m.extend(index.to_be_bytes());
        m.extend([0xF8, 0xE5, 0xE7, 0x81, 20]);
        m.extend([account; 20]);
        m.extend([0xE1, 0xE1, 0xF1]);
        m
    }

    #[test]
    fn indexes_answer_tx_ledger_and_account_history() {
        let dir = tempfile::tempdir().unwrap();
        let s = StateStore::open(dir.path()).unwrap();
        s.load_snapshot(1, &header(1), std::iter::empty()).unwrap();
        // Ledgers 2..=4 with two transactions each; account 7 is in all of them,
        // account 8 only in the second transaction of ledger 3. The order in the block
        // is the reverse of the application order, and history follows TransactionIndex.
        for n in 2..=4u32 {
            let second = if n == 3 { 8 } else { 7 };
            let l = Ledger {
                header: header(n),
                transactions: vec![
                    (vec![n as u8, 1], meta(1, second)),
                    (vec![n as u8, 0], meta(0, 7)),
                ],
                changes: Vec::new(),
            };
            s.apply_ledger(n, &l, b"").unwrap();
        }
        let id = witness_core::shamap::tx_id(&[3, 1]);
        assert_eq!(s.tx_location(&id).unwrap(), Some((3, 0)));
        let h = Ledger::header(&empty(4)).unwrap().hash();
        assert_eq!(s.ledger_by_hash(&h).unwrap(), Some(4));

        let pos = |l, i| TxPosition {
            ledger: l,
            index: i,
        };
        let page = s.account_tx(&[7; 20], 1, 10, false, 3, None).unwrap();
        let got: Vec<_> = page.transactions.iter().map(|t| (t.at, t.pos)).collect();
        assert_eq!(got, vec![(pos(4, 1), 0), (pos(4, 0), 1), (pos(3, 0), 1)]);
        assert_eq!(page.marker, Some(pos(2, 1)));
        let rest = s
            .account_tx(&[7; 20], 1, 10, false, 3, page.marker)
            .unwrap();
        assert_eq!(rest.transactions.len(), 2);
        assert_eq!(rest.marker, None);
        let fwd = s.account_tx(&[7; 20], 3, 4, true, 10, None).unwrap();
        let got: Vec<_> = fwd.transactions.iter().map(|t| t.at).collect();
        assert_eq!(got, vec![pos(3, 0), pos(4, 0), pos(4, 1)]);
        let only = s.account_tx(&[8; 20], 1, 10, true, 10, None).unwrap();
        assert_eq!(only.transactions.len(), 1);
        assert_eq!(only.transactions[0].at, pos(3, 1));
    }

    /// A header with a sequence and AccountHash.
    fn header_with(n: u32, account_hash: [u8; 32]) -> Vec<u8> {
        let mut h = header(n);
        h[76..108].copy_from_slice(&account_hash);
        h
    }

    #[test]
    fn state_root_is_checked_on_every_ledger() {
        use witness_core::shamap::{root, state_leaf_hash};
        let dir = tempfile::tempdir().unwrap();
        let s = StateStore::open(dir.path()).unwrap();
        let objs: Vec<([u8; 32], Vec<u8>)> = (1..=5u8).map(|i| ([i; 32], vec![i, i])).collect();
        let leaves = |o: &[([u8; 32], Vec<u8>)]| -> Vec<([u8; 32], [u8; 32])> {
            o.iter().map(|(k, v)| (*k, state_leaf_hash(v, k))).collect()
        };
        let h1 = header_with(1, root(&leaves(&objs)));
        s.load_snapshot(1, &h1, objs.clone().into_iter().map(Ok))
            .unwrap();
        assert_eq!(s.build_tree().unwrap(), (1, 5));
        assert_eq!(s.tree_ledger().unwrap(), Some(1));

        // Ledger 2: modify object 1, delete 2, create 9, with a correct root.
        let after: Vec<([u8; 32], Vec<u8>)> = vec![
            ([1; 32], vec![7]),
            ([3; 32], vec![3, 3]),
            ([4; 32], vec![4, 4]),
            ([5; 32], vec![5, 5]),
            ([9; 32], vec![9]),
        ];
        let l2 = Ledger {
            header: header_with(2, root(&leaves(&after))),
            transactions: Vec::new(),
            changes: vec![
                ch(1, Change::Modified, &[7]),
                ch(2, Change::Deleted, b""),
                ch(9, Change::Created, &[9]),
            ],
        };
        s.apply_ledger(2, &l2, b"").unwrap();
        assert_eq!(
            (s.last().unwrap(), s.tree_ledger().unwrap()),
            (Some(2), Some(2))
        );

        // Ledger 3 with a tampered object: the root does not match, so it is rejected.
        let l3 = Ledger {
            header: header_with(3, root(&leaves(&after))),
            transactions: Vec::new(),
            changes: vec![ch(3, Change::Modified, &[0xFF])],
        };
        let e = s.apply_ledger(3, &l3, b"").unwrap_err();
        assert!(e.contains("state root"), "{e}");
        assert_eq!(s.last().unwrap(), Some(2));
        assert_eq!(s.get(&[3; 32], 2).unwrap().unwrap(), vec![3, 3]);
        assert_eq!(s.tree_root().unwrap(), root(&leaves(&after)));

        // Proofs from the tree match the header's AccountHash.
        use witness_core::stateproof::StateProof;
        let proof = |k: [u8; 32]| {
            let t = s.tree_path(&k).unwrap();
            assert_eq!(t.ledger, 2);
            let (object, other) = match &t.leaf {
                Leaf::Present(o) => (Some(o.clone()), None),
                Leaf::Empty => (None, None),
                Leaf::Other(ok, o) => (None, Some((*ok, o.clone()))),
            };
            StateProof::new(
                &t.header,
                &k,
                object.as_deref(),
                other.as_ref().map(|(k, o)| (k, &o[..])),
                &t.path,
            )
            .verify()
            .unwrap()
        };
        assert!(proof([1; 32]).present);
        assert!(proof([9; 32]).present);
        assert!(!proof([2; 32]).present, "deleted in ledger 2");
        let mut near = [3u8; 32];
        near[31] = 4;
        assert!(
            !proof(near).present,
            "neighbouring key under the same prefix"
        );
    }

    #[test]
    fn paths_at_earlier_ledgers_from_the_tree_history() {
        use std::collections::BTreeMap;
        use witness_core::sha512_half;
        use witness_core::shamap::{root, state_leaf_hash};
        use witness_core::stateproof::StateProof;
        let dir = tempfile::tempdir().unwrap();
        let s = StateStore::open(dir.path()).unwrap();
        // Dense enough that every node above depth 3 is an inner node, as on
        // mainnet; the subtrees at depth 3 hold zero, one or a few keys.
        let key = |i: u32| sha512_half(&i.to_be_bytes());
        let mut state: BTreeMap<[u8; 32], Vec<u8>> =
            (0..6000u32).map(|i| (key(i), vec![i as u8, 1])).collect();
        let hdr = |seq: u32, st: &BTreeMap<[u8; 32], Vec<u8>>| {
            let leaves: Vec<_> = st
                .iter()
                .map(|(k, v)| (*k, state_leaf_hash(v, k)))
                .collect();
            header_with(seq, root(&leaves))
        };
        s.load_snapshot(1, &hdr(1, &state), state.clone().into_iter().map(Ok))
            .unwrap();
        s.build_tree().unwrap();
        let snapshot = state.clone();
        let mut at = BTreeMap::new();
        for seq in 2..=300u32 {
            let mut changes = Vec::new();
            for j in 0..12u32 {
                let i = (seq * 131 + j * 977) % 6400;
                let (k, change) = match (state.contains_key(&key(i)), (seq + j) % 5) {
                    (true, 0) => (key(i), Change::Deleted),
                    (true, _) => (key(i), Change::Modified),
                    (false, _) => (key(i), Change::Created),
                };
                if changes.iter().any(|c: &StateChange| c.key == k) {
                    continue;
                }
                let data = vec![i as u8, seq as u8, 2];
                match change {
                    Change::Deleted => state.remove(&k),
                    _ => state.insert(k, data.clone()),
                };
                changes.push(StateChange {
                    key: k,
                    change,
                    data: if change == Change::Deleted {
                        Vec::new()
                    } else {
                        data
                    },
                });
            }
            let l = Ledger {
                header: hdr(seq, &state),
                transactions: Vec::new(),
                changes,
            };
            s.apply_ledger(seq, &l, b"").unwrap();
            if [2, 3, 100, 255, 256, 257, 300].contains(&seq) {
                at.insert(seq, state.clone());
            }
        }
        assert_eq!(s.levels_from().unwrap(), Some(2));
        assert!(
            s.state_path_at(&key(1), 1)
                .unwrap_err()
                .contains("start at ledger 2")
        );

        // As if the history had started at 256: rebuilt down to the snapshot,
        // in windows, it is the history written while loading, plus ledger 1.
        let records = |s: &StateStore| -> BTreeMap<u32, Vec<u8>> {
            s.levels
                .iter()
                .map(|g| {
                    let (k, v) = g.into_inner().unwrap();
                    (u32::from_be_bytes(k[..].try_into().unwrap()), v.to_vec())
                })
                .collect()
        };
        let written = records(&s);
        let mut b = s.db.batch();
        for seq in written.keys().filter(|seq| **seq < 256) {
            b.remove(&s.levels, seq.to_be_bytes());
        }
        b.insert(&s.meta, LEVELS_FROM, 256u32.to_be_bytes());
        b.commit().unwrap();
        assert!(s.state_path_at(&key(1), 100).is_err());
        let scratch = dir.path().join("scratch");
        // Stopped after the second window, it goes on from there.
        let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.backfill_levels(&scratch, 50, |done, _| assert_ne!(done, 101))
        }));
        assert!(stopped.is_err());
        assert!(scratch.exists());
        assert_eq!(s.levels_from().unwrap(), Some(256));
        let seen = std::cell::RefCell::new(Vec::new());
        assert_eq!(
            s.backfill_levels(&scratch, 50, |done, _| seen.borrow_mut().push(done))
                .unwrap(),
            Some((1, 255))
        );
        assert_eq!(seen.into_inner(), [151, 201, 251, 256]);
        assert_eq!(s.levels_from().unwrap(), Some(1));
        assert!(!scratch.exists());
        let rebuilt = records(&s);
        // Ledger 2 was a full set while loading; the rebuild puts that at 1.
        for (seq, v) in written.iter().filter(|(seq, _)| **seq != 2) {
            assert_eq!(rebuilt.get(seq), Some(v), "ledger {seq}");
        }
        assert_eq!(rebuilt[&1].len(), LEVEL_SLOTS * 34);
        assert_eq!(s.backfill_levels(&scratch, 50, |_, _| {}).unwrap(), None);
        at.insert(1, snapshot.clone());
        for (seq, st) in &at {
            for i in [0u32, 7, 4321, 6001, 6399, 9999] {
                let k = key(i);
                let t = s.state_path_at(&k, *seq).unwrap();
                let (object, other) = match &t.leaf {
                    Leaf::Present(o) => (Some(o.clone()), None),
                    Leaf::Empty => (None, None),
                    Leaf::Other(ok, o) => (None, Some((*ok, o.clone()))),
                };
                let p = StateProof::new(
                    &t.header,
                    &k,
                    object.as_deref(),
                    other.as_ref().map(|(k, o)| (k, &o[..])),
                    &t.path,
                )
                .verify()
                .unwrap_or_else(|e| panic!("ledger {seq}, key {i}: {e}"));
                assert_eq!(p.ledger_index, *seq);
                assert_eq!(object.as_ref(), st.get(&k), "ledger {seq}, key {i}");
            }
        }
    }

    #[test]
    fn pending_ledgers_wait_for_their_block() {
        let dir = tempfile::tempdir().unwrap();
        let s = StateStore::open(dir.path()).unwrap();
        s.load_snapshot(1, &[0; 118], std::iter::empty()).unwrap();
        for n in 2..=5u32 {
            s.apply_ledger(n, &empty(n), &n.to_le_bytes()).unwrap();
        }
        s.drop_pending(3).unwrap();
        assert_eq!(
            s.pending().unwrap(),
            vec![
                (4, 4u32.to_le_bytes().to_vec()),
                (5, 5u32.to_le_bytes().to_vec())
            ]
        );
    }
}
