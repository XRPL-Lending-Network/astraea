//! Replays the state patches of cold history and checks them against the headers.
//!
//! The XRPLA archive carries no state trees, so the patches in its cold segments
//! have never been compared with `AccountHash`, and nothing serves them. This
//! does the comparison: start from the whole state at one ledger, apply each
//! following ledger's patches, and require the rebuilt root to equal the header's
//! `AccountHash` on every ledger. The first ledger that differs stops the replay,
//! so everything before it is known to be good.
//!
//! The tree is held in memory, one `SubTree` for each slot at `LEVEL_DEPTH`, as
//! leaf hashes and inner nodes only: the objects themselves are not kept. Only
//! the slots a ledger changed are hashed again, on several threads when there
//! are enough of them. Patches are read and their leaves hashed ahead, on
//! reader threads.
//!
//! A checkpoint holds the leaves and the header of one ledger whose root
//! matched. It checks itself: loaded again, its leaves must give that header's
//! `AccountHash`, and the header must be the one in the cold history.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use witness_core::ledger::{HEADER_LEN, LedgerHeader};

use crate::cold::{Cold, sync_write};
use crate::statetree::{
    LEVEL_DEPTH, LEVEL_SLOTS, SubTree, inner_hash, level_range, level_slot, state_leaf_hash_of,
};

type Hash = [u8; 32];

/// Fewer changed slots than this are hashed on the calling thread: starting
/// threads would cost more than it saves.
const PARALLEL_MIN: usize = 32;
/// Ledgers each reader may run ahead.
const READ_AHEAD: usize = 64;
const MAGIC: &[u8; 6] = b"XWRC\x00\x01";

/// The state tree during a replay.
pub struct StateTree {
    trees: Vec<SubTree>,
    hashes: Vec<Hash>,
    counts: Vec<u32>,
    dirty: Vec<u16>,
    /// Hash and key count of each node one level above the slots.
    mid: Vec<(Hash, u64)>,
    /// The same two levels above the slots, just below the root.
    top: Vec<(Hash, u64)>,
    tops_ready: bool,
    objects: u64,
    threads: usize,
}

/// A node above the slots from its 16 children, by the tree rule: zeros if
/// empty, the one leaf if alone, else an inner node.
fn node(children: impl Iterator<Item = (Hash, u64)>) -> (Hash, u64) {
    let mut hashes = [[0; 32]; 16];
    let mut total = 0;
    let mut single = [0; 32];
    for (i, (h, c)) in children.enumerate() {
        hashes[i] = h;
        total += c;
        if c == 1 {
            single = h;
        }
    }
    match total {
        0 => ([0; 32], 0),
        1 => (single, 1),
        _ => (inner_hash(&hashes), total),
    }
}

impl std::fmt::Debug for StateTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateTree")
            .field("objects", &self.objects)
            .field("threads", &self.threads)
            .finish_non_exhaustive()
    }
}

impl Default for StateTree {
    fn default() -> Self {
        Self::with_threads(1)
    }
}

impl StateTree {
    /// An empty tree that hashes changed slots on up to `threads` threads.
    pub fn with_threads(threads: usize) -> Self {
        Self {
            trees: (0..LEVEL_SLOTS)
                .map(|s| SubTree::new(level_range(s as u16).0, LEVEL_DEPTH))
                .collect(),
            hashes: vec![[0; 32]; LEVEL_SLOTS],
            counts: vec![0; LEVEL_SLOTS],
            dirty: Vec::new(),
            mid: vec![([0; 32], 0); LEVEL_SLOTS / 16],
            top: vec![([0; 32], 0); 16],
            tops_ready: false,
            objects: 0,
            threads: threads.clamp(1, LEVEL_SLOTS),
        }
    }

    /// Sets an object, or removes it when `data` is empty.
    pub fn set(&mut self, key: Hash, data: &[u8]) {
        self.set_leaf(key, state_leaf_hash_of(data, &key));
    }

    /// Sets a key's leaf hash, or removes the key with `None`.
    pub fn set_leaf(&mut self, key: Hash, leaf: Option<Hash>) {
        let slot = level_slot(&key);
        let tree = &mut self.trees[usize::from(slot)];
        let before = tree.len();
        tree.set(key, leaf);
        self.objects = self.objects + tree.len() as u64 - before as u64;
        self.dirty.push(slot);
    }

    /// Objects in the state now.
    pub fn objects(&self) -> u64 {
        self.objects
    }

    /// Root of the tree, hashing again only what changed since the last call:
    /// the changed slots, and the nodes above them.
    pub fn root(&mut self) -> Hash {
        let mut dirty = std::mem::take(&mut self.dirty);
        dirty.sort_unstable();
        dirty.dedup();
        if self.threads == 1 || dirty.len() < PARALLEL_MIN {
            for &slot in &dirty {
                let i = usize::from(slot);
                self.hashes[i] = self.trees[i].hash();
                self.counts[i] = self.trees[i].len() as u32;
            }
        } else {
            // Contiguous ranges of slots, one per thread; each thread owns its
            // range of trees, hashes and counts.
            let per = LEVEL_SLOTS.div_ceil(self.threads);
            std::thread::scope(|s| {
                let ranges = self
                    .trees
                    .chunks_mut(per)
                    .zip(self.hashes.chunks_mut(per))
                    .zip(self.counts.chunks_mut(per))
                    .enumerate();
                for (n, ((trees, hashes), counts)) in ranges {
                    let first = n * per;
                    let lo = dirty.partition_point(|&d| usize::from(d) < first);
                    let hi = dirty.partition_point(|&d| usize::from(d) < first + per);
                    let mine = &dirty[lo..hi];
                    if mine.is_empty() {
                        continue;
                    }
                    s.spawn(move || {
                        for &slot in mine {
                            let i = usize::from(slot) - first;
                            hashes[i] = trees[i].hash();
                            counts[i] = trees[i].len() as u32;
                        }
                    });
                }
            });
        }
        // The two levels between the slots and the root: 256 nodes of 16
        // slots, then 16 nodes of 16 of those. Only the ancestors of changed
        // slots are hashed again, all of them on the first call.
        let all: Vec<u16>;
        let changed = if self.tops_ready {
            &dirty
        } else {
            all = (0..LEVEL_SLOTS as u16).collect();
            &all
        };
        let mut last = None;
        for mid in changed.iter().map(|&s| usize::from(s) >> 4) {
            if last != Some(mid) {
                last = Some(mid);
                let r = mid * 16..mid * 16 + 16;
                self.mid[mid] = node(
                    self.hashes[r.clone()]
                        .iter()
                        .zip(&self.counts[r])
                        .map(|(h, c)| (*h, u64::from(*c))),
                );
            }
        }
        let mut last = None;
        for top in changed.iter().map(|&s| usize::from(s) >> 8) {
            if last != Some(top) {
                last = Some(top);
                self.top[top] = node(self.mid[top * 16..top * 16 + 16].iter().copied());
            }
        }
        self.tops_ready = true;
        dirty.clear();
        self.dirty = dirty;
        // The root is always an inner node.
        let mut children = [[0; 32]; 16];
        for (c, t) in children.iter_mut().zip(&self.top) {
            *c = t.0;
        }
        inner_hash(&children)
    }

    /// Keys and leaf hashes of the whole state, in key order.
    fn leaves(&self) -> impl Iterator<Item = (&Hash, &Hash)> {
        self.trees.iter().flat_map(|t| t.leaves())
    }
}

/// What a replay went through.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// The last ledger whose root matched.
    pub ledger: u32,
    /// Object versions applied.
    pub versions: u64,
    /// Bytes of object data in those versions, as stored in a ledger.
    pub bytes: u64,
    /// Objects in the state at `ledger`.
    pub objects: u64,
}

/// How to run a replay.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// `report` is called every this many ledgers; 0 for never.
    pub every: u32,
    /// Threads that read patches ahead; at least one.
    pub readers: usize,
    /// Directory for checkpoints and how many ledgers apart they are.
    pub checkpoint: Option<(PathBuf, u32)>,
}

/// One ledger as a reader prepares it: header, leaf changes, bytes of data.
type Prepared = Result<(Vec<u8>, Vec<(Hash, Option<Hash>)>, u64), String>;

fn prepare(cold: &Cold, seq: u32) -> Prepared {
    let (raw, patches) = cold
        .patches(seq)
        .map_err(|e| format!("ledger {seq}: {e}"))?
        .ok_or(format!("ledger {seq} is not in the cold history"))?;
    let bytes = patches.iter().map(|(_, d)| d.len() as u64).sum();
    let leaves = patches
        .iter()
        .map(|(k, d)| (*k, state_leaf_hash_of(d, k)))
        .collect();
    Ok((raw, leaves, bytes))
}

/// Replays `from + 1..=to` over `tree`, which holds the state at `from` with
/// header `base`; `before` is what earlier runs did, for the counters. The
/// error names the first ledger that doesn't hold; `Progress` in the `Err` is
/// what did.
pub fn replay(
    cold: &Cold,
    tree: &mut StateTree,
    base: &[u8],
    before: Progress,
    to: u32,
    opts: &Options,
    mut report: impl FnMut(&Progress),
) -> Result<Progress, (Progress, String)> {
    let parsed = LedgerHeader::parse(base).map_err(|e| (before, e.to_string()))?;
    let mut done = Progress {
        ledger: parsed.sequence,
        objects: tree.objects(),
        ..before
    };
    if base.len() != HEADER_LEN {
        return Err((done, format!("base header is {} bytes", base.len())));
    }
    let root = tree.root();
    if root != parsed.account_hash {
        return Err((
            done,
            format!(
                "base ledger {}: state root {} does not match AccountHash {}",
                parsed.sequence,
                hex::encode_upper(root),
                hex::encode_upper(parsed.account_hash)
            ),
        ));
    }
    let start = parsed.sequence + 1;
    if start > to {
        return Ok(done);
    }
    let readers = opts.readers.max(1);
    std::thread::scope(|s| {
        let mut queues = Vec::with_capacity(readers);
        for r in 0..readers {
            let (tx, rx) = mpsc::sync_channel::<Prepared>(READ_AHEAD);
            queues.push(rx);
            s.spawn(move || {
                for seq in (start + r as u32..=to).step_by(readers) {
                    // A closed queue means the replay stopped.
                    if tx.send(prepare(cold, seq)).is_err() {
                        break;
                    }
                }
            });
        }
        let mut parent = parsed.hash();
        for seq in start..=to {
            let next = queues[((seq - start) as usize) % readers]
                .recv()
                .map_err(|_| (done, format!("ledger {seq}: reader stopped")))?;
            let (raw, leaves, bytes) = next.map_err(|e| (done, e))?;
            let header = LedgerHeader::parse(&raw).map_err(|e| (done, e.to_string()))?;
            if header.sequence != seq {
                return Err((
                    done,
                    format!("ledger {seq}: header says {}", header.sequence),
                ));
            }
            if header.parent_hash != parent {
                return Err((done, format!("ledger {seq}: parent hash breaks the chain")));
            }
            let count = leaves.len();
            for (key, leaf) in leaves {
                tree.set_leaf(key, leaf);
            }
            let root = tree.root();
            if root != header.account_hash {
                return Err((
                    done,
                    format!(
                        "ledger {seq}: state root {} does not match AccountHash {} after {count} patches",
                        hex::encode_upper(root),
                        hex::encode_upper(header.account_hash)
                    ),
                ));
            }
            parent = header.hash();
            done.versions += count as u64;
            done.bytes += bytes;
            done.ledger = seq;
            done.objects = tree.objects();
            if opts.every != 0 && seq.is_multiple_of(opts.every) {
                report(&done);
            }
            if let Some((dir, every)) = &opts.checkpoint
                && *every != 0
                && seq.is_multiple_of(*every)
            {
                save(dir, tree, &raw, &done).map_err(|e| (done, e))?;
            }
        }
        Ok(done)
    })
}

fn checkpoint_path(dir: &Path, seq: u32) -> PathBuf {
    dir.join(format!("replay-{seq:010}.xwrc"))
}

fn checkpoints(dir: &Path) -> Result<Vec<(u32, PathBuf)>, String> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = e.map_err(|e| e.to_string())?.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(seq) = name
            .strip_prefix("replay-")
            .and_then(|n| n.strip_suffix(".xwrc"))
            .and_then(|n| n.parse().ok())
        {
            out.push((seq, p));
        }
    }
    out.sort();
    Ok(out)
}

/// Writes a checkpoint for the ledger with header `raw` and keeps only the
/// latest two.
pub fn save(dir: &Path, tree: &StateTree, raw: &[u8], done: &Progress) -> Result<(), String> {
    let mut out = Vec::with_capacity(MAGIC.len() + HEADER_LEN + 24 + tree.objects() as usize * 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(raw);
    out.extend_from_slice(&done.versions.to_le_bytes());
    out.extend_from_slice(&done.bytes.to_le_bytes());
    out.extend_from_slice(&tree.objects().to_le_bytes());
    for (k, h) in tree.leaves() {
        out.extend_from_slice(k);
        out.extend_from_slice(h);
    }
    sync_write(&checkpoint_path(dir, done.ledger), &out)?;
    let all = checkpoints(dir)?;
    for (_, p) in all.iter().rev().skip(2) {
        fs::remove_file(p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    Ok(())
}

/// Reads a checkpoint into `tree`, which must be empty. Returns the header and
/// the counters. The caller's replay then checks the root against the header.
pub fn load(path: &Path, tree: &mut StateTree) -> Result<(Vec<u8>, Progress), String> {
    let b = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let head = MAGIC.len() + HEADER_LEN + 24;
    if b.len() < head || &b[..MAGIC.len()] != MAGIC {
        return Err(format!("{}: not a replay checkpoint", path.display()));
    }
    let raw = b[MAGIC.len()..MAGIC.len() + HEADER_LEN].to_vec();
    let num = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
    let at = MAGIC.len() + HEADER_LEN;
    let (versions, bytes, objects) = (num(at), num(at + 8), num(at + 16));
    if (b.len() - head) as u64 != objects * 64 {
        return Err(format!(
            "{}: {} bytes of leaves for {objects} objects",
            path.display(),
            b.len() - head
        ));
    }
    if tree.objects() != 0 {
        return Err("checkpoint loaded into a tree that is not empty".into());
    }
    let mut last: Option<&[u8]> = None;
    for leaf in b[head..].as_chunks::<64>().0 {
        if last.is_some_and(|l| l >= &leaf[..32]) {
            return Err(format!("{}: keys out of order", path.display()));
        }
        last = Some(&leaf[..32]);
        let mut k = [0; 32];
        let mut h = [0; 32];
        k.copy_from_slice(&leaf[..32]);
        h.copy_from_slice(&leaf[32..]);
        tree.set_leaf(k, Some(h));
    }
    let ledger = LedgerHeader::parse(&raw)
        .map_err(|e| e.to_string())?
        .sequence;
    Ok((
        raw,
        Progress {
            ledger,
            versions,
            bytes,
            objects,
        },
    ))
}

/// The latest checkpoint in `dir`, if any.
pub fn latest(dir: &Path) -> Result<Option<PathBuf>, String> {
    Ok(checkpoints(dir)?.pop().map(|(_, p)| p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use witness_core::shamap::{root, state_leaf_hash};

    fn key(a: u8, b: u8, c: u8) -> Hash {
        let mut k = [0u8; 32];
        k[0] = a;
        k[1] = b;
        k[31] = c;
        k
    }

    fn expected(objects: &[(Hash, Vec<u8>)]) -> Hash {
        let mut leaves: Vec<_> = objects
            .iter()
            .map(|(k, d)| (*k, state_leaf_hash(d, k)))
            .collect();
        leaves.sort_unstable_by_key(|l| l.0);
        root(&leaves)
    }

    /// Keys spread over many slots, from a small deterministic generator.
    fn spread(n: usize, seed: u64) -> Vec<(Hash, Vec<u8>)> {
        let mut x = seed;
        (0..n)
            .map(|i| {
                let mut k = [0u8; 32];
                for b in k.iter_mut() {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    *b = x as u8;
                }
                (k, vec![i as u8, (i >> 8) as u8, 7])
            })
            .collect()
    }

    #[test]
    fn root_follows_changes_like_a_tree_built_from_scratch() {
        // Keys that share slots, that share a prefix below a slot, and that are
        // alone under a nibble at the top.
        let mut objects = vec![
            (key(0x10, 0x00, 1), vec![1]),
            (key(0x10, 0x00, 2), vec![2]),
            (key(0x10, 0x0F, 3), vec![3]),
            (key(0x1F, 0xF0, 4), vec![4]),
            (key(0xF0, 0x00, 5), vec![5]),
        ];
        let mut tree = StateTree::default();
        for (k, d) in &objects {
            tree.set(*k, d);
        }
        assert_eq!(tree.root(), expected(&objects));
        assert_eq!(tree.objects(), 5);

        // Modified.
        objects[0].1 = vec![9];
        tree.set(objects[0].0, &[9]);
        assert_eq!(tree.root(), expected(&objects));

        // Deleted, leaving one key under a prefix that had two.
        let gone = objects.remove(1);
        tree.set(gone.0, &[]);
        assert_eq!(tree.root(), expected(&objects));
        assert_eq!(tree.objects(), 4);

        // The prefix fills again: no stale inner node may come back.
        objects.push((gone.0, vec![7]));
        tree.set(gone.0, &[7]);
        assert_eq!(tree.root(), expected(&objects));

        // A slot emptied entirely.
        let last = objects.remove(3);
        assert_eq!(last.0, key(0xF0, 0x00, 5));
        tree.set(last.0, &[]);
        assert_eq!(tree.root(), expected(&objects));
    }

    #[test]
    fn a_change_is_seen_in_the_root() {
        let mut tree = StateTree::default();
        tree.set(key(1, 2, 3), &[1]);
        let before = tree.root();
        tree.set(key(1, 2, 3), &[2]);
        assert_ne!(tree.root(), before);
    }

    #[test]
    fn threads_give_the_same_root_as_one() {
        let mut objects = spread(3000, 11);
        let mut one = StateTree::with_threads(1);
        let mut many = StateTree::with_threads(7);
        for round in 0..4 {
            for (k, d) in &objects {
                one.set(*k, d);
                many.set(*k, d);
            }
            let r = one.root();
            assert_eq!(many.root(), r);
            assert_eq!(r, expected(&objects));
            // Change some, delete some, between rounds.
            for (i, o) in objects.iter_mut().enumerate() {
                if i % 3 == round {
                    o.1.push(round as u8);
                }
            }
            for (k, _) in objects.drain(..200) {
                one.set(k, &[]);
                many.set(k, &[]);
            }
        }
        assert_eq!(many.objects(), one.objects());
    }

    #[test]
    fn cached_upper_levels_agree_with_a_full_recount() {
        // Few keys, so that nodes above the slots are empty, hold one leaf or
        // several, and move between those as keys come and go.
        let objects = spread(40, 3);
        let mut tree = StateTree::with_threads(1);
        let mut live: Vec<(Hash, Vec<u8>)> = Vec::new();
        for (i, o) in objects.iter().enumerate() {
            tree.set(o.0, &o.1);
            live.push(o.clone());
            if i % 3 == 2 {
                let gone = live.remove(i % live.len());
                tree.set(gone.0, &[]);
            }
            let r = tree.root();
            assert_eq!(
                r,
                crate::statetree::root_of_levels(&tree.hashes, &tree.counts)
            );
            assert_eq!(r, expected(&live));
        }
        // Down to one key, then none.
        while live.len() > 1 {
            let gone = live.pop().unwrap();
            tree.set(gone.0, &[]);
            assert_eq!(tree.root(), expected(&live));
        }
        let last = live.pop().unwrap();
        tree.set(last.0, &[]);
        assert_eq!(
            tree.root(),
            crate::statetree::root_of_levels(&tree.hashes, &tree.counts)
        );
    }

    #[test]
    fn a_checkpoint_comes_back_with_the_same_root_and_counters() {
        let dir = tempfile::tempdir().unwrap();
        let objects = spread(500, 5);
        let mut tree = StateTree::with_threads(3);
        for (k, d) in &objects {
            tree.set(*k, d);
        }
        let r = tree.root();
        let mut raw = vec![0u8; HEADER_LEN];
        raw[..4].copy_from_slice(&1234u32.to_be_bytes());
        let done = Progress {
            ledger: 1234,
            versions: 99,
            bytes: 4567,
            objects: tree.objects(),
        };
        save(dir.path(), &tree, &raw, &done).unwrap();
        let path = latest(dir.path()).unwrap().unwrap();
        let mut back = StateTree::with_threads(2);
        let (h, p) = load(&path, &mut back).unwrap();
        assert_eq!(h, raw);
        assert_eq!(p, done);
        assert_eq!(back.root(), r);

        // A changed leaf no longer gives the root.
        let mut b = fs::read(&path).unwrap();
        let last = b.len() - 1;
        b[last] ^= 1;
        fs::write(&path, &b).unwrap();
        let mut bad = StateTree::default();
        load(&path, &mut bad).unwrap();
        assert_ne!(bad.root(), r);

        // A cut file is refused.
        fs::write(&path, &b[..b.len() - 10]).unwrap();
        assert!(load(&path, &mut StateTree::default()).is_err());
    }

    #[test]
    fn only_the_latest_two_checkpoints_stay() {
        let dir = tempfile::tempdir().unwrap();
        let tree = StateTree::default();
        for seq in [10u32, 20, 30, 40] {
            let mut raw = vec![0u8; HEADER_LEN];
            raw[..4].copy_from_slice(&seq.to_be_bytes());
            let done = Progress {
                ledger: seq,
                ..Progress::default()
            };
            save(dir.path(), &tree, &raw, &done).unwrap();
        }
        let left: Vec<u32> = checkpoints(dir.path())
            .unwrap()
            .into_iter()
            .map(|c| c.0)
            .collect();
        assert_eq!(left, [30, 40]);
    }
}
