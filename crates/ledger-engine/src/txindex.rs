//! Static indexes for closed history: transaction by hash and
//! account history. They are built once over an immutable range of ledgers;
//! fresh ledgers still go into the fjall indexes.
//!
//! **Transaction by hash (`XTXH`).** The range's transactions are numbered in
//! order: ledger, then position in the ledger. Buckets are keyed by the top `b`
//! bits of the hash; a bucket holds fixed-width entries: a 16-bit fingerprint (the
//! next bits of the hash) and the transaction number. The full hash is not stored:
//! a candidate is read and checked by recomputing its hash, so a matching
//! fingerprint never returns the wrong transaction. A false candidate for a missing
//! hash happens with probability about bucket size / 65 536.
//!
//! **Account history (`XACC`).** Directory: account (20 bytes, ascending),
//! offset and entry count; the lists hold positions (ledger, TransactionIndex) in
//! ascending order, delta-encoded as varints. List order is account_tx order.
//! Version 2 stores the same lists with Rice codes: a position becomes a transaction
//! number within the partition (by ledger, then by TransactionIndex; the transaction
//! count of every ledger is stored in the index), and the differences between
//! numbers are written with one Rice parameter per list; rare large differences are
//! written as length and bits. Lists longer than `SKIP_EVERY` get entry points every
//! `SKIP_EVERY` positions (bit offset and the number before the block), so an
//! account_tx page in either direction decodes one or two blocks, not the whole list.

use std::collections::BTreeMap;

use crate::index::AccountId;

type Res<T> = Result<T, String>;

const TXH_MAGIC: &[u8; 6] = b"XTXH\x00\x01";
const ACC_MAGIC: &[u8; 6] = b"XACC\x00\x01";
const ACC2_MAGIC: &[u8; 6] = b"XACC\x00\x02";
/// Rice quotient from which a difference is written as length and bits.
const RICE_ESCAPE: u64 = 16;
/// Positions per block between entry points of a version 2 list.
const SKIP_EVERY: u64 = 128;
/// Target average bucket size used to pick the number of bucket bits.
const BUCKET_TARGET: u64 = 64;

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_varint(b: &[u8], at: &mut usize) -> Res<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*at).ok_or("varint truncated")?;
        *at += 1;
        v |= u64::from(x & 0x7F) << shift;
        if x & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err("varint too long".into())
}

fn u32_at(b: &[u8], at: usize) -> Res<u32> {
    let x = b.get(at..at + 4).ok_or("index truncated")?;
    Ok(u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

/// Top 64 bits of a hash.
pub(crate) fn top64(h: &[u8; 32]) -> u64 {
    u64::from_be_bytes(h[..8].try_into().unwrap_or_default())
}

/// "Transaction by hash" index over a range of ledgers.
#[derive(Debug)]
pub struct TxHashIndex<'a> {
    first: u32,
    /// Where each ledger's transaction numbering starts (plus the end of the last one).
    starts: Vec<u32>,
    bucket_bits: u32,
    ord_bits: u32,
    offsets: &'a [u8],
    entries: &'a [u8],
}

/// Builds the index: `ledgers` holds, for each ledger of the range in order,
/// the hashes of its transactions in storage order.
pub fn build_tx_index(first: u32, ledgers: &[Vec<[u8; 32]>]) -> Vec<u8> {
    let counts: Vec<u32> = ledgers.iter().map(|l| l.len() as u32).collect();
    let mut tops = Vec::with_capacity(counts.iter().map(|c| *c as usize).sum());
    let mut ordinal = 0u32;
    for txs in ledgers {
        for h in txs {
            tops.push((top64(h), ordinal));
            ordinal += 1;
        }
    }
    build_tx_index_tops(first, &counts, tops)
}

/// Same, from the top 64 bits of the hashes: (bits, transaction number in the range)
/// and each ledger's transaction count, without full hashes in memory.
pub fn build_tx_index_tops(first: u32, counts: &[u32], tops: Vec<(u64, u32)>) -> Vec<u8> {
    let n = tops.len() as u64;
    let bucket_bits = (64 - (n / BUCKET_TARGET).max(1).leading_zeros())
        .saturating_sub(1)
        .min(32);
    let ord_bits = (64 - n.max(1).leading_zeros()).max(1);
    let mut rows: Vec<(u64, u32, u32)> = Vec::with_capacity(n as usize);
    for (t, ordinal) in tops {
        let bucket = if bucket_bits == 0 {
            0
        } else {
            (t >> (64 - bucket_bits)) as u32
        };
        let fp = ((t << bucket_bits) >> 48) as u32;
        rows.push((u64::from(bucket), fp, ordinal));
    }
    rows.sort_unstable();
    let mut out = TXH_MAGIC.to_vec();
    out.extend(first.to_le_bytes());
    out.extend((counts.len() as u32).to_le_bytes());
    out.extend(n.to_le_bytes());
    out.push(bucket_bits as u8);
    out.push(ord_bits as u8);
    let mut acc = 0u32;
    for c in counts {
        out.extend(acc.to_le_bytes());
        acc += c;
    }
    out.extend(acc.to_le_bytes());
    let buckets = 1u64 << bucket_bits;
    let mut i = 0usize;
    for bkt in 0..=buckets {
        while i < rows.len() && rows[i].0 < bkt {
            i += 1;
        }
        out.extend((i as u32).to_le_bytes());
    }
    // Entries: 16-bit fingerprint and number, packed back to back at bit level.
    let width = 16 + ord_bits as usize;
    let mut bits = vec![0u8; (rows.len() * width).div_ceil(8) + 8];
    for (k, (_, fp, ord)) in rows.iter().enumerate() {
        let v = (u64::from(*fp) << ord_bits) | u64::from(*ord);
        put_bits(&mut bits, k * width, width, v);
    }
    out.extend(bits);
    out
}

fn put_bits(b: &mut [u8], at: usize, width: usize, v: u64) {
    for j in 0..width {
        if v >> (width - 1 - j) & 1 == 1 {
            let p = at + j;
            b[p / 8] |= 0x80 >> (p % 8);
        }
    }
}

fn get_bits(b: &[u8], at: usize, width: usize) -> u64 {
    let mut v = 0u64;
    for j in 0..width {
        let p = at + j;
        v = (v << 1) | u64::from(b.get(p / 8).is_some_and(|x| x & (0x80 >> (p % 8)) != 0));
    }
    v
}

impl<'a> TxHashIndex<'a> {
    pub fn open(b: &'a [u8]) -> Res<TxHashIndex<'a>> {
        if !b.starts_with(TXH_MAGIC) {
            return Err("not an XTXH index".into());
        }
        let first = u32_at(b, 6)?;
        let ledgers = u32_at(b, 10)? as usize;
        let n = u64::from_le_bytes(
            b.get(14..22)
                .ok_or("truncated")?
                .try_into()
                .map_err(|_| "n")?,
        );
        let bucket_bits = u32::from(*b.get(22).ok_or("truncated")?);
        let ord_bits = u32::from(*b.get(23).ok_or("truncated")?);
        if bucket_bits > 32 || ord_bits > 40 || ord_bits == 0 {
            return Err("index parameters out of range".into());
        }
        let mut at = 24;
        let mut starts = Vec::with_capacity(ledgers + 1);
        for _ in 0..=ledgers {
            starts.push(u32_at(b, at)?);
            at += 4;
        }
        if u64::from(*starts.last().unwrap_or(&0)) != n {
            return Err("transaction count does not match".into());
        }
        let off_len = ((1usize << bucket_bits) + 1) * 4;
        let offsets = b.get(at..at + off_len).ok_or("buckets truncated")?;
        let entries = &b[at + off_len..];
        let need = (n as usize * (16 + ord_bits as usize)).div_ceil(8);
        if entries.len() < need {
            return Err("entries truncated".into());
        }
        Ok(TxHashIndex {
            first,
            starts,
            bucket_bits,
            ord_bits,
            offsets,
            entries,
        })
    }

    /// Candidates (ledger, position) for a hash; they must be read and checked.
    pub fn candidates(&self, h: &[u8; 32]) -> Res<Vec<(u32, u32)>> {
        let t = top64(h);
        let bucket = if self.bucket_bits == 0 {
            0
        } else {
            (t >> (64 - self.bucket_bits)) as usize
        };
        let fp = (t << self.bucket_bits) >> 48;
        let lo = u32_at(self.offsets, bucket * 4)? as usize;
        let hi = u32_at(self.offsets, bucket * 4 + 4)? as usize;
        let width = 16 + self.ord_bits as usize;
        let mut out = Vec::new();
        for k in lo..hi {
            let v = get_bits(self.entries, k * width, width);
            if v >> self.ord_bits == fp {
                let ord = (v & ((1u64 << self.ord_bits) - 1)) as u32;
                let li = self.starts.partition_point(|s| *s <= ord) - 1;
                out.push((self.first + li as u32, ord - self.starts[li]));
            }
        }
        Ok(out)
    }
}

/// A position in account history: ledger and TransactionIndex.
pub type Posting = (u32, u32);

/// Builds the account history index from entries (account → positions).
pub fn build_account_index(first: u32, postings: &BTreeMap<AccountId, Vec<Posting>>) -> Vec<u8> {
    let mut lists = Vec::new();
    let mut dir = Vec::new();
    for (acc, ps) in postings {
        let off = lists.len() as u64;
        let (mut pl, mut pi) = (first, 0u32);
        for (k, &(l, i)) in ps.iter().enumerate() {
            let dl = l - if k == 0 { first } else { pl };
            put_varint(&mut lists, u64::from(dl));
            // Within the same ledger store the TransactionIndex difference, otherwise the value itself.
            put_varint(
                &mut lists,
                u64::from(if dl == 0 && k > 0 { i - pi } else { i }),
            );
            (pl, pi) = (l, i);
        }
        dir.extend_from_slice(acc);
        put_varint(&mut dir, off);
        put_varint(&mut dir, ps.len() as u64);
    }
    let mut out = ACC_MAGIC.to_vec();
    out.extend(first.to_le_bytes());
    out.extend((postings.len() as u32).to_le_bytes());
    out.extend((dir.len() as u32).to_le_bytes());
    out.extend(dir);
    out.extend(lists);
    out
}

/// Builds a version 2 account history index with Rice-coded lists. `counts` is
/// the transaction count of each ledger in the partition, in order.
pub fn build_account_index_v2(
    first: u32,
    counts: &[u32],
    postings: &BTreeMap<AccountId, Vec<Posting>>,
) -> Res<Vec<u8>> {
    let mut starts = Vec::with_capacity(counts.len());
    let mut acc = 0u64;
    let mut cs = Vec::new();
    for &c in counts {
        starts.push(acc);
        acc += u64::from(c);
        put_varint(&mut cs, u64::from(c));
    }
    let key = |&(l, i): &Posting| -> Res<u64> {
        let d = l.checked_sub(first).ok_or("ledger before the partition")? as usize;
        match (starts.get(d), counts.get(d)) {
            (Some(&s0), Some(&c)) if i < c => Ok(s0 + u64::from(i)),
            _ => Err(format!("position {l}/{i} outside the partition")),
        }
    };
    let mut lists = BitWriter::default();
    let mut dir = Vec::new();
    let mut skips = Vec::new();
    for (a, ps) in postings {
        let last = ps.last().map_or(Ok(0), key)?;
        let mean = (last + 1) / ps.len().max(1) as u64;
        let k = if mean <= 1 {
            0
        } else {
            63 - mean.leading_zeros()
        };
        let off = lists.len;
        let skip_off = skips.len() as u64;
        let (mut prev, mut block_at, mut block_base) = (0u64, off, 0u64);
        for (j, p) in ps.iter().enumerate() {
            if j > 0 && (j as u64).is_multiple_of(SKIP_EVERY) {
                put_varint(&mut skips, lists.len - block_at);
                put_varint(&mut skips, prev - block_base);
                (block_at, block_base) = (lists.len, prev);
            }
            let v = key(p)?;
            lists.rice(v.checked_sub(prev).ok_or("positions not ascending")?, k);
            prev = v;
        }
        dir.extend_from_slice(a);
        put_varint(&mut dir, off);
        put_varint(&mut dir, ps.len() as u64);
        dir.push(k as u8);
        if ps.len() as u64 > SKIP_EVERY {
            put_varint(&mut dir, skip_off);
        }
    }
    let mut out = ACC2_MAGIC.to_vec();
    out.extend(first.to_le_bytes());
    out.extend((postings.len() as u32).to_le_bytes());
    out.extend((dir.len() as u32).to_le_bytes());
    out.extend((counts.len() as u32).to_le_bytes());
    out.extend((cs.len() as u32).to_le_bytes());
    out.extend((skips.len() as u32).to_le_bytes());
    out.extend(cs);
    out.extend(dir);
    out.extend(skips);
    out.extend(lists.bytes);
    Ok(out)
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    len: u64,
}

impl BitWriter {
    fn bit(&mut self, b: bool) {
        if self.len.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if b && let Some(x) = self.bytes.last_mut() {
            *x |= 0x80 >> (self.len % 8);
        }
        self.len += 1;
    }

    fn bits(&mut self, v: u64, width: u32) {
        for j in (0..width).rev() {
            self.bit(v >> j & 1 == 1);
        }
    }

    fn rice(&mut self, g: u64, k: u32) {
        let q = g >> k;
        if q < RICE_ESCAPE {
            for _ in 0..q {
                self.bit(true);
            }
            self.bit(false);
            self.bits(g, k);
        } else {
            for _ in 0..RICE_ESCAPE {
                self.bit(true);
            }
            let w = 64 - g.leading_zeros();
            self.bits(u64::from(w), 7);
            self.bits(g, w);
        }
    }
}

struct BitReader<'a> {
    b: &'a [u8],
    at: u64,
}

impl BitReader<'_> {
    fn bit(&mut self) -> Res<bool> {
        let x = *self
            .b
            .get(usize::try_from(self.at / 8).map_err(|e| e.to_string())?)
            .ok_or("list truncated")?;
        let v = x & (0x80 >> (self.at % 8)) != 0;
        self.at += 1;
        Ok(v)
    }

    fn bits(&mut self, width: u32) -> Res<u64> {
        let mut v = 0u64;
        for _ in 0..width {
            v = (v << 1) | u64::from(self.bit()?);
        }
        Ok(v)
    }

    fn rice(&mut self, k: u32) -> Res<u64> {
        let mut q = 0u64;
        while q < RICE_ESCAPE && self.bit()? {
            q += 1;
        }
        if q < RICE_ESCAPE {
            return Ok((q << k) | self.bits(k)?);
        }
        let w = self.bits(7)? as u32;
        if w > 64 {
            return Err("list difference wider than 64 bits".into());
        }
        self.bits(w)
    }
}

/// Account history index.
#[derive(Debug)]
pub struct AccountIndex<'a> {
    first: u32,
    /// Version 2: where each ledger's transaction numbering starts, plus the end of
    /// the last one; empty means version 1 (varint lists).
    starts: Vec<u64>,
    /// Account → (offset, entry count, Rice parameter, entry point offset).
    dir: Vec<(AccountId, u64, u64, u32, u64)>,
    skips: &'a [u8],
    lists: &'a [u8],
}

impl<'a> AccountIndex<'a> {
    pub fn open(b: &'a [u8]) -> Res<AccountIndex<'a>> {
        let v2 = b.starts_with(ACC2_MAGIC);
        if !v2 && !b.starts_with(ACC_MAGIC) {
            return Err("not an XACC index".into());
        }
        let first = u32_at(b, 6)?;
        let n = u32_at(b, 10)? as usize;
        let dl = u32_at(b, 14)? as usize;
        let (starts, head, sl) = if v2 {
            let ledgers = u32_at(b, 18)? as usize;
            let cl = u32_at(b, 22)? as usize;
            let sl = u32_at(b, 26)? as usize;
            let cs = b.get(30..30 + cl).ok_or("transaction counts truncated")?;
            let mut starts = Vec::with_capacity(ledgers.min(1 << 24) + 1);
            let (mut at, mut acc) = (0, 0u64);
            starts.push(0);
            for _ in 0..ledgers {
                acc += get_varint(cs, &mut at)?;
                starts.push(acc);
            }
            (starts, 30 + cl, sl)
        } else {
            (Vec::new(), 18, 0)
        };
        let d = b.get(head..head + dl).ok_or("directory truncated")?;
        let mut dir = Vec::with_capacity(n);
        let mut at = 0;
        for _ in 0..n {
            let acc: AccountId = d
                .get(at..at + 20)
                .ok_or("directory truncated")?
                .try_into()
                .map_err(|_| "account")?;
            at += 20;
            let off = get_varint(d, &mut at)?;
            let cnt = get_varint(d, &mut at)?;
            let (mut k, mut skip) = (0, 0);
            if v2 {
                k = u32::from((*d.get(at).ok_or("directory truncated")?).min(63));
                at += 1;
                if cnt > SKIP_EVERY {
                    skip = get_varint(d, &mut at)?;
                }
            }
            dir.push((acc, off, cnt, k, skip));
        }
        let skips = b
            .get(head + dl..head + dl + sl)
            .ok_or("entry points truncated")?;
        Ok(AccountIndex {
            first,
            starts,
            dir,
            skips,
            lists: &b[head + dl + sl..],
        })
    }

    /// All of an account's positions in ascending order.
    pub fn postings(&self, acc: &AccountId) -> Res<Vec<Posting>> {
        let Ok(k) = self.dir.binary_search_by(|x| x.0.cmp(acc)) else {
            return Ok(Vec::new());
        };
        let (_, off, cnt, rk, _) = self.dir[k];
        let mut out = Vec::with_capacity(cnt.min(1 << 20) as usize);
        if !self.starts.is_empty() {
            for v in self.decode(off, 0, cnt, rk)? {
                out.push(self.posting_of(v)?);
            }
            return Ok(out);
        }
        let mut at = usize::try_from(off).map_err(|e| e.to_string())?;
        let (mut pl, mut pi) = (self.first, 0u32);
        for j in 0..cnt {
            let dl = get_varint(self.lists, &mut at)? as u32;
            let v = get_varint(self.lists, &mut at)? as u32;
            let l = if j == 0 { self.first + dl } else { pl + dl };
            let i = if dl == 0 && j > 0 { pi + v } else { v };
            out.push((l, i));
            (pl, pi) = (l, i);
        }
        Ok(out)
    }

    /// A page of account history: up to `limit` positions strictly after `cursor` in
    /// ascending order or, with `desc`, strictly before it in descending order; without
    /// a cursor, from the start or the end. Version 2 decodes only the blocks it needs.
    pub fn page(
        &self,
        acc: &AccountId,
        cursor: Option<Posting>,
        limit: usize,
        desc: bool,
    ) -> Res<Vec<Posting>> {
        let Ok(k) = self.dir.binary_search_by(|x| x.0.cmp(acc)) else {
            return Ok(Vec::new());
        };
        if self.starts.is_empty() {
            let all = self.postings(acc)?;
            let it: Box<dyn Iterator<Item = &Posting>> = if desc {
                Box::new(all.iter().rev().filter(|p| cursor.is_none_or(|c| **p < c)))
            } else {
                Box::new(all.iter().filter(|p| cursor.is_none_or(|c| **p > c)))
            };
            return Ok(it.take(limit).copied().collect());
        }
        let (_, off, cnt, rk, skip) = self.dir[k];
        let blocks = self.blocks(off, cnt, skip)?;
        // Boundary in numbers: forward takes numbers from it, backward takes numbers below it.
        let x = cursor.map(|c| self.bound(c, desc));
        // Starting block: the last one whose base (the last number of the previous
        // block) is below the boundary; earlier blocks lie entirely beyond it.
        let start = match x {
            Some(x) => blocks.partition_point(|b| b.1 < x).saturating_sub(1),
            None if desc => blocks.len() - 1,
            None => 0,
        };
        let mut out = Vec::new();
        let mut j = start;
        loop {
            let n = (cnt - j as u64 * SKIP_EVERY).min(SKIP_EVERY);
            let vs = self.decode(blocks[j].0, blocks[j].1, n, rk)?;
            if desc {
                for &v in vs.iter().rev().filter(|&&v| x.is_none_or(|x| v < x)) {
                    out.push(self.posting_of(v)?);
                    if out.len() == limit {
                        return Ok(out);
                    }
                }
                if j == 0 {
                    return Ok(out);
                }
                j -= 1;
            } else {
                for &v in vs.iter().filter(|&&v| x.is_none_or(|x| v >= x)) {
                    out.push(self.posting_of(v)?);
                    if out.len() == limit {
                        return Ok(out);
                    }
                }
                j += 1;
                if j == blocks.len() {
                    return Ok(out);
                }
            }
        }
    }

    pub fn accounts(&self) -> usize {
        self.dir.len()
    }

    /// List blocks: (bit offset, number before the block).
    fn blocks(&self, off: u64, cnt: u64, skip: u64) -> Res<Vec<(u64, u64)>> {
        let n = cnt.div_ceil(SKIP_EVERY).max(1);
        let mut out = Vec::with_capacity(n.min(1 << 20) as usize);
        out.push((off, 0));
        let mut at = usize::try_from(skip).map_err(|e| e.to_string())?;
        let (mut bit, mut base) = (off, 0u64);
        for _ in 1..n {
            bit = bit
                .checked_add(get_varint(self.skips, &mut at)?)
                .ok_or("entry point outside the list")?;
            base = base
                .checked_add(get_varint(self.skips, &mut at)?)
                .ok_or("entry point outside the partition")?;
            out.push((bit, base));
        }
        Ok(out)
    }

    /// `n` list numbers starting at bit `at`, after number `base`.
    fn decode(&self, at: u64, base: u64, n: u64, k: u32) -> Res<Vec<u64>> {
        let mut r = BitReader { b: self.lists, at };
        let mut v = base;
        let mut out = Vec::with_capacity(n.min(1 << 20) as usize);
        for _ in 0..n {
            v = v
                .checked_add(r.rice(k)?)
                .ok_or("position outside the partition")?;
            out.push(v);
        }
        Ok(out)
    }

    fn posting_of(&self, v: u64) -> Res<Posting> {
        let d = self.starts.partition_point(|&x| x <= v);
        if d == 0 || d >= self.starts.len() {
            return Err("position outside the partition".into());
        }
        let l = u32::try_from(d - 1)
            .ok()
            .and_then(|d| self.first.checked_add(d))
            .ok_or("position outside the partition")?;
        Ok((l, (v - self.starts[d - 1]) as u32))
    }

    /// Boundary for a cursor: the first position number after it (forward) or
    /// the number of partition positions before it (backward, `desc`).
    fn bound(&self, (l, i): Posting, desc: bool) -> u64 {
        let last = self.starts.len() - 1;
        match l.checked_sub(self.first).map(|d| d as usize) {
            None => 0,
            Some(d) if d >= last => self.starts[last],
            Some(d) => {
                let n = self.starts[d + 1] - self.starts[d];
                let i = u64::from(i).min(n);
                self.starts[d] + if desc || i == n { i } else { i + 1 }
            }
        }
    }
}

/// Every how-many-th account directory entry goes into the sparse directory kept
/// in memory by the on-disk reader.
const SPARSE: usize = 128;
/// Every how-many-th XACC ledger start is kept in memory.
const MARK: usize = 64;
/// Maximum bit length of a single difference: 16 ones, 7 length bits, 64 bits.
const MAX_GAP_BITS: u64 = RICE_ESCAPE + 7 + 64;

fn pread(f: &std::fs::File, at: u64, len: usize) -> Res<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut b = vec![0u8; len];
    f.read_exact_at(&mut b, at).map_err(|e| e.to_string())?;
    Ok(b)
}

/// XTXH from disk: only the parameters live in memory; ledger starts, the bucket
/// table and bucket entries are read with pread on demand (the full history is
/// hundreds of millions of ledgers, too many to keep in memory).
#[derive(Debug)]
pub struct TxHashFile {
    file: std::fs::File,
    first: u32,
    ledgers: u32,
    bucket_bits: u32,
    ord_bits: u32,
    offsets_at: u64,
    entries_at: u64,
    entries_len: u64,
}

/// XTXH ledger starts come right after the header.
const TXH_STARTS_AT: u64 = 24;

impl TxHashFile {
    pub fn open(path: &std::path::Path) -> Res<TxHashFile> {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        let h = pread(&file, 0, 24)?;
        if !h.starts_with(TXH_MAGIC) {
            return Err("not an XTXH index".into());
        }
        let first = u32_at(&h, 6)?;
        let ledgers = u32_at(&h, 10)?;
        let n = u64::from_le_bytes(h[14..22].try_into().map_err(|_| "n")?);
        let (bucket_bits, ord_bits) = (u32::from(h[22]), u32::from(h[23]));
        if bucket_bits > 32 || ord_bits > 40 || ord_bits == 0 {
            return Err("index parameters out of range".into());
        }
        let sl = (u64::from(ledgers) + 1) * 4;
        let ol = ((1u64 << bucket_bits) + 1) * 4;
        if TXH_STARTS_AT + sl + ol > len {
            return Err("XTXH index truncated".into());
        }
        let offsets_at = TXH_STARTS_AT + sl;
        let entries_at = offsets_at + ol;
        let f = TxHashFile {
            file,
            first,
            ledgers,
            bucket_bits,
            ord_bits,
            offsets_at,
            entries_at,
            entries_len: len - entries_at,
        };
        if u64::from(f.start(ledgers)?) != n || u64::from(f.word(entries_at - 4)?) != n {
            return Err("XTXH index is inconsistent".into());
        }
        let need = (n * u64::from(16 + ord_bits)).div_ceil(8);
        if f.entries_len < need {
            return Err("XTXH entries truncated".into());
        }
        Ok(f)
    }

    fn word(&self, at: u64) -> Res<u32> {
        u32_at(&pread(&self.file, at, 4)?, 0)
    }

    /// Number of the first transaction of ledger `d`, counted from the partition start.
    fn start(&self, d: u32) -> Res<u32> {
        self.word(TXH_STARTS_AT + u64::from(d) * 4)
    }

    pub fn first(&self) -> u32 {
        self.first
    }

    /// Last ledger of the range.
    pub fn last(&self) -> u32 {
        self.first + self.ledgers - 1
    }

    /// Candidates (ledger, position) for a hash; they must be read and checked.
    pub fn candidates(&self, h: &[u8; 32]) -> Res<Vec<(u32, u32)>> {
        let t = top64(h);
        let bucket = if self.bucket_bits == 0 {
            0
        } else {
            t >> (64 - self.bucket_bits)
        };
        let fp = (t << self.bucket_bits) >> 48;
        let o = pread(&self.file, self.offsets_at + bucket * 4, 8)?;
        let (lo, hi) = (u64::from(u32_at(&o, 0)?), u64::from(u32_at(&o, 4)?));
        if lo >= hi {
            return Ok(Vec::new());
        }
        let width = u64::from(16 + self.ord_bits);
        let (b0, b1) = (
            lo * width / 8,
            (hi * width).div_ceil(8).min(self.entries_len),
        );
        let len = b1
            .checked_sub(b0)
            .ok_or("hash index corrupt: bucket outside the file")?;
        let w = pread(&self.file, self.entries_at + b0, len as usize)?;
        let mut out = Vec::new();
        for k in lo..hi {
            let v = get_bits(&w, (k * width - b0 * 8) as usize, width as usize);
            if v >> self.ord_bits == fp {
                let ord = (v & ((1u64 << self.ord_bits) - 1)) as u32;
                // The last ledger whose start is no later than ord.
                let (mut a, mut b) = (0u32, self.ledgers);
                while b - a > 1 {
                    let m = a + (b - a) / 2;
                    if self.start(m)? <= ord {
                        a = m;
                    } else {
                        b = m;
                    }
                }
                out.push((self.first + a, ord - self.start(a)?));
            }
        }
        Ok(out)
    }
}

/// XACC v2 from disk: memory holds anchor points for ledger starts (every
/// `MARK`-th) and a sparse directory (every `SPARSE`-th entry); ledger starts
/// between anchors, directory entries, entry points and list blocks are read
/// with pread on demand.
#[derive(Debug)]
pub struct AccountFile {
    file: std::fs::File,
    first: u32,
    ledgers: usize,
    /// Start of ledger `k * MARK` and the offset of its difference at the start of the file.
    marks: Vec<(u64, u32)>,
    /// Positions in the partition: the start of the ledger after the last one.
    total: u64,
    cs_len: u64,
    dir_at: u64,
    dir_len: u64,
    skips_at: u64,
    skips_len: u64,
    lists_at: u64,
    lists_len: u64,
    sparse: Vec<(AccountId, u64)>,
    accounts: usize,
}

/// Directory entry: list offset in bits, position count, Rice parameter,
/// entry point offset.
type DirEntry = (u64, u64, u32, u64);

impl AccountFile {
    pub fn open(path: &std::path::Path) -> Res<AccountFile> {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        let h = pread(&file, 0, 30)?;
        if !h.starts_with(ACC2_MAGIC) {
            return Err("not a version 2 XACC index".into());
        }
        let first = u32_at(&h, 6)?;
        let n = u32_at(&h, 10)? as usize;
        let dl = u64::from(u32_at(&h, 14)?);
        let ledgers = u32_at(&h, 18)? as usize;
        let cl = u64::from(u32_at(&h, 22)?);
        let sl = u64::from(u32_at(&h, 26)?);
        if 30 + cl + dl + sl > len {
            return Err("XACC index truncated".into());
        }
        let cs = pread(&file, 30, cl as usize)?;
        let mut marks = Vec::with_capacity(ledgers / MARK + 1);
        let (mut at, mut acc) = (0, 0u64);
        for d in 0..ledgers {
            if d.is_multiple_of(MARK) {
                marks.push((acc, at as u32));
            }
            acc += get_varint(&cs, &mut at)?;
        }
        if ledgers.is_multiple_of(MARK) {
            marks.push((acc, at as u32));
        }
        drop(cs);
        // The directory is read in full once, to build the sparse directory.
        let dir = pread(&file, 30 + cl, dl as usize)?;
        let mut sparse = Vec::with_capacity(n / SPARSE + 1);
        let mut at = 0usize;
        for k in 0..n {
            let start = at;
            let a: AccountId = dir
                .get(at..at + 20)
                .ok_or("directory truncated")?
                .try_into()
                .map_err(|_| "account")?;
            at += 20;
            get_varint(&dir, &mut at)?;
            let cnt = get_varint(&dir, &mut at)?;
            at += 1;
            if cnt > SKIP_EVERY {
                get_varint(&dir, &mut at)?;
            }
            if k % SPARSE == 0 {
                sparse.push((a, start as u64));
            }
        }
        if at as u64 != dl {
            return Err("XACC directory is inconsistent".into());
        }
        let lists_at = 30 + cl + dl + sl;
        Ok(AccountFile {
            file,
            first,
            ledgers,
            marks,
            total: acc,
            cs_len: cl,
            dir_at: 30 + cl,
            dir_len: dl,
            skips_at: 30 + cl + dl,
            skips_len: sl,
            lists_at,
            lists_len: len - lists_at,
            sparse,
            accounts: n,
        })
    }

    pub fn accounts(&self) -> usize {
        self.accounts
    }

    fn entry(&self, acc: &AccountId) -> Res<Option<DirEntry>> {
        let Some(i) = self.sparse.partition_point(|x| x.0 <= *acc).checked_sub(1) else {
            return Ok(None);
        };
        let from = self.sparse[i].1;
        let to = self.sparse.get(i + 1).map_or(self.dir_len, |x| x.1);
        let d = pread(&self.file, self.dir_at + from, (to - from) as usize)?;
        let mut at = 0;
        while at < d.len() {
            let a: AccountId = d
                .get(at..at + 20)
                .ok_or("directory truncated")?
                .try_into()
                .map_err(|_| "account")?;
            at += 20;
            let off = get_varint(&d, &mut at)?;
            let cnt = get_varint(&d, &mut at)?;
            let k = u32::from((*d.get(at).ok_or("directory truncated")?).min(63));
            at += 1;
            let skip = if cnt > SKIP_EVERY {
                get_varint(&d, &mut at)?
            } else {
                0
            };
            if a == *acc {
                return Ok(Some((off, cnt, k, skip)));
            }
            if a > *acc {
                break;
            }
        }
        Ok(None)
    }

    /// Ledger starts `k * MARK ..= min((k + 1) * MARK, ledgers)`.
    fn starts(&self, k: usize) -> Res<Vec<u64>> {
        let (mut v, off) = self.marks[k];
        let n = MARK.min(self.ledgers - k * MARK);
        let len = ((n * 10) as u64).min(self.cs_len - u64::from(off));
        let b = pread(&self.file, 30 + u64::from(off), len as usize)?;
        let mut out = Vec::with_capacity(n + 1);
        out.push(v);
        let mut at = 0;
        for _ in 0..n {
            v += get_varint(&b, &mut at)?;
            out.push(v);
        }
        Ok(out)
    }

    /// Number of the first position no earlier than (ledger, TransactionIndex).
    fn ordinal_at(&self, (l, i): Posting) -> Res<u64> {
        Ok(match l.checked_sub(self.first).map(|d| d as usize) {
            None => 0,
            Some(d) if d >= self.ledgers => self.total,
            Some(d) => {
                let s = self.starts(d / MARK)?;
                let (a, b) = (s[d % MARK], s[d % MARK + 1]);
                a + u64::from(i).min(b - a)
            }
        })
    }

    fn posting_of(&self, v: u64) -> Res<Posting> {
        let Some(k) = self.marks.partition_point(|m| m.0 <= v).checked_sub(1) else {
            return Err("position outside the partition".into());
        };
        let k = k.min(self.ledgers.saturating_sub(1) / MARK);
        let s = self.starts(k)?;
        let j = s.partition_point(|&x| x <= v);
        let d = k * MARK + j;
        if j == 0 || d > self.ledgers {
            return Err("position outside the partition".into());
        }
        Ok((self.first + (d - 1) as u32, (v - s[j - 1]) as u32))
    }

    /// Account positions in [lo, hi] inclusive, at most `limit`; in
    /// ascending order or, with `desc`, descending.
    pub fn range(
        &self,
        acc: &AccountId,
        lo: Posting,
        hi: Posting,
        limit: usize,
        desc: bool,
    ) -> Res<Vec<Posting>> {
        let Some((off, cnt, k, skip)) = self.entry(acc)? else {
            return Ok(Vec::new());
        };
        let a = self.ordinal_at(lo)?;
        // First position strictly after hi.
        let b = self.ordinal_at((hi.0, hi.1.saturating_add(1)))?;
        if a >= b || limit == 0 {
            return Ok(Vec::new());
        }
        // Blocks: (start bit, number before the block).
        let nblocks = cnt.div_ceil(SKIP_EVERY).max(1) as usize;
        let mut blocks = Vec::with_capacity(nblocks);
        blocks.push((off, 0u64));
        if nblocks > 1 {
            let rest = self
                .skips_len
                .checked_sub(skip)
                .ok_or("account index corrupt: entry points outside the file")?;
            let len = ((nblocks - 1) * 20).min(rest as usize);
            let sk = pread(&self.file, self.skips_at + skip, len)?;
            let (mut at, mut bit, mut base) = (0, off, 0u64);
            for _ in 1..nblocks {
                bit = bit
                    .checked_add(get_varint(&sk, &mut at)?)
                    .ok_or("entry point outside the list")?;
                base = base
                    .checked_add(get_varint(&sk, &mut at)?)
                    .ok_or("entry point outside the partition")?;
                blocks.push((bit, base));
            }
        }
        let decode = |j: usize| -> Res<Vec<u64>> {
            let n = (cnt - j as u64 * SKIP_EVERY).min(SKIP_EVERY);
            let start = blocks[j].0;
            let end = blocks
                .get(j + 1)
                .map_or(start + n * MAX_GAP_BITS, |x| x.0)
                .min(self.lists_len * 8);
            let (b0, b1) = (start / 8, end.div_ceil(8).min(self.lists_len));
            let len = b1
                .checked_sub(b0)
                .ok_or("account index corrupt: block outside the file")?;
            let w = pread(&self.file, self.lists_at + b0, len as usize)?;
            let mut r = BitReader {
                b: &w,
                at: start - b0 * 8,
            };
            let mut v = blocks[j].1;
            let mut out = Vec::with_capacity(n as usize);
            for _ in 0..n {
                v = v
                    .checked_add(r.rice(k)?)
                    .ok_or("position outside the partition")?;
                out.push(v);
            }
            Ok(out)
        };
        let x = if desc { b } else { a };
        let mut j = blocks.partition_point(|bl| bl.1 < x).saturating_sub(1);
        let mut out = Vec::new();
        loop {
            let vs = decode(j)?;
            if desc {
                for &v in vs.iter().rev() {
                    if v >= b {
                        continue;
                    }
                    if v < a {
                        return Ok(out);
                    }
                    out.push(self.posting_of(v)?);
                    if out.len() == limit {
                        return Ok(out);
                    }
                }
                if j == 0 {
                    return Ok(out);
                }
                j -= 1;
            } else {
                for &v in &vs {
                    if v < a {
                        continue;
                    }
                    if v >= b {
                        return Ok(out);
                    }
                    out.push(self.posting_of(v)?);
                    if out.len() == limit {
                        return Ok(out);
                    }
                }
                j += 1;
                if j == blocks.len() {
                    return Ok(out);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_index_finds_every_hash_and_rejects_strangers() {
        let mut ledgers = Vec::new();
        let mut all = Vec::new();
        for l in 0..50u32 {
            let txs: Vec<[u8; 32]> = (0..(l % 7) * 13)
                .map(|i| witness_core::sha512_half(&[l.to_le_bytes(), i.to_le_bytes()].concat()))
                .collect();
            all.extend(txs.iter().enumerate().map(|(p, h)| (*h, 100 + l, p as u32)));
            ledgers.push(txs);
        }
        let b = build_tx_index(100, &ledgers);
        let idx = TxHashIndex::open(&b).unwrap();
        for (h, l, p) in &all {
            assert!(idx.candidates(h).unwrap().contains(&(*l, *p)));
        }
        let stranger = witness_core::sha512_half(b"absent hash");
        assert!(idx.candidates(&stranger).unwrap().len() <= 1);
    }

    #[test]
    fn account_postings_round_trip() {
        let mut m: BTreeMap<AccountId, Vec<Posting>> = BTreeMap::new();
        m.insert([1; 20], vec![(10, 0), (10, 5), (12, 1), (40, 3)]);
        m.insert([2; 20], vec![(11, 2)]);
        let b = build_account_index(10, &m);
        let idx = AccountIndex::open(&b).unwrap();
        assert_eq!(idx.postings(&[1; 20]).unwrap(), m[&[1; 20]]);
        assert_eq!(idx.postings(&[2; 20]).unwrap(), m[&[2; 20]]);
        assert!(idx.postings(&[3; 20]).unwrap().is_empty());
        let b2 = build_account_index_v2(10, &[6; 31], &m).unwrap();
        let idx2 = AccountIndex::open(&b2).unwrap();
        for (acc, ps) in &m {
            assert_eq!(&idx2.postings(acc).unwrap(), ps);
        }
        assert!(idx2.postings(&[3; 20]).unwrap().is_empty());
    }

    #[test]
    fn pages_match_the_full_list_both_ways() {
        let mut m: BTreeMap<AccountId, Vec<Posting>> = BTreeMap::new();
        let long: Vec<Posting> = (0..1000u32)
            .flat_map(|l| (0..(l % 3)).map(move |i| (100 + l, i * 2)))
            .collect();
        m.insert([1; 20], long.clone());
        m.insert([2; 20], vec![(150, 1)]);
        let counts = vec![6u32; 1000];
        let b = build_account_index_v2(100, &counts, &m).unwrap();
        let idx = AccountIndex::open(&b).unwrap();
        assert_eq!(idx.postings(&[1; 20]).unwrap(), long);
        let cursors = [
            None,
            Some((99, 0)),
            Some((100, 0)),
            Some((612, 2)),
            Some((613, 1)),
            Some((1099, 4)),
            Some((5000, 0)),
        ];
        for c in cursors {
            for limit in [1, 7, 128, 300, 5000] {
                let fwd: Vec<Posting> = long
                    .iter()
                    .copied()
                    .filter(|p| c.is_none_or(|c| *p > c))
                    .take(limit)
                    .collect();
                let back: Vec<Posting> = long
                    .iter()
                    .rev()
                    .copied()
                    .filter(|p| c.is_none_or(|c| *p < c))
                    .take(limit)
                    .collect();
                assert_eq!(
                    idx.page(&[1; 20], c, limit, false).unwrap(),
                    fwd,
                    "{c:?} {limit}"
                );
                assert_eq!(
                    idx.page(&[1; 20], c, limit, true).unwrap(),
                    back,
                    "{c:?} {limit} desc"
                );
            }
        }
        assert_eq!(idx.page(&[2; 20], None, 10, true).unwrap(), vec![(150, 1)]);
        assert!(idx.page(&[3; 20], None, 10, true).unwrap().is_empty());
    }

    #[test]
    fn file_readers_match_memory_indexes() {
        // Ledger counts that are and are not multiples of MARK, below one anchor step and exactly one.
        for total in [300u32, 320, 64, 1] {
            file_readers_match(total);
        }
    }

    fn file_readers_match(total: u32) {
        let dir = tempfile::tempdir().unwrap();
        let mut ledgers = Vec::new();
        let mut m: BTreeMap<AccountId, Vec<Posting>> = BTreeMap::new();
        for l in 0..total {
            let n = (l % 9) * 3;
            let txs: Vec<[u8; 32]> = (0..n)
                .map(|i| witness_core::sha512_half(&[l.to_le_bytes(), i.to_le_bytes()].concat()))
                .collect();
            for i in 0..n {
                m.entry([(i % 4) as u8; 20])
                    .or_default()
                    .push((1000 + l, i));
                if i % 2 == 0 {
                    m.entry([9; 20]).or_default().push((1000 + l, i));
                }
            }
            ledgers.push(txs);
        }
        for v in m.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        let counts: Vec<u32> = ledgers.iter().map(|l| l.len() as u32).collect();
        let xt = dir.path().join("t.xtxh");
        let xa = dir.path().join("t.xacc");
        std::fs::write(&xt, build_tx_index(1000, &ledgers)).unwrap();
        std::fs::write(&xa, build_account_index_v2(1000, &counts, &m).unwrap()).unwrap();
        let tf = TxHashFile::open(&xt).unwrap();
        assert_eq!((tf.first(), tf.last()), (1000, 999 + total));
        for (l, txs) in ledgers.iter().enumerate() {
            for (p, h) in txs.iter().enumerate() {
                assert!(
                    tf.candidates(h)
                        .unwrap()
                        .contains(&(1000 + l as u32, p as u32))
                );
            }
        }
        let af = AccountFile::open(&xa).unwrap();
        for (acc, ps) in &m {
            let all = af
                .range(acc, (0, 0), (u32::MAX, u32::MAX), usize::MAX, false)
                .unwrap();
            assert_eq!(&all, ps);
            let back = af.range(acc, (1100, 3), (1250, 2), 37, true).unwrap();
            let want: Vec<Posting> = ps
                .iter()
                .rev()
                .copied()
                .filter(|p| *p >= (1100, 3) && *p <= (1250, 2))
                .take(37)
                .collect();
            assert_eq!(back, want);
        }
        assert!(
            af.range(&[7; 20], (0, 0), (u32::MAX, u32::MAX), 10, true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rice_escape_round_trips_wide_gaps() {
        let mut m: BTreeMap<AccountId, Vec<Posting>> = BTreeMap::new();
        m.insert(
            [7; 20],
            vec![(5, 0), (6, 900), (4_000_000, 1), (4_000_000, 2)],
        );
        m.insert([8; 20], (5..400).map(|l| (l, l % 3)).collect());
        let mut counts = vec![3u32; 4_000_000 - 5];
        counts.push(5);
        counts[1] = 901;
        let b = build_account_index_v2(5, &counts, &m).unwrap();
        let idx = AccountIndex::open(&b).unwrap();
        for (acc, ps) in &m {
            assert_eq!(&idx.postings(acc).unwrap(), ps);
        }
    }
}
