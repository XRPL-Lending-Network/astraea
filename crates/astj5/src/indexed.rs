//! Compact persisted indexes. Fingerprints only select candidates; callers must compare full hashes/keys.
use super::*;
use std::collections::BTreeMap;
fn width(n: u64) -> u8 {
    (64 - n.leading_zeros()) as u8
}
#[derive(Clone)]
struct Packed {
    n: usize,
    w: u8,
    words: Vec<u64>,
}
impl Packed {
    fn new(v: &[u64], w: u8) -> Self {
        let mut out = Self {
            n: v.len(),
            w,
            words: vec![0; (v.len() * w as usize).div_ceil(64)],
        };
        if w > 0 {
            for (i, &x) in v.iter().enumerate() {
                let at = i * w as usize;
                let k = at / 64;
                let s = at % 64;
                out.words[k] |= x << s;
                if s + w as usize > 64 {
                    out.words[k + 1] |= x >> (64 - s);
                }
            }
        }
        out
    }
    fn get(&self, i: usize) -> u64 {
        assert!(i < self.n);
        if self.w == 0 {
            return 0;
        }
        let at = i * self.w as usize;
        let k = at / 64;
        let s = at % 64;
        let mut x = self.words[k] >> s;
        if s + self.w as usize > 64 {
            x |= self.words[k + 1] << (64 - s)
        }
        if self.w < 64 {
            x & ((1u64 << self.w) - 1)
        } else {
            x
        }
    }
    fn write(&self, out: &mut Vec<u8>) {
        put(out, self.n as u64);
        out.push(self.w);
        put(out, self.words.len() as u64);
        for x in &self.words {
            out.extend(x.to_le_bytes())
        }
    }
    fn read(r: &mut Read) -> Res<Self> {
        let n = r.count()?;
        let w = r.byte()?;
        if w > 64 {
            return Err("packed width".into());
        }
        let size = r.count()?;
        if size != (n * w as usize).div_ceil(64) {
            return Err("packed size".into());
        }
        let mut words = vec![];
        for _ in 0..size {
            words.push(u64::from_le_bytes(r.take(8)?.try_into().unwrap()));
        }
        Ok(Self { n, w, words })
    }
}
/// Nondecreasing u64 values, Elias-Fano with select samples every 128 values.
#[derive(Clone)]
struct Ef {
    n: usize,
    low: Packed,
    high: Vec<u64>,
    samples: Vec<u64>,
}
impl Ef {
    fn new(v: &[u64]) -> Res<Self> {
        if v.windows(2).any(|w| w[0] > w[1]) {
            return Err("EF order".into());
        }
        let n = v.len();
        let maximum = v.last().copied().unwrap_or(0);
        let ratio = maximum.saturating_add(1) / (n.max(1) as u64);
        let l = width(ratio).saturating_sub(1).min(63);
        let mask = (1u64 << l) - 1;
        let lows: Vec<_> = v.iter().map(|x| x & mask).collect();
        let bits = (maximum >> l) as usize + n + 1;
        let mut high = vec![0; bits.div_ceil(64)];
        let mut samples = vec![];
        for (i, x) in v.iter().enumerate() {
            let at = (x >> l) as usize + i;
            high[at / 64] |= 1u64 << (at % 64);
            if i % 128 == 0 {
                samples.push(at as u64);
            }
        }
        Ok(Self {
            n,
            low: Packed::new(&lows, l),
            high,
            samples,
        })
    }
    fn get(&self, i: usize) -> u64 {
        assert!(i < self.n);
        let p = self.samples[i / 128] as usize;
        let mut left = i % 128;
        let position = if left == 0 {
            p
        } else {
            let mut k = (p + 1) / 64;
            let mut word = self.high[k] & (!0u64 << ((p + 1) % 64));
            loop {
                let c = word.count_ones() as usize;
                if left <= c {
                    while left > 1 {
                        word &= word - 1;
                        left -= 1;
                    }
                    break k * 64 + word.trailing_zeros() as usize;
                } else {
                    left -= c;
                    k += 1;
                    word = self.high[k];
                }
            }
        };
        (((position - i) as u64) << self.low.w) | self.low.get(i)
    }
    fn lower(&self, x: u64) -> usize {
        let (mut l, mut h) = (0, self.n);
        while l < h {
            let m = (l + h) / 2;
            if self.get(m) < x { l = m + 1 } else { h = m }
        }
        l
    }
    fn write(&self, out: &mut Vec<u8>) {
        put(out, self.n as u64);
        self.low.write(out);
        put(out, self.high.len() as u64);
        for x in &self.high {
            out.extend(x.to_le_bytes())
        }
        put(out, self.samples.len() as u64);
        for x in &self.samples {
            out.extend(x.to_le_bytes())
        }
    }
    fn read(r: &mut Read) -> Res<Self> {
        let n = r.count()?;
        let low = Packed::read(r)?;
        if low.n != n || low.w > 63 {
            return Err("EF count/width".into());
        }
        let nh = r.count()?;
        let mut high = vec![];
        for _ in 0..nh {
            high.push(u64::from_le_bytes(r.take(8)?.try_into().unwrap()));
        }
        let ns = r.count()?;
        if ns != n.div_ceil(128) {
            return Err("EF samples".into());
        }
        let mut samples = vec![];
        for _ in 0..ns {
            samples.push(u64::from_le_bytes(r.take(8)?.try_into().unwrap()));
        }
        if high.iter().map(|w| w.count_ones() as usize).sum::<usize>() != n {
            return Err("EF high bits".into());
        }
        // Validate select anchors against the bitvector before permitting random access.
        let mut ordinal = 0;
        let mut si = 0;
        for (k, &w) in high.iter().enumerate() {
            let mut w = w;
            while w != 0 {
                let at = k * 64 + w.trailing_zeros() as usize;
                if ordinal % 128 == 0 {
                    if samples[si] != at as u64 {
                        return Err("EF sample mismatch".into());
                    }
                    si += 1;
                }
                ordinal += 1;
                w &= w - 1;
            }
        }
        let e = Self {
            n,
            low,
            high,
            samples,
        };
        if (1..n).any(|i| e.get(i - 1) > e.get(i)) {
            return Err("EF order".into());
        }
        Ok(e)
    }
}
fn prefix(hash: &[u8; 32], bits: u8) -> u64 {
    u64::from_be_bytes(hash[..8].try_into().unwrap()) >> (64 - bits)
}
struct HashIndex {
    bits: u8,
    values: Ef,
    positions: Packed,
}
impl HashIndex {
    fn new(hashes: &[([u8; 32], u64)], forced: Option<u8>) -> Res<Self> {
        let bits = forced
            .unwrap_or((width(hashes.len().saturating_sub(1) as u64) + 16).min(63))
            .max(1);
        let mut xs: Vec<_> = hashes.iter().map(|(h, p)| (prefix(h, bits), *p)).collect();
        xs.sort_unstable();
        let vals: Vec<_> = xs.iter().map(|x| x.0).collect();
        let pos: Vec<_> = xs.iter().map(|x| x.1).collect();
        let w = width(pos.iter().copied().max().unwrap_or(0));
        Ok(Self {
            bits,
            values: Ef::new(&vals)?,
            positions: Packed::new(&pos, w),
        })
    }
    fn candidates(&self, h: &[u8; 32]) -> Vec<u64> {
        let x = prefix(h, self.bits);
        let at = self.values.lower(x);
        let mut out = vec![];
        for i in at..self.values.n {
            if self.values.get(i) != x {
                break;
            }
            out.push(if self.positions.n == 0 {
                i as u64
            } else {
                self.positions.get(i)
            });
        }
        out
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.bits);
        self.values.write(out);
        self.positions.write(out)
    }
    fn read(r: &mut Read) -> Res<Self> {
        let bits = r.byte()?;
        if bits == 0 || bits > 63 {
            return Err("fingerprint width".into());
        }
        let values = Ef::read(r)?;
        let positions = Packed::read(r)?;
        if positions.n != 0 && values.n != positions.n {
            return Err("hash index lengths".into());
        }
        Ok(Self {
            bits,
            values,
            positions,
        })
    }
}
enum List {
    Var(Vec<u64>),
    Ef(Ef),
}
impl List {
    fn len(&self) -> usize {
        match self {
            Self::Var(v) => v.len(),
            Self::Ef(e) => e.n,
        }
    }
    fn get(&self, i: usize) -> u64 {
        match self {
            Self::Var(v) => v[i],
            Self::Ef(e) => e.get(i),
        }
    }
    fn tail(&self, minimum: u64, maximum: u64, limit: usize) -> Vec<u64> {
        let (mut l, mut h) = (0, self.len());
        while l < h {
            let m = (l + h) / 2;
            if self.get(m) <= maximum {
                l = m + 1
            } else {
                h = m
            }
        }
        let mut out = vec![];
        while l > 0 && out.len() < limit {
            l -= 1;
            let x = self.get(l);
            if x < minimum {
                break;
            }
            out.push(x);
        }
        out
    }
}
struct Posts {
    first: Packed,
    offsets: Ef,
    data: Vec<u8>,
}
impl Posts {
    fn new(lists: impl Iterator<Item = Vec<u64>>) -> Res<Self> {
        let mut starts = vec![];
        let mut offsets = vec![0];
        let mut data = vec![];
        for xs in lists {
            let first = *xs.first().ok_or("empty posting list")?;
            starts.push(first);
            if xs.len() > 1 {
                let mut var = vec![0];
                let mut prev = first;
                for &x in &xs[1..] {
                    if x <= prev {
                        return Err("posting order".into());
                    }
                    put(&mut var, x - prev);
                    prev = x;
                }
                if xs.len() >= 32 {
                    let mut ef = vec![1];
                    Ef::new(&xs)?.write(&mut ef);
                    if ef.len() < var.len() {
                        var = ef;
                    }
                }
                data.extend(var);
            }
            offsets.push(data.len() as u64);
        }
        let bits = width(starts.iter().copied().max().unwrap_or(0));
        Ok(Self {
            first: Packed::new(&starts, bits),
            offsets: Ef::new(&offsets)?,
            data,
        })
    }
    fn list(&self, id: usize) -> Res<List> {
        if id >= self.first.n {
            return Err("posting id".into());
        }
        let first = self.first.get(id);
        let b = &self.data[self.offsets.get(id) as usize..self.offsets.get(id + 1) as usize];
        if b.is_empty() {
            return Ok(List::Var(vec![first]));
        }
        let mut r = Read::new(b);
        let list = match r.byte()? {
            0 => {
                let mut v = vec![first];
                let mut prev = first;
                while r.p < r.b.len() {
                    let d = r.var()?;
                    if d == 0 {
                        return Err("zero posting delta".into());
                    }
                    prev = prev.checked_add(d).ok_or("posting overflow")?;
                    v.push(prev);
                }
                List::Var(v)
            }
            1 => {
                let e = Ef::read(&mut r)?;
                if e.n == 0 || e.get(0) != first {
                    return Err("posting first".into());
                }
                List::Ef(e)
            }
            _ => return Err("posting mode".into()),
        };
        r.end()?;
        Ok(list)
    }
    fn write(&self, out: &mut Vec<u8>) {
        self.first.write(out);
        self.offsets.write(out);
        blob(out, &self.data)
    }
    fn read(r: &mut Read) -> Res<Self> {
        let first = Packed::read(r)?;
        let offsets = Ef::read(r)?;
        let data = r.blob()?.to_vec();
        if offsets.n != first.n + 1
            || offsets.get(0) != 0
            || offsets.get(offsets.n - 1) != data.len() as u64
        {
            return Err("posting extent".into());
        }
        Ok(Self {
            first,
            offsets,
            data,
        })
    }
}
#[derive(Clone)]
struct Route {
    seq: u32,
    tx_first: u64,
    txs: usize,
    patch_first: u64,
    patches: usize,
    order: Option<Packed>,
}
pub struct Indexes {
    tx: HashIndex,
    ledger: HashIndex,
    accounts: Vec<[u8; 20]>,
    account_posts: Posts,
    objects: HashIndex,
    object_posts: Posts,
    routes: Vec<Route>,
}
/// Matches the pinned project's metadata account rule and rippled TxMeta::getAffectedAccounts.
pub fn affected(meta: &[u8]) -> Res<(u32, Vec<[u8; 20]>)> {
    let fs = stobject::fields(meta).map_err(er)?;
    let index = field(&fs, 2, 28)
        .filter(|b| b.len() == 4)
        .ok_or("TransactionIndex")?;
    let index = u32::from_be_bytes(index.try_into().unwrap());
    let nodes = fs
        .iter()
        .find(|f| f.id.type_code == 15 && f.id.field_code == 8)
        .ok_or("AffectedNodes")?;
    let mut accounts = vec![];
    for node in stobject::children(nodes).map_err(er)? {
        let want = if node.id.type_code == 14 && node.id.field_code == 3 {
            8
        } else {
            7
        };
        let fields = stobject::children(&node).map_err(er)?;
        if let Some(group) = fields
            .iter()
            .find(|f| f.id.type_code == 14 && f.id.field_code == want)
        {
            for f in stobject::children(group).map_err(er)? {
                let value = if f.id.type_code == 8 && f.value.len() == 20 {
                    Some(f.value)
                } else if f.id.type_code == 6
                    && [4, 5, 6, 7].contains(&f.id.field_code)
                    && f.value.len() == 48
                {
                    Some(&f.value[28..])
                } else if f.id.type_code == 21 && f.id.field_code == 1 && f.value.len() == 24 {
                    Some(&f.value[4..])
                } else {
                    None
                };
                if let Some(v) = value {
                    let a: [u8; 20] = v.try_into().map_err(|_| "account width")?;
                    if a != [0; 20] {
                        accounts.push(a);
                    }
                }
            }
        }
    }
    accounts.sort_unstable();
    accounts.dedup();
    Ok((index, accounts))
}
impl Indexes {
    pub fn build(rows: &[Row]) -> Res<Self> {
        let mut tx = vec![];
        let mut ledger = vec![];
        let mut accounts: BTreeMap<[u8; 20], Vec<u64>> = BTreeMap::new();
        let mut objects: BTreeMap<[u8; 32], Vec<u64>> = BTreeMap::new();
        let mut routes = vec![];
        let (mut tn, mut pn) = (0u64, 0u64);
        for (ri, row) in rows.iter().enumerate() {
            ledger.push((
                LedgerHeader::parse(&row.header).map_err(er)?.hash(),
                ri as u64,
            ));
            let mut order = vec![];
            for (pos, (_, meta)) in row.txs.iter().enumerate() {
                let (index, accounts) = affected(meta)?;
                order.push((index, pos, accounts));
            }
            order.sort_by_key(|x| x.0);
            if order.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err("duplicate TransactionIndex".into());
            }
            let positions: Vec<_> = order.iter().map(|x| x.1 as u64).collect();
            let perm = if positions.iter().enumerate().all(|(i, p)| i as u64 == *p) {
                None
            } else {
                Some(Packed::new(
                    &positions,
                    width(positions.len().saturating_sub(1) as u64),
                ))
            };
            routes.push(Route {
                seq: row.seq,
                tx_first: tn,
                txs: row.txs.len(),
                patch_first: pn,
                patches: row.patches.len(),
                order: perm,
            });
            for (_, pos, aa) in order {
                tx.push((shamap::tx_id(&row.txs[pos].0), tn));
                for a in aa {
                    accounts.entry(a).or_default().push(tn);
                }
                tn += 1;
            }
            for (key, _) in &row.patches {
                objects.entry(*key).or_default().push(pn);
                pn += 1;
            }
        }
        let account_keys = accounts.keys().copied().collect();
        let account_posts = Posts::new(accounts.into_values())?;
        let object_hashes: Vec<_> = objects
            .keys()
            .enumerate()
            .map(|(i, k)| (sha512_half(k), i as u64))
            .collect();
        let mut object_index = HashIndex::new(&object_hashes, None)?;
        let mut lists: Vec<_> = objects.into_values().collect();
        let ordered: Vec<_> = (0..object_index.positions.n)
            .map(|i| std::mem::take(&mut lists[object_index.positions.get(i) as usize]))
            .collect();
        let object_posts = Posts::new(ordered.into_iter())?;
        object_index.positions = Packed::new(&[], 0);
        Ok(Self {
            tx: HashIndex::new(&tx, None)?,
            ledger: HashIndex::new(&ledger, None)?,
            accounts: account_keys,
            account_posts,
            objects: object_index,
            object_posts,
            routes,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"ASIX2\0\0\0".to_vec();
        self.tx.write(&mut out);
        self.ledger.write(&mut out);
        put(&mut out, self.accounts.len() as u64);
        for a in &self.accounts {
            out.extend(a)
        }
        self.account_posts.write(&mut out);
        self.objects.write(&mut out);
        self.object_posts.write(&mut out);
        put(&mut out, self.routes.len() as u64);
        for r in &self.routes {
            put(&mut out, u64::from(r.seq));
            put(&mut out, r.txs as u64);
            put(&mut out, r.patches as u64);
            if let Some(p) = &r.order {
                out.push(1);
                p.write(&mut out)
            } else {
                out.push(0)
            }
        }
        out.extend(sha512_half(&out));
        out
    }
    pub fn decode(b: &[u8]) -> Res<Self> {
        if b.len() < 40 || sha512_half(&b[..b.len() - 32]) != b[b.len() - 32..] {
            return Err("index checksum".into());
        }
        let mut r = Read::new(&b[..b.len() - 32]);
        if r.take(8)? != b"ASIX2\0\0\0" {
            return Err("index magic".into());
        }
        let tx = HashIndex::read(&mut r)?;
        let ledger = HashIndex::read(&mut r)?;
        let mut accounts = vec![];
        for _ in 0..r.count()? {
            accounts.push(r.take(20)?.try_into().unwrap())
        }
        let account_posts = Posts::read(&mut r)?;
        let objects = HashIndex::read(&mut r)?;
        let object_posts = Posts::read(&mut r)?;
        let mut routes = vec![];
        let (mut tn, mut pn) = (0u64, 0u64);
        for _ in 0..r.count()? {
            let seq = u32::try_from(r.var()?).map_err(er)?;
            let txs = r.count()?;
            let patches = r.count()?;
            let order = match r.byte()? {
                0 => None,
                1 => Some(Packed::read(&mut r)?),
                _ => return Err("route mode".into()),
            };
            if let Some(p) = &order
                && (p.n != txs || (0..p.n).any(|i| p.get(i) >= txs as u64))
            {
                return Err("route permutation".into());
            }
            routes.push(Route {
                seq,
                txs,
                patches,
                tx_first: tn,
                patch_first: pn,
                order,
            });
            tn += txs as u64;
            pn += patches as u64;
        }
        r.end()?;
        if accounts.len() + 1 != account_posts.offsets.n
            || objects.values.n + 1 != object_posts.offsets.n
            || tn != tx.values.n as u64
            || ledger.values.n != routes.len()
        {
            return Err("index cardinality".into());
        }
        Ok(Self {
            tx,
            ledger,
            accounts,
            account_posts,
            objects,
            object_posts,
            routes,
        })
    }
    pub fn storage_ordinal(&self, chronological: u64) -> Res<usize> {
        let i = self
            .routes
            .partition_point(|r| r.tx_first <= chronological)
            .checked_sub(1)
            .ok_or("TX route")?;
        let r = &self.routes[i];
        let within = chronological - r.tx_first;
        if within >= r.txs as u64 {
            return Err("TX route extent".into());
        }
        Ok((r.tx_first + r.order.as_ref().map_or(within, |p| p.get(within as usize))) as usize)
    }
    pub fn tx_candidates(&self, hash: &[u8; 32]) -> Res<Vec<usize>> {
        self.tx
            .candidates(hash)
            .into_iter()
            .map(|x| self.storage_ordinal(x))
            .collect()
    }
    pub fn ledger_candidates(&self, hash: &[u8; 32]) -> Vec<usize> {
        self.ledger
            .candidates(hash)
            .into_iter()
            .map(|x| x as usize)
            .collect()
    }
    pub fn account_page(
        &self,
        account: &[u8; 20],
        max_ledger: u32,
        before: Option<u64>,
        limit: usize,
    ) -> Res<Vec<(u64, usize)>> {
        let Ok(id) = self.accounts.binary_search(account) else {
            return Ok(vec![]);
        };
        let Some(r) = self.routes.iter().rev().find(|r| r.seq <= max_ledger) else {
            return Ok(vec![]);
        };
        if r.tx_first + r.txs as u64 == 0 {
            return Ok(vec![]);
        }
        let mut maximum = r.tx_first + r.txs as u64 - 1;
        if let Some(before) = before {
            if before == 0 {
                return Ok(vec![]);
            }
            maximum = maximum.min(before - 1);
        }
        self.account_posts
            .list(id)?
            .tail(0, maximum, limit)
            .into_iter()
            .map(|rank| Ok((rank, self.storage_ordinal(rank)?)))
            .collect()
    }
    pub fn object_candidates(&self, key: &[u8; 32], ledger: u32) -> Res<Vec<usize>> {
        let Some(r) = self.routes.iter().rev().find(|r| r.seq <= ledger) else {
            return Ok(vec![]);
        };
        if r.patch_first + r.patches as u64 == 0 {
            return Ok(vec![]);
        }
        let maximum = r.patch_first + r.patches as u64 - 1;
        let mut out = vec![];
        for id in self.objects.candidates(&sha512_half(key)) {
            out.extend(
                self.object_posts
                    .list(id as usize)?
                    .tail(0, maximum, 1)
                    .into_iter()
                    .map(|x| x as usize),
            );
        }
        Ok(out)
    }
    pub fn tx_ledger(&self, storage: usize) -> Res<u32> {
        self.routes
            .iter()
            .find(|r| storage as u64 >= r.tx_first && (storage as u64) < r.tx_first + r.txs as u64)
            .map(|r| r.seq)
            .ok_or_else(|| "TX route".into())
    }
    pub fn storage_location(&self, storage: usize) -> Res<(u32, usize)> {
        let i = self
            .routes
            .partition_point(|r| r.tx_first <= storage as u64)
            .checked_sub(1)
            .ok_or("TX route")?;
        let r = &self.routes[i];
        let within = (storage as u64).checked_sub(r.tx_first).ok_or("TX route")?;
        if within >= r.txs as u64 {
            return Err("TX route extent".into());
        }
        Ok((r.seq, within as usize))
    }
    pub fn patch_ledger(&self, storage: usize) -> Res<u32> {
        self.routes
            .iter()
            .find(|r| {
                storage as u64 >= r.patch_first
                    && (storage as u64) < r.patch_first + r.patches as u64
            })
            .map(|r| r.seq)
            .ok_or_else(|| "patch route".into())
    }
    pub fn account_keys(&self) -> &[[u8; 20]] {
        &self.accounts
    }
    /// Capacity-based allocation estimate; excludes allocator overhead and RSS.
    pub fn memory_bytes(&self) -> usize {
        fn packed(p: &Packed) -> usize {
            p.words.capacity() * 8
        }
        fn ef(e: &Ef) -> usize {
            packed(&e.low) + (e.high.capacity() + e.samples.capacity()) * 8
        }
        fn hash(h: &HashIndex) -> usize {
            ef(&h.values) + packed(&h.positions)
        }
        fn posts(p: &Posts) -> usize {
            packed(&p.first) + ef(&p.offsets) + p.data.capacity()
        }
        hash(&self.tx)
            + hash(&self.ledger)
            + hash(&self.objects)
            + posts(&self.account_posts)
            + posts(&self.object_posts)
            + self.accounts.capacity() * 20
            + self.routes.capacity() * std::mem::size_of::<Route>()
            + self
                .routes
                .iter()
                .filter_map(|r| r.order.as_ref())
                .map(packed)
                .sum::<usize>()
    }
    /// Exact serialized subcomponents. Account-count framing remains in routing_and_framing.
    pub fn component_detail_bytes(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        let mut b = vec![];
        self.tx.values.write(&mut b);
        m.insert("tx_fingerprint_ef_and_width", b.len() + 1);
        b.clear();
        self.tx.positions.write(&mut b);
        m.insert("tx_positions", b.len());
        b.clear();
        m.insert("account_keys", 20 * self.accounts.len());
        self.account_posts.first.write(&mut b);
        m.insert("account_first_positions", b.len());
        b.clear();
        self.account_posts.offsets.write(&mut b);
        m.insert("account_tail_offsets", b.len());
        b.clear();
        blob(&mut b, &self.account_posts.data);
        m.insert("account_tail_lists_and_length", b.len());
        let aggregate = self.component_bytes();
        for key in ["ledger_hash", "object_versions", "routing_and_framing"] {
            m.insert(key, aggregate[key]);
        }
        m
    }
    pub fn component_bytes(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        let mut b = vec![];
        self.tx.write(&mut b);
        m.insert("tx_hash", b.len());
        b.clear();
        self.ledger.write(&mut b);
        m.insert("ledger_hash", b.len());
        b.clear();
        self.account_posts.write(&mut b);
        m.insert("account", b.len() + 20 * self.accounts.len());
        b.clear();
        self.objects.write(&mut b);
        self.object_posts.write(&mut b);
        m.insert("object_versions", b.len());
        let total = self.encode().len();
        m.insert("routing_and_framing", total - m.values().sum::<usize>());
        m
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_logical_positions_are_not_truncated() {
        let values = [0, 5_185_000_000, (1u64 << 40) + 5, u64::MAX - 1];
        let packed = Packed::new(&values, 64);
        let mut b = vec![];
        packed.write(&mut b);
        let back = Packed::read(&mut Read::new(&b)).unwrap();
        assert_eq!((0..4).map(|i| back.get(i)).collect::<Vec<_>>(), values);
        let ef = Ef::new(&values).unwrap();
        let mut b = vec![];
        ef.write(&mut b);
        let back = Ef::read(&mut Read::new(&b)).unwrap();
        assert_eq!((0..4).map(|i| back.get(i)).collect::<Vec<_>>(), values);
    }
    #[test]
    fn ef_handles_duplicates_and_word_boundaries() {
        for n in [0, 1, 2, 63, 64, 127, 128, 129, 1000] {
            let v: Vec<_> = (0..n).map(|i| (i / 3) as u64 * 997).collect();
            let e = Ef::new(&v).unwrap();
            let mut b = vec![];
            e.write(&mut b);
            let back = Ef::read(&mut Read::new(&b)).unwrap();
            assert_eq!((0..n).map(|i| back.get(i)).collect::<Vec<_>>(), v);
        }
    }
    #[test]
    fn truncated_hash_collisions_require_full_comparison() {
        let mut h1 = [1; 32];
        h1[0] = 0;
        let mut h2 = h1;
        h2[31] = 2;
        let ix = HashIndex::new(&[(h1, 7), (h2, 11)], Some(1)).unwrap();
        assert_eq!(ix.candidates(&h1), vec![7, 11]);
        let actual = [(7, h1), (11, h2)];
        assert_eq!(
            ix.candidates(&h2)
                .into_iter()
                .find(|p| actual.iter().any(|(q, h)| p == q && h == &h2)),
            Some(11)
        );
        let mut absent = h1;
        absent[30] = 99;
        assert!(!actual.iter().any(|(_, h)| h == &absent));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    fn meta(index: u32) -> Vec<u8> {
        let mut b = vec![0x20, 28];
        b.extend(index.to_be_bytes());
        b.extend([0xf8, 0xe5, 0xe7, 0x81, 20]);
        b.extend([7; 20]);
        b.extend([0xe1, 0xe1, 0xf1]);
        b
    }
    #[test]
    fn persisted_routes_order_markers_tombstones_and_checksum() {
        let mut header = vec![0; 118];
        header[..4].copy_from_slice(&1u32.to_be_bytes());
        let first = Row {
            seq: 1,
            header: header.clone(),
            txs: vec![(vec![1], meta(1)), (vec![2], meta(0))],
            patches: vec![([9; 32], vec![0x81, 0])],
        };
        header[..4].copy_from_slice(&2u32.to_be_bytes());
        let second = Row {
            seq: 2,
            header,
            txs: vec![],
            patches: vec![([9; 32], vec![])],
        };
        let index = Indexes::build(&[first, second]).unwrap();
        let mut b = index.encode();
        let index = Indexes::decode(&b).unwrap();
        assert_eq!(index.tx_candidates(&shamap::tx_id(&[1])).unwrap(), vec![0]);
        assert_eq!(index.tx_candidates(&shamap::tx_id(&[2])).unwrap(), vec![1]);
        let page = index.account_page(&[7; 20], 2, None, 1).unwrap();
        assert_eq!(page, vec![(1, 0)]);
        assert_eq!(
            index
                .account_page(&[7; 20], 2, Some(page[0].0), 200)
                .unwrap(),
            vec![(0, 1)]
        );
        assert!(
            index
                .account_page(&[8; 20], 2, None, 200)
                .unwrap()
                .is_empty()
        );
        assert!(index.object_candidates(&[9; 32], 0).unwrap().is_empty());
        assert_eq!(index.object_candidates(&[9; 32], 1).unwrap(), vec![0]);
        assert_eq!(index.object_candidates(&[9; 32], 2).unwrap(), vec![1]);
        b[10] ^= 1;
        assert!(Indexes::decode(&b).is_err());
    }
    #[test]
    fn posting_lists_keep_singletons_and_long_sparse_histories() {
        let lists = vec![vec![0], vec![99], (0..1000).map(|i| i * 10_003).collect()];
        let p = Posts::new(lists.clone().into_iter()).unwrap();
        let mut b = vec![];
        p.write(&mut b);
        let back = Posts::read(&mut Read::new(&b)).unwrap();
        for (i, expected) in lists.iter().enumerate() {
            let list = back.list(i).unwrap();
            assert_eq!(
                (0..list.len()).map(|j| list.get(j)).collect::<Vec<_>>(),
                *expected
            );
        }
    }
}
