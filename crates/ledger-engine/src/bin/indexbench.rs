//! astraea-indexbench: compact indexes for closed history:
//! transaction by hash (fingerprint + number) and account history (position lists
//! as deltas). The corpus is XWCP (`astraea-xrpla fetch`) or consecutive
//! Astraea history ledgers. The range is cut into partitions of `--parts`
//! ledgers; for each partition size it reports bytes per transaction by component,
//! checks every transaction and every account, false candidates for
//! missing hashes, and lookup latency.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use ledger_engine::history::HistoryReader;
use ledger_engine::index::{AccountId, entries};
use ledger_engine::ledger::Ledger;
use ledger_engine::txindex::{
    AccountIndex, Posting, TxHashIndex, build_account_index, build_account_index_v2, build_tx_index,
};

#[derive(Parser)]
struct Args {
    /// XWCP corpus; or `--history` with `--from` and `--ledgers`.
    corpus: Option<PathBuf>,
    /// Astraea history directory.
    #[arg(long)]
    history: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    from: u32,
    #[arg(long, default_value_t = 4096)]
    ledgers: u32,
    /// Partition sizes in ledgers, comma-separated; defaults to the whole corpus.
    #[arg(long, value_delimiter = ',')]
    parts: Vec<usize>,
}

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

fn pct(mut v: Vec<f64>) -> String {
    v.sort_by(f64::total_cmp);
    let p = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    format!("{:.4} / {:.4} / {:.4}", p(0.5), p(0.95), p(0.99))
}

fn varint_len(v: u64) -> usize {
    ((64 - v.max(1).leading_zeros()) as usize).div_ceil(7)
}

/// What the indexes need from a ledger: hashes in order and each transaction's accounts.
struct Row {
    seq: u32,
    hashes: Vec<[u8; 32]>,
    /// (TransactionIndex, accounts) in storage order.
    txs: Vec<(u32, Vec<AccountId>)>,
}

fn row(l: &Ledger) -> Res<Row> {
    let seq = l.header()?.sequence;
    let es = entries(l)?;
    Ok(Row {
        seq,
        hashes: es.iter().map(|x| x.id).collect(),
        txs: es.into_iter().map(|x| (x.index, x.accounts)).collect(),
    })
}

fn load(a: &Args) -> Res<Vec<Row>> {
    match (&a.corpus, &a.history) {
        (Some(c), _) => {
            let b = std::fs::read(c).map_err(e)?;
            let rest = b
                .strip_prefix(b"XWCP\x00\x01".as_slice())
                .ok_or("not an XWCP corpus")?;
            let mut rows = Vec::new();
            let mut at = 0;
            while at < rest.len() {
                let n = u32::from_le_bytes(rest[at..at + 4].try_into().map_err(e)?) as usize;
                rows.push(row(&Ledger::decode(&rest[at + 4..at + 4 + n])?)?);
                at += 4 + n;
            }
            Ok(rows)
        }
        (None, Some(h)) => {
            let r = HistoryReader::open(h)?;
            (a.from..a.from + a.ledgers)
                .map(|s| row(&r.get_txs(s)?.ok_or(format!("no ledger {s}"))?))
                .collect()
        }
        (None, None) => Err("need an XWCP corpus or --history".into()),
    }
}

#[derive(Default)]
struct Sum {
    parts: usize,
    txh: usize,
    acc: usize,
    acc_z: usize,
    acc2: usize,
    acc2_z: usize,
    dir20: usize,
    dir_ids: usize,
    accounts: usize,
    extra: usize,
    false_c: usize,
    ms: Vec<f64>,
    ams: Vec<f64>,
    ams2: Vec<f64>,
    pms: Vec<f64>,
}

/// Builds and checks both indexes for a partition.
fn part(rows: &[Row], ids: &HashMap<AccountId, u32>, s: &mut Sum) -> Res<()> {
    let first = rows[0].seq;
    let hashes: Vec<Vec<[u8; 32]>> = rows.iter().map(|r| r.hashes.clone()).collect();
    let mut postings: BTreeMap<AccountId, Vec<Posting>> = BTreeMap::new();
    for r in rows {
        for (index, accs) in &r.txs {
            for acc in accs {
                postings.entry(*acc).or_default().push((r.seq, *index));
            }
        }
    }
    for v in postings.values_mut() {
        v.sort_unstable();
    }
    let txi = build_tx_index(first, &hashes);
    let acc = build_account_index(first, &postings);
    let counts: Vec<u32> = rows.iter().map(|r| r.txs.len() as u32).collect();
    let acc2 = build_account_index_v2(first, &counts, &postings)?;

    let ti = TxHashIndex::open(&txi)?;
    let mut k = 0usize;
    for r in rows {
        for (p, h) in r.hashes.iter().enumerate() {
            let t = Instant::now();
            let c = ti.candidates(h)?;
            if k.is_multiple_of(37) {
                s.ms.push(t.elapsed().as_secs_f64() * 1000.0);
            }
            k += 1;
            if !c.contains(&(r.seq, p as u32)) {
                return Err(format!("transaction {} not found", hex::encode_upper(h)));
            }
            s.extra += c.len() - 1;
        }
    }
    for i in 0..10_000u32 {
        let h = witness_core::sha512_half(
            &[b"absent".as_slice(), &first.to_le_bytes(), &i.to_le_bytes()].concat(),
        );
        s.false_c += ti.candidates(&h)?.len();
    }
    for (bytes, ams) in [(&acc, &mut s.ams), (&acc2, &mut s.ams2)] {
        let ai = AccountIndex::open(bytes)?;
        for (k, (a2, ps)) in postings.iter().enumerate() {
            let t = Instant::now();
            let got = ai.postings(a2)?;
            if k.is_multiple_of(7) {
                ams.push(t.elapsed().as_secs_f64() * 1000.0);
            }
            if &got != ps {
                return Err(format!(
                    "account history {} does not match",
                    hex::encode_upper(a2)
                ));
            }
        }
    }
    // account_tx pages from v2: 200 newest and 200 after the middle of the list.
    let ai2 = AccountIndex::open(&acc2)?;
    for (k, (a2, ps)) in postings.iter().enumerate() {
        let t = Instant::now();
        let newest = ai2.page(a2, None, 200, true)?;
        if k.is_multiple_of(7) {
            s.pms.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        let mid = ps[ps.len() / 2];
        let after = ai2.page(a2, Some(mid), 200, false)?;
        let want_new: Vec<Posting> = ps.iter().rev().take(200).copied().collect();
        let want_after: Vec<Posting> = ps.iter().filter(|p| **p > mid).take(200).copied().collect();
        if newest != want_new || after != want_after {
            return Err(format!(
                "account page {} does not match",
                hex::encode_upper(a2)
            ));
        }
    }
    // Directory with global account numbers (estimate): in increasing number order,
    // the number delta, list length in bytes and entry count, as varints.
    let mut by_id: Vec<(u32, usize, usize)> = postings
        .iter()
        .map(|(a2, ps)| (ids[a2], list_bytes(ps, first), ps.len()))
        .collect();
    by_id.sort_unstable();
    let mut prev = 0u32;
    for (id, len, cnt) in by_id {
        s.dir_ids +=
            varint_len(u64::from(id - prev)) + varint_len(len as u64) + varint_len(cnt as u64);
        prev = id;
    }
    s.parts += 1;
    s.txh += txi.len();
    s.acc += acc.len();
    s.acc_z += zstd::bulk::compress(&acc, 19).map_err(e)?.len();
    s.acc2 += acc2.len();
    s.acc2_z += zstd::bulk::compress(&acc2, 19).map_err(e)?.len();
    s.dir20 += acc.len() - 18 - lists_bytes(&postings, first);
    s.accounts += postings.len();
    Ok(())
}

/// Bytes of a position list, as in `build_account_index`.
fn list_bytes(ps: &[Posting], first: u32) -> usize {
    let (mut pl, mut pi) = (first, 0u32);
    let mut n = 0;
    for (k, &(l, i)) in ps.iter().enumerate() {
        let dl = l - if k == 0 { first } else { pl };
        n += varint_len(u64::from(dl));
        n += varint_len(u64::from(if dl == 0 && k > 0 { i - pi } else { i }));
        (pl, pi) = (l, i);
    }
    n
}

fn lists_bytes(postings: &BTreeMap<AccountId, Vec<Posting>>, first: u32) -> usize {
    postings.values().map(|ps| list_bytes(ps, first)).sum()
}

fn main() -> Res<()> {
    let a = Args::parse();
    let t0 = Instant::now();
    let rows = load(&a)?;
    let first = rows.first().ok_or("empty corpus")?.seq;
    for w in rows.windows(2) {
        if w[1].seq != w[0].seq + 1 {
            return Err(format!("gap after ledger {}", w[0].seq));
        }
    }
    let txs: usize = rows.iter().map(|r| r.hashes.len()).sum();
    let n_post: usize = rows
        .iter()
        .flat_map(|r| &r.txs)
        .map(|(_, a2)| a2.len())
        .sum();
    // Global account numbers, by first appearance in the range.
    let mut ids: HashMap<AccountId, u32> = HashMap::new();
    for r in &rows {
        for (_, accs) in &r.txs {
            for acc in accs {
                let n = ids.len() as u32;
                ids.entry(*acc).or_insert(n);
            }
        }
    }
    println!(
        "corpus: {} ledgers from {first}, {txs} transactions, {} accounts, {n_post} history entries ({:.2} per transaction); loaded in {:.1} s",
        rows.len(),
        ids.len(),
        n_post as f64 / txs as f64,
        t0.elapsed().as_secs_f64()
    );
    let per = |x: usize| x as f64 / txs as f64;
    println!(
        "| partition, ledgers | partitions | XTXH B/tx | XACC B/tx | of which directory | directory with account numbers (estimate) | XACC zstd-19 | XACC v2 (Rice) | v2 zstd-19 | both (v2) | hash lookup p50/p95/p99, ms | account history v1 p50/p95/p99, ms | v2 p50/p95/p99, ms | page of 200 newest from v2 p50/p95/p99, ms | check |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|---|"
    );
    let mut sizes = a.parts.clone();
    if sizes.is_empty() {
        sizes.push(rows.len());
    }
    for p in sizes {
        let mut s = Sum::default();
        for chunk in rows.chunks(p) {
            part(chunk, &ids, &mut s)?;
        }
        println!(
            "| {p} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} | all {txs} found, {} extra candidates; out of {} missing, {} false; all {} account lists match in both versions, v2 pages match the full lists |",
            s.parts,
            per(s.txh),
            per(s.acc),
            per(s.dir20),
            per(s.dir_ids),
            per(s.acc_z),
            per(s.acc2),
            per(s.acc2_z),
            per(s.txh + s.acc2),
            pct(std::mem::take(&mut s.ms)),
            pct(std::mem::take(&mut s.ams)),
            pct(std::mem::take(&mut s.ams2)),
            pct(std::mem::take(&mut s.pms)),
            s.extra,
            s.parts * 10_000,
            s.false_c,
            s.accounts
        );
    }
    println!(
        "account dictionary (20 bytes per account, one for the whole history): {:.2} B/tx on this range; fjall currently uses ≈28 B/tx per hash and ≈10 B per history entry ≈ {:.1} B/tx",
        per(ids.len() * 20),
        28.0 + 10.0 * n_post as f64 / txs as f64
    );
    Ok(())
}
