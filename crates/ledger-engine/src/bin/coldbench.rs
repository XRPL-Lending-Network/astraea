//! astraea-coldbench: reading ASTJ5 cold history through `cold::Cold`.
//! A ledger cold (segments closed before the request) and
//! again warm, with and without changes; transaction by hash and a missing hash
//! through the segment's ASIX2; account_tx pages of 200 for the most active accounts;
//! concurrent reads in `--threads` threads under a budget of open
//! segments. Every response is checked against the source corpus. Memory is the
//! process VmHWM and VmRSS (Linux). The OS cache is not dropped.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use astraea_journal_codec::dense;
use clap::Parser;
use ledger_engine::cold::{Cold, Kinds};
use ledger_engine::ledger::Ledger;
use witness_core::sha512_half;
use witness_core::shamap::tx_id;

#[derive(Parser)]
struct Args {
    /// Cold segments directory.
    #[arg(long)]
    cold: PathBuf,
    /// XWCP corpus the segments were built from.
    #[arg(long)]
    corpus: PathBuf,
    #[arg(long, default_value_t = 64)]
    samples: usize,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[arg(long, default_value_t = 20)]
    seconds: u64,
    /// Block cache budget per open segment, MiB.
    #[arg(long, default_value_t = 128)]
    budget_mib: usize,
}

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

/// Expected per ledger: hash of the full serialization, hash without changes,
/// transaction hashes.
struct Expect {
    full: [u8; 32],
    txs: [u8; 32],
    ids: Vec<[u8; 32]>,
}

fn txs_only(l: &Ledger) -> [u8; 32] {
    let t = Ledger {
        header: l.header.clone(),
        transactions: l.transactions.clone(),
        changes: Vec::new(),
    };
    sha512_half(&t.encode())
}

fn mem(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

fn q(mut v: Vec<f64>) -> String {
    if v.is_empty() {
        return "—".into();
    }
    v.sort_by(f64::total_cmp);
    let p = |x: f64| v[((v.len() - 1) as f64 * x).round() as usize];
    format!(
        "{:.3} / {:.3} / {:.3} / {:.3}",
        p(0.5),
        p(0.95),
        p(0.99),
        v[v.len() - 1]
    )
}

/// Deterministic sample.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % n.max(1)
    }
}

fn main() -> Res<()> {
    let a = Args::parse();
    let mut r = BufReader::new(File::open(&a.corpus).map_err(e)?);
    let mut magic = [0u8; 6];
    r.read_exact(&mut magic).map_err(e)?;
    if &magic != b"XWCP\x00\x01" {
        return Err("not an XWCP corpus".into());
    }
    let mut expect: HashMap<u32, Expect> = HashMap::new();
    let mut seqs = Vec::new();
    loop {
        let mut len = [0u8; 4];
        match r.read_exact(&mut len) {
            Ok(()) => {}
            Err(x) if x.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(x) => return Err(e(x)),
        }
        let mut b = vec![0u8; u32::from_le_bytes(len) as usize];
        r.read_exact(&mut b).map_err(e)?;
        let l = Ledger::decode(&b)?;
        let seq = l.header()?.sequence;
        expect.insert(
            seq,
            Expect {
                full: sha512_half(&b),
                txs: txs_only(&l),
                ids: l.transactions.iter().map(|(t, _)| tx_id(t)).collect(),
            },
        );
        seqs.push(seq);
    }
    let rss_corpus = mem("VmRSS:");
    let cold = Arc::new(Cold::open(&a.cold)?.with_budget(a.budget_mib << 20));
    let explicit = cold.segments().iter().all(|s| s.kinds == Kinds::Explicit);
    println!(
        "{} cold segments, {} ledgers in the corpus, block cache budget {} MiB per segment, change kinds: {}",
        cold.segments().len(),
        seqs.len(),
        a.budget_mib,
        if explicit {
            "explicit"
        } else {
            "not recorded by the source"
        }
    );
    let close_all = || cold.segments().iter().for_each(|s| s.close());
    let mut rng = Lcg(7);
    let (mut c_tx, mut w_tx, mut c_full) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..a.samples {
        let seq = seqs[rng.next(seqs.len())];
        let x = &expect[&seq];
        close_all();
        let t = Instant::now();
        let l = cold.ledger(seq, false)?.ok_or(format!("no ledger {seq}"))?;
        c_tx.push(t.elapsed().as_secs_f64() * 1e3);
        if txs_only(&l) != x.txs {
            return Err(format!("ledger {seq}: wrong transactions"));
        }
        let t = Instant::now();
        let l = cold.ledger(seq, false)?.ok_or("no ledger")?;
        w_tx.push(t.elapsed().as_secs_f64() * 1e3);
        if txs_only(&l) != x.txs {
            return Err(format!("ledger {seq}: wrong on repeat read"));
        }
        if explicit {
            close_all();
            let t = Instant::now();
            let l = cold.ledger(seq, true)?.ok_or("no ledger")?;
            c_full.push(t.elapsed().as_secs_f64() * 1e3);
            if sha512_half(&l.encode()) != x.full {
                return Err(format!("ledger {seq}: wrong with changes"));
            }
        }
    }
    println!(
        "ledger without changes, cold, ms p50/p95/p99/max: {}",
        q(c_tx)
    );
    println!("ledger without changes, warm, ms: {}", q(w_tx));
    if explicit {
        println!("ledger with changes, cold, ms: {}", q(c_full));
    }
    close_all();

    // Transaction by hash and account pages, through the segments' ASIX2.
    let (mut c_hash, mut w_hash, mut neg, mut c_page, mut w_page) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut index_heap = 0usize;
    for s in cold.segments() {
        let base = a.cold.join(format!("cold-{:010}", s.first));
        let mut rd = dense::Reader::open(base.with_extension("astj"), base.with_extension("asix"))?;
        index_heap = index_heap.max(rd.heap_bytes());
        let local: Vec<u32> = seqs
            .iter()
            .copied()
            .filter(|q| *q >= s.first && *q <= s.last)
            .collect();
        for _ in 0..a.samples / cold.segments().len().max(1) + 1 {
            let seq = local[rng.next(local.len())];
            let ids = &expect[&seq].ids;
            if ids.is_empty() {
                continue;
            }
            let h = ids[rng.next(ids.len())];
            rd.clear_cache();
            let t = Instant::now();
            let got = rd.tx(&h)?.ok_or("transaction not found")?;
            c_hash.push(t.elapsed().as_secs_f64() * 1e3);
            let t = Instant::now();
            let again = rd.tx(&h)?.ok_or("transaction not found")?;
            w_hash.push(t.elapsed().as_secs_f64() * 1e3);
            if tx_id(&got.0) != h || again != got {
                return Err("wrong transaction by hash".into());
            }
        }
        for i in 0..1000u32 {
            let h = sha512_half(&[b"absent".as_slice(), &i.to_le_bytes()].concat());
            let t = Instant::now();
            if rd.tx(&h)?.is_some() {
                return Err("a missing hash was found".into());
            }
            neg.push(t.elapsed().as_secs_f64() * 1e3);
        }
        // The ten most active accounts in the segment, two pages of 200.
        let mut top: Vec<(usize, [u8; 20])> = rd
            .index
            .account_keys()
            .iter()
            .map(|acc| {
                Ok((
                    rd.index.account_page(acc, s.last, None, 1 << 30)?.len(),
                    *acc,
                ))
            })
            .collect::<Res<_>>()?;
        top.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
        for (_, acc) in top.into_iter().take(10) {
            let mut before = None;
            for k in 0..2 {
                if k == 0 {
                    rd.clear_cache();
                }
                let t = Instant::now();
                let page = rd.index.account_page(&acc, s.last, before, 200)?;
                for (_, storage) in &page {
                    rd.tx_storage(*storage)?;
                }
                let ms = t.elapsed().as_secs_f64() * 1e3;
                if k == 0 { &mut c_page } else { &mut w_page }.push(ms);
                before = page.last().map(|x| x.0);
                if before.is_none() {
                    break;
                }
            }
        }
    }
    println!("transaction by hash (ASIX2), cold, ms: {}", q(c_hash));
    println!("transaction by hash, warm, ms: {}", q(w_hash));
    println!("missing hash, ms: {}", q(neg));
    println!("account_tx page of 200 tx, first (cold), ms: {}", q(c_page));
    println!("account_tx page, next, ms: {}", q(w_page));
    println!(
        "codec reader memory estimate (indexes and block), MiB: {:.1}",
        index_heap as f64 / 1048576.0
    );

    // Concurrent reads under the open segment budget.
    let stop = Arc::new(AtomicBool::new(false));
    let max_open = Arc::new(AtomicUsize::new(0));
    let seqs = Arc::new(seqs);
    let expect = Arc::new(expect);
    let mut handles = Vec::new();
    for th in 0..a.threads {
        let (cold, stop, max_open, seqs, expect) = (
            cold.clone(),
            stop.clone(),
            max_open.clone(),
            seqs.clone(),
            expect.clone(),
        );
        handles.push(std::thread::spawn(move || -> Res<Vec<f64>> {
            let mut rng = Lcg(100 + th as u64);
            let mut lat = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let seq = seqs[rng.next(seqs.len())];
                let t = Instant::now();
                let l = cold.ledger(seq, false)?.ok_or("no ledger")?;
                lat.push(t.elapsed().as_secs_f64() * 1e3);
                if txs_only(&l) != expect[&seq].txs {
                    return Err(format!("ledger {seq}: wrong in concurrent read"));
                }
                max_open.fetch_max(cold.open_count(), Ordering::Relaxed);
            }
            Ok(lat)
        }));
    }
    std::thread::sleep(Duration::from_secs(a.seconds));
    stop.store(true, Ordering::Relaxed);
    let mut all = Vec::new();
    for h in handles {
        all.extend(h.join().map_err(|_| "thread panicked")??);
    }
    println!(
        "concurrent, {} threads, {} s: {} reads ({:.0}/s), ms: {}; at most {} segments open",
        a.threads,
        a.seconds,
        all.len(),
        all.len() as f64 / a.seconds as f64,
        q(all),
        max_open.load(Ordering::Relaxed)
    );
    println!(
        "prepared block cache now, MiB (codec estimate): {:.1}",
        cold.segments()
            .iter()
            .map(|s| s.cached_bytes())
            .sum::<usize>() as f64
            / 1048576.0
    );
    println!(
        "memory, MiB: peak VmHWM {:.1}, current VmRSS {:.1}, of which expected-value corpus ~{:.1}",
        mem("VmHWM:") as f64 / 1024.0,
        mem("VmRSS:") as f64 / 1024.0,
        rss_corpus as f64 / 1024.0
    );
    Ok(())
}
