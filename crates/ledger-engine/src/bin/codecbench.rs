//! astraea-codecbench: bytes per transaction with the segment-table codec
//! versus the current per-ledger frame.
//!
//! The corpus is `--ledgers` history ledgers starting at `--from`; zstd dictionaries
//! are trained on the `--train` ledgers before it. Every variant must restore each
//! transaction and its metadata byte for byte, or it gets no result. Size counts
//! frames, segment tables (zstd-19) and the dictionary. Reading one transaction
//! means decompressing the frame and expanding it; the tables are already in memory
//! (read once per segment).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use ledger_engine::delta;
use ledger_engine::history::{HistoryReader, tx_frame};
use ledger_engine::ledger::{Change, Ledger};
use ledger_engine::txcodec::{
    Tables, ViewStats, decode_frame, decode_frame_views, encode_frame, encode_frame_views,
};
use witness_core::ledger::HEADER_LEN;
use witness_core::stobject::{self, types};

#[derive(Debug, Parser)]
struct Args {
    /// Astraea history directory; or `--rows` for a sample from a file.
    history: Option<PathBuf>,
    /// Corpus from a `.rows` or `XWCP` file (astraea-xrpla fetch): the first third
    /// trains the dictionary, the rest is measured.
    #[arg(long)]
    rows: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    from: u32,
    #[arg(long, default_value_t = 4096)]
    ledgers: u32,
    #[arg(long, default_value_t = 512)]
    train: u32,
    /// Only measure metadata repetition of object versions.
    #[arg(long)]
    redundancy_only: bool,
    /// Cold storage: self-contained blocks of this many ledgers (the whole
    /// corpus file, no training part); several values can be comma-separated.
    #[arg(long, value_delimiter = ',')]
    cold: Vec<usize>,
    /// A value goes into the segment table if it occurs this many times.
    #[arg(long, default_value_t = 2)]
    min: u32,
}

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

fn pct(mut v: Vec<f64>) -> String {
    v.sort_by(f64::total_cmp);
    let p = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    format!("{:.3} / {:.3} / {:.3}", p(0.5), p(0.95), p(0.99))
}

/// Raw bytes by kind: hashes, accounts, currencies and issuers, signatures, keys, other.
#[derive(Default, Debug)]
struct Breakdown {
    hashes: u64,
    accounts: u64,
    iou_parts: u64,
    signatures: u64,
    pubkeys: u64,
    total: u64,
}

fn breakdown(buf: &[u8], b: &mut Breakdown) -> Res<()> {
    breakdown_fields(&stobject::fields(buf).map_err(e)?, b)
}

fn breakdown_fields(fs: &[stobject::Field<'_>], b: &mut Breakdown) -> Res<()> {
    for f in fs {
        let t = f.id.type_code;
        if t == types::OBJECT {
            breakdown(f.value, b)?;
            continue;
        }
        if t == types::ARRAY {
            for item in stobject::items(f.value).map_err(e)? {
                breakdown(item.value, b)?;
            }
            continue;
        }
        let n = f.value.len() as u64;
        match (t, f.id.field_code) {
            (types::HASH256, _) => b.hashes += n,
            (types::ACCOUNT, _) => b.accounts += n,
            (types::AMOUNT, _) if n == 48 => b.iou_parts += 40,
            (types::BLOB, 4) => b.signatures += n,
            (types::BLOB, 3) => b.pubkeys += n,
            _ => {}
        }
    }
    Ok(())
}

/// Corpus from a `.rows` file (per-epoch samples from the XRPLA publication): u32
/// record count, then records (u32 length): sequence, header, transactions.
fn load_rows(path: &std::path::Path) -> Res<Vec<Ledger>> {
    let b = std::fs::read(path).map_err(e)?;
    if let Some(rest) = b.strip_prefix(b"XWCP\x00\x01".as_slice()) {
        let mut out = Vec::new();
        let mut at = 0;
        while at < rest.len() {
            let n = u32::from_le_bytes(
                rest.get(at..at + 4)
                    .ok_or("truncated")?
                    .try_into()
                    .map_err(e)?,
            ) as usize;
            out.push(Ledger::decode(
                rest.get(at + 4..at + 4 + n).ok_or("truncated")?,
            )?);
            at += 4 + n;
        }
        return Ok(out);
    }
    let u32_at = |b: &[u8], at: &mut usize| -> Res<u32> {
        let x = b.get(*at..*at + 4).ok_or("truncated")?;
        *at += 4;
        Ok(u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
    };
    let blob = |b: &[u8], at: &mut usize| -> Res<Vec<u8>> {
        let n = u32_at(b, at)? as usize;
        let v = b.get(*at..*at + n).ok_or("truncated")?.to_vec();
        *at += n;
        Ok(v)
    };
    let mut at = 0;
    let n = u32_at(&b, &mut at)?;
    let mut out = Vec::new();
    for _ in 0..n {
        let r = blob(&b, &mut at)?;
        let mut p = 0;
        let _seq = u32_at(&r, &mut p)?;
        let header = blob(&r, &mut p)?;
        let nt = u32_at(&r, &mut p)?;
        let mut transactions = Vec::new();
        for _ in 0..nt {
            let t = blob(&r, &mut p)?;
            let m = blob(&r, &mut p)?;
            transactions.push((t, m));
        }
        out.push(Ledger {
            header,
            transactions,
            changes: Vec::new(),
        });
    }
    Ok(out)
}

fn main() -> Res<()> {
    let a = Args::parse();
    let (train, corpus) = match (&a.rows, &a.history) {
        (Some(rows), _) => {
            let mut all = load_rows(rows)?;
            let cut = (all.len() / 3).max(1);
            let corpus = all.split_off(cut);
            (all, corpus)
        }
        (None, Some(h)) => {
            let r = HistoryReader::open(h)?;
            let load = |from: u32, n: u32| -> Res<Vec<Ledger>> {
                (from..from + n)
                    .map(|s| r.get_txs(s)?.ok_or(format!("no ledger {s}")))
                    .collect()
            };
            (load(a.from - a.train, a.train)?, load(a.from, a.ledgers)?)
        }
        (None, None) => return Err("need a history directory or --rows".into()),
    };
    if !a.cold.is_empty() {
        let mut all = train.clone();
        all.extend(corpus.iter().cloned());
        for l in &all {
            l.verify()?;
        }
        for &n in &a.cold {
            cold(&all, n)?;
        }
        return Ok(());
    }
    // Transaction roots before measuring: the corpus itself is intact.
    for l in train.iter().chain(&corpus) {
        l.verify()?;
    }
    let digest = {
        let mut all = Vec::new();
        for l in &corpus {
            all.extend(tx_frame(l));
        }
        hex::encode_upper(&witness_core::sha512_half(&all)[..8])
    };
    let txs: usize = corpus.iter().map(|l| l.transactions.len()).sum();
    let raw: usize = corpus.iter().map(|l| tx_frame(l).len()).sum();
    let first = corpus
        .first()
        .and_then(|l| l.header().ok())
        .map_or(0, |h| h.sequence);
    println!(
        "corpus: {} ledgers from {first}, {txs} transactions, {:.1} MB uncompressed ({:.0} B/tx), fingerprint {digest}; dictionaries from {} ledgers before it; transaction roots verified",
        corpus.len(),
        raw as f64 / 1e6,
        raw as f64 / txs as f64,
        train.len()
    );
    if a.redundancy_only {
        return redundancy(&train, &corpus, txs);
    }
    let mut b = Breakdown::default();
    let mut unparsed = 0;
    for l in &corpus {
        for (t, m) in &l.transactions {
            for o in [t, m] {
                if breakdown(o, &mut b).is_err() {
                    unparsed += 1;
                }
            }
            b.total += (t.len() + m.len()) as u64;
        }
    }
    let per = |x: u64| x as f64 / txs as f64;
    println!(
        "per transaction, bytes: hashes {:.1}, accounts {:.1}, amount currencies and issuers {:.1}, signatures {:.1}, keys {:.1}; objects not parsed: {unparsed}",
        per(b.hashes),
        per(b.accounts),
        per(b.iou_parts),
        per(b.signatures),
        per(b.pubkeys)
    );
    println!(
        "| variant | B/tx | total, MB | of which tables/dictionary, KB | one tx p50/p95/p99, ms | restored |"
    );
    println!("|---|---:|---:|---:|---|---|");
    let samples: Vec<(usize, usize)> = (0..2000)
        .map(|i| {
            let li = (i * 7919) % corpus.len();
            let n = corpus[li].transactions.len().max(1);
            (li, (i * 104_729) % n)
        })
        .filter(|(li, _)| !corpus[*li].transactions.is_empty())
        .collect();

    // Current per-ledger frame with a dictionary.
    let train_frames: Vec<Vec<u8>> = train.iter().map(tx_frame).collect();
    let dict = zstd::dict::from_samples(&train_frames, 112 << 10).map_err(e)?;
    for level in [9, 19] {
        let mut c = zstd::bulk::Compressor::with_dictionary(level, &dict).map_err(e)?;
        let mut d = zstd::bulk::Decompressor::with_dictionary(&dict).map_err(e)?;
        let frames: Vec<Vec<u8>> = corpus
            .iter()
            .map(|l| c.compress(&tx_frame(l)).map_err(e))
            .collect::<Res<_>>()?;
        let mut ok = 0;
        for (l, z) in corpus.iter().zip(&frames) {
            if d.decompress(z, 256 << 20).map_err(e)? != tx_frame(l) {
                return Err("per-ledger frame: decoded data does not match the source".into());
            }
            ok += 1;
        }
        let mut ms = Vec::new();
        for &(li, pos) in &samples {
            let t0 = Instant::now();
            let f = d.decompress(&frames[li], 256 << 20).map_err(e)?;
            let l = Ledger::decode(&[&f[..], &0u32.to_le_bytes()].concat())?;
            std::hint::black_box(&l.transactions[pos]);
            ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let total = frames.iter().map(Vec::len).sum::<usize>() + dict.len();
        println!(
            "| per-ledger frame, zstd-{level}, dictionary (current) | {:.0} | {:.1} | {:.0} | {} | {ok} of {} ledgers |",
            total as f64 / txs as f64,
            total as f64 / 1e6,
            dict.len() as f64 / 1e3,
            pct(ms),
            corpus.len()
        );
    }

    // Segment tables.
    let objects = |ls: &[Ledger]| -> Vec<Vec<u8>> {
        ls.iter()
            .flat_map(|l| {
                l.transactions
                    .iter()
                    .flat_map(|(t, m)| [t.clone(), m.clone()])
            })
            .collect()
    };
    let t_train = Tables::build(objects(&train).iter().map(Vec::as_slice), a.min)?;
    let t_corpus = Tables::build(objects(&corpus).iter().map(Vec::as_slice), a.min)?;
    let enc = |ls: &[Ledger], t: &Tables| -> Res<(Vec<Vec<u8>>, usize)> {
        let mut literal = 0;
        let frames = ls
            .iter()
            .map(|l| {
                let (f, n) = encode_frame(&l.header, &l.transactions, t)?;
                literal += n;
                Ok(f)
            })
            .collect::<Res<_>>()?;
        Ok((frames, literal))
    };
    let (train_enc, _) = enc(&train, &t_train)?;
    let (corpus_enc, literal) = enc(&corpus, &t_corpus)?;
    // Decode with tables that went through the full storage path: bytes → zstd →
    // back.
    let table_stored = zstd::bulk::compress(&t_corpus.to_bytes(), 19).map_err(e)?;
    let table_z = table_stored.len();
    let t_corpus = Tables::from_bytes(&zstd::bulk::decompress(&table_stored, 1 << 30).map_err(e)?)?;
    println!("objects stored as is (not parsed by the codec): {literal}");
    let dict2 = zstd::dict::from_samples(&train_enc, 112 << 10).map_err(e)?;
    let mut tx_best = 0usize;
    for level in [9, 19] {
        let mut c = zstd::bulk::Compressor::with_dictionary(level, &dict2).map_err(e)?;
        let mut d = zstd::bulk::Decompressor::with_dictionary(&dict2).map_err(e)?;
        let frames: Vec<Vec<u8>> = corpus_enc
            .iter()
            .map(|f| c.compress(f).map_err(e))
            .collect::<Res<_>>()?;
        let mut ok = 0;
        for (l, z) in corpus.iter().zip(&frames) {
            let f = d.decompress(z, 256 << 20).map_err(e)?;
            if f[..HEADER_LEN] != l.header[..]
                || decode_frame(&f, HEADER_LEN, &t_corpus, None)? != l.transactions
            {
                return Err("segment tables: decoded data does not match the source".into());
            }
            ok += 1;
        }
        let mut ms = Vec::new();
        for &(li, pos) in &samples {
            let t0 = Instant::now();
            let f = d.decompress(&frames[li], 256 << 20).map_err(e)?;
            let got = decode_frame(&f, HEADER_LEN, &t_corpus, Some(pos))?;
            std::hint::black_box(&got);
            ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let total = frames.iter().map(Vec::len).sum::<usize>() + dict2.len() + table_z;
        if level == 19 {
            tx_best = total;
        }
        println!(
            "| segment tables (hashes {}, accounts {}, currencies {}), zstd-{level}, dictionary | {:.0} | {:.1} | {:.0} | {} | {ok} of {} ledgers |",
            t_corpus.hashes.values.len(),
            t_corpus.accounts.values.len(),
            t_corpus.currencies.values.len(),
            total as f64 / txs as f64,
            total as f64 / 1e6,
            (dict2.len() + table_z) as f64 / 1e3,
            pct(ms),
            corpus.len()
        );
    }
    let views_best = views(&train, &corpus, txs, &t_train, &t_corpus, &samples)?;
    let s3 = state(&train, &corpus, txs, tx_best)?;
    if let (Some(v), Some(s3)) = (views_best, s3) {
        println!(
            "TOTAL WITH VIEWS (transactions with tables and metadata views, zstd-19 + format 3 changes): {:.0} B/tx",
            (v + s3) as f64 / txs as f64
        );
    }
    redundancy(&train, &corpus, txs)?;
    Ok(())
}

/// Object fields: (type, code) → the whole field.
fn field_map(obj: &[u8]) -> HashMap<(u16, u16), Vec<u8>> {
    stobject::fields(obj)
        .map(|fs| {
            fs.into_iter()
                .map(|f| ((f.id.type_code, f.id.field_code), f.raw.to_vec()))
                .collect()
        })
        .unwrap_or_default()
}

/// How many metadata bytes repeat object versions (input for a unified
/// journal). For each AffectedNodes node: FinalFields fields unchanged
/// since the object version at the start of the ledger; PreviousFields against the version
/// at the start; NewFields against the created version. Raw bytes, uncompressed:
/// an upper bound on what need not be stored when versions are available. Objects
/// touched by several transactions in a ledger are counted separately: they have
/// intermediate versions, so matches are lower.
fn redundancy(train: &[Ledger], corpus: &[Ledger], txs: usize) -> Res<()> {
    const AFFECTED: (u16, u16) = (types::ARRAY, 8);
    const KEY: (u16, u16) = (types::HASH256, 6);
    if corpus.iter().all(|l| l.changes.is_empty()) {
        return Ok(());
    }
    let mut versions: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let remember = |v: &mut HashMap<[u8; 32], Vec<u8>>, l: &Ledger| {
        for c in &l.changes {
            if c.change == Change::Deleted {
                v.remove(&c.key);
            } else {
                v.insert(c.key, c.data.clone());
            }
        }
    };
    for l in train {
        remember(&mut versions, l);
    }
    #[derive(Default)]
    struct Acc {
        meta: usize,
        nodes: usize,
        multi_nodes: usize,
        final_total: usize,
        final_same_end: usize,
        prev_total: usize,
        prev_same_start: usize,
        new_total: usize,
        new_same_end: usize,
    }
    let mut a = Acc::default();
    for l in corpus {
        let end: HashMap<[u8; 32], &Vec<u8>> = l
            .changes
            .iter()
            .filter(|c| c.change != Change::Deleted)
            .map(|c| (c.key, &c.data))
            .collect();
        // How many times the object is touched in this ledger.
        let mut touched: HashMap<[u8; 32], usize> = HashMap::new();
        let mut nodes = Vec::new();
        for (_, m) in &l.transactions {
            a.meta += m.len();
            let Ok(fs) = stobject::fields(m) else {
                continue;
            };
            for f in fs
                .iter()
                .filter(|f| (f.id.type_code, f.id.field_code) == AFFECTED)
            {
                for node in stobject::items(f.value).map_err(e)? {
                    let inner = stobject::fields(node.value).map_err(e)?;
                    let key: Option<[u8; 32]> = inner
                        .iter()
                        .find(|x| (x.id.type_code, x.id.field_code) == KEY)
                        .and_then(|x| x.value.try_into().ok());
                    if let Some(k) = key {
                        *touched.entry(k).or_default() += 1;
                        nodes.push((k, node.value.to_vec()));
                    }
                }
            }
        }
        for (k, body) in &nodes {
            a.nodes += 1;
            let once = touched.get(k) == Some(&1);
            if !once {
                a.multi_nodes += 1;
            }
            let start = versions.get(k).map(|v| field_map(v)).unwrap_or_default();
            let fin = end.get(k).map(|v| field_map(v)).unwrap_or_default();
            for part in stobject::fields(body).map_err(e)? {
                let (t, c) = (part.id.type_code, part.id.field_code);
                if t != types::OBJECT || !(6..=8).contains(&c) {
                    continue;
                }
                for x in stobject::fields(part.value).map_err(e)? {
                    let id = (x.id.type_code, x.id.field_code);
                    let n = x.raw.len();
                    match c {
                        6 => {
                            a.prev_total += n;
                            if once && start.get(&id).is_some_and(|v| *v == x.raw) {
                                a.prev_same_start += n;
                            }
                        }
                        7 => {
                            a.final_total += n;
                            // The field did not change since the previous object version: its
                            // repeat in FinalFields is what need not be stored when the
                            // version at the start of the ledger is available.
                            if once && start.get(&id).is_some_and(|v| *v == x.raw) {
                                a.final_same_end += n;
                            }
                        }
                        _ => {
                            a.new_total += n;
                            if once && fin.get(&id).is_some_and(|v| *v == x.raw) {
                                a.new_same_end += n;
                            }
                        }
                    }
                }
            }
        }
        remember(&mut versions, l);
    }
    let per = |x: usize| x as f64 / txs as f64;
    println!(
        "metadata: {:.0} B/tx raw, {:.1} nodes per transaction, of which {:.0}% belong to objects touched more than once in the ledger",
        per(a.meta),
        a.nodes as f64 / txs as f64,
        100.0 * a.multi_nodes as f64 / a.nodes.max(1) as f64
    );
    println!(
        "repeating object versions (raw B/tx): unchanged FinalFields {:.0} of {:.0}, PreviousFields {:.0} of {:.0}, NewFields {:.0} of {:.0}; overall {:.0} B/tx ({:.0}% of metadata)",
        per(a.final_same_end),
        per(a.final_total),
        per(a.prev_same_start),
        per(a.prev_total),
        per(a.new_same_end),
        per(a.new_total),
        per(a.final_same_end + a.prev_same_start + a.new_same_end),
        100.0 * (a.final_same_end + a.prev_same_start + a.new_same_end) as f64
            / a.meta.max(1) as f64
    );
    Ok(())
}

/// Object keys from the metadata AffectedNodes.
fn affected_keys(meta: &[u8]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    let Ok(fs) = stobject::fields(meta) else {
        return out;
    };
    for f in fs
        .iter()
        .filter(|f| (f.id.type_code, f.id.field_code) == (types::ARRAY, 8))
    {
        for node in stobject::items(f.value).unwrap_or_default() {
            for x in stobject::fields(node.value).unwrap_or_default() {
                if (x.id.type_code, x.id.field_code) == (types::HASH256, 6)
                    && let Ok(k) = <[u8; 32]>::try_from(x.value)
                {
                    out.push(k);
                }
            }
        }
    }
    out
}

fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn take_blob<'a>(b: &'a [u8], at: &mut usize) -> Res<&'a [u8]> {
    let n = u32::from_le_bytes(
        b.get(*at..*at + 4)
            .ok_or("block truncated")?
            .try_into()
            .map_err(e)?,
    ) as usize;
    let v = b.get(*at + 4..*at + 4 + n).ok_or("block truncated")?;
    *at += 4 + n;
    Ok(v)
}

/// Cold storage: a self-contained block of `n` ledgers. The block starts with
/// segment tables for the block; then, per ledger, a frame with metadata views and
/// format 3 changes. Object versions for views and changes come from the
/// changes of earlier ledgers in the same block (the first touch in a block
/// comes from metadata). The whole block is one zstd-19 stream. Decoding: the whole
/// block, byte-for-byte comparison of transactions, metadata and changes.
fn cold(all: &[Ledger], n: usize) -> Res<()> {
    let txs: usize = all.iter().map(|l| l.transactions.len()).sum();
    let (mut total, mut blocks, mut dec_ms) = (0usize, 0usize, Vec::new());
    let mut raw_total = 0usize;
    for chunk in all.chunks(n.max(1)) {
        let objs: Vec<Vec<u8>> = chunk
            .iter()
            .flat_map(|l| {
                l.transactions
                    .iter()
                    .flat_map(|(t, m)| [t.clone(), m.clone()])
            })
            .collect();
        let tables = Tables::build(objs.iter().map(Vec::as_slice), 2)?;
        let mut stream = Vec::new();
        put_blob(&mut stream, &tables.to_bytes());
        let mut objects: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        for l in chunk {
            let seq = l.header()?.sequence;
            let start = |k: &[u8; 32]| objects.get(k).cloned();
            let (frame, _) = encode_frame_views(&l.header, &l.transactions, &tables, &start)?;
            let prev = |k: &[u8; 32]| -> Res<Option<Vec<u8>>> { Ok(objects.get(k).cloned()) };
            let (patch, _) = delta::encode(l, seq, &prev)?;
            put_blob(&mut stream, &frame);
            put_blob(&mut stream, &patch);
            remember_versions(&mut objects, l);
        }
        raw_total += stream.len();
        let z = zstd::bulk::compress(&stream, 19).map_err(e)?;
        total += z.len() + 20;
        blocks += 1;
        // Decode the block from scratch and compare.
        let t0 = Instant::now();
        let raw = zstd::bulk::decompress(&z, 1 << 31).map_err(e)?;
        let mut at = 0;
        let t = Tables::from_bytes(take_blob(&raw, &mut at)?)?;
        let mut objects: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let mut back = Vec::with_capacity(chunk.len());
        for _ in chunk {
            let frame = take_blob(&raw, &mut at)?;
            let patch = take_blob(&raw, &mut at)?;
            let start = |k: &[u8; 32]| objects.get(k).cloned();
            let txs_back = decode_frame_views(frame, HEADER_LEN, &t, &start, None)?;
            let l = Ledger {
                header: frame[..HEADER_LEN].to_vec(),
                transactions: txs_back,
                changes: Vec::new(),
            };
            let seq = l.header()?.sequence;
            let prev = |k: &[u8; 32]| -> Res<Option<Vec<u8>>> { Ok(objects.get(k).cloned()) };
            let changes = delta::decode(&l, seq, patch, &prev)?;
            let l = Ledger { changes, ..l };
            remember_versions(&mut objects, &l);
            back.push(l);
        }
        dec_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        for (a, b) in chunk.iter().zip(&back) {
            let same_changes = a.changes.len() == b.changes.len()
                && a.changes
                    .iter()
                    .zip(&b.changes)
                    .all(|(x, y)| x.key == y.key && x.data == y.data);
            if a.header != b.header || a.transactions != b.transactions || !same_changes {
                return Err("cold block did not decode back to the source".into());
            }
        }
    }
    println!(
        "| cold block of {n} ledgers: tables + views + format 3 changes, zstd-19 | {:.1} B/tx | {blocks} blocks, {:.1} MB ({:.1} uncompressed) | block decode p50/p95/max {} ms | all ledgers, transactions, metadata and changes match |",
        total as f64 / txs as f64,
        total as f64 / 1e6,
        raw_total as f64 / 1e6,
        {
            let mut v = dec_ms.clone();
            v.sort_by(f64::total_cmp);
            format!(
                "{:.0} / {:.0} / {:.0}",
                v[v.len() / 2],
                v[(v.len() * 95 / 100).min(v.len() - 1)],
                v[v.len() - 1]
            )
        }
    );
    Ok(())
}

/// Object versions along the corpus: ledger start → frame → changes.
fn remember_versions(v: &mut HashMap<[u8; 32], Vec<u8>>, l: &Ledger) {
    for c in &l.changes {
        if c.change == Change::Deleted {
            v.remove(&c.key);
        } else {
            v.insert(c.key, c.data.clone());
        }
    }
}

/// Segment tables plus metadata as views against the current object version. Versions
/// at the start of each ledger come from the corpus (the training part warms them up);
/// in the server these are state store reads, here they are in memory.
fn views(
    train: &[Ledger],
    corpus: &[Ledger],
    txs: usize,
    t_train: &Tables,
    t_corpus: &Tables,
    samples: &[(usize, usize)],
) -> Res<Option<usize>> {
    if corpus.iter().all(|l| l.changes.is_empty()) {
        return Ok(None);
    }
    let mut versions: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let mut train_enc = Vec::new();
    for l in train {
        let start = |k: &[u8; 32]| versions.get(k).cloned();
        train_enc.push(encode_frame_views(&l.header, &l.transactions, t_train, &start)?.0);
        remember_versions(&mut versions, l);
    }
    // Snapshot of versions at the start of each measured ledger, for decoding and
    // random single-transaction reads.
    let mut frames_raw = Vec::with_capacity(corpus.len());
    let mut starts: Vec<HashMap<[u8; 32], Vec<u8>>> = Vec::new();
    let mut st = ViewStats::default();
    for l in corpus {
        // We need versions of the objects the ledger metadata touches, not
        // only the final changes: an object can be created and deleted in
        // the same ledger.
        let mut keys: Vec<[u8; 32]> = l.changes.iter().map(|c| c.key).collect();
        for (_, m) in &l.transactions {
            keys.extend(affected_keys(m));
        }
        let touched: HashMap<[u8; 32], Vec<u8>> = keys
            .into_iter()
            .filter_map(|k| versions.get(&k).map(|v| (k, v.clone())))
            .collect();
        let start = |k: &[u8; 32]| versions.get(k).cloned();
        let (f, s) = encode_frame_views(&l.header, &l.transactions, t_corpus, &start)?;
        st.literal_tx += s.literal_tx;
        st.meta_table += s.meta_table;
        st.meta_literal += s.meta_literal;
        st.meta_view += s.meta_view;
        frames_raw.push(f);
        starts.push(touched);
        remember_versions(&mut versions, l);
    }
    let table_z = zstd::bulk::compress(&t_corpus.to_bytes(), 19)
        .map_err(e)?
        .len();
    let dict = zstd::dict::from_samples(&train_enc, 112 << 10).map_err(e)?;
    let mut best = 0;
    for level in [9, 19] {
        let mut c = zstd::bulk::Compressor::with_dictionary(level, &dict).map_err(e)?;
        let mut d = zstd::bulk::Decompressor::with_dictionary(&dict).map_err(e)?;
        let frames: Vec<Vec<u8>> = frames_raw
            .iter()
            .map(|f| c.compress(f).map_err(e))
            .collect::<Res<_>>()?;
        for ((l, z), sv) in corpus.iter().zip(&frames).zip(&starts) {
            let f = d.decompress(z, 256 << 20).map_err(e)?;
            let start = |k: &[u8; 32]| sv.get(k).cloned();
            if f[..HEADER_LEN] != l.header[..]
                || decode_frame_views(&f, HEADER_LEN, t_corpus, &start, None)? != l.transactions
            {
                return Err("metadata views: decoded data does not match the source".into());
            }
        }
        let mut ms = Vec::new();
        for &(li, pos) in samples {
            let t0 = Instant::now();
            let f = d.decompress(&frames[li], 256 << 20).map_err(e)?;
            let sv = &starts[li];
            let start = |k: &[u8; 32]| sv.get(k).cloned();
            std::hint::black_box(decode_frame_views(
                &f,
                HEADER_LEN,
                t_corpus,
                &start,
                Some(pos),
            )?);
            ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let total = frames.iter().map(Vec::len).sum::<usize>() + dict.len() + table_z;
        if level == 19 {
            best = total;
        }
        println!(
            "| segment tables + metadata views, zstd-{level}, dictionary | {:.0} | {:.1} | {:.0} | {} | {} of {} ledgers |",
            total as f64 / txs as f64,
            total as f64 / 1e6,
            (dict.len() + table_z) as f64 / 1e3,
            pct(ms),
            corpus.len(),
            corpus.len()
        );
    }
    println!(
        "metadata: {} as views, {} via tables, {} as is; transactions as is {}",
        st.meta_view, st.meta_table, st.meta_literal, st.literal_tx
    );
    Ok(Some(best))
}

/// Changes in `Ledger::encode` serialization without header and transactions.
fn changes_part(l: &Ledger) -> Vec<u8> {
    let mut e = Ledger {
        header: Vec::new(),
        transactions: Vec::new(),
        changes: l.changes.clone(),
    }
    .encode();
    e.drain(..4);
    e
}

/// Blocks of 128 ledgers, zstd-19, like changes in history.
fn blocks128(records: &[Vec<u8>]) -> Res<usize> {
    let mut total = 0;
    for chunk in records.chunks(128) {
        let mut raw = (chunk.len() as u32).to_le_bytes().to_vec();
        for r in chunk {
            raw.extend_from_slice(&(r.len() as u32).to_le_bytes());
        }
        for r in chunk {
            raw.extend_from_slice(r);
        }
        total += zstd::bulk::compress(&raw, 19).map_err(e)?.len() + 20;
    }
    Ok(total)
}

/// State changes: format 2 (full objects) and format 3 (remainder against the
/// previous version and metadata). Previous versions come from the corpus itself:
/// the training part warms them up, and an object first seen in the measured part
/// is built from metadata. Every ledger is decoded back and compared.
fn state(train: &[Ledger], corpus: &[Ledger], txs: usize, tx_best: usize) -> Res<Option<usize>> {
    if corpus.iter().all(|l| l.changes.is_empty()) {
        println!("no state changes in the corpus, skipping");
        return Ok(None);
    }
    let mut versions: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let remember = |v: &mut HashMap<[u8; 32], Vec<u8>>, l: &Ledger| {
        for c in &l.changes {
            if c.change == Change::Deleted {
                v.remove(&c.key);
            } else {
                v.insert(c.key, c.data.clone());
            }
        }
    };
    for l in train {
        remember(&mut versions, l);
    }
    let (mut f2, mut f3) = (Vec::new(), Vec::new());
    let (mut full, mut n, mut deleted, mut first_touch) = (0usize, 0usize, 0usize, 0usize);
    for l in corpus {
        let seq = l.header()?.sequence;
        let prev = |k: &[u8; 32]| -> Res<Option<Vec<u8>>> { Ok(versions.get(k).cloned()) };
        let (rec, fc) = delta::encode(l, seq, &prev)?;
        let back = delta::decode(l, seq, &rec, &prev)?;
        let same = back.len() == l.changes.len()
            && back
                .iter()
                .zip(&l.changes)
                .all(|(a, b)| a.key == b.key && a.data == b.data);
        if !same {
            return Err(format!(
                "{seq}: format 3 did not decode back to the original changes"
            ));
        }
        for c in &l.changes {
            n += 1;
            if c.change == Change::Deleted {
                deleted += 1;
            } else if !versions.contains_key(&c.key) {
                first_touch += 1;
            }
        }
        full += fc;
        f2.push(changes_part(l));
        f3.push(rec);
        remember(&mut versions, l);
    }
    let (s2, s3) = (blocks128(&f2)?, blocks128(&f3)?);
    let per = |x: usize| x as f64 / txs as f64;
    println!(
        "state changes: {n} ({:.1} per transaction), {deleted} deletions, {first_touch} first touches in the window, {full} whole objects in format 3; all ledgers decoded back",
        n as f64 / txs as f64
    );
    println!(
        "| changes | B/tx |\n|---|---:|\n| format 2: full objects, blocks of 128, zstd-19 | {:.0} |\n| format 3: remainder against version and metadata, blocks of 128, zstd-19 | {:.0} |",
        per(s2),
        per(s3)
    );
    println!(
        "TOTAL (transactions with segment tables, zstd-19 + format 3 changes): {:.0} B/tx",
        per(tx_best + s3)
    );
    Ok(Some(s3))
}
