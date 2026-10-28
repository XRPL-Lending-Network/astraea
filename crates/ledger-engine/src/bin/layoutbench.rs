//! astraea-layoutbench: which layout to store transactions in, so that tx and
//! account_tx are fast and history stays small.
//!
//! Method:
//! - dictionaries are trained on ledgers *before* the measured range;
//! - any compression or decompression error is fatal; every variant must
//!   restore each transaction and its metadata byte for byte, otherwise
//!   it gets no result;
//! - size is a model estimate of the format: compressed frames, a model addressing
//!   index (frame offset and length, transaction position in the frame), dictionaries;
//!   incomplete groups are padded out. Housekeeping structures of real history
//!   (file headers, change group indexes) are not counted: this compares
//!   variants against each other, not file sizes on disk;
//! - account_tx pages are real: transaction positions of real accounts
//!   (`--pages`, JSON lines `[[ledger, TransactionIndex], …]`);
//! - this measures CPU on in-memory data: decompressing the needed frames and
//!   extracting transactions. The HTTP path for the selected variants is
//!   measured separately.
//!
//! State changes are counted as a separate stream, the same for all
//! transaction variants; ledger headers are stored outside history (in the
//! state store) and are not counted for any variant: in the
//! "shared block" the header bytes in the frame are zeroed.
//!
//! Format 3 history can only be decoded with previous object versions:
//! it needs `--state`, a copy of the state store.

use std::collections::HashMap;
use std::io::BufRead;
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use ledger_engine::history::HistoryReader;
use ledger_engine::ledger::Ledger;
use witness_core::ledger::HEADER_LEN;
use witness_core::stobject;

#[derive(Debug, Parser)]
struct Args {
    /// Loader blocks directory.
    blocks: PathBuf,
    /// First measured ledger; dictionaries are trained on `--train` ledgers before it.
    #[arg(long)]
    from: u32,
    #[arg(long, default_value_t = 4096)]
    ledgers: u32,
    #[arg(long, default_value_t = 512)]
    train: u32,
    /// account_tx pages: JSON lines with positions.
    #[arg(long)]
    pages: PathBuf,
    /// Copy of the state store: previous object versions for format 3
    /// history. Without it only format 2 can be read.
    #[arg(long)]
    state: Option<PathBuf>,
    #[arg(long, default_value_t = 9)]
    level: i32,
}

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

/// Compression with a prepared dictionary, once per variant rather than per frame.
struct Codec {
    comp: zstd::bulk::Compressor<'static>,
    dec: zstd::bulk::Decompressor<'static>,
}

impl Codec {
    fn new(level: i32, dict: Option<&[u8]>) -> Res<Codec> {
        Ok(match dict {
            Some(d) => Codec {
                comp: zstd::bulk::Compressor::with_dictionary(level, d).map_err(e)?,
                dec: zstd::bulk::Decompressor::with_dictionary(d).map_err(e)?,
            },
            None => Codec {
                comp: zstd::bulk::Compressor::new(level).map_err(e)?,
                dec: zstd::bulk::Decompressor::new().map_err(e)?,
            },
        })
    }
}

/// A (tx, meta) pair as a frame: u32 len, tx, u32 len, meta.
fn pair(t: &[u8], m: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(t.len() as u32).to_le_bytes());
    out.extend_from_slice(t);
    out.extend_from_slice(&(m.len() as u32).to_le_bytes());
    out.extend_from_slice(m);
}

/// A ledger's transactions as one chunk: pairs back to back.
fn tx_part(l: &Ledger) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, m) in &l.transactions {
        pair(t, m, &mut out);
    }
    out
}

/// The i-th pair from `tx_part` chunks, starting at `at`.
fn nth_pair(raw: &[u8], mut at: usize, i: usize) -> Res<(&[u8], &[u8])> {
    let take = |at: &mut usize| -> Res<&[u8]> {
        let b = raw.get(*at..*at + 4).ok_or("frame truncated")?;
        let l = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        let s = raw.get(*at + 4..*at + 4 + l).ok_or("frame truncated")?;
        *at += 4 + l;
        Ok(s)
    };
    for _ in 0..i {
        take(&mut at)?;
        take(&mut at)?;
    }
    Ok((take(&mut at)?, take(&mut at)?))
}

fn tx_index(meta: &[u8]) -> Res<u32> {
    let f = stobject::fields(meta).map_err(e)?;
    stobject::find(&f, stobject::FieldId::new(stobject::types::UINT32, 28))
        .and_then(stobject::u32_of)
        .ok_or_else(|| "no TransactionIndex".into())
}

fn u32_at(raw: &[u8], at: usize) -> Res<usize> {
    let b = raw.get(at..at + 4).ok_or("frame truncated")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
}

#[derive(Clone, Copy)]
enum Kind {
    /// A frame per `n` ledgers: chunk count, chunk offsets, chunks.
    Group(u32),
    /// A frame per transaction.
    PerTx,
    /// Current layout: a block of 32 whole serialized ledgers.
    Combined,
}

struct Variant {
    name: String,
    kind: Kind,
    codec: Codec,
    dict_bytes: u64,
    frames: Vec<Vec<u8>>,
    /// Ledger → (frame number, chunk number in the frame); for PerTx, the first frame.
    at: HashMap<u32, (usize, usize)>,
    pending: Vec<Vec<u8>>,
}

impl Variant {
    fn new(name: &str, kind: Kind, level: i32, dict: Option<&[u8]>) -> Res<Variant> {
        Ok(Variant {
            name: name.into(),
            kind,
            codec: Codec::new(level, dict)?,
            dict_bytes: dict.map_or(0, |d| d.len() as u64),
            frames: Vec::new(),
            at: HashMap::new(),
            pending: Vec::new(),
        })
    }

    fn add(&mut self, seq: u32, l: &Ledger) -> Res<()> {
        match self.kind {
            Kind::PerTx => {
                self.at.insert(seq, (self.frames.len(), 0));
                for (t, m) in &l.transactions {
                    let mut raw = Vec::with_capacity(t.len() + m.len() + 8);
                    pair(t, m, &mut raw);
                    let z = self.codec.comp.compress(&raw).map_err(e)?;
                    self.frames.push(z);
                }
            }
            Kind::Group(n) => {
                self.at.insert(seq, (self.frames.len(), self.pending.len()));
                self.pending.push(tx_part(l));
                if self.pending.len() as u32 == n {
                    self.flush()?;
                }
            }
            Kind::Combined => {
                self.at.insert(seq, (self.frames.len(), self.pending.len()));
                // The header is not counted, as for the other variants: zeros
                // compress to a few bytes, and frame parsing does not change.
                let mut b = l.encode();
                b[..HEADER_LEN].fill(0);
                self.pending.push(b);
                if self.pending.len() == 32 {
                    self.flush()?;
                }
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Res<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let mut raw = Vec::new();
        raw.extend_from_slice(&(self.pending.len() as u32).to_le_bytes());
        let mut off = 0u32;
        for p in &self.pending {
            raw.extend_from_slice(&off.to_le_bytes());
            off += p.len() as u32;
        }
        for p in &self.pending {
            raw.extend_from_slice(p);
        }
        let z = self.codec.comp.compress(&raw).map_err(e)?;
        self.frames.push(z);
        self.pending.clear();
        Ok(())
    }

    /// Model estimate of the format: frames, frame index (u64 offset + u32
    /// length), ledger index (u32 frame number), dictionary.
    fn bytes(&self) -> u64 {
        let frames: u64 = self.frames.iter().map(|f| f.len() as u64).sum();
        frames + self.frames.len() as u64 * 12 + self.at.len() as u64 * 4 + self.dict_bytes
    }

    /// Transaction `pos` of ledger `seq`: (tx, meta) as bytes. A frame needed
    /// twice is decompressed once.
    fn get(
        &mut self,
        seq: u32,
        pos: usize,
        cache: &mut HashMap<usize, Vec<u8>>,
    ) -> Res<(Vec<u8>, Vec<u8>)> {
        let &(frame, chunk) = self.at.get(&seq).ok_or("no such ledger")?;
        if let Kind::PerTx = self.kind {
            let raw = self
                .codec
                .dec
                .decompress(&self.frames[frame + pos], 64 << 20)
                .map_err(e)?;
            let (t, m) = nth_pair(&raw, 0, 0)?;
            return Ok((t.to_vec(), m.to_vec()));
        }
        if let std::collections::hash_map::Entry::Vacant(slot) = cache.entry(frame) {
            let raw = self
                .codec
                .dec
                .decompress(&self.frames[frame], 512 << 20)
                .map_err(e)?;
            slot.insert(raw);
        }
        let raw = &cache[&frame];
        let n = u32_at(raw, 0)?;
        let base = 4 + n * 4;
        let start = base + u32_at(raw, 4 + chunk * 4)?;
        if let Kind::Combined = self.kind {
            // Current layout: the whole ledger is decoded.
            let end = if chunk + 1 < n {
                base + u32_at(raw, 8 + chunk * 4)?
            } else {
                raw.len()
            };
            let l = Ledger::decode(raw.get(start..end).ok_or("frame truncated")?)?;
            let (t, m) = l.transactions.get(pos).ok_or("no such position")?;
            return Ok((t.clone(), m.clone()));
        }
        let (t, m) = nth_pair(raw, start, pos)?;
        Ok((t.to_vec(), m.to_vec()))
    }
}

fn pct(mut v: Vec<f64>) -> String {
    if v.is_empty() {
        return "—".into();
    }
    v.sort_by(f64::total_cmp);
    let p = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    format!("{:.2} / {:.2} / {:.2}", p(0.5), p(0.95), p(0.99))
}

fn fingerprint(t: &[u8], m: &[u8]) -> [u8; 32] {
    let mut h = witness_core::sha512_half(t).to_vec();
    h.extend(witness_core::sha512_half(m));
    witness_core::sha512_half(&h)
}

fn main() -> Res<()> {
    let args = Args::parse();
    let mut r = HistoryReader::open(&args.blocks)?;
    if let Some(dir) = &args.state {
        let state = std::sync::Arc::new(ledger_engine::state::StateStore::open(dir)?);
        r = r.with_prev(std::sync::Arc::new(move |k: &[u8; 32], at: u32| {
            state.get(k, at)
        }));
    }
    let get = |seq: u32| -> Res<Ledger> {
        Ledger::decode(&r.get(seq)?.ok_or(format!("no ledger {seq}"))?)
    };
    let (first, last) = (args.from, args.from + args.ledgers - 1);

    // Dictionaries are trained on ledgers before the range.
    let (mut per_tx, mut per_ledger) = (Vec::new(), Vec::new());
    for seq in first - args.train..first {
        let l = get(seq)?;
        per_ledger.push(tx_part(&l));
        for (t, m) in &l.transactions {
            let mut raw = Vec::new();
            pair(t, m, &mut raw);
            per_tx.push(raw);
        }
    }
    let train = |s: &[Vec<u8>], size: usize| zstd::dict::from_samples(s, size).map_err(e);
    let d_tx = train(&per_tx, 112 << 10)?;
    let d_tx_big = train(&per_tx, 1 << 20)?;
    let d_ledger = train(&per_ledger, 112 << 10)?;
    println!(
        "dictionaries trained on {} ledgers before {first}: {} transactions",
        args.train,
        per_tx.len()
    );
    drop((per_tx, per_ledger));

    let lv = args.level;
    let mut vs = vec![
        Variant::new(
            "current: block 32, transactions and changes together",
            Kind::Combined,
            lv,
            None,
        )?,
        Variant::new("transactions only, block 32", Kind::Group(32), lv, None)?,
        Variant::new("transactions only, block 8", Kind::Group(8), lv, None)?,
        Variant::new("transactions only, block 4", Kind::Group(4), lv, None)?,
        Variant::new(
            "transactions only, frame per ledger",
            Kind::Group(1),
            lv,
            None,
        )?,
        Variant::new(
            "frame per ledger, 112K dictionary",
            Kind::Group(1),
            lv,
            Some(&d_ledger),
        )?,
        Variant::new(
            "frame per transaction, 112K dictionary",
            Kind::PerTx,
            lv,
            Some(&d_tx),
        )?,
        Variant::new(
            "frame per transaction, 1M dictionary",
            Kind::PerTx,
            lv,
            Some(&d_tx_big),
        )?,
    ];

    // State changes as a separate stream, for the total.
    let (mut ch_raw, mut ch128, mut tx_raw) = (0u64, 0u64, 0u64);
    let mut ch_buf = Vec::new();
    let mut positions: HashMap<(u32, u32), usize> = HashMap::new();
    let mut originals: Vec<(u32, usize, [u8; 32])> = Vec::new();
    let t = Instant::now();
    for seq in first..=last {
        let l = get(seq)?;
        l.verify()?;
        for (pos, (tx, meta)) in l.transactions.iter().enumerate() {
            positions.insert((seq, tx_index(meta)?), pos);
            originals.push((seq, pos, fingerprint(tx, meta)));
        }
        tx_raw += tx_part(&l).len() as u64;
        let mut ch = Ledger {
            header: l.header.clone(),
            transactions: Vec::new(),
            changes: l.changes.clone(),
        }
        .encode();
        ch.drain(..l.header.len());
        ch_raw += ch.len() as u64;
        ch_buf.extend_from_slice(&ch);
        if (seq - first + 1).is_multiple_of(128) || seq == last {
            ch128 += zstd::bulk::compress(&ch_buf, 19).map_err(e)?.len() as u64;
            ch_buf.clear();
        }
        for v in &mut vs {
            v.add(seq, &l)?;
        }
    }
    for v in &mut vs {
        v.flush()?;
    }
    let per = |b: u64| b as f64 / f64::from(args.ledgers) / 1000.0;
    println!(
        "{} ledgers {first}…{last}, {} transactions, all variants compressed in {:.0} s; uncompressed: transactions {:.1} KB/ledger, changes {:.1} KB/ledger",
        args.ledgers,
        originals.len(),
        t.elapsed().as_secs_f64(),
        per(tx_raw),
        per(ch_raw)
    );
    println!(
        "changes separately, blocks of 128, zstd-19: {:.1} KB/ledger",
        per(ch128)
    );

    // Real account_tx pages, as positions.
    let mut pages: Vec<Vec<(u32, usize)>> = Vec::new();
    let f = std::fs::File::open(&args.pages).map_err(e)?;
    for line in std::io::BufReader::new(f).lines() {
        let items: Vec<(u32, u32)> = serde_json::from_str(&line.map_err(e)?).map_err(e)?;
        let page: Option<Vec<(u32, usize)>> = items
            .iter()
            .map(|k| positions.get(k).map(|p| (k.0, *p)))
            .collect();
        if let Some(p) = page.filter(|p| !p.is_empty()) {
            pages.push(p);
        }
    }
    let avg = pages.iter().map(Vec::len).sum::<usize>() as f64 / pages.len().max(1) as f64;
    println!(
        "account_tx pages fully inside the range: {} ({avg:.0} transactions on average)",
        pages.len()
    );

    println!(
        "| variant | KB/ledger (format model) | total with changes, KB/ledger | restored | account_tx page p50/p95/p99, ms | one tx p50/p95/p99, ms |"
    );
    println!("|---|---:|---:|---|---:|---:|");
    for v in &mut vs {
        // Every transaction byte for byte (by fingerprint).
        let mut cache = HashMap::new();
        for (seq, pos, fp) in &originals {
            if cache.len() > 8 {
                cache.clear();
            }
            let (t, m) = v.get(*seq, *pos, &mut cache)?;
            if fingerprint(&t, &m) != *fp {
                return Err(format!(
                    "{}: ledger {seq}, position {pos} restored incorrectly",
                    v.name
                ));
            }
        }
        let mut page_ms = Vec::new();
        for p in &pages {
            let t = Instant::now();
            let mut cache = HashMap::new();
            for (seq, pos) in p {
                std::hint::black_box(v.get(*seq, *pos, &mut cache)?);
            }
            page_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        // Single tx at random, no cache.
        let mut one_ms = Vec::new();
        for i in (0..originals.len()).step_by((originals.len() / 2000).max(1)) {
            let (seq, pos, _) = originals[i];
            let t = Instant::now();
            std::hint::black_box(v.get(seq, pos, &mut HashMap::new())?);
            one_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        let with_changes = if let Kind::Combined = v.kind {
            v.bytes()
        } else {
            v.bytes() + ch128
        };
        println!(
            "| {} | {:.1} | {:.1} | {} of {} | {} | {} |",
            v.name,
            per(v.bytes()),
            per(with_changes),
            originals.len(),
            originals.len(),
            pct(page_ms),
            pct(one_ms)
        );
    }
    Ok(())
}
