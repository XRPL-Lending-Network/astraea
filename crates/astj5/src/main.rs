use astraea_journal_codec::{
    ArchiveFile, Options, Row, Stats, load_rows, pack, rows_bytes, unpack, verify,
};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};

type Result<T> = std::result::Result<T, String>;
const USAGE: &str = "pack input.rows output.astj [block-ledgers] | unpack input.astj output.rows | ledger archive seq output.rows | bench samples output-dir [sizes] | readbench source.rows archive | ablate source.rows [block-ledgers] | dictbench source.rows [block-ledgers]";

fn read(path: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| format!("{path}: {e}"))
}
fn write(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    fs::write(path.as_ref(), bytes).map_err(|e| format!("{}: {e}", path.as_ref().display()))
}
fn number(s: &str) -> Result<usize> {
    let n = s
        .parse()
        .map_err(|_| format!("invalid positive integer: {s}"))?;
    if n == 0 {
        return Err("zero size".into());
    }
    Ok(n)
}
fn size(a: &[String], i: usize, default: usize) -> Result<usize> {
    a.get(i).map(|s| number(s)).unwrap_or(Ok(default))
}
fn stats_json(s: &Stats) -> Value {
    json!({"dictionary_values":s.dictionary_values, "derived_hashes":s.derived_hashes,
        "templates":s.templates, "columns":s.columns, "literal_objects":s.literal_objects,
        "inner_bytes":s.inner_bytes, "journal_zstd_bytes":s.compressed_bytes,
        "delta_columns":s.delta_columns, "derived_keys":s.derived_keys, "context_repeats":s.context_repeats})
}
fn baseline(rows: &[Row], block_ledgers: usize) -> Result<usize> {
    let mut n = 12;
    for block in rows.chunks(block_ledgers) {
        n += 56
            + 9
            + zstd::bulk::compress(&rows_bytes(block), 19)
                .map_err(|e| e.to_string())?
                .len();
    }
    Ok(n)
}
fn bench(a: &[String]) -> Result<()> {
    let outdir = Path::new(&a[3]);
    fs::create_dir_all(outdir).map_err(|e| e.to_string())?;
    let mut files = vec![];
    for entry in fs::read_dir(&a[2]).map_err(|e| e.to_string())? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.extension().is_some_and(|x| x == "rows") {
            files.push(p);
        }
    }
    files.sort();
    let sizes = a
        .get(4)
        .map(|s| s.split(',').map(number).collect::<Result<Vec<_>>>())
        .unwrap_or(Ok(vec![8, 32, 64, 256]))?;
    if files.is_empty() {
        return Err("no .rows files".into());
    }
    for p in files {
        let input = fs::read(&p).map_err(|e| e.to_string())?;
        let rs = load_rows(&input)?;
        verify(&rs)?;
        let nt: usize = rs.iter().map(|r| r.txs.len()).sum();
        let name = p.file_stem().ok_or("file stem")?.to_string_lossy();
        for &bs in &sizes {
            let t = Instant::now();
            let (archive, stats) = pack(&rs, bs, Options::default())?;
            let encode_ms = t.elapsed().as_secs_f64() * 1e3;
            let t = Instant::now();
            let back = unpack(&archive)?;
            let decode_ms = t.elapsed().as_secs_f64() * 1e3;
            if rows_bytes(&back) != input {
                return Err(format!("file mismatch {name}/{bs}"));
            }
            let base = baseline(&rs, bs)?;
            write(outdir.join(format!("{name}-{bs}.astj")), &archive)?;
            println!(
                "{}",
                json!({"sample":name,"block_ledgers":bs,"ledgers":rs.len(),"txs":nt,
                "input_bytes":input.len(),"archive_bytes":archive.len(),"bpt":archive.len() as f64/nt as f64,
                "baseline_bytes":base,"baseline_bpt":base as f64/nt as f64,
                "savings_percent":100.0*(base as f64-archive.len() as f64)/base as f64,
                "encode_ms":encode_ms,"decode_ms_including_roots":decode_ms,
                "roundtrip_exact_file":true,"roots_and_chain":true,
                "raw_sha512_half":hex::encode(witness_core::sha512_half(&input)),
                "stats":stats.iter().map(stats_json).collect::<Vec<_>>()})
            );
        }
    }
    Ok(())
}
fn readbench(a: &[String]) -> Result<()> {
    let rs = load_rows(&read(&a[2])?)?;
    if rs.is_empty() {
        return Err("empty source".into());
    }
    let mut file = ArchiveFile::open(&a[3])?;
    let mut ms = vec![];
    for i in 0..24 {
        let row = &rs[(i * 7919) % rs.len()];
        let t = Instant::now();
        let back = file.ledger(row.seq)?;
        ms.push(t.elapsed().as_secs_f64() * 1e3);
        if back != *row {
            return Err("random ledger mismatch".into());
        }
    }
    ms.sort_by(f64::total_cmp);
    println!(
        "{}",
        json!({"archive":a[3],"queries":24,"file_reads_with_os_cache_uncontrolled":true,
        "includes_block_hash_and_tx_roots":true,"p50_ms":ms[11],"p95_ms":ms[22],"max_ms":ms[23],"all_exact":true})
    );
    Ok(())
}
fn ablate(a: &[String]) -> Result<()> {
    let rs = load_rows(&read(&a[2])?)?;
    let nt: usize = rs.iter().map(|r| r.txs.len()).sum();
    let bs = size(a, 3, 256)?;
    for name in [
        "all",
        "no_context",
        "no_key_recipes",
        "no_tx_hash_recipes",
        "no_shared_dictionary",
        "no_numeric_delta",
        "no_signature_compaction",
    ] {
        let mut o = Options::default();
        match name {
            "no_context" => o.contextual = false,
            "no_key_recipes" => o.derive_keys = false,
            "no_tx_hash_recipes" => o.derive_hashes = false,
            "no_shared_dictionary" => o.dictionaries = false,
            "no_numeric_delta" => o.numeric_delta = false,
            "no_signature_compaction" => o.compact_signatures = false,
            _ => {}
        }
        let (archive, _) = pack(&rs, bs, o)?;
        if unpack(&archive)? != rs {
            return Err("ablation mismatch".into());
        }
        println!(
            "{}",
            json!({"variant":name,"block_ledgers":bs,"bytes":archive.len(),"txs":nt,
            "bpt":archive.len() as f64/nt as f64,"exact":true})
        );
    }
    Ok(())
}
// Strengthened baseline: dictionary is trained only on preceding ledgers.
// Charge the complete dictionary once to this evaluation window.
fn dictbench(a: &[String]) -> Result<()> {
    let rs = load_rows(&read(&a[2])?)?;
    if rs.len() < 512 {
        return Err("dictbench needs at least 512 ledgers".into());
    }
    verify(&rs)?;
    let bs = size(a, 3, 256)?;
    let (train, test) = rs.split_at(256);
    let samples: Vec<_> = train
        .iter()
        .map(|r| rows_bytes(std::slice::from_ref(r)))
        .collect();
    let nt: usize = test.iter().map(|r| r.txs.len()).sum();
    let (archive, _) = pack(test, bs, Options::default())?;
    if unpack(&archive)? != test {
        return Err("journal mismatch".into());
    }
    let base = baseline(test, bs)?;
    for capacity in [65_536, 262_144] {
        let dict = zstd::dict::from_samples(&samples, capacity).map_err(|e| e.to_string())?;
        let mut c =
            zstd::bulk::Compressor::with_dictionary(19, &dict).map_err(|e| e.to_string())?;
        let mut d = zstd::bulk::Decompressor::with_dictionary(&dict).map_err(|e| e.to_string())?;
        let mut dict_payload = 12;
        for block in test.chunks(bs) {
            let raw = rows_bytes(block);
            let z = c.compress(&raw).map_err(|e| e.to_string())?;
            if d.decompress(&z, raw.len()).map_err(|e| e.to_string())? != raw {
                return Err("dictionary baseline mismatch".into());
            }
            dict_payload += 56 + 9 + z.len();
        }
        println!(
            "{}",
            json!({"source":a[2],"training_first":train[0].seq,
            "training_last":train[255].seq,"test_first":test[0].seq,"test_last":test.last().ok_or("test")?.seq,
            "test_ledgers":test.len(),"txs":nt,"block_ledgers":bs,"dictionary_bytes":dict.len(),
            "baseline_plain_bytes":base,"baseline_dictionary_payload_bytes":dict_payload,
            "baseline_dictionary_total_bytes":dict_payload+dict.len(),"journal_bytes":archive.len(),
            "journal_bpt":archive.len() as f64/nt as f64,
            "dictionary_bpt_including_dictionary":(dict_payload+dict.len()) as f64/nt as f64,
            "all_exact":true,"training_precedes_test":true})
        );
    }
    Ok(())
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let command = a.get(1).ok_or(USAGE)?;
    let minimum = match command.as_str() {
        "ledger" => 5,
        "pack" | "unpack" | "bench" | "readbench" => 4,
        "ablate" | "dictbench" => 3,
        _ => return Err(USAGE.into()),
    };
    if a.len() < minimum {
        return Err(USAGE.into());
    }
    match command.as_str() {
        "pack" => {
            let input = read(&a[2])?;
            let rs = load_rows(&input)?;
            let (out, _) = pack(&rs, size(&a, 4, 64)?, Options::default())?;
            if rows_bytes(&unpack(&out)?) != input {
                return Err("exact file mismatch".into());
            }
            write(&a[3], &out)?;
            println!(
                "{}",
                json!({"input_bytes":input.len(),"archive_bytes":out.len(),"exact":true})
            );
        }
        "unpack" => write(&a[3], &rows_bytes(&unpack(&read(&a[2])?)?))?,
        "ledger" => {
            let seq = a[3].parse().map_err(|_| "ledger number")?;
            let row = ArchiveFile::open(&a[2])?.ledger(seq)?;
            write(&a[4], &rows_bytes(&[row]))?;
        }
        "bench" => bench(&a)?,
        "readbench" => readbench(&a)?,
        "ablate" => ablate(&a)?,
        "dictbench" => dictbench(&a)?,
        _ => unreachable!(),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
