#![recursion_limit = "256"]
use astraea_journal_codec::*;
use serde_json::json;
use std::{collections::BTreeMap, fs, path::Path, time::Instant};
fn quantile(v: &mut [f64]) -> serde_json::Value {
    v.sort_by(f64::total_cmp);
    let n = v.len();
    json!({"n":n,"p50_ms":v[(n-1)/2],"p99_ms":v[((n as f64*0.99).ceil()as usize).saturating_sub(1)],"max_ms":v[n-1]})
}
fn main() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() < 5 {
        return Err("input.rows output-dir pool-chunk-bytes docs-per-chunk".into());
    }
    for flag in &a[5..] {
        if ![
            "--reuse",
            "--columns",
            "--inline",
            "--compact",
            "--numeric",
            "--ledgers",
        ]
        .contains(&flag.as_str())
            && !flag.starts_with("--shared=")
            && !flag.starts_with("--min-fields=")
        {
            return Err(format!("unknown option: {flag}"));
        }
    }
    let input = fs::read(&a[1]).map_err(|e| e.to_string())?;
    let rows = load_rows(&input)?;
    verify(&rows)?;
    let nt: usize = rows.iter().map(|r| r.txs.len()).sum();
    let np: usize = rows.iter().map(|r| r.patches.len()).sum();
    let pc: usize = a[3].parse().map_err(|_| "pool size")?;
    let dc: usize = a[4].parse().map_err(|_| "doc size")?;
    fs::create_dir_all(&a[2]).map_err(|e| e.to_string())?;
    let name = Path::new(&a[1])
        .file_stem()
        .ok_or("stem")?
        .to_string_lossy();
    let ap = Path::new(&a[2]).join(format!("{name}-{pc}-{dc}.asts"));
    let ip = Path::new(&a[2]).join(format!("{name}.asix"));
    let reuse = a.iter().any(|s| s == "--reuse");
    let columns = a.iter().any(|s| s == "--columns");
    let shared_depth = a
        .iter()
        .find_map(|x| x.strip_prefix("--shared="))
        .map(|x| x.parse::<usize>().map_err(|_| "shared depth"))
        .transpose()?;
    let min_fields = a
        .iter()
        .find_map(|s| s.strip_prefix("--min-fields="))
        .map(|s| s.parse::<usize>().map_err(|_| "min fields"))
        .transpose()?
        .unwrap_or(0);
    let numeric = a.iter().any(|s| s == "--numeric");
    let compact = a.iter().any(|s| s == "--compact");
    let inline = a.iter().any(|s| s == "--inline");
    if (columns && (shared_depth.is_some() || inline || numeric || compact))
        || ((inline || numeric || compact || min_fields != 0) && shared_depth.is_none())
        || (compact && (!inline || numeric))
    {
        return Err("incompatible encoding options".into());
    }
    let expected_format = if numeric {
        "ASTS8"
    } else if compact {
        "ASTS7"
    } else if inline {
        "ASTS6"
    } else if shared_depth.is_some() {
        "ASTS5"
    } else if columns {
        "ASTS4"
    } else {
        "ASTS3"
    };
    let mut shared_stats = None;
    let mut encode_ms = None;
    let mut index_build_ms = None;
    if !reuse {
        let options = Options {
            split_shapes: true,
            context_delta: true,
            ..Options::default()
        };
        let t = Instant::now();
        let (frame, _) = encode_block(&rows, options)?;
        let prepared = fast::Prepared::parse(&frame)?;
        let archive = if let Some(depth) = shared_depth {
            let (archive, stats) = if numeric {
                seek::pack_shared_numeric(&prepared, &rows, pc, dc, depth, min_fields)?
            } else if inline {
                seek::pack_shared_compact(&prepared, &rows, pc, dc, depth, min_fields, compact)?
            } else {
                seek::pack_shared(&prepared, &rows, pc, dc, depth)?
            };
            shared_stats = Some(stats.json());
            archive
        } else if columns {
            seek::pack_columns(&prepared, pc, dc)?
        } else {
            seek::pack(&prepared, pc, dc)?
        };
        encode_ms = Some(t.elapsed().as_secs_f64() * 1000.);
        fs::write(&ap, &archive).map_err(|e| e.to_string())?;
        let t = Instant::now();
        let indexes = indexed::Indexes::build(&rows)?;
        fs::write(&ip, indexes.encode()).map_err(|e| e.to_string())?;
        index_build_ms = Some(t.elapsed().as_secs_f64() * 1000.);
    }
    let t = Instant::now();
    let index_bytes = fs::read(&ip).map_err(|e| e.to_string())?;
    let indexes = indexed::Indexes::decode(&index_bytes)?;
    let index_open_ms = t.elapsed().as_secs_f64() * 1000.;
    let index_heap = indexes.memory_bytes();
    let components = indexes.component_bytes();
    let original: Vec<_> = rows.iter().flat_map(|r| r.txs.iter()).collect();
    let patches: Vec<_> = rows.iter().flat_map(|r| r.patches.iter()).collect();
    // Check every hash lookup, comparing complete hashes after fingerprint routing.
    for (i, (tx, _)) in original.iter().enumerate() {
        let h = witness_core::shamap::tx_id(tx);
        let found = indexes
            .tx_candidates(&h)?
            .into_iter()
            .find(|j| witness_core::shamap::tx_id(&original[*j].0) == h);
        if found != Some(i) {
            return Err("TX index mismatch".into());
        }
    }
    let mut naive_accounts: BTreeMap<[u8; 20], Vec<(u32, u32, usize)>> = BTreeMap::new();
    let mut storage = 0;
    for row in &rows {
        for (_, meta) in &row.txs {
            let (index, aa) = indexed::affected(meta)?;
            for account in aa {
                naive_accounts
                    .entry(account)
                    .or_default()
                    .push((row.seq, index, storage));
            }
            storage += 1;
        }
    }
    for (account, list) in &mut naive_accounts {
        list.sort_unstable();
        let found = indexes.account_page(account, u32::MAX, None, usize::MAX)?;
        let expected: Vec<_> = list.iter().rev().map(|x| x.2).collect();
        if found.iter().map(|x| x.1).collect::<Vec<_>>() != expected {
            return Err("account order mismatch".into());
        }
    }
    for row in &rows {
        let h = witness_core::ledger::LedgerHeader::parse(&row.header)
            .map_err(|e| e.to_string())?
            .hash();
        if !indexes
            .ledger_candidates(&h)
            .into_iter()
            .any(|i| rows[i].seq == row.seq)
        {
            return Err("ledger index mismatch".into());
        }
    }
    let mut naive_objects: BTreeMap<[u8; 32], Vec<(u32, usize)>> = BTreeMap::new();
    let mut ordinal = 0;
    for row in &rows {
        for (key, _) in &row.patches {
            naive_objects
                .entry(*key)
                .or_default()
                .push((row.seq, ordinal));
            ordinal += 1;
        }
    }
    for (key, list) in &naive_objects {
        for row in [
            rows.first().ok_or("empty")?,
            &rows[rows.len() / 2],
            rows.last().ok_or("empty")?,
        ] {
            let expected = list.iter().rev().find(|x| x.0 <= row.seq).map(|x| x.1);
            let found = indexes
                .object_candidates(key, row.seq)?
                .into_iter()
                .find(|i| patches[*i].0 == *key);
            if found != expected {
                return Err("object predecessor mismatch".into());
            }
        }
    }
    for n in 0..10_000u64 {
        let h = witness_core::sha512_half(&n.to_le_bytes());
        if indexes
            .tx_candidates(&h)?
            .into_iter()
            .any(|i| witness_core::shamap::tx_id(&original[i].0) == h)
        {
            return Err("negative hash unexpectedly present".into());
        }
    }
    let t = Instant::now();
    let mut reader = seek::Reader::open(&ap)?;
    let open_ms = t.elapsed().as_secs_f64() * 1000.;
    if reader.format_name() != expected_format {
        return Err("archive mode mismatch".into());
    }
    let initial_heap = reader.memory_bytes();
    let t = Instant::now();
    let back = reader.all_rows()?;
    let full_decode_ms = t.elapsed().as_secs_f64() * 1000.;
    if rows_bytes(&back) != input {
        return Err("seek full roundtrip mismatch".into());
    }
    verify(&back)?;
    drop(back);
    let mut tx_cold = vec![];
    let mut tx_warm = vec![];
    let mut read_bytes = vec![];
    for q in 0..200 {
        let i = q * 7919 % nt;
        let h = witness_core::shamap::tx_id(&original[i].0);
        reader.clear_data_cache();
        let before = reader.bytes_read;
        let t = Instant::now();
        let mut found = None;
        for candidate in indexes.tx_candidates(&h)? {
            let tx = reader.tx(candidate)?;
            if witness_core::shamap::tx_id(&tx.0) == h {
                found = Some(tx);
                break;
            }
        }
        tx_cold.push(t.elapsed().as_secs_f64() * 1000.);
        read_bytes.push(reader.bytes_read - before);
        if found.as_ref() != Some(original[i]) {
            return Err("disk TX mismatch".into());
        }
        let t = Instant::now();
        let tx = reader.tx(i)?;
        tx_warm.push(t.elapsed().as_secs_f64() * 1000.);
        if tx != *original[i] {
            return Err("warm TX mismatch".into());
        }
    }
    let mut hot: Vec<_> = naive_accounts.iter().collect();
    hot.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    let mut account_ms = vec![];
    let mut account_lengths = vec![];
    for (key, list) in hot.into_iter().take(20) {
        reader.clear_data_cache();
        let t = Instant::now();
        let page = indexes.account_page(key, u32::MAX, None, 200)?;
        let mut fetched = vec![];
        for &(_, i) in &page {
            fetched.push(reader.tx(i)?);
        }
        account_ms.push(t.elapsed().as_secs_f64() * 1000.);
        account_lengths.push(page.len());
        for (back, expected) in fetched.iter().zip(list.iter().rev()) {
            if back != original[expected.2] {
                return Err("account page data mismatch".into());
            }
        }
        if let Some((rank, _)) = page.last() {
            let next = indexes.account_page(key, u32::MAX, Some(*rank), 200)?;
            let expected: Vec<_> = list
                .iter()
                .rev()
                .skip(page.len())
                .take(200)
                .map(|x| x.2)
                .collect();
            if next.iter().map(|x| x.1).collect::<Vec<_>>() != expected {
                return Err("account marker mismatch".into());
            }
        }
    }
    let object_keys: Vec<_> = naive_objects.keys().collect();
    let mut object_ms = vec![];
    let mut object_hits = 0usize;
    for q in 0..200 {
        let key = object_keys[q * 7919 % object_keys.len()];
        let target = rows[q * 53 % rows.len()].seq;
        reader.clear_data_cache();
        let t = Instant::now();
        let mut found = None;
        for i in indexes.object_candidates(key, target)? {
            let p = reader.patch(i)?;
            if p.0 == *key {
                found = Some((i, p));
                break;
            }
        }
        object_ms.push(t.elapsed().as_secs_f64() * 1000.);
        let expected = naive_objects[key]
            .iter()
            .rev()
            .find(|x| x.0 <= target)
            .map(|x| x.1);
        if found.as_ref().map(|x| x.0) != expected {
            return Err("object disk predecessor".into());
        }
        if let Some((i, p)) = found {
            object_hits += 1;
            if &p != patches[i] {
                return Err("object disk bytes".into());
            }
        }
    }
    let mut ledger_cold = vec![];
    let mut ledger_warm = vec![];
    let mut ledger_cases = vec![];
    if a.iter().any(|s| s == "--ledgers") {
        ledger_cases.extend((0..12).map(|q| q * 53 % rows.len()));
        let mut largest: Vec<_> = (0..rows.len()).collect();
        largest.sort_by_key(|&i| std::cmp::Reverse(rows[i].txs.len() + rows[i].patches.len()));
        ledger_cases.extend(largest.into_iter().take(12));
        ledger_cases.sort_unstable();
        ledger_cases.dedup();
        for &i in &ledger_cases {
            reader.clear_data_cache();
            let t = Instant::now();
            let row = reader.row(i)?;
            verify(std::slice::from_ref(&row))?;
            ledger_cold.push(t.elapsed().as_secs_f64() * 1000.);
            if row != rows[i] {
                return Err("cold ledger bytes".into());
            }
            let t = Instant::now();
            let row = reader.row(i)?;
            verify(std::slice::from_ref(&row))?;
            ledger_warm.push(t.elapsed().as_secs_f64() * 1000.);
            if row != rows[i] {
                return Err("repeat ledger bytes".into());
            }
        }
    }
    let ledger_cold_stats = if ledger_cold.is_empty() {
        json!(null)
    } else {
        quantile(&mut ledger_cold)
    };
    let ledger_warm_stats = if ledger_warm.is_empty() {
        json!(null)
    } else {
        quantile(&mut ledger_warm)
    };
    let mut proof_ms = vec![];
    let mut proof_read_bytes = vec![];
    for q in 0..20 {
        let i = q * 7919 % nt;
        reader.clear_data_cache();
        let before = reader.bytes_read;
        let t = Instant::now();
        let proof = reader.proof_tx(i)?;
        proof_ms.push(t.elapsed().as_secs_f64() * 1000.);
        proof_read_bytes.push(reader.bytes_read - before);
        if (proof.tx, proof.meta) != *original[i] {
            return Err("proof source mismatch".into());
        }
    }
    let ab = fs::metadata(&ap).map_err(|e| e.to_string())?.len();
    let ib = index_bytes.len();
    println!(
        "{}",
        json!({"source":a[1],"archive":ap,"index":ip,"pool_chunk_bytes":pc,"docs_per_chunk":dc,"ledgers":rows.len(),"txs":nt,"patches":np,"archive_bytes":ab,"shared_min_fields":min_fields,"shared_depth":shared_depth,"shared_stats":shared_stats,"format":reader.format_name(),"ledger_cases":ledger_cases,"ledger_cold_application_cache":ledger_cold_stats,"ledger_repeat_same_reader":ledger_warm_stats,"index_format":"ASIX2","payload_components":reader.components(),"index_bytes":ib,"total_bpt":(ab as f64+ib as f64)/nt as f64,"payload_bpt":ab as f64/nt as f64,"index_bpt":ib as f64/nt as f64,"index_components":components,"accounts":naive_accounts.len(),"account_postings":naive_accounts.values().map(|v|v.len()).sum::<usize>(),"objects":naive_objects.len(),"encode_ms":encode_ms,"index_build_ms":index_build_ms,"index_open_ms":index_open_ms,"index_heap_bytes":index_heap,"reuse_existing_archive":reuse,"program_offset_cache":true,"open_directory_ms":open_ms,"directory_heap_bytes":initial_heap,"full_decode_ms":full_decode_ms,"reader_heap_bytes_after_queries":reader.memory_bytes(),"tx_cold_application_cache":quantile(&mut tx_cold),"tx_repeat_same_reader":quantile(&mut tx_warm),"tx_bytes_read_mean":read_bytes.iter().sum::<u64>()as f64/read_bytes.len()as f64,"account_pages":quantile(&mut account_ms),"account_page_lengths":account_lengths,"object_queries":quantile(&mut object_ms),"object_hits":object_hits,"proof_tx":quantile(&mut proof_ms),"proof_compressed_bytes_read_mean":proof_read_bytes.iter().sum::<u64>() as f64/proof_read_bytes.len() as f64,"all_bytes_exact":true,"tx_roots":true,"all_index_entries_checked":true,"negative_tx_queries":10000,"os_cache_uncontrolled":true,"initial_state_snapshot_included":false,"point_integrity":"compressed chunk SHA512Half plus full TX hash or object key; full roots checked outside point timer"})
    );
    Ok(())
}
