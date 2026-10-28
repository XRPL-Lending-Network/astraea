use astraea_journal_codec::*;
use serde_json::json;
use std::{fs, path::Path, time::Instant};
fn er(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn main() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 6 || a[1] != "encode" {
        return Err("jointbench encode source.rows NEW_DIR baseline|adaptive|order|cached|sequential|canonical raw_MiB".into());
    }
    let joint = match a[4].as_str() {
        "joint" | "adaptive" | "recent" | "order" | "cached" | "sequential" | "canonical" => true,
        "baseline" => false,
        _ => return Err("mode".into()),
    };
    let cap = a[5]
        .parse::<usize>()
        .map_err(er)?
        .checked_mul(1 << 20)
        .ok_or("cap")?;
    let input = fs::read(&a[2]).map_err(er)?;
    let rows = load_rows(&input)?;
    let t = Instant::now();
    let (archive, stats) = pack_bounded(
        &rows,
        1024,
        cap,
        Options {
            joint,
            adaptive: a[4] != "joint",
            chronological: ["order", "sequential", "canonical"].contains(&a[4].as_str()),
            hash_order: a[4] == "canonical",
            cached_slots: ["cached", "sequential", "canonical"].contains(&a[4].as_str()),
            recent: a[4] == "recent",
            split_shapes: true,
            context_delta: true,
            ..Options::default()
        },
    )?;
    let encode_ms = t.elapsed().as_secs_f64() * 1000.;
    let t = Instant::now();
    let restored = unpack(&archive)?;
    if rows_bytes(&restored) != input {
        return Err("exact restoration".into());
    }
    let restore_ms = t.elapsed().as_secs_f64() * 1000.;
    drop(restored);
    let indexes = indexed::Indexes::build(&rows)?;
    let index = indexes.encode();
    if indexed::Indexes::decode(&index)?.encode() != index {
        return Err("index roundtrip".into());
    }
    let out = Path::new(&a[3]);
    fs::create_dir(out).map_err(er)?;
    fs::write(out.join("payload.astj"), &archive).map_err(er)?;
    fs::write(out.join("index.asix"), &index).map_err(er)?;
    let txs: usize = rows.iter().map(|r| r.txs.len()).sum();
    let count = u32::from_le_bytes(archive[8..12].try_into().unwrap()) as usize;
    let mut at = 0;
    let mut blocks = vec![];
    for i in 0..count {
        let p = 12 + i * 56;
        let n = u32::from_le_bytes(archive[p + 4..p + 8].try_into().unwrap()) as usize;
        blocks.push(json!({"first":rows[at].seq,"last":rows[at+n-1].seq,"ledgers":n,"raw_bytes":rows_bytes(&rows[at..at+n]).len()}));
        at += n;
    }
    let manifest = json!({"format":"ASTJ-RESEARCH2","payload_format":if ["order","cached","sequential","canonical"].contains(&a[4].as_str()){"ASTJ5"}else if joint{"ASTJ4"}else{"ASTJ3"},"archive":"payload.astj","index":"index.asix","archive_bytes":archive.len(),"index_bytes":index.len(),"archive_sha512half":hex::encode(witness_core::sha512_half(&archive)),"index_sha512half":hex::encode(witness_core::sha512_half(&index)),"source_sha512half":hex::encode(witness_core::sha512_half(&input)),"source_bytes":input.len(),"first":rows[0].seq,"last":rows.last().unwrap().seq,"txs":txs,"blocks":blocks,"max_raw_bytes":cap,"max_ledgers":1024,"initial_state_snapshot":false,"global_router":false,"explicit_change_kinds":false});
    let manifest = serde_json::to_vec_pretty(&manifest).map_err(er)?;
    fs::write(out.join("manifest.json"), &manifest).map_err(er)?;
    println!(
        "{}",
        json!({"mode":a[4],"directory":a[3],"ledgers":rows.len(),"txs":txs,"payload_bytes":archive.len(),"index_bytes":index.len(),"manifest_bytes":manifest.len(),"total_bytes":archive.len()+index.len()+manifest.len(),"total_bpt":(archive.len()+index.len()+manifest.len())as f64/txs as f64,"encode_ms":encode_ms,"restore_verify_ms":restore_ms,"exact":true,"blocks":blocks,"stats":stats.iter().map(|s|json!({"reordered_ledgers":s.reordered_ledgers,"canonical_ledgers":s.canonical_ledgers,"order_bytes_raw":s.order_bytes,"templates":s.templates,"context_repeats":s.context_repeats,"dictionary_values":s.dictionary_values,"dictionary_bytes_raw":s.dictionary_bytes,"columns_bytes_raw":s.column_bytes,"inner_bytes":s.inner_bytes,"compressed_frame_bytes":s.compressed_bytes,"derived_hashes":s.derived_hashes,"derived_keys":s.derived_keys})).collect::<Vec<_>>()})
    );
    Ok(())
}
