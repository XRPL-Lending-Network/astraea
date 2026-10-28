//! Reader-only process: no source rows or encoder allocations are resident.
use astraea_journal_codec::{indexed, seek, verify};
use serde_json::json;
use std::{fs, time::Instant};
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 4 {
        return Err("readprobe payload index ledger-index...".into());
    }
    let t = Instant::now();
    let index = indexed::Indexes::decode(&fs::read(&args[2]).map_err(|e| e.to_string())?)?;
    let mut reader = seek::Reader::open(&args[1])?;
    let open_ms = t.elapsed().as_secs_f64() * 1000.;
    let initial = reader.memory_bytes() + index.memory_bytes();
    let mut cases = vec![];
    for arg in &args[3..] {
        let i = arg.parse::<usize>().map_err(|_| "ledger index")?;
        reader.clear_data_cache();
        let t = Instant::now();
        let row = reader.row(i)?;
        verify(std::slice::from_ref(&row))?;
        cases.push(json!({"ledger":row.seq,"index":i,"txs":row.txs.len(),"patches":row.patches.len(),"ms":t.elapsed().as_secs_f64()*1000.}));
    }
    println!(
        "{}",
        json!({"open_ms":open_ms,"initial_estimated_heap":initial,"final_estimated_heap":reader.memory_bytes()+index.memory_bytes(),"cases":cases,"os_cache_uncontrolled":true,"manifest_hashing_included":false})
    );
    Ok(())
}
