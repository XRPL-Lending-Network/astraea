use astraea_journal_codec::*;
use serde_json::json;
use std::{fs, path::Path, time::Instant};
fn main() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("variants") => {
            let input = fs::read(&a[2]).map_err(|e| e.to_string())?;
            let rows = load_rows(&input)?;
            let bs: usize = a[4].parse().map_err(|_| "block size")?;
            fs::create_dir_all(&a[3]).map_err(|e| e.to_string())?;
            let nt: usize = rows.iter().map(|r| r.txs.len()).sum();
            let name = Path::new(&a[2])
                .file_stem()
                .ok_or("stem")?
                .to_string_lossy();
            for mode in a
                .get(5)
                .map(String::as_str)
                .unwrap_or("legacy,split,delta")
                .split(',')
            {
                let o = Options {
                    split_shapes: mode != "legacy",
                    context_delta: mode == "delta",
                    ..Options::default()
                };
                let t = Instant::now();
                let (out, _) = pack(&rows, bs, o)?;
                let enc = t.elapsed().as_secs_f64() * 1000.;
                let t = Instant::now();
                let back = unpack(&out)?;
                let dec = t.elapsed().as_secs_f64() * 1000.;
                if rows_bytes(&back) != input {
                    return Err("roundtrip mismatch".into());
                }
                let p = Path::new(&a[3]).join(format!("{name}-{bs}-{mode}.astj"));
                fs::write(&p, &out).map_err(|e| e.to_string())?;
                println!(
                    "{}",
                    json!({"source":a[2],"archive":p,"mode":mode,"block_ledgers":bs,"ledgers":rows.len(),"txs":nt,"bytes":out.len(),"bpt":out.len()as f64/nt as f64,"encode_ms":enc,"decode_verify_ms":dec,"exact":true,"tx_roots":true,"raw_sha512half":hex::encode(witness_core::sha512_half(&input))})
                );
            }
        }
        Some("fastbench" | "fastbench-all") => {
            let archive = fs::read(&a[2]).map_err(|e| e.to_string())?;
            let n = u32::from_le_bytes(archive[8..12].try_into().unwrap());
            let mut results = vec![];
            for i in 0..(if a[1] == "fastbench-all" { n } else { n.min(4) }) as usize {
                let at = 12 + i * 56;
                let off = u64::from_le_bytes(archive[at + 8..at + 16].try_into().unwrap()) as usize;
                let len =
                    u64::from_le_bytes(archive[at + 16..at + 24].try_into().unwrap()) as usize;
                let p = &archive[off..off + len];
                if p[0] != 1 {
                    continue;
                }
                let t = Instant::now();
                let mut f = fast::Prepared::parse(&p[1..])?;
                let prepare = t.elapsed().as_secs_f64() * 1000.;
                let t = Instant::now();
                let all = f.all_rows()?;
                let decode = t.elapsed().as_secs_f64() * 1000.;
                if witness_core::sha512_half(&rows_bytes(&all)) != archive[at + 24..at + 56] {
                    return Err("block raw hash".into());
                }
                verify(&all)?;
                let expected: Vec<_> = all.iter().flat_map(|r| r.txs.iter()).collect();
                let mut us = vec![];
                for q in 0..200 {
                    let ix = (q * 7919) % expected.len();
                    let t = Instant::now();
                    let tx = f.tx(ix)?;
                    let elapsed = t.elapsed().as_secs_f64() * 1e6;
                    if tx != *expected[ix] {
                        return Err("point TX mismatch".into());
                    }
                    us.push(elapsed);
                }
                us.sort_by(f64::total_cmp);
                let largest = (0..all.len())
                    .max_by_key(|&r| {
                        all[r]
                            .txs
                            .iter()
                            .map(|(t, m)| t.len() + m.len())
                            .sum::<usize>()
                            + all[r].patches.iter().map(|(_, v)| v.len()).sum::<usize>()
                    })
                    .ok_or("empty block")?;
                let mut row_ms = vec![];
                for row_id in [0, all.len() - 1, largest] {
                    let t = Instant::now();
                    let row = f.row(row_id)?;
                    row_ms.push(t.elapsed().as_secs_f64() * 1000.);
                    if row != all[row_id] {
                        return Err("prepared row mismatch".into());
                    }
                }
                row_ms.sort_by(f64::total_cmp);
                results.push(json!({"block":i,"txs":expected.len(),"prepare_ms":prepare,"all_rows_ms":decode,"prepared_heap_bytes":f.memory_bytes(),"prepared_ledger_max_ms":row_ms[2],"prepared_ledger_samples":row_ms.len(),"point_p50_us":us[99],"point_p99_us":us[197],"point_max_us":us[199]}));
            }
            println!(
                "{}",
                json!({"archive":a[2],"blocks":results,"exact":true,"point_timing":"prepared block; TX plus metadata; full-block validation outside query timer; OS cache uncontrolled"})
            );
        }
        _ => {
            return Err("variants input.rows outdir block_size [modes] | fastbench archive".into());
        }
    };
    Ok(())
}
