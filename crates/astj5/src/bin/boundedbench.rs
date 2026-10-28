use astraea_journal_codec::*;
use serde_json::json;
use std::{fs, io::Read, time::Instant};
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn q(v: &mut [f64]) -> serde_json::Value {
    v.sort_by(f64::total_cmp);
    json!({"n":v.len(),"p50_ms":v[(v.len()-1)/2],"p99_ms":v[((v.len()as f64*0.99).ceil()as usize)-1],"max_ms":v[v.len()-1]})
}
fn main() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("encode") if a.len() == 4 || a.len() == 5 => {
            let max_mib = if a.len() == 5 {
                a[4].parse::<usize>().map_err(err)?
            } else {
                64
            };
            let max_raw = max_mib.checked_mul(1 << 20).ok_or("raw limit overflow")?;
            let input = fs::read(&a[2]).map_err(err)?;
            let rows = load_rows(&input)?;
            let t = Instant::now();
            let (archive, _) = pack_bounded(
                &rows,
                1024,
                max_raw,
                Options {
                    split_shapes: true,
                    context_delta: true,
                    ..Options::default()
                },
            )?;
            let encode_ms = t.elapsed().as_secs_f64() * 1000.;
            let restored = unpack(&archive)?;
            if rows_bytes(&restored) != input {
                return Err("bounded roundtrip".into());
            }
            let n = u32::from_le_bytes(archive[8..12].try_into().unwrap()) as usize;
            let mut at = 0;
            let mut blocks = vec![];
            for i in 0..n {
                let p = 12 + i * 56;
                let count = u32::from_le_bytes(archive[p + 4..p + 8].try_into().unwrap()) as usize;
                let size = rows_bytes(&rows[at..at + count]).len();
                if size > max_raw || count > 1024 {
                    return Err("bounded extent".into());
                }
                blocks.push(json!({"first":rows[at].seq,"last":rows[at+count-1].seq,"ledgers":count,"raw_bytes":size}));
                at += count;
            }
            if at != rows.len() {
                return Err("bounded coverage".into());
            }
            fs::write(&a[3], &archive).map_err(err)?;
            let txs = rows.iter().map(|r| r.txs.len()).sum::<usize>();
            println!(
                "{}",
                json!({"archive":a[3],"bytes":archive.len(),"txs":txs,"max_raw_mib":max_mib,"payload_bpt":archive.len()as f64/txs as f64,"blocks":blocks,"encode_ms":encode_ms,"exact":true,"tx_roots":true,"source_sha512half":hex::encode(witness_core::sha512_half(&input))})
            );
        }
        Some("read") if a.len() == 4 => {
            let index = indexed::Indexes::decode(&fs::read(&a[3]).map_err(err)?)?;
            let mut file = fs::File::open(&a[2]).map_err(err)?;
            let mut head = [0u8; 12];
            file.read_exact(&mut head).map_err(err)?;
            let n = u32::from_le_bytes(head[8..].try_into().unwrap()) as usize;
            let mut targets = vec![];
            for _ in 0..n {
                let mut e = [0u8; 56];
                file.read_exact(&mut e).map_err(err)?;
                let first = u32::from_le_bytes(e[..4].try_into().unwrap());
                let count = u32::from_le_bytes(e[4..8].try_into().unwrap());
                targets.extend([first, first + count / 2, first + count - 1]);
            }
            targets.sort_unstable();
            targets.dedup();
            let mut reader = ArchiveFile::open(&a[2])?;
            let mut times = vec![];
            for &seq in &targets {
                let t = Instant::now();
                let row = reader.ledger(seq)?;
                times.push(t.elapsed().as_secs_f64() * 1000.);
                if row.seq != seq {
                    return Err("ledger lookup".into());
                }
            }
            println!(
                "{}",
                json!({"archive":a[2],"cold_application_block_cache":q(&mut times),"ledgers":targets,"index_heap":index.memory_bytes(),"os_cache_uncontrolled":true,"raw_hash_and_all_block_tx_roots_in_timer":true})
            );
        }
        _ => {
            return Err(
                "boundedbench encode SOURCE.rows NEW.astj [max_raw_MiB] | read archive index"
                    .into(),
            );
        }
    }
    Ok(())
}
