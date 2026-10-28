use astraea_journal_codec::*;
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};
fn er(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn hash(b: &[u8]) -> String {
    hex::encode(witness_core::sha512_half(b))
}
fn quantile(v: &mut [f64]) -> Value {
    v.sort_by(f64::total_cmp);
    let n = v.len();
    json!({"n":n,"p50_ms":v[(n-1)/2],"p99_ms":v[((n as f64*0.99).ceil()as usize)-1],"max_ms":v[n-1]})
}
fn hx<const N: usize>(v: &Value) -> Result<[u8; N], String> {
    hex::decode(v.as_str().ok_or("hex string")?)
        .map_err(er)?
        .try_into()
        .map_err(|_| "hex size".into())
}
fn tx_record(t: &(Vec<u8>, Vec<u8>)) -> Value {
    json!({"hash":hex::encode(witness_core::shamap::tx_id(&t.0)),"metadata":hash(&t.1)})
}
fn main() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("prepare") if a.len() == 4 => {
            let input = fs::read(&a[2]).map_err(er)?;
            let rows = load_rows(&input)?;
            verify(&rows)?;
            let ix = indexed::Indexes::build(&rows)?;
            let txs: Vec<_> = rows.iter().flat_map(|r| r.txs.iter()).collect();
            for (i, t) in txs.iter().enumerate() {
                let h = witness_core::shamap::tx_id(&t.0);
                let found = ix
                    .tx_candidates(&h)?
                    .into_iter()
                    .find(|&j| witness_core::shamap::tx_id(&txs[j].0) == h);
                if found != Some(i) {
                    return Err("all-index-entry check".into());
                }
            }
            let tx = (0..64)
                .map(|i| tx_record(txs[(i * 7919) % txs.len()]))
                .collect::<Vec<_>>();
            let mut ids: Vec<_> = (0..rows.len()).collect();
            ids.sort_by_key(|&i| std::cmp::Reverse(rows[i].txs.len() + rows[i].patches.len()));
            ids.truncate(12);
            ids.extend((0..12).map(|i| i * (rows.len() - 1) / 11));
            ids.sort_unstable();
            ids.dedup();
            let ledgers = ids
                .iter()
                .map(|&i| json!({"seq":rows[i].seq,"hash":hash(&rows_bytes(&rows[i..i+1]))}))
                .collect::<Vec<_>>();
            let last = rows.last().unwrap().seq;
            let mut accounts = vec![];
            for acc in ix.account_keys() {
                let p = ix.account_page(acc, last, None, 1000000)?;
                accounts.push((p.len(), *acc));
            }
            accounts.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            accounts.truncate(10);
            let mut pages = vec![];
            for (_, acc) in accounts {
                let mut before = None;
                for _ in 0..2 {
                    let page = ix.account_page(&acc, last, before, 200)?;
                    if page.is_empty() {
                        break;
                    }
                    let expected = page
                        .iter()
                        .map(|(rank, storage)| json!({"rank":rank,"tx":tx_record(txs[*storage])}))
                        .collect::<Vec<_>>();
                    pages.push(json!({"account":hex::encode(acc),"before":before,"last":last,"expected":expected}));
                    before = page.last().map(|x| x.0);
                }
            }
            let fixture = json!({"source_sha512half":hash(&input),"all_tx_index_entries_checked":txs.len(),"tx":tx,"ledgers":ledgers,"pages":pages});
            fs::write(&a[3], serde_json::to_vec_pretty(&fixture).map_err(er)?).map_err(er)?;
            println!(
                "{}",
                json!({"fixture":a[3],"all_tx_index_entries_checked":txs.len(),"tx_queries":tx.len(),"ledger_queries":ledgers.len(),"account_pages":pages.len()})
            );
        }
        Some("probe") if a.len() == 4 => {
            let dir = Path::new(&a[2]);
            let fixture: Value =
                serde_json::from_slice(&fs::read(&a[3]).map_err(er)?).map_err(er)?;
            let m: Value =
                serde_json::from_slice(&fs::read(dir.join("manifest.json")).map_err(er)?)
                    .map_err(er)?;
            let t = Instant::now();
            if hash(&fs::read(dir.join("payload.astj")).map_err(er)?) != m["archive_sha512half"]
                || hash(&fs::read(dir.join("index.asix")).map_err(er)?) != m["index_sha512half"]
                || m["source_sha512half"] != fixture["source_sha512half"]
            {
                return Err("manifest binding".into());
            }
            let bind_ms = t.elapsed().as_secs_f64() * 1000.;
            let mut r = dense::Reader::open(dir.join("payload.astj"), dir.join("index.asix"))?;
            let (mut cold, mut warm, mut lc, mut lw, mut ac, mut aw) =
                (vec![], vec![], vec![], vec![], vec![], vec![]);
            let mut page_loads = vec![];
            let mut heap = 0;
            for q in fixture["tx"].as_array().ok_or("tx queries")? {
                let h = hx::<32>(&q["hash"])?;
                r.clear_cache();
                let t = Instant::now();
                let value = r.tx(&h)?.ok_or("TX missing")?;
                cold.push(t.elapsed().as_secs_f64() * 1000.);
                if tx_record(&value) != *q {
                    return Err("TX bytes mismatch".into());
                }
                heap = heap.max(r.heap_bytes());
                let t = Instant::now();
                let value = r.tx(&h)?.ok_or("TX missing")?;
                warm.push(t.elapsed().as_secs_f64() * 1000.);
                if tx_record(&value) != *q {
                    return Err("warm TX mismatch".into());
                }
            }
            for q in fixture["ledgers"].as_array().ok_or("ledger queries")? {
                let seq = q["seq"].as_u64().ok_or("seq")? as u32;
                r.clear_cache();
                let t = Instant::now();
                let row = r.ledger(seq)?;
                lc.push(t.elapsed().as_secs_f64() * 1000.);
                if hash(&rows_bytes(&[row])) != q["hash"] {
                    return Err("ledger mismatch".into());
                }
                heap = heap.max(r.heap_bytes());
                let t = Instant::now();
                let row = r.ledger(seq)?;
                lw.push(t.elapsed().as_secs_f64() * 1000.);
                if hash(&rows_bytes(&[row])) != q["hash"] {
                    return Err("warm ledger mismatch".into());
                }
            }
            for q in fixture["pages"].as_array().ok_or("pages")? {
                let acc = hx::<20>(&q["account"])?;
                let before = q["before"].as_u64();
                let last = q["last"].as_u64().ok_or("last")? as u32;
                r.clear_cache();
                for repeat in 0..2 {
                    let loads = r.block_loads;
                    let t = Instant::now();
                    let positions = r.index.account_page(&acc, last, before, 200)?;
                    let mut values = vec![];
                    for (rank, p) in positions {
                        values.push((rank, r.tx_storage(p)?));
                    }
                    let elapsed = t.elapsed().as_secs_f64() * 1000.;
                    if repeat == 0 {
                        ac.push(elapsed);
                        page_loads.push(r.block_loads - loads);
                    } else {
                        aw.push(elapsed);
                    }
                    let got = values
                        .iter()
                        .map(|(rank, tx)| json!({"rank":rank,"tx":tx_record(tx)}))
                        .collect::<Vec<_>>();
                    if Value::Array(got) != q["expected"] {
                        return Err("account page mismatch".into());
                    }
                    heap = heap.max(r.heap_bytes());
                }
            }
            r.clear_cache();
            let loads = r.block_loads;
            let mut negative_ms = vec![];
            for i in 0..10000u32 {
                let mut b = b"joint-negative-test".to_vec();
                b.extend(i.to_le_bytes());
                let h = witness_core::sha512_half(&b);
                let t = Instant::now();
                if r.tx(&h)?.is_some() {
                    return Err("negative hash found".into());
                }
                negative_ms.push(t.elapsed().as_secs_f64() * 1000.);
            }
            println!(
                "{}",
                json!({"directory":a[2],"manifest_binding_ms":bind_ms,"cold_tx":quantile(&mut cold),"prepared_tx":quantile(&mut warm),"cold_ledger":quantile(&mut lc),"prepared_ledger":quantile(&mut lw),"cold_account_page":quantile(&mut ac),"repeat_account_page":quantile(&mut aw),"account_page_block_loads":page_loads,"negative_queries":quantile(&mut negative_ms),"negative_candidate_block_loads":r.block_loads-loads,"max_estimated_heap_bytes":heap,"exact":true,"cold_cache":"one application block cache cleared per query; OS cache uncontrolled","query_includes":"ASIX2 lookup, candidate decode and full TX hash check; cold block raw hash and TX roots; account returns TX plus metadata","excludes":"API/network serialization, global history router"})
            );
        }
        _ => return Err(
            "querybench prepare source.rows fixture.json | probe archive_directory fixture.json"
                .into(),
        ),
    }
    Ok(())
}
