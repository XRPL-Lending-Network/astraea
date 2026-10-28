//! Local single-window store. JSON-lines mode keeps verified metadata/indexes resident.
use astraea_journal_codec::{fast, indexed, seek, *};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use witness_core::{ledger::LedgerHeader, sha512_half, shamap};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn read(p: impl AsRef<Path>) -> Result<Vec<u8>> {
    fs::read(p).map_err(err)
}
fn write_new(p: impl AsRef<Path>, b: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .map_err(err)?;
    f.write_all(b).map_err(err)
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or_else(|| format!("missing {key}"))
}
fn hexval<const N: usize>(s: &str) -> Result<[u8; N]> {
    hex::decode(s)
        .map_err(err)?
        .try_into()
        .map_err(|_| format!("expected {N} bytes in hex"))
}
fn named(base: &Path, name: &str) -> Result<PathBuf> {
    if Path::new(name).components().count() != 1 || Path::new(name).file_name().is_none() {
        return Err("manifest paths must be plain filenames".into());
    }
    Ok(base.join(name))
}
fn manifest(ap: &Path, ip: &Path, input: &[u8]) -> Result<Value> {
    let rows = load_rows(input)?;
    verify(&rows)?;
    let mut reader = seek::Reader::open(ap)?;
    let back = reader.all_rows()?;
    if rows_bytes(&back) != input {
        return Err("archive does not reproduce source".into());
    }
    verify(&back)?;
    let ib = read(ip)?;
    let _ = indexed::Indexes::decode(&ib)?;
    if indexed::Indexes::build(&back)?.encode() != ib {
        return Err("index does not match archive".into());
    }
    let ab = read(ap)?;
    Ok(
        json!({"format":"ASTORE1","payload_format":String::from_utf8_lossy(&ab[..5]),"explicit_change_kinds":false,"archive":ap.file_name().ok_or("archive name")?.to_string_lossy(),
        "index":ip.file_name().ok_or("index name")?.to_string_lossy(),
        "archive_sha512half":hex::encode(sha512_half(&ab)),"index_sha512half":hex::encode(sha512_half(&ib)),
        "source_sha512half":hex::encode(sha512_half(input)),"source_bytes":input.len(),
        "archive_bytes":ab.len(),"index_bytes":ib.len(),"first_ledger":rows.first().ok_or("empty")?.seq,
        "last_ledger":rows.last().ok_or("empty")?.seq,"ledgers":rows.len(),
        "txs":rows.iter().map(|r|r.txs.len()).sum::<usize>(),"patches":rows.iter().map(|r|r.patches.len()).sum::<usize>(),
        "initial_state_snapshot":false,"external_trust_anchor":false,"state_root_replay":false}),
    )
}
struct Store {
    reader: seek::Reader,
    indexes: indexed::Indexes,
    manifest: Value,
    first: u32,
    last: u32,
}
impl Store {
    fn open(path: &Path) -> Result<Self> {
        let m: Value = serde_json::from_slice(&read(path)?).map_err(err)?;
        if m["format"] != "ASTORE1" {
            return Err("manifest format".into());
        }
        let base = path.parent().ok_or("manifest directory")?;
        let ap = named(base, field(&m, "archive")?)?;
        let ip = named(base, field(&m, "index")?)?;
        let ab = read(&ap)?;
        let ib = read(&ip)?;
        if hex::encode(sha512_half(&ab)) != field(&m, "archive_sha512half")?
            || hex::encode(sha512_half(&ib)) != field(&m, "index_sha512half")?
        {
            return Err("archive/index manifest mismatch".into());
        }
        drop(ab);
        let indexes = indexed::Indexes::decode(&ib)?;
        let reader = seek::Reader::open(ap)?;
        let (first, last) = reader.coverage()?;
        if m["first_ledger"].as_u64() != Some(first.into())
            || m["last_ledger"].as_u64() != Some(last.into())
        {
            return Err("manifest coverage mismatch".into());
        }
        Ok(Self {
            reader,
            indexes,
            manifest: m,
            first,
            last,
        })
    }
    fn ledger(&self, q: &Value) -> Result<u32> {
        let n = q["ledger"].as_u64().unwrap_or(self.last as u64);
        let n = u32::try_from(n).map_err(err)?;
        if n < self.first || n > self.last {
            return Err(format!(
                "outside covered window {}..{}",
                self.first, self.last
            ));
        }
        Ok(n)
    }
    fn query(&mut self, q: &Value) -> Result<Value> {
        if q["clear_data_cache"].as_bool() == Some(true) {
            self.reader.clear_data_cache();
        }
        let start = Instant::now();
        let before = self.reader.bytes_read;
        let mut v = match field(q, "op")? {
            "tx" | "proof_tx" => {
                let hash = hexval::<32>(field(q, "hash")?)?;
                let mut result = json!({"status":"not_found_in_window"});
                for i in self.indexes.tx_candidates(&hash)? {
                    let (tx, meta) = self.reader.tx(i)?;
                    if shamap::tx_id(&tx) == hash {
                        result = json!({"status":"found","ledger":self.indexes.tx_ledger(i)?,"tx":hex::encode(tx),"meta":hex::encode(meta)});
                        if q["op"] == "proof_tx" {
                            let p = self.reader.proof_tx(i)?;
                            result["header"] = json!(hex::encode(p.header));
                            result["proof_levels"] = json!(
                                p.path
                                    .levels
                                    .iter()
                                    .map(|l| l.iter().map(hex::encode).collect::<Vec<_>>())
                                    .collect::<Vec<_>>()
                            );
                            result["verified_against_stored_header"] = json!(true);
                        }
                        break;
                    }
                }
                result
            }
            "account" => {
                let account = hexval::<20>(field(q, "account_hex")?)?;
                let at = self.ledger(q)?;
                let before = q["before_rank"].as_u64();
                let limit = q["limit"].as_u64().unwrap_or(200).min(200) as usize;
                let page = self.indexes.account_page(&account, at, before, limit)?;
                let mut txs = vec![];
                for &(rank, i) in &page {
                    let (tx, meta) = self.reader.tx(i)?;
                    txs.push(json!({"rank":rank,"ledger":self.indexes.tx_ledger(i)?,"hash":hex::encode(shamap::tx_id(&tx)),"tx":hex::encode(tx),"meta":hex::encode(meta)}));
                }
                json!({"status":"window_history","order":"ledger_then_TransactionIndex_desc","items":txs,"next_before_rank":page.last().map(|x|x.0)})
            }
            "object" => {
                let key = hexval::<32>(field(q, "key")?)?;
                let at = self.ledger(q)?;
                let mut result = json!({"status":"unknown_initial_state","at_ledger":at});
                for i in self.indexes.object_candidates(&key, at)? {
                    let (back, value) = self.reader.patch(i)?;
                    if back == key {
                        result = json!({"status":if value.is_empty(){"deleted"}else{"found"},"at_ledger":at,"changed_at_ledger":self.indexes.patch_ledger(i)?,"value":hex::encode(value)});
                        break;
                    }
                }
                result
            }
            "ledger" => {
                let hash = hexval::<32>(field(q, "hash")?)?;
                let mut result = json!({"status":"not_found_in_window"});
                for i in self.indexes.ledger_candidates(&hash) {
                    let row = self.reader.row(i)?;
                    if LedgerHeader::parse(&row.header).map_err(err)?.hash() == hash {
                        verify(std::slice::from_ref(&row))?;
                        result = json!({"status":"found","ledger":row.seq,"tx_root_verified":true,"rows_hex":hex::encode(rows_bytes(&[row]))});
                        break;
                    }
                }
                result
            }
            _ => return Err("op must be tx, proof_tx, account, object or ledger".into()),
        };
        v["covered_window"] = json!([self.first, self.last]);
        v["elapsed_ms"] = json!(start.elapsed().as_secs_f64() * 1000.);
        v["compressed_bytes_read"] = json!(self.reader.bytes_read - before);
        Ok(v)
    }
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let usage = "astore build input.rows NEW_DIR [pool_bytes docs_per_chunk] | seal archive index source.rows NEW_manifest.json | verify manifest | unpack manifest NEW_output.rows | query manifest JSON | serve manifest";
    match a.get(1).map(String::as_str) {
        Some("build") if a.len() == 4 || a.len() == 6 => {
            let input = read(&a[2])?;
            let rows = load_rows(&input)?;
            verify(&rows)?;
            let pc = a
                .get(4)
                .map(|s| s.parse::<usize>().map_err(err))
                .transpose()?
                .unwrap_or(4096);
            let dc = a
                .get(5)
                .map(|s| s.parse::<usize>().map_err(err))
                .transpose()?
                .unwrap_or(512);
            let (frame, _) = encode_block(
                &rows,
                Options {
                    split_shapes: true,
                    context_delta: true,
                    ..Options::default()
                },
            )?;
            let prepared = fast::Prepared::parse(&frame)?;
            let archive = seek::pack(&prepared, pc, dc)?;
            let index = indexed::Indexes::build(&rows)?.encode();
            let base = Path::new(&a[3]);
            fs::create_dir(base).map_err(err)?;
            let ap = base.join("payload.asts");
            let ip = base.join("indexes.asix");
            write_new(&ap, &archive)?;
            write_new(&ip, &index)?;
            let m = manifest(&ap, &ip, &input)?;
            write_new(
                base.join("manifest.json"),
                &serde_json::to_vec_pretty(&m).map_err(err)?,
            )?;
            println!("{m}");
        }
        Some("seal") if a.len() == 6 => {
            let ap = Path::new(&a[2]);
            let ip = Path::new(&a[3]);
            let mp = Path::new(&a[5]);
            if ap.parent() != ip.parent() || ap.parent() != mp.parent() {
                return Err("seal files must share directory".into());
            }
            let m = manifest(ap, ip, &read(&a[4])?)?;
            write_new(mp, &serde_json::to_vec_pretty(&m).map_err(err)?)?;
            println!("{m}");
        }
        Some("verify" | "unpack") if a.len() == 3 || a.len() == 4 => {
            if (a[1] == "unpack") != (a.len() == 4) {
                return Err(usage.into());
            }
            let mut store = Store::open(Path::new(&a[2]))?;
            let rows = store.reader.all_rows()?;
            verify(&rows)?;
            let raw = rows_bytes(&rows);
            if hex::encode(sha512_half(&raw)) != field(&store.manifest, "source_sha512half")? {
                return Err("restored source hash mismatch".into());
            }
            if indexed::Indexes::build(&rows)?.encode()
                != read(named(
                    Path::new(&a[2]).parent().ok_or("parent")?,
                    field(&store.manifest, "index")?,
                )?)?
            {
                return Err("index mismatch".into());
            }
            if a.len() == 4 {
                write_new(&a[3], &raw)?;
            }
            println!(
                "{}",
                json!({"verified":true,"raw_bytes":raw.len(),"ledgers":rows.len(),"state_root_replay":false,"source_sha512half":hex::encode(sha512_half(&raw))})
            );
        }
        Some("query") if a.len() == 4 => {
            let t = Instant::now();
            let mut store = Store::open(Path::new(&a[2]))?;
            let open_ms = t.elapsed().as_secs_f64() * 1000.;
            let mut v = store.query(&serde_json::from_str(&a[3]).map_err(err)?)?;
            v["manifest_checked_open_ms"] = json!(open_ms);
            println!("{v}");
        }
        Some("serve") if a.len() == 3 => {
            let t = Instant::now();
            let mut store = Store::open(Path::new(&a[2]))?;
            eprintln!(
                "{}",
                json!({"ready":true,"manifest_checked_open_ms":t.elapsed().as_secs_f64()*1000.,"covered_window":[store.first,store.last]})
            );
            for line in io::stdin().lock().lines() {
                let result = line
                    .map_err(err)
                    .and_then(|s| serde_json::from_str(&s).map_err(err))
                    .and_then(|q| store.query(&q));
                match result {
                    Ok(v) => println!("{v}"),
                    Err(e) => println!("{}", json!({"error":e})),
                }
                io::stdout().flush().map_err(err)?;
            }
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}
