//! End-to-end CLI checks against independent source bytes; no persistent data changes.
use astraea_journal_codec::*;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
use witness_core::{ledger::LedgerHeader, shamap};
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn main() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 3 {
        return Err("storecheck manifest source.rows".into());
    }
    let rows = load_rows(&fs::read(&a[2]).map_err(err)?)?;
    verify(&rows)?;
    let first = rows
        .iter()
        .find(|r| !r.txs.is_empty())
        .ok_or("empty TX corpus")?;
    let (tx, meta) = &first.txs[0];
    let hash = shamap::tx_id(tx);
    let last = rows.last().ok_or("empty")?.seq;
    let index = indexed::Indexes::build(&rows)?;
    let account = *index.account_keys().first().ok_or("no accounts")?;
    let page = index.account_page(&account, last, None, 5)?;
    let before = page.last().map(|x| x.0).ok_or("empty page")?;
    let second = index.account_page(&account, last, Some(before), 5)?;
    let originals: Vec<_> = rows.iter().flat_map(|r| r.txs.iter()).collect();
    let mut latest = std::collections::BTreeMap::new();
    for row in &rows {
        for (key, value) in &row.patches {
            latest.insert(*key, (row.seq, value));
        }
    }
    let key = *latest.keys().next().ok_or("no patches")?;
    let mut unknown = [0; 32];
    while latest.contains_key(&unknown) {
        unknown[31] += 1;
    }
    // Validate every object-version boundary against the persisted index, not only three snapshots.
    let manifest_value: Value =
        serde_json::from_slice(&fs::read(&a[1]).map_err(err)?).map_err(err)?;
    let saved_path = Path::new(&a[1])
        .parent()
        .ok_or("parent")?
        .join(manifest_value["index"].as_str().ok_or("index")?);
    let saved_bytes = fs::read(saved_path).map_err(err)?;
    if saved_bytes != index.encode() {
        return Err("saved index differs from source rebuild".into());
    }
    let saved = indexed::Indexes::decode(&saved_bytes)?;
    let mut histories = std::collections::BTreeMap::<[u8; 32], Vec<(u32, usize)>>::new();
    let patches: Vec<_> = rows.iter().flat_map(|r| r.patches.iter()).collect();
    let mut ordinal = 0;
    for row in &rows {
        for (k, _) in &row.patches {
            histories.entry(*k).or_default().push((row.seq, ordinal));
            ordinal += 1;
        }
    }
    let mut object_boundary_checks = 0;
    for (key, list) in &histories {
        for (at, _) in list {
            for target in [at.saturating_sub(1), *at] {
                let expected = list
                    .partition_point(|(seq, _)| *seq <= target)
                    .checked_sub(1)
                    .map(|i| list[i].1);
                let found = saved
                    .object_candidates(key, target)?
                    .into_iter()
                    .find(|i| patches[*i].0 == *key);
                if found != expected {
                    return Err("persisted object boundary mismatch".into());
                }
                object_boundary_checks += 1;
            }
        }
    }
    let mut requests = vec![
        json!({"op":"tx","hash":hex::encode(hash),"clear_data_cache":true}),
        json!({"op":"proof_tx","hash":hex::encode(hash),"clear_data_cache":true}),
        json!({"op":"account","account_hex":hex::encode(account),"limit":5,"ledger":last}),
        json!({"op":"account","account_hex":hex::encode(account),"limit":5,"ledger":last,"before_rank":before}),
        json!({"op":"object","key":hex::encode(key),"ledger":last}),
        json!({"op":"object","key":hex::encode(unknown),"ledger":last}),
        json!({"op":"object","key":hex::encode(key),"ledger":last+1}),
        json!({"op":"tx","hash":"bad"}),
        json!({"op":"ledger","hash":hex::encode(LedgerHeader::parse(&first.header).map_err(err)?.hash())}),
        json!({"op":"tx","hash":hex::encode([0;32])}),
    ];
    let deleted = latest
        .iter()
        .find(|(_, (_, v))| v.is_empty())
        .map(|(k, _)| *k);
    if let Some(k) = deleted {
        requests.push(json!({"op":"object","key":hex::encode(k),"ledger":last}));
    }
    let binary = std::env::current_exe()
        .map_err(err)?
        .with_file_name("astore");
    let mut child = Command::new(&binary)
        .args(["serve", &a[1]])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(err)?;
    {
        let mut stdin = child.stdin.take().ok_or("stdin")?;
        for request in &requests {
            writeln!(stdin, "{request}").map_err(err)?;
        }
    }
    let out = child.wait_with_output().map_err(err)?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into());
    }
    let answers: Vec<Value> = String::from_utf8(out.stdout)
        .map_err(err)?
        .lines()
        .map(|s| serde_json::from_str(s).map_err(err))
        .collect::<Result<_, _>>()?;
    if answers.len() != requests.len() {
        return Err("response count".into());
    }
    for v in &answers[..2] {
        if v["tx"] != hex::encode(tx) || v["meta"] != hex::encode(meta) {
            return Err("CLI TX bytes".into());
        }
    }
    let p = &answers[1];
    let mut levels = vec![];
    for level in p["proof_levels"].as_array().ok_or("proof levels")? {
        let mut hashes = [[0; 32]; 16];
        for (i, h) in level.as_array().ok_or("level")?.iter().enumerate() {
            hashes[i] = hex::decode(h.as_str().ok_or("hash")?)
                .map_err(err)?
                .try_into()
                .map_err(|_| "width")?;
        }
        levels.push(hashes);
    }
    let h = LedgerHeader::parse(&first.header).map_err(err)?;
    if p["header"] != hex::encode(&first.header)
        || !shamap::verify(
            &shamap::Path { levels },
            &hash,
            &shamap::tx_leaf_hash(tx, meta, &hash),
            &h.transaction_hash,
        )
    {
        return Err("external proof verification".into());
    }
    for (v, page) in [(&answers[2], page), (&answers[3], second)] {
        let items = v["items"].as_array().ok_or("account items")?;
        if items.len() != page.len() {
            return Err("page size".into());
        }
        for (item, (rank, i)) in items.iter().zip(page) {
            if item["rank"] != rank
                || item["tx"] != hex::encode(&originals[i].0)
                || item["meta"] != hex::encode(&originals[i].1)
            {
                return Err("page bytes/order".into());
            }
        }
    }
    if answers[4]["value"] != hex::encode(latest[&key].1)
        || answers[4]["changed_at_ledger"] != latest[&key].0
    {
        return Err("object source bytes".into());
    }
    if answers[5]["status"] != "unknown_initial_state"
        || answers[6]["error"].is_null()
        || answers[7]["error"].is_null()
    {
        return Err("coverage or malformed input".into());
    }
    if answers[8]["rows_hex"] != hex::encode(rows_bytes(std::slice::from_ref(first)))
        || answers[9]["status"] != "not_found_in_window"
    {
        return Err("ledger or negative TX".into());
    }
    if deleted.is_some() && answers[10]["status"] != "deleted" {
        return Err("tombstone status".into());
    }
    let mp = Path::new(&a[1]);
    let mut bad: Value = serde_json::from_slice(&fs::read(mp).map_err(err)?).map_err(err)?;
    bad["index_sha512half"] = json!(hex::encode([0; 32]));
    let bp = mp.with_file_name(format!("bad-manifest-{}.json", std::process::id()));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&bp)
            .map_err(err)?;
        f.write_all(&serde_json::to_vec(&bad).map_err(err)?)
            .map_err(err)?;
    }
    let rejected = Command::new(binary)
        .args([
            "query",
            bp.to_str().ok_or("path")?,
            "{\"op\":\"tx\",\"hash\":\"00\"}",
        ])
        .output()
        .map_err(err)?;
    fs::remove_file(bp).map_err(err)?;
    if rejected.status.success() {
        return Err("changed manifest accepted".into());
    }
    println!(
        "{}",
        json!({"manifest":a[1],"source":a[2],"queries":answers.len(),"all_exact":true,"persisted_object_boundary_checks":object_boundary_checks,"proof_verified_from_cli_response":true,"manifest_mismatch_rejected":true,"tombstone_checked":deleted.is_some(),"ready":serde_json::from_slice::<Value>(&out.stderr).map_err(err)?})
    );
    Ok(())
}
