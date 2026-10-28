use astraea_journal_codec::dense;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
fn er(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn rss() -> Result<u64, String> {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .map_err(er)?;
    let s = std::str::from_utf8(&out.stdout).map_err(er)?;
    Ok(s.trim().parse::<u64>().map_err(er)? * 1024)
}
fn main() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 3 {
        return Err("memoryprobe archive_dir fixture.json".into());
    }
    let dir = Path::new(&a[1]);
    let fixture: Value = serde_json::from_slice(&fs::read(&a[2]).map_err(er)?).map_err(er)?;
    let q = &fixture["tx"][0];
    let h: [u8; 32] = hex::decode(q["hash"].as_str().ok_or("hash")?)
        .map_err(er)?
        .try_into()
        .map_err(|_| "hash size")?;
    let mut r = dense::Reader::open(dir.join("payload.astj"), dir.join("index.asix"))?;
    let mut samples = vec![];
    for n in 1..=256 {
        r.clear_cache();
        let tx = r.tx(&h)?.ok_or("TX")?;
        if hex::encode(witness_core::sha512_half(&tx.1)) != q["metadata"] {
            return Err("metadata".into());
        }
        if [1, 2, 4, 8, 16, 32, 64, 128, 256].contains(&n) {
            samples.push(json!({"misses":n,"current_rss_bytes":rss()?,"estimated_heap_bytes":r.heap_bytes()}));
        }
    }
    r.clear_cache();
    samples.push(
        json!({"after_drop":true,"current_rss_bytes":rss()?,"estimated_heap_bytes":r.heap_bytes()}),
    );
    println!(
        "{}",
        json!({"samples":samples,"exact":true,"measurement":"ps RSS outside timers; same TX, application block cache cleared each iteration"})
    );
    Ok(())
}
