use astraea_journal_codec::indexed::Indexes;
use serde_json::json;
fn main() -> Result<(), String> {
    for path in std::env::args().skip(1) {
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        let index = Indexes::decode(&bytes)?;
        let details = index.component_detail_bytes();
        if details.values().sum::<usize>() != bytes.len() {
            return Err("index component sum".into());
        }
        println!(
            "{}",
            json!({"path":path,"bytes":bytes.len(),"components":details,"sum_verified":true})
        );
    }
    Ok(())
}
