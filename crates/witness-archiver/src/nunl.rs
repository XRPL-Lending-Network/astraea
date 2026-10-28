//! Negative UNL per flag ledger.
//!
//! The list of validators disabled by the network changes only in flag
//! ledgers (every 256). On each new flag ledger the archiver asks its node
//! for the NegativeUNL object in binary form and writes the response as a
//! line in `negative_unl/observations.jsonl`, as is, including "object not
//! found": an empty list is evidence too.
//!
//! For now this is on the node's word: proving that the object is in the
//! state tree of the confirmed ledger is the job of inclusion proofs.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use witness_core::negative_unl::INDEX;

/// The Negative UNL request id is a string containing the flag ledger. A
/// number does not work: the xrpld JSON parser rejects integers wider than
/// 32 bits and answers `jsonInvalid` without the request id (checked on
/// 2026-10-24). A string is returned as is, and it cannot be confused with
/// the numeric manifest request ids.
const ID_PREFIX: &str = "nunl:";

/// Ask not right away, but once the flag ledger is surely validated.
const SETTLE: u32 = 4;

#[derive(Debug)]
pub struct Watch {
    path: PathBuf,
    last_flag: Option<u32>,
}

impl Watch {
    pub fn open(data_dir: &Path) -> std::io::Result<Watch> {
        let dir = data_dir.join("negative_unl");
        fs::create_dir_all(&dir)?;
        Ok(Watch {
            path: dir.join("observations.jsonl"),
            last_flag: None,
        })
    }

    /// A request for the last validated flag ledger, if this process has not
    /// asked about it yet.
    pub fn request_for(&mut self, network_ledger: u32) -> Option<String> {
        let flag = network_ledger.checked_sub(SETTLE)? / 256 * 256;
        if flag == 0 || self.last_flag == Some(flag) {
            return None;
        }
        self.last_flag = Some(flag);
        Some(
            json!({"id": format!("{ID_PREFIX}{flag}"), "command": "ledger_entry",
                   "index": INDEX, "ledger_index": flag, "binary": true})
            .to_string(),
        )
    }

    fn flag_of(v: &Value) -> Option<u64> {
        v.get("id")?.as_str()?.strip_prefix(ID_PREFIX)?.parse().ok()
    }

    pub fn is_ours(v: &Value) -> bool {
        v.get("type").and_then(Value::as_str) == Some("response") && Self::flag_of(v).is_some()
    }

    /// Writes the node's response. Returns the flag ledger and the outcome: the
    /// object size (0 means no object) or a node error of another kind.
    pub fn absorb(
        &mut self,
        v: &Value,
        at_ms: u64,
    ) -> std::io::Result<(u64, Result<usize, String>)> {
        let flag = Self::flag_of(v).unwrap_or(0);
        let result = v.get("result").cloned().unwrap_or(Value::Null);
        let node_binary = result.get("node_binary").and_then(Value::as_str);
        // In a WebSocket error response the fields are at the top level, not in result.
        let field = |k: &str| result.get(k).or_else(|| v.get(k)).cloned();
        let error = field("error");
        let line = json!({
            "at_ms": at_ms,
            "flag_ledger": flag,
            "ledger_index": field("ledger_index"),
            "ledger_hash": field("ledger_hash"),
            "validated": field("validated"),
            "status": v.get("status"),
            "error": error,
            "node_binary": node_binary,
        });
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(format!("{line}\n").as_bytes())?;
        f.sync_data()?;
        let outcome = match (node_binary, error.as_ref().and_then(Value::as_str)) {
            (Some(b), _) => Ok(b.len() / 2),
            (None, Some("entryNotFound")) => Ok(0),
            (None, e) => Err(e.unwrap_or("response without an object").to_owned()),
        };
        Ok((flag, outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asks_once_per_flag_ledger_after_it_settles() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Watch::open(dir.path()).unwrap();
        // 107,854,848 is a flag ledger; 3 ledgers later it is still too early to count it.
        assert!(w.request_for(107_854_851).unwrap().contains("107854592"));
        assert!(w.request_for(107_854_852).unwrap().contains("107854848"));
        assert!(w.request_for(107_854_900).is_none());
        assert!(w.request_for(107_855_108).unwrap().contains("107855104"));
    }

    #[test]
    fn empty_answer_is_recorded_too() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Watch::open(dir.path()).unwrap();
        let v = json!({"id": "nunl:107854848", "type": "response", "status": "error",
                       "error": "entryNotFound", "result": {"ledger_index": 107_854_848}});
        assert!(Watch::is_ours(&v));
        assert_eq!(w.absorb(&v, 1).unwrap(), (107_854_848, Ok(0)));
        let lost = json!({"id": "nunl:21767168", "type": "response", "status": "error",
                          "error": "lgrNotFound"});
        assert_eq!(
            w.absorb(&lost, 2).unwrap(),
            (21_767_168, Err("lgrNotFound".into()))
        );
        let log = fs::read_to_string(dir.path().join("negative_unl/observations.jsonl")).unwrap();
        assert!(log.contains("entryNotFound"));
        assert!(!Watch::is_ours(&json!({"id": 1000, "type": "response"})));
    }
}
