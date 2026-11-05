//! Validator manifests: the link between a signing key and a master key.
//!
//! The validation stream carries only the signing key. Which validator it
//! belongs to is stated by the manifest, a record signed by the master key
//! saying "my current signing key is such-and-such". Without it a signature
//! cannot be matched to the UNL or to the validator's history. Manifests for
//! UNL validators are inside the publishers' lists, but manifests for other
//! validators are only available from nodes, so we ask the node.
//!
//! The first time it sees a signing key, the archiver sends its node a
//! `manifest` command over the same connection. The response is stored byte
//! for byte: the manifest is signed, so its authenticity can be checked later.
//! A key rotation produces a new signing key, and therefore a new request.
//!
//! Layout: `manifests/<master-key>-<seq>-<hash>.bin` for raw manifests,
//! `manifests/observations.jsonl` for every response received.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde_json::{Value, json};
use witness_core::sha512_half;

/// The node does not know every manifest: as of 2026-10-23, 38 of the 112
/// validators in the stream. The rest may reach it later, so unknown keys are
/// asked about again, but no more than once an hour.
const RETRY_MS: u64 = 3_600_000;

/// Manifest request ids start here so they are not confused with the
/// subscription (id 1).
const FIRST_ID: u64 = 1000;

#[derive(Debug)]
pub struct Book {
    dir: PathBuf,
    asked: HashSet<String>,
    /// Keys whose manifest the node did not know, and when to ask again.
    retry_at: HashMap<String, u64>,
    stored: HashSet<String>,
    next_id: u64,
    pub stored_total: u64,
}

/// Result of parsing the node's response.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// New manifest, stored.
    Stored { master_key: String, seq: u64 },
    /// Already stored.
    Known,
    /// The node does not know the manifest; usually a validator from another network.
    Unknown,
}

impl Book {
    pub fn open(data_dir: &Path) -> std::io::Result<Book> {
        let dir = data_dir.join("manifests");
        fs::create_dir_all(&dir)?;
        let mut stored = HashSet::new();
        for entry in fs::read_dir(&dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(hash) = name.strip_suffix(".bin").and_then(|n| n.rsplit('-').next()) {
                stored.insert(hash.to_owned());
            }
        }
        Ok(Book {
            dir,
            asked: HashSet::new(),
            retry_at: HashMap::new(),
            stored,
            next_id: FIRST_ID,
            stored_total: 0,
        })
    }

    /// A manifest request, if this key has not been asked about yet or it is
    /// time to ask again.
    pub fn request_for(&mut self, signing_key: &str, now_ms: u64) -> Option<String> {
        if !self.asked.insert(signing_key.to_owned()) {
            match self.retry_at.get(signing_key) {
                Some(&at) if at <= now_ms => {
                    self.retry_at.remove(signing_key);
                }
                _ => return None,
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        Some(json!({"id": id, "command": "manifest", "public_key": signing_key}).to_string())
    }

    /// A response to our manifest request, identified by the request id.
    pub fn is_ours(v: &Value) -> bool {
        v.get("type").and_then(Value::as_str) == Some("response")
            && v.get("id")
                .and_then(Value::as_u64)
                .is_some_and(|id| id >= FIRST_ID)
    }

    /// Parses and stores the node's response.
    pub fn absorb(&mut self, v: &Value, at_ms: u64) -> std::io::Result<Outcome> {
        let result = v.get("result").cloned().unwrap_or(Value::Null);
        let requested = result
            .get("requested")
            .and_then(Value::as_str)
            .unwrap_or("");
        let details = result.get("details").cloned().unwrap_or(Value::Null);
        let Some(raw) = result
            .get("manifest")
            .and_then(Value::as_str)
            .and_then(|m| base64::engine::general_purpose::STANDARD.decode(m).ok())
        else {
            if !requested.is_empty() {
                self.retry_at.insert(requested.to_owned(), at_ms + RETRY_MS);
            }
            return Ok(Outcome::Unknown);
        };
        let hash = hex::encode_upper(sha512_half(&raw));
        let short = &hash[..16];
        if self.stored.contains(short) {
            return Ok(Outcome::Known);
        }
        // The file name is taken from the node's word; the truth about the
        // master key comes from verifying the manifest signature, but this is
        // good enough for finding files by eye.
        let master_key = details
            .get("master_key")
            .and_then(Value::as_str)
            .filter(|k| k.chars().all(|c| c.is_ascii_alphanumeric()))
            .unwrap_or("unknown")
            .to_owned();
        let seq = details.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let path = self.dir.join(format!("{master_key}-{seq:010}-{short}.bin"));
        witness_core::util::write_atomic(&path, &raw)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("observations.jsonl"))?;
        let line = json!({"at_ms": at_ms, "requested": requested, "details": details,
                          "manifest_hash": hash, "file": path.file_name().map(|n| n.to_string_lossy())});
        f.write_all(format!("{line}\n").as_bytes())?;
        f.sync_data()?;
        self.stored.insert(short.to_owned());
        self.stored_total += 1;
        Ok(Outcome::Stored { master_key, seq })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(id: u64, manifest: Option<&[u8]>) -> Value {
        let mut result = json!({"requested": "n9Kkey"});
        if let Some(m) = manifest {
            result["manifest"] = json!(base64::engine::general_purpose::STANDARD.encode(m));
            result["details"] = json!({"master_key": "nHBmaster", "seq": 3, "domain": "x.org"});
        }
        json!({"id": id, "type": "response", "status": "success", "result": result})
    }

    #[test]
    fn each_key_is_asked_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = Book::open(dir.path()).unwrap();
        assert!(b.request_for("n9A", 0).is_some());
        assert!(b.request_for("n9A", 0).is_none());
        assert!(b.request_for("n9B", 0).unwrap().contains("\"id\":1001"));
    }

    #[test]
    fn unknown_keys_are_asked_again_after_an_hour() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = Book::open(dir.path()).unwrap();
        assert!(b.request_for("n9Kkey", 0).is_some());
        assert_eq!(b.absorb(&reply(1000, None), 10).unwrap(), Outcome::Unknown);
        assert!(b.request_for("n9Kkey", 10 + RETRY_MS - 1).is_none());
        assert!(b.request_for("n9Kkey", 10 + RETRY_MS).is_some());
        assert!(b.request_for("n9Kkey", 10 + RETRY_MS).is_none());
    }

    #[test]
    fn manifests_are_stored_once_and_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = Book::open(dir.path()).unwrap();
        let r = reply(1000, Some(b"raw-manifest"));
        assert!(Book::is_ours(&r));
        assert_eq!(
            b.absorb(&r, 1).unwrap(),
            Outcome::Stored {
                master_key: "nHBmaster".into(),
                seq: 3
            }
        );
        assert_eq!(b.absorb(&r, 2).unwrap(), Outcome::Known);
        let mut again = Book::open(dir.path()).unwrap();
        assert_eq!(again.absorb(&r, 3).unwrap(), Outcome::Known);
        assert_eq!(
            again.absorb(&reply(1001, None), 4).unwrap(),
            Outcome::Unknown
        );
        assert!(!Book::is_ours(&json!({"id": 1, "type": "response"})));
    }
}
