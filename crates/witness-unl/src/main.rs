//! Collector of signed UNL lists.
//!
//! The quorum check needs the trust policy as of the ledger's date, but list
//! publishers (vl.ripple.com, unl.xrplf.org) only serve the current version.
//! Past versions cannot be obtained anywhere, so, as with validations, we
//! build up the list history ourselves, starting from day one.
//!
//! What it does:
//! - polls each publisher every `--interval-secs`;
//! - stores each new response byte for byte: it contains the publisher's
//!   signature and manifest, so authenticity can be checked later, without us;
//! - writes every poll, successful or not, as a line in `observations.jsonl`:
//!   when we looked, what the server answered, which list sequences were in
//!   the response. This is our evidence of *when* a list was in effect; the
//!   list itself does not say;
//! - if a publisher's list sequence jumped by more than one, the observation
//!   marks it: we never saw the intermediate versions.
//!
//! Layout: `<data-dir>/<publisher>/<sequence>-<hash>.json` for raw responses,
//! `<data-dir>/observations.jsonl` for the poll log.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use clap::Parser;
use serde_json::{Value, json};
use tracing::{error, info, warn};
use witness_core::sha512_half;

/// A publisher response is tens of kilobytes; anything over a megabyte is not a list.
const MAX_BODY: u64 = 1 << 20;

#[derive(Debug, Parser)]
#[command(version, about = "Collector of signed UNL lists")]
struct Args {
    /// Directory of the list archive.
    #[arg(long, env = "WITNESS_UNL_DIR")]
    data_dir: PathBuf,
    /// Publishers as comma-separated name=url pairs. The name is the directory in the archive.
    #[arg(
        long,
        env = "WITNESS_UNL_SITES",
        value_delimiter = ',',
        default_value = "vl.ripple.com=https://vl.ripple.com,unl.xrplf.org=https://unl.xrplf.org"
    )]
    sites: Vec<String>,
    /// Pause between polls. Lists change every few weeks or months, but we want
    /// to see a new version within the hour, not the next day.
    #[arg(long, default_value_t = 600)]
    interval_secs: u64,
    /// Make one pass and exit, for manual checks.
    #[arg(long)]
    once: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct Site {
    name: String,
    url: String,
}

fn parse_site(s: &str) -> Result<Site, String> {
    let (name, url) = s
        .split_once('=')
        .ok_or_else(|| format!("publisher \"{s}\": expected name=url"))?;
    let name = name.trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!(
            "publisher name \"{name}\" is not a valid directory name"
        ));
    }
    Ok(Site {
        name: name.to_owned(),
        url: url.trim().to_owned(),
    })
}

/// What is inside a publisher response: the key and the list sequences. The
/// parse is only for the log; the response is stored whole, not the parsed form.
#[derive(Debug, Default, PartialEq)]
struct Summary {
    version: Option<u64>,
    public_key: Option<String>,
    /// For each list in the response: sequence, expiration, effective date
    /// (the v2 format can carry lists that take effect "in the future"), and
    /// the number of validators.
    lists: Vec<ListInfo>,
}

#[derive(Debug, PartialEq)]
struct ListInfo {
    sequence: u64,
    expiration: Option<u64>,
    effective: Option<u64>,
    validators: usize,
}

fn summarize(body: &[u8]) -> Result<Summary, String> {
    let v: Value = serde_json::from_slice(body).map_err(|e| format!("json: {e}"))?;
    let mut blobs: Vec<&str> = Vec::new();
    if let Some(b) = v.get("blob").and_then(Value::as_str) {
        blobs.push(b);
    }
    if let Some(arr) = v.get("blobs_v2").and_then(Value::as_array) {
        blobs.extend(
            arr.iter()
                .filter_map(|x| x.get("blob").and_then(Value::as_str)),
        );
    }
    if blobs.is_empty() {
        return Err("response has neither blob nor blobs_v2".into());
    }
    let mut lists = Vec::new();
    for b in blobs {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b)
            .map_err(|e| format!("blob is not base64: {e}"))?;
        let l: Value =
            serde_json::from_slice(&raw).map_err(|e| format!("blob is not json: {e}"))?;
        lists.push(ListInfo {
            sequence: l
                .get("sequence")
                .and_then(Value::as_u64)
                .ok_or("list has no sequence")?,
            expiration: l.get("expiration").and_then(Value::as_u64),
            effective: l.get("effective").and_then(Value::as_u64),
            validators: l
                .get("validators")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
        });
    }
    Ok(Summary {
        version: v.get("version").and_then(Value::as_u64),
        public_key: v
            .get("public_key")
            .and_then(Value::as_str)
            .map(str::to_owned),
        lists,
    })
}

fn append_line(path: &Path, v: &Value) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(format!("{v}\n").as_bytes())?;
    f.sync_data()
}

/// State kept between polls: the last list sequence per publisher key, so
/// that skipped versions can be noticed.
#[derive(Debug, Default)]
struct Seen {
    last_sequence: HashMap<String, u64>,
}

impl Seen {
    /// Restores the last sequences from responses already stored.
    fn load(dir: &Path) -> Seen {
        let mut seen = Seen::default();
        let Ok(sites) = fs::read_dir(dir) else {
            return seen;
        };
        for site in sites.flatten() {
            let Ok(files) = fs::read_dir(site.path()) else {
                continue;
            };
            for f in files.flatten() {
                if let Ok(body) = fs::read(f.path())
                    && let Ok(s) = summarize(&body)
                {
                    seen.note(&s);
                }
            }
        }
        seen
    }

    /// Records a response; returns the skipped sequences, if any.
    fn note(&mut self, s: &Summary) -> Option<[u64; 2]> {
        let key = s.public_key.clone()?;
        let max = s.lists.iter().map(|l| l.sequence).max()?;
        let last = self.last_sequence.get(&key).copied();
        let gap = match last {
            Some(prev) if max > prev + 1 => Some([prev + 1, max - 1]),
            _ => None,
        };
        if last.is_none_or(|prev| max > prev) {
            self.last_sequence.insert(key, max);
        }
        gap
    }
}

struct Fetched {
    status: u16,
    headers: Value,
    body: Vec<u8>,
}

fn fetch(agent: &ureq::Agent, url: &str) -> Result<Fetched, String> {
    let mut resp = agent.get(url).call().map_err(|e| e.to_string())?;
    let mut headers = serde_json::Map::new();
    for name in ["date", "last-modified", "etag", "age", "cache-control"] {
        if let Some(v) = resp.headers().get(name).and_then(|v| v.to_str().ok()) {
            headers.insert(name.into(), Value::String(v.into()));
        }
    }
    let body = resp
        .body_mut()
        .with_config()
        .limit(MAX_BODY)
        .read_to_vec()
        .map_err(|e| format!("reading body: {e}"))?;
    Ok(Fetched {
        status: resp.status().as_u16(),
        headers: Value::Object(headers),
        body,
    })
}

fn poll(agent: &ureq::Agent, site: &Site, dir: &Path, seen: &mut Seen) -> std::io::Result<()> {
    let at_ms = witness_core::util::now_ms();
    let mut obs = json!({"at_ms": at_ms, "site": site.name, "url": site.url});
    match fetch(agent, &site.url) {
        Err(e) => {
            warn!("{}: {e}", site.name);
            obs["error"] = Value::String(e);
        }
        Ok(f) => {
            let hash = hex::encode_upper(sha512_half(&f.body));
            obs["status"] = json!(f.status);
            obs["headers"] = f.headers;
            obs["body_hash"] = json!(hash);
            obs["body_bytes"] = json!(f.body.len());
            match summarize(&f.body) {
                Err(e) => {
                    warn!("{}: could not parse response: {e}", site.name);
                    obs["error"] = json!(format!("parse: {e}"));
                }
                Ok(s) => {
                    let max = s.lists.iter().map(|l| l.sequence).max().unwrap_or(0);
                    obs["version"] = json!(s.version);
                    obs["public_key"] = json!(s.public_key);
                    obs["lists"] = s
                        .lists
                        .iter()
                        .map(|l| {
                            json!({"sequence": l.sequence, "expiration": l.expiration,
                                   "effective": l.effective, "validators": l.validators})
                        })
                        .collect();
                    if let Some([a, b]) = seen.note(&s) {
                        warn!("{}: missed list versions {a}..{b}", site.name);
                        obs["missed_sequences"] = json!([a, b]);
                    }
                    let site_dir = dir.join(&site.name);
                    fs::create_dir_all(&site_dir)?;
                    let path = site_dir.join(format!("{max:010}-{}.json", &hash[..16]));
                    if !path.exists() {
                        witness_core::util::write_atomic(&path, &f.body)?;
                        info!(
                            "{}: new version, list {max}, stored {}",
                            site.name,
                            path.display()
                        );
                        obs["stored"] = json!(true);
                    }
                }
            }
        }
    }
    append_line(&dir.join("observations.jsonl"), &obs)
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time() // journald adds the timestamp
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    let args = Args::parse();
    if let Err(e) = run(&args) {
        error!("stopped with error: {e}");
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let sites = args
        .sites
        .iter()
        .map(|s| parse_site(s))
        .collect::<Result<Vec<_>, _>>()?;
    fs::create_dir_all(&args.data_dir)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!("xrpl-witness-unl/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut seen = Seen::load(&args.data_dir);
    info!(
        "publishers: {}, polling every {} s, known keys: {}",
        sites.len(),
        args.interval_secs,
        seen.last_sequence.len()
    );
    loop {
        for site in &sites {
            // A disk write error is a reason to stop: observations must not be
            // lost silently. systemd will restart us, and alerting will notice.
            poll(&agent, site, &args.data_dir, &mut seen)?;
        }
        if args.once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(args.interval_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(seq: u64, v2: bool) -> Vec<u8> {
        let list = json!({"sequence": seq, "expiration": 900, "validators": [{"a": 1}, {"b": 2}]});
        let blob = base64::engine::general_purpose::STANDARD.encode(list.to_string());
        let v = if v2 {
            json!({"version": 2, "public_key": "ED00", "manifest": "m",
                   "blobs_v2": [{"blob": blob, "signature": "s"}]})
        } else {
            json!({"version": 1, "public_key": "ED00", "manifest": "m",
                   "blob": blob, "signature": "s"})
        };
        v.to_string().into_bytes()
    }

    #[test]
    fn both_formats_are_summarized() {
        for v2 in [false, true] {
            let s = summarize(&response(85, v2)).unwrap();
            assert_eq!(s.public_key.as_deref(), Some("ED00"));
            assert_eq!(s.lists.len(), 1);
            assert_eq!(s.lists[0].sequence, 85);
            assert_eq!(s.lists[0].validators, 2);
        }
        assert!(summarize(br#"{"version":1}"#).is_err());
    }

    #[test]
    fn skipped_versions_are_reported() {
        let mut seen = Seen::default();
        assert_eq!(seen.note(&summarize(&response(85, false)).unwrap()), None);
        assert_eq!(seen.note(&summarize(&response(85, false)).unwrap()), None);
        assert_eq!(seen.note(&summarize(&response(86, false)).unwrap()), None);
        assert_eq!(
            seen.note(&summarize(&response(90, false)).unwrap()),
            Some([87, 89])
        );
    }

    #[test]
    fn site_names_are_safe_directories() {
        assert_eq!(
            parse_site("vl.ripple.com=https://vl.ripple.com").unwrap(),
            Site {
                name: "vl.ripple.com".into(),
                url: "https://vl.ripple.com".into()
            }
        );
        assert!(parse_site("../etc=https://x").is_err());
        assert!(parse_site("no-url").is_err());
    }

    #[test]
    fn seen_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("vl.ripple.com");
        fs::create_dir_all(&site).unwrap();
        fs::write(site.join("0000000085-AB.json"), response(85, false)).unwrap();
        let mut seen = Seen::load(dir.path());
        assert_eq!(
            seen.note(&summarize(&response(87, false)).unwrap()),
            Some([86, 86])
        );
    }
}
