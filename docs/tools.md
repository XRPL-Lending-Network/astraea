# Maintenance tools

Besides the server, `astraea-ingest`, an operator has a few command-line tools. They load old history, keep the cold store in shape, prepare and check the state store, and check the proof archive. How the processes fit together is in [Running](running.md); the stores and formats are described in [Storage](storage.md) and [Loader](loader.md).

| Binary | Crate | Job |
|---|---|---|
| `astraea-xrpla` | `ledger-engine` | downloads and checks history from the XRPLA publication |
| `astraea-state` | `ledger-engine` | every offline job on the state store, the hot history and the cold store |
| `astraea-snapshot` | `ledger-engine` | takes a full state snapshot from an xrpld node over gRPC |
| `witness-unl`, `witness-archiver` | `witness-unl`, `witness-archiver` | long-running archives for the Proof Engine |
| `witness-verify` | `witness-verify` | checks the validation archive and evidence packages |

`astraea-ingest` has no subcommands. `tools/readme-art.py` only draws the README graphics; it is not an operator tool.

## Two rules for `astraea-state`

- `--db` (or `ASTRAEA_STATE_DIR`) is required on every call, even by subcommands that never open the store. The scripts pass `--db /nonexistent` for those.
- Only one process can open the state store. `astraea-ingest` holds it while it runs, so every subcommand that opens the store needs the server stopped, or a copy of the store. The tables below say which ones do.

Opening a hot history directory also finishes file swaps that `astraea-ingest` left pending. For that reason `astraea-full-publish.py` doesn't run `history-anchor` on the live directory.

## Loading full history

The deep past comes from the XRPLA archive. The order is: `fetch`, then `history-cold`, then `history-cold-index`, then publish.

| Step | What it does | Writes | While the server runs | Key arguments |
|---|---|---|---|---|
| `astraea-xrpla catalog` | Downloads the signed catalog, checks its Ed25519 signature and prints the ranges, size and transaction count. | nothing | yes | `--url`, `--key` (both have pinned defaults) |
| `astraea-xrpla fetch` | Downloads only the segments that cover the range, checks every digest, transaction root and the parent-hash chain, and writes an `XWCP` corpus. Fails unless every ledger of the range is there, in order. | the `--out` file | yes | `--from`, `--to`, `--out` |
| `astraea-state history-cold` | Writes cold segments from an `XWCP` corpus. Each segment is written as ASTJ6 with a seal and the manifest last, then every ledger is read back and compared. | segments in `--to` | yes, into a directory the server doesn't read | `<corpus>`, `--to`, `--kinds` (`explicit` by default; `not-recorded` for XRPLA input), `--segment-ledgers` (32768), `--block-ledgers` (1024), `--block-mib` (4) |
| `astraea-state history-cold-index` | Builds the index partition (`coldidx-F.*`) for transaction by hash, account history and ledger by hash, and checks it. | index files in `<dir>` | yes, on a directory not yet published | `<dir>`, `--first`, `--last` (whole cold range by default) |
| `scripts/astraea-full-publish.py` | Groups finished chunks, runs `history-cold-index` on each group, checks that the group's last ledger is the parent of the next served ledger, then links the files into the live directory: segment data, segment manifests, index files, index manifest. | links in `LIVE`, `published.json` | yes, that is its purpose | environment variables, listed in [Running](running.md) |

`scripts/astraea-full-history.sh` runs `fetch` and `history-cold` for many chunks of 32768 ledgers in parallel, from `TOP` down to `BOTTOM`. A rerun skips finished chunks. A `STOP` file in its working directory stops new chunks from starting.

`astraea-xrpla fetch` retries dropped connections, timeouts, 5xx answers and short ranges, pausing 5, 15, 30, 60 and 120 seconds. One request may take up to 30 minutes.

`astraea-xrpla compare --corpus <file> --blocks <dir>` compares a corpus with blocks of the old loader format, byte for byte. It reads only.

## Cold store upkeep

All of these work on a cold directory, normally the live history directory, and don't open the state store.

| Command | What it does | Writes | While the server runs | Key arguments |
|---|---|---|---|---|
| `history-cold-seal` | Checks every block of a segment in full once and writes `cold-F.seal`, for segments written before seals (0.2). Sealed segments are skipped. The server uses the seal the next time it opens the segment. | seal files | yes | `<dir>`, `--force` (seal again), `--threads` (8) |
| `history-cold-recode` | Rewrites segments in the current format: ASTJ6 parts, and only the patches the metadata doesn't give (`astraea-cold/2`). Segments already in it are skipped. Each new file is checked, then put in place by rename. | segments in place | yes | `<dir>`, `--first`, `--last`, `--threads` (4 segments at once), `--part` (part size in bytes, 1 MiB) |
| `history-cold-drop-index` | Removes the unused ASIX2 indexes (`cold-F.asix`) of segments written before 0.3: the manifest first, then the file. | manifests, deletes files | yes, once the server runs 0.3 or later | `<dir>` |
| `history-anchor` | Checks that the last cold ledger is the parent of the first hot ledger. | nothing, but finishes pending swaps in `--history` | not on the live directory | `--cold`, `--history` |
| `cold-index-check` | Compares the cold indexes with the state store's own indexes on the shared range: account history pages both ways, and transactions by hash on a sample. | nothing | no, opens the store | `<dir>`, `--samples` (2000) |

Upgrade the server before `history-cold-recode`: earlier versions refuse `astraea-cold/2` segments, and a version that has read them can't be swapped for an earlier one.

## State store

The state store needs a snapshot of the full state before the first start. Commands that open it need `astraea-ingest` stopped.

| Command | What it does | Writes | While the server runs | Key arguments |
|---|---|---|---|---|
| `astraea-snapshot` | Downloads every object of one ledger over gRPC, in parallel key ranges, and builds the state tree. Writes the `.xwls.zst` file and a `.json` summary, and exits with an error if the root doesn't match `AccountHash`. | `--out` and its `.json` | yes, it only talks to the node | `--grpc` (or `ASTRAEA_GRPC`), `--out`, `--ledger` (latest validated by default), `--parallel` (16), `--zstd-level` (9), `--user` (`astraea`) |
| `load` | Loads a snapshot into an empty store. | the store | no | `<snapshot>` |
| `apply` | Applies ledgers from an old loader journal, strictly in order after the last applied ledger; a gap is an error. | the store | no | `<ledgers>` |
| `verify` | Computes the root of the whole state at a ledger and compares it with `AccountHash`. Exits 1 on a mismatch. | nothing | no | `--at` (latest by default) |
| `tree-build` | Builds the state tree at the latest ledger. | the store | no | `--rebuild` (delete the tree and build it again) |
| `history-state-replay` | From a base snapshot, applies each cold ledger's patches and compares the state root with `AccountHash` and the parent hash with the ledger before. Stops at the first ledger that differs. Since 0.5.5. | checkpoints only, the latest two | yes, it reads the cold directory | `--cold`, `--base`, `--to`, `--checkpoint-dir` (resume from the latest), `--checkpoint-every` (1,000,000), `--threads` (8), `--readers` (2), `--cache-mib` (1024), `--every` (100,000) |
| `history-state-index` | Builds the version index over cold history from the ledger after `--base` through `--to`, then checks every file it wrote. Run it only over a range a replay has checked. `astraea-ingest` can't serve it yet. Since 0.5.5. | the `--out` directory | yes, it reads the cold directory | `--cold`, `--out`, `--base`, `--to`, `--spill-after` (200,000,000 pairs in memory) |

`history-state-replay` and `history-state-index` don't open the store, though `--db` is still required. A node without full history can't give an old ledger's state over gRPC. `scripts/astraea-base-state.py --url <server> --ledger <seq> --out <file>` takes it over JSON-RPC from a full-history server instead. The server isn't trusted: the replay checks the snapshot's root against its header and the header's hash against the parent of the first cold ledger.

## Checks and measurements

These read only. The ones marked "store" open the state store and need the server stopped.

| Command | What it does | Key arguments |
|---|---|---|
| `blocks` (store) | Checks that every ledger after the snapshot is in the hot history or pending, with a matching transaction tree and the same header as the state. | `<dir>` |
| `ledgers` | Prints sequence, hash and transaction count of each hot-history ledger as JSON lines, for `scripts/astraea-clio-compare.py`. Doesn't need the store. | `<dir>`, `--from`, `--to` |
| `json` | Prints transactions and changed objects as xrpld JSON, for `scripts/astraea-json-compare.py`. Uses the store if it can open it. | `<blocks>`, `--from`, `--to` |
| `tx`, `account-tx`, `get` (store) | A transaction by hash, an account's history, an object by key at a ledger. | `account-tx`: `--min`, `--max`, `--forward`, `--limit` (200), `--marker`; `get`: `--at` |
| `bench` (store) | Index query latencies on a random sample, and index sizes. | `<blocks>`, `--samples` (2000) |
| `history-cold-contention` | Times one reader of recent ledgers while other threads read random ones, for each open-segment limit, cache budget and thread count. Since 0.5.5. | `--cold`, `--from`, `--to`, `--own-span`, `--public-threads`, `--open-limits`, `--cache-mibs`, `--secs` |
| `history-versions-measure` | Size of a version index over a window, and reads of old objects through it. | `--cold`, `--from`, `--to`, `--samples-out` |
| `history-state-replay-bench` | Time to hash the state tree in a replay, for each thread count. Roots aren't checked. | `--cold`, `--base`, `--from`, `--to`, `--threads` (`1,8`) |

## Older hot-history formats

Format moves for stores made by earlier loaders. `history-migrate` moves old-format blocks (`--blocks`) into a new, empty history directory (`--to`) and checks every ledger. `history-convert <history>` prepares format 3 changes next to closed format 2 segments, using the store for previous versions; with the loader running, point `--db` at a copy of the store. `history-swap <history>` then puts them in place, with the loader stopped. `history-export <history> --from --to --out` writes an `XWCP` corpus from hot history, checking transaction roots and the header chain, for `history-cold`.

## Proof side

| Tool | What it does | Writes | While the server runs | Key arguments |
|---|---|---|---|---|
| `witness-unl` | Polls the UNL publishers and keeps every signed list. Runs all the time; see [Running](running.md). | the list archive | yes | `--data-dir`, `--sites`, `--interval-secs` (600), `--once` (one pass, then exit) |
| `witness-archiver` | Keeps raw signed validations in sealed segments. Runs all the time. | the archive | yes | `--url`, `--data-dir`, `--source`, `--segment-ledgers` (1024), `--grace-ledgers` (32), `--stall-secs` (60), `--unl-dir`, `--metrics-addr` |
| `witness-verify archive` | Checks every sealed segment against its seal, the seal chain and every validation's signature. | nothing | yes | `<segments dir>`, `--examples` (3) |
| `witness-verify quorum` | Says whether each ledger of a range reached quorum under a trust policy. | nothing | yes | `<archive root>`, `--from`, `--to`, `--publisher`, `--threshold`, `--trust`, `--negative-unl`, `--details` |
| `witness-verify export` | Builds an evidence package for one ledger from the archive and prints it. | stdout | yes | `<archive root>`, `--ledger`, `--tx`, `--rpc` (needed with `--tx`), trust options as above |
| `witness-verify evidence` | Checks a package offline, against your own trust policy. | nothing | yes | `<package>`, `--publisher`, `--threshold`, `--trust` |

`witness-verify` prints JSON. Exit code 1 means something didn't match; 2 means the check couldn't be carried out.

## Example: loading one range of old history

This loads ledgers 1,000,000 to 1,032,767 into a server whose history starts at 1,032,768.

```bash
B=/var/lib/astraea/src/target/release
G=/var/lib/astraea/history-full/groups/manual
LIVE=/var/lib/astraea/engine/history

$B/astraea-xrpla fetch --from 1000000 --to 1032767 --out /var/lib/astraea/tmp/1000000.xwcp
$B/astraea-state --db /nonexistent history-cold /var/lib/astraea/tmp/1000000.xwcp \
  --to $G --kinds not-recorded --segment-ledgers 32768
$B/astraea-state --db /nonexistent history-cold-index $G
```

Before publishing, check that the hash of ledger 1,032,767 is the `parent_hash` of ledger 1,032,768 on the server (the `ledger` method). Then put the files into `$LIVE` in the order the server expects: data files, segment manifests (`cold-*.json`), index files, and the index manifest (`coldidx-*.json`) last. [Loader](loader.md#publishing-history-without-a-restart) explains why the order matters. `scripts/astraea-full-publish.py` does this for the chunks made by `scripts/astraea-full-history.sh`, with the adjacency check, locks and free-space checks, and is the reference for the order.

The server re-reads the directory every 15 seconds, and `complete_ledgers` in `server_info` then starts at 1000000.
