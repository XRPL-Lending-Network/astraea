# Running Astraea

A working setup has four processes. Only `astraea-ingest` is needed to serve the API; the other three feed the Proof Engine and keep its archive.

| Process | Job |
|---|---|
| `witness-unl` | keeps every signed UNL list the publishers serve |
| `witness-archiver` | keeps raw signed validations from a node |
| `astraea-ingest` | loads and checks ledgers, confirms them by quorum, serves the API |
| `astraea-xrpla` + `astraea-state` | one-off tools for loading older history |

## What you need

- An xrpld node with gRPC enabled and a WebSocket port that streams validations. The node's `[secure_gateway]` should list the Astraea host if you don't want it rate-limited.
- Disk: the hot store grows with state versions; full mainnet history in the cold store takes on the order of 1.2 TB.
- Rust 1.99.1 to build (pinned in `rust-toolchain.toml`).

## Building

`cargo build --release` gives a binary for any x86-64 processor. If the server's processor has AVX2 (Intel since 2013, AMD since 2017), build for that level:

```bash
RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --release
```

On a mix of history and state requests (expanded ledgers across the whole range, transactions by hash, `account_tx` pages, account state, `book_changes`) this cut p99 latency by 14% and CPU per request by 5%. We also measured mimalloc in place of the system allocator: peak memory fell from 8.3 to 4.8 GB, but 16 parallel clients got 19% fewer requests per second, so the system allocator stays.

## UNL archive

```bash
witness-unl --data-dir /var/lib/astraea/unl
```

It polls every 600 seconds by default (`--interval-secs`). Publishers come from `--sites name=url,...`, with vl.ripple.com and unl.xrplf.org by default. Start it first and leave it running: publishers only serve the current list, so a list you missed is gone.

## Validation archive

```bash
witness-archiver \
  --url ws://<node-host>:6006 \
  --source <node-name> \
  --data-dir /var/lib/astraea/validations \
  --unl-dir /var/lib/astraea/unl
```

It writes a journal that is flushed every second, closes segments of 1024 ledgers with a chained seal, and records every disconnect and reconnect in `gaps.jsonl`, so holes in the archive are visible instead of guessed. `--metrics-addr` exposes Prometheus metrics.

## Ingest and API

```bash
astraea-ingest \
  --grpc http://<node-host>:50051 \
  --data-dir /var/lib/astraea/engine \
  --validations-ws ws://<node-host>:6006 \
  --unl-dir /var/lib/astraea/unl \
  --api-addr 127.0.0.1:51233 \
  --forward-rpc http://<node-host>:51234
```

| Option | Meaning |
|---|---|
| `--grpc` | xrpld gRPC endpoint that ledgers are loaded from |
| `--data-dir` | where `state` and `history` live |
| `--validations-ws` | one or more WebSocket endpoints for the validations stream, comma separated |
| `--unl-dir` | the `witness-unl` archive |
| `--publishers` | UNL publisher keys to trust, hex; defaults to vl.ripple.com and unl.xrplf.org |
| `--api-addr` | where to serve JSON-RPC and WebSocket, one or more addresses, comma separated; no API without it. An address that is busy is retried every 10 s, so Astraea takes over a port as soon as the server holding it stops |
| `--forward-rpc` | node JSON-RPC endpoints for forwarded methods; without them those methods return `unknownCmd` |
| `--forward-timeout` | per-node timeout for forwarding, seconds (default 5) |
| `--network-id` | network ID for CTIDs, 0 for mainnet |
| `--metrics-addr` | Prometheus metrics, described in [metrics.md](metrics.md) |
| `--max-requests` | weighted requests per client per interval; with none of the three limits, clients are not limited |
| `--max-response-bytes` | response bytes per client per interval |
| `--max-connections` | connections per client open at once: HTTP requests in progress and WebSocket sessions |
| `--sweep-secs` | the interval the request and byte budgets cover, seconds (default 1) |
| `--limit-whitelist` | addresses or CIDR networks that are never limited, comma separated |
| `--trusted-proxies` | proxies whose `CF-Connecting-IP`, `Forwarded` or `X-Forwarded-For` header names the client, comma separated |

Before the first start, take a snapshot of the full ledger state with `astraea-snapshot` (it downloads every object over gRPC and refuses the result unless the rebuilt state tree matches the header's `account_hash`) and load it with `astraea-state --db <data-dir>/state load <snapshot>`. From then on `astraea-ingest` follows the network. History before the snapshot comes from the cold store.

Astraea serves at most 32 requests at once, 4 of them proofs, and gives each request 10 seconds. It doesn't terminate TLS: put it behind a reverse proxy or a tunnel for anything public.

### Public access

Per-client limits work like Clio's `dos_guard`. A client over its request or byte budget, or at its connection cap, gets `slowDown` until the interval ends: over HTTP as status 503, over WebSocket as an error response. Requests that walk many objects count more: a proof 10, `ledger_data` and a ledger with expanded transactions 5, `account_tx`, `nft_history`, `book_changes` and `nfts_by_issuer` 2, the rest 1. Your own services go in `--limit-whitelist`.

Behind a proxy every request comes from the proxy's address. List the proxy in `--trusted-proxies` (for `cloudflared` on the same host, `127.0.0.1`), and the client is taken from `CF-Connecting-IP`, the last `for=` of `Forwarded`, or the first address of `X-Forwarded-For`. These headers are ignored from anyone else, so a client can't pose as another.

Answers that can never change (a transaction, or anything about a ledger named by sequence or hash) carry `Cache-Control: public, max-age=86400, immutable`; the rest carry `no-store`. JSON-RPC requests are POSTs, which CDNs don't cache by default, so an edge cache needs a rule or worker that keys on the request body; the header tells it what it may keep.

## Loading older history

`scripts/astraea-full-history.sh` downloads the XRPLA archive in chunks of 32,768 ledgers from the top down, several chunks at a time, and writes each into cold segments. `scripts/astraea-full-publish.py` picks up finished chunks in order, groups them, builds indexes, checks that each group joins the history already served, and publishes it into the live directory without restarting the server. Both scripts can be stopped and restarted at any point. Segments written by this version come with a seal, so the server checks each block once instead of on every load; for segments written earlier, run `astraea-state history-cold-seal <dir>` on the live directory. Segments are written as ASTJ6, whose blocks are cut into parts read on their own; `astraea-state history-cold-recode <dir>` rewrites older ASTJ5 segments in place, a few at a time (`--threads`), while the server keeps serving them. A recent segment takes about two and a half minutes per thread.

Segments written before 0.3 also carry ASIX2 indexes (`cold-F.asix`) that nothing reads; `astraea-state history-cold-drop-index <dir>` removes them, the manifest first and then the file. Run it after the server has been upgraded to 0.3: earlier versions refuse a segment whose manifest lacks the file.

Their settings come from environment variables; `ASTRAEA_HOME` defaults to `/var/lib/astraea`:

| Variable | Default | Meaning |
|---|---|---|
| `B` | `$ASTRAEA_HOME/src/target/release` | where the binaries are |
| `R` | `$ASTRAEA_HOME/history-full` | working directory: chunks, groups, logs |
| `T` | `$ASTRAEA_HOME/tmp` | temporary downloads |
| `LIVE` | `$ASTRAEA_HOME/engine/history` | the live history directory of `astraea-ingest` |
| `TOP` | required | the ledger just below the history already served |
| `BOTTOM` | 32571 | the first ledger to load |
| `STREAMS` | 8 | chunks in parallel |
| `MIN_FREE_GB` | 300 | stop starting new chunks below this free space |

A chunk of recent mainnet history (2 to 4 million transactions) takes 15 to 30 minutes and up to 3.5 GB of memory to write. Early history is much lighter. On a 32-core machine the whole archive takes several days.

## Comparing with Clio

`scripts/` has the tools used to check Astraea against a running Clio:

- `astraea-client-replay.py` replays recorded client requests against both servers and compares the answers;
- `astraea-cold-compare.py` samples ledgers, transactions and account history across a range;
- `astraea-beta-compare.py`, `astraea-subs-compare.py`, `astraea-ws-compare.py` cover forwarding, `server_info` and subscriptions;
- `astraea-clio-bench.py` measures latency and throughput of both servers on the same requests;
- `astraea-client-latency.py` does the same on a client's real requests from the Clio log, in their real mix.
