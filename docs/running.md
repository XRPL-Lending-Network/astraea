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
| `--api-addr` | where to serve JSON-RPC and WebSocket; no API without it |
| `--forward-rpc` | node JSON-RPC endpoints for forwarded methods; without them those methods return `unknownCmd` |
| `--forward-timeout` | per-node timeout for forwarding, seconds (default 5) |
| `--network-id` | network ID for CTIDs, 0 for mainnet |
| `--metrics-addr` | Prometheus metrics |

Before the first start, take a snapshot of the full ledger state with `astraea-snapshot` (it downloads every object over gRPC and refuses the result unless the rebuilt state tree matches the header's `account_hash`) and load it with `astraea-state --db <data-dir>/state load <snapshot>`. From then on `astraea-ingest` follows the network. History before the snapshot comes from the cold store.

Astraea doesn't terminate TLS or limit request rates on its own. Put it behind a reverse proxy for anything public.

## Loading older history

`scripts/astraea-full-history.sh` downloads the XRPLA archive in chunks of 32,768 ledgers from the top down, several chunks at a time, and writes each into cold segments. `scripts/astraea-full-publish.py` picks up finished chunks in order, groups them, builds indexes, checks that each group joins the history already served, and publishes it into the live directory without restarting the server. Both scripts can be stopped and restarted at any point. Segments written by this version come with a seal, so the server checks each block once instead of on every load; for segments written earlier, run `astraea-state history-cold-seal <dir>` on the live directory.

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
- `astraea-beta-compare.py`, `astraea-subs-compare.py`, `astraea-ws-compare.py` cover forwarding, `server_info` and subscriptions.
- `astraea-clio-bench.py` measures latency and throughput of both servers on the same requests.
