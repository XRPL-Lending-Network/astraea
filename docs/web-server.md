# Web server subsystem

The web server is the part of `astraea-ingest` that clients talk to. It answers JSON-RPC over HTTP and WebSocket on one port, as Clio does, and keeps the WebSocket subscriptions. The code is in `crates/ledger-engine/src/server.rs`, with per-client limits in `guard.rs`, the request time limit in `limits.rs` and subscriptions in `subs.rs`. How a method is answered is described in [RPC subsystem](rpc.md). Flags and their defaults are in [Running](running.md).

## Listeners

There are three kinds of listener, each on its own addresses:

| Flag | Serves |
|---|---|
| `--api-addr` | the own door: JSON-RPC and WebSocket for your own services |
| `--public-api-addr` | the public door: the same API for strangers, with its own slots and limits |
| `--metrics-addr` | Prometheus metrics on `/metrics`, see [Metrics](metrics.md) |

Both API doors have the same routes:

- `POST /`: a JSON-RPC request;
- `GET /` with an upgrade: a WebSocket session;
- `GET /health`: `200` with `"status": "ok"` while the last ledger is at most 60 seconds old, otherwise `503` with `lagging` or `noLedger`.

Without `--api-addr` there is no API at all, and `--public-api-addr` is ignored too: the public door is started together with the own door. An address that can't be bound is retried every 10 seconds on its own, so the server takes over a port as soon as the process holding it stops, and loading goes on in the meantime. The metrics listener retries the same way.

The two doors share the data, the forwarder, the proof cache and one set of subscriptions. They don't share request slots or client limits.

The metrics listener is a small HTTP/1.1 server of its own. It answers `GET /metrics` and gives `404` for anything else, closes the connection after each answer, and drops a connection that takes more than 5 seconds.

## Runtime

The process runs on Tokio's multi-threaded runtime (`#[tokio::main]`), and HTTP is axum 0.8 with only HTTP/1 enabled. Astraea doesn't terminate TLS.

Accepting connections, reading requests and writing answers happen on the async runtime. The handlers themselves are synchronous (fjall and zstd are blocking), so every request that reads data runs on Tokio's blocking pool through `spawn_blocking`. So do forwarded requests, `submit` and `simulate`, the `ledger` part of `subscribe`, the `/health` check, and publishing to subscribers.

## Request slots

A request needs a slot before it reaches the data. Each door has three pools, each a semaphore:

| Pool | Own door | Public door | When it is full |
|---|---|---|---|
| reads (`inflight`) | 32 | `--public-max-inflight` | wait, then `tooBusy` |
| proof bundles (`proofs`) | 4 | `--public-max-proofs` | `tooBusy` at once, no queue |
| requests to a node (`forwards`) | 16 | `--public-max-forwards` | wait, then `tooBusy` |

A request waits for a read or forward slot for at most 5 seconds on the own door and 0.5 seconds on the public door; past that it gets `tooBusy` (code 9). Forwards have their own pool so that a node that stopped answering can't hold the slots that reads need.

## Time limit

A blocking thread can't be stopped from outside, so a request stops itself. Before calling the handler the server sets a deadline for the thread: 10 seconds on the own door, 5 on the public door. The loops whose length the client controls (owner directory pages, cold index partitions, the transactions of a page or a ledger) call `limits::check`. Past the deadline the request ends with `tooBusy` and the message "The request took too long. Ask for less: a smaller limit or a narrower ledger range." Threads that read cold blocks for a request take its deadline with them.

The deadline covers requests answered from our own data. Forwarded requests have the forwarder's limits instead: `--forward-timeout` per node and 8 seconds over all nodes. There is no HTTP-level timeout on a connection.

## HTTP requests

A `POST /` goes through these steps:

1. The client address is found (see [Who the client is](#who-the-client-is)) and the client takes a connection from its limit. At the cap or over budget, the answer is `slowDown`.
2. The body is parsed as a JSON object. Anything else gets `400` with a plain-text message.
3. `method` and the first element of `params` are read, and the request is counted against the client's budget with its weight. Over budget, the answer is `slowDown`.
4. The request is dispatched (see [RPC subsystem](rpc.md)) and the answer is built: `result` with `status`, plus a `warnings` entry that says this is an Astraea server. Errors go inside `result`, as in Clio.
5. The response bytes are counted against the client's byte budget.

The answer carries `Cache-Control: public, max-age=86400, immutable` when it can never change (a transaction, or a ledger named by sequence or hash) and `no-store` otherwise.

The body limit is axum's default on the own door and 256 KiB on the public door (`DefaultBodyLimit`). A larger body is refused by axum before the handler runs.

## WebSocket sessions

On upgrade the client is checked against its connection limit, and on the public door against the cap on all public sessions together (`--public-max-sessions`). If either is reached, the upgrade is refused with `slowDown` as an HTTP `503`. On the public door one message may be at most 256 KiB.

The session holds a connection from the client's limit for as long as it is open. It handles one request at a time: it reads a text message, answers it, and only then reads the next. Between requests it sends the messages queued for it by the subscriptions. Binary and ping messages are ignored. On a close frame the server flushes its reply before ending, so the client sees a normal close rather than `1006`.

A request over WebSocket is counted against the client's budget like an HTTP one; over budget it gets a `slowDown` error response and the session stays open. The answer has `result`, `status`, `type`, `id` and `api_version` at the top level, and errors at the top level, as in Clio.

## Protection of the public door

The public door is for strangers. Per-client limits alone don't protect your services, since many addresses each within budget can still fill every slot. So the public door has the following, on top of its own smaller pools.

- **Stepping aside.** When the own door has fewer than 8 free read slots, every public request that needs a slot gets `tooBusy` at once. This protects the own door's queue, not the machine: disk and CPU stay shared.
- **Per-client limits are required.** `astraea-ingest` refuses to start with `--public-api-addr` unless at least one of `--max-requests`, `--max-response-bytes` or `--max-connections` is set. With a public door these limits apply to it alone, and the own door has none.
- **Methods it doesn't take.** `submit`, `simulate` and `ripple_path_find` get `notSupported` (code 75), whatever `--forward-submissions` says.
- **Size and sessions.** 256 KiB per request, `--public-max-sessions` WebSocket sessions in all, and `--public-max-accounts` accounts per session across its subscribes; more gives `invalidParams` with `accountsTooMany`.
- **Shorter waits.** 0.5 seconds for a slot and 5 seconds to run, as above.

Without `--public-api-addr` there is one door, and the per-client limits, if set, apply to `--api-addr`.

## Per-client limits

`guard.rs` works like Clio's `dos_guard`. It is off unless one of the three limits is set. Each client address has, per interval of `--sweep-secs`:

- a budget of weighted requests (`--max-requests`): a proof counts 10, `ledger_data` and `ledger` with expanded transactions 5, a forwarded request 3, `account_tx`, `nft_history`, `book_changes` and `nfts_by_issuer` 2, anything else 1; `/health` counts 1;
- a budget of response bytes (`--max-response-bytes`), counted after each answer is sent;
- a cap on connections open at once (`--max-connections`): HTTP requests in progress and WebSocket sessions.

A request is refused when it would take the client over its request budget, or when the client is already over a budget. A client over budget or at its cap gets `slowDown` (code 10) until the next sweep: over HTTP as status `503` with the error in the body, over WebSocket as an error response. A sweep refills the budgets and keeps open connections counted.

Addresses and CIDR networks in `--limit-whitelist` are never counted. An IPv4 address seen as IPv6 (`::ffff:a.b.c.d`) is treated as the IPv4 address.

### Who the client is

Behind a proxy every request comes from the proxy's address. Only for a peer in `--trusted-proxies` is the client taken from the request: `CF-Connecting-IP`, else the last `for=` of `Forwarded`, else the first address of `X-Forwarded-For`. From anyone else these headers are ignored.

## Subscriptions

`subscribe` and `unsubscribe` work only over WebSocket. The streams are `ledger`, `transactions`, `book_changes`, `validations` and `manifests`, plus transactions per account through `accounts` (at most 10,000 in one request). `transactions_proposed`, `accounts_proposed` and `books` get `notSupported`.

One task, `subs::run`, checks every 250 ms whether a new ledger was confirmed. For each new ledger it publishes, in order, `ledgerClosed`, then the transactions by `TransactionIndex`, then `bookChanges`. An account gets a transaction when it is among the affected accounts, the same set as `account_tx`. Each message is built once per API version and copied to every session that wants it. When publishing falls more than 256 ledgers behind, it skips ahead and publishes only the last 256. With no subscribers it only tracks the tip, so a new subscriber doesn't get old ledgers. `subscribe` with `ledger` answers with the latest ledger, and `ledgerClosed` messages start with the next one.

`validations` and `manifests` come from the nodes' streams that the Proof Engine listens to anyway. They are passed on as received. A message that two nodes both send goes out once.

Each session has a queue of 1500 messages, like `ws_max_sending_queue_size` in Clio. Publishing never waits: if a session's queue is full, the session is dropped from the subscriptions, its queue is closed, and the session ends. This is counted and logged.

## Logging and metrics

The server logs, through `tracing`, each address it listens on, a failure to bind it, the client limits at startup, and from the subscriptions: a session dropped for not reading, publishing falling behind, and a ledger or transaction that could not be published. It doesn't log individual requests. The level comes from `RUST_LOG`; without it the filter is `info,fjall=warn,lsm_tree=warn`.

Every finished request is counted by transport (`http`, `ws`, `public_http`, `public_ws`), method and status, with its duration and response size. Refusals for `slowDown` are counted too; an HTTP body that isn't JSON and a `slowDown` on `/health` are not. Method names a client made up are counted as `other`. Every 5 seconds the server samples the slots in use per pool, public sessions, subscribers per stream and dropped sessions. The metric names are in [Metrics](metrics.md).
