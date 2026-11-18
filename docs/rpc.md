# RPC subsystem

This page is for developers. It follows a request from the wire to a handler and back, and shows how to add a method. The methods themselves are listed in [API](api.md). How the data behind them is stored is in [Storage](storage.md).

All of it lives in `crates/ledger-engine/src`. The main files:

| File | Role |
|---|---|
| `server.rs` | reads requests, picks local or forwarded, builds the response |
| `api.rs` | `Engine`, `Engine::handle` (the method dispatch), `RpcError` and shared parsing helpers |
| `owned.rs`, `nft.rs`, `proof.rs` | more handlers, as further `impl Engine` blocks |
| `selector.rs` | object key from `ledger_entry` and `proof_entry` params |
| `forward.rs` | which requests go to xrpld, and the client that sends them |
| `subs.rs` | `subscribe` and `unsubscribe` |
| `limits.rs` | the time limit of one request |
| `guard.rs` | per-client limits and request weights |
| `xrpl_json.rs` | binary objects and transactions as JSON, as xrpld writes them |
| `ter.rs` | transaction result codes and messages for stream messages |

## From the wire to a handler

There are two entry points in `server.rs`, one per transport.

- HTTP: `http_rpc` takes `POST /` with `{"method": ..., "params": [{...}]}`. A body that is not a JSON object gets status 400 and a plain text message. `params_of` takes the first element of `params`; a missing, null or empty `params` gives an empty object, and anything that is not an object gives `badSyntax`. An empty `method` gives `unknownCmd`.
- WebSocket: `ws_answer` handles one text message. The method is `command`, or `method` if there is no `command`. The params are the whole message without `command`, `method` and `id`. A message that is not a JSON object gets `badSyntax`.

Both then ask `Guard::request` whether the client is within its budget, with a weight from `guard::weight`. Over it, the client gets `slowDown`. On WebSocket, `subscribe` and `unsubscribe` go to `subscription`, which uses `subs::parse` and the `Hub`. Over HTTP there is no such branch, so they end in `unknownCmd`.

Everything else goes to `call`. It decides, in this order:

1. On a public listener, `submit`, `simulate` and `ripple_path_find` get `notSupported`.
2. `submit` and `simulate` go to a node only if the server was started to forward them and has a forwarder. Otherwise they get `unknownCmd`. Their params pass through `forward::submission_params` first.
3. If `forward::forwarded` says so, the request goes to a node. Without a forwarder it gets `unknownCmd`.
4. The rest is answered locally by `call_own`.

`call_own` takes a request slot, runs the handler on a blocking thread with `tokio::task::spawn_blocking`, and starts the time limit on that thread with `limits::start` just before it calls `Engine::handle`. For `server_info`, `call` then adds `load_factor` and `rippled_version` from the node's last `server_info` (`forward::node_info`), without waiting for the node.

## The method dispatch

`Engine::handle(method, params)` in `api.rs` is the one place where a method name meets its handler. It is a `match` on the name. Each arm calls a method on `Engine` that takes the params as `&Map<String, Value>` and returns `Res<Map<String, Value>>`, which is `Result<Map<String, Value>, RpcError>`. A name with no arm gets `unknownCmd`.

Before the match, `handle` reads the API version with `api::api_version`. A missing or null `api_version` is 2. Values 1 and 2 are accepted, as a number or a string. Anything else gets `invalid_API_version` (code 6000), for every method. The handlers whose answer differs between versions take the version as a second argument, for example `ledger_rpc(p, api)` and `account_tx(p, api)`. The others ignore it.

Handlers read params straight from the map. `api.rs` has helpers for the common cases, and they return the errors Clio returns:

- `account_id`: a base58 address, or `actMalformed`;
- `hash256`: a 64-character hex hash, or `invalidParams` with the message `<what>Malformed`;
- `as_u32` and `as_bool`: numbers and flags, accepting the forms clients send;
- `Engine::resolve`: the ledger from `ledger_hash` or `ledger_index`, or the latest validated one. A ledger outside the served range gets `lgrNotFound`;
- `Engine::resolve_state` and `Engine::resolve_old_state`: the same for methods that read state, which exists only from the state snapshot on (or where the old-state index covers it).

The handler returns only its fields. `server.rs` adds `status`, the `warnings` entry with id 2001, and on WebSocket `id`, `api_version` and `type`.

## Local and forwarded methods

Astraea serves only validated ledgers. Requests it can't answer from validated data go to xrpld, by the rule Clio uses. `forward::forwarded` returns true for:

- the node methods in `FORWARDED`: `server_state`, `fee`, `ledger_current`, `server_definitions`;
- a method in `CURRENT_ON_NODE` asked with `ledger_index` of `"current"` or `"closed"`;
- `account_info` or `ledger` with `"queue": true`.

`CURRENT_ON_NODE` is an allowlist on purpose. Without it, `ledger_index: "current"` would pass any method to the node, admin ones included. Methods in `CLIO_ONLY` (for example `nft_history` and `mpt_holders`) are never forwarded, as Clio always serves them itself. The user-facing list is in [API](api.md).

`Forwarder::forward` sends the method and params to the nodes as JSON-RPC and returns the node's `result` as it is, including a node's own error. Nodes are tried in turn, a node that just failed last, within `TOTAL_LIMIT` (8 seconds) over all of them. Identical requests within `CACHE_FOR` (250 ms) get the cached answer. When all nodes fail, the answer is `failedToForward` (code 90), and for the next `DOWN_FOR` (5 seconds) it is given at once. `Forwarder::send_transaction` handles `submit`: never cached, and sent to another node only when the first can't have received it.

Forwarded answers carry `"forwarded": true`. They never pass through `Engine::handle`, so a forwarded method needs no handler.

## Errors

An error is an `RpcError`: a fixed error name (`error`), a number (`code`) and a `message`. Handlers build one with `api::rpc_err` or a shortcut: `invalid_params`, `lgr_not_found`, `internal`. Lower modules that return `String` errors are mapped with `internal`, which gives `internal` (code 73), except for the time-limit error described below.

The names and codes follow Clio. The common ones are below; handlers build more where a method needs them, such as `actNotFound`, `txnNotFound`, `entryNotFound`, `invalidLgrRange` and the `malformed*` codes of `ledger_entry`. Search for `rpc_err` to see them all.

| Error | Code | Where |
|---|---|---|
| `badSyntax` | 1 | request is not a JSON object, or `params` is not an object |
| `tooBusy` | 9 | no slot in time, or past the time limit |
| `slowDown` | 10 | client over its `guard` budget |
| `lgrNotFound` | 21 | ledger outside the served range |
| `invalidParams` | 31 | bad or missing parameter; the message names it, as in Clio |
| `unknownCmd` | 32 | no such method, or not available on this server |
| `actMalformed` | 35 | bad account address |
| `internal` | 73 | store or decoding error |
| `notSupported` | 75 | method refused on a public listener; unsupported stream; `ledger_data` with `out_of_order` |
| `failedToForward` | 90 | no node answered |
| `invalid_API_version` | 6000 | `api_version` other than 1 or 2 |

`server.rs` turns an `RpcError` into the client format with `error_fields`: `error`, `error_code`, `error_message`, `status: "error"`, `type: "response"` and the original `request`. Over HTTP these sit inside `result`, as in Clio. Over WebSocket they are at the top level. A node error in a forwarded answer stays an error over WebSocket too, with its fields at the top level. A client over its budget on HTTP gets status 503, as from Clio.

## Limits a handler runs under

A handler runs on a blocking thread, which can't be stopped from outside. So it stops itself. `limits::start` sets a deadline on the thread: `REQUEST_LIMIT` (10 seconds), or `PUBLIC_REQUEST_LIMIT` (5 seconds) on a public listener. A loop whose length the client controls calls `limits::check_rpc()` (or `limits::check()` where errors are strings). Past the deadline the request ends with `tooBusy`, and `api::internal` turns the string error `limits::EXCEEDED` back into `tooBusy`. Threads that read for a request take its deadline with `limits::current` and `limits::start_at`.

The request also needs a slot. Local requests share `MAX_INFLIGHT` (32) slots, forwarded ones `MAX_FORWARDS` (16). `proof_*` methods have their own `MAX_PROOFS` (4) and don't queue: when those are taken, the answer is `tooBusy` at once. Proofs for a transaction or a fixed ledger are cached. Each request also counts against the client's budget in `guard` by `guard::weight`; the weights are listed on [Web server](web-server.md).

Listeners, public access and these numbers in more detail are on [Web server](web-server.md).

## Adding a method

For a new method, open an issue first (`CONTRIBUTING.md`). Astraea answers like Clio 2.8, field for field, so start from Clio's answer for the same request.

1. Write the handler as a method on `Engine`: `fn my_method(&self, p: &Map<String, Value>) -> Res<Map<String, Value>>`, with `api: u32` as a second argument if the answer depends on the version. Put it in the module of its kind (`api.rs`, `owned.rs`, `nft.rs`, `proof.rs`) or in a new module declared in `lib.rs` with its own `impl Engine` block.
2. Read params with the helpers in `api.rs`, and resolve the ledger with `Engine::resolve` or `Engine::resolve_state`. Return only fields from validated ledgers in the served range.
3. Build object and transaction JSON with `xrpl_json` (`xrpl_json::ledger_entry`, `xrpl_json::transaction`, `xrpl_json::metadata`), not by hand.
4. Return errors with the names, codes and messages Clio uses for the same case.
5. Call `limits::check_rpc()` inside every loop whose length depends on the request.
6. Add an arm to the `match` in `Engine::handle`.
7. In `server.rs`, check whether the method belongs in `FIXED_BY_LEDGER` (its answer for a ledger named by sequence or hash never changes, so HTTP may send `immutable`). In `guard.rs`, give it a weight in `weight` if it costs more than an ordinary read.
8. If Clio passes the method to xrpld instead, don't write a handler: add it to `FORWARDED` or `CURRENT_ON_NODE` in `forward.rs`, and extend the test `forwarding_follows_clio_rule`.

Tests come in three kinds, by what they exercise:

- Pure parsing and formatting: a unit test in the same file, in `#[cfg(test)] mod tests`. For example `keys_match_xrpld` in `selector.rs` checks keys against what xrpld 3.4.1 returns for the same params.
- A handler over real stores: an integration test in `crates/ledger-engine/tests/`. `tests/old_ledger_state.rs` builds `Engine` values over temporary directories (`tempfile`), writes a snapshot and history from a fixture of public ledger data, and calls `Engine::handle` directly; `four_methods_match_direct_state` compares the answers of two servers that hold the same data differently. Integration test files start with `#![allow(clippy::unwrap_used, clippy::expect_used)]`.
- The request path: `server.rs` has tests that build the router with `apps`, listen on a local port and send JSON-RPC, for example `submissions_stay_off_the_public_door_and_off_by_default`.

Answers that must match Clio are also compared with a live Clio. That belongs in `scripts/`, not in `cargo test`; `scripts/astraea-api-compare.py` sends the same requests to both servers and compares the whole `result`. Say in the pull request what you ran and what came out.

Before the pull request, run the checks CI runs: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` and `cargo deny check`. No `unwrap` or `expect` outside tests. Add the method to `docs/api.md`, and a line under `## Unreleased` in `CHANGELOG.md` (add the heading if it is missing).
