# Metrics

`astraea-ingest --metrics-addr` serves Prometheus metrics on `/metrics`. Besides what a history server usually reports (requests, latency, load progress), they say how far the data can be trusted: how the last ledger was confirmed, which UNL lists are in effect, how proofs were built, and what part of history is served with state and with proofs.

## Trust

| Metric | Type | Meaning |
|---|---|---|
| `astraea_ingest_confirmed_ledger` | gauge | last ledger confirmed by a quorum of UNL validators; every ledger before it is confirmed by the parent hash chain |
| `astraea_quorum_signers` | gauge | UNL validators that signed the last confirmed ledger |
| `astraea_quorum_needed` | gauge | signatures the quorum rule needed for it (80% of the whole UNL, `full-unl`) |
| `astraea_unl_size` | gauge | validators in the UNL the decision was made with |
| `astraea_unl_list_sequence{publisher}` | gauge | sequence of each configured publisher's latest list |
| `astraea_unl_list_validators{publisher}` | gauge | validators in that list |
| `astraea_unl_list_expiration_timestamp_seconds{publisher}` | gauge | when that list expires, Unix time |
| `astraea_ingest_evidence_ledger` | gauge | last ledger with stored anchor evidence (written every 256 ledgers) |
| `astraea_ingest_validations_total`, `_rejected_total` | counter | validations received with a valid signature, and rejected ones |
| `astraea_proof_bundles_total{method,confirmed_by}` | counter | evidence bundles built; `confirmed_by` is `quorum`, `hash-chain` or `skip-list` |
| `astraea_proof_cache_hits_total` | counter | bundles served from the cache of bundles that never change |

`astraea_quorum_signers - astraea_quorum_needed` is the margin: how many validators can go quiet before confirmation stops.

## API

| Metric | Type | Meaning |
|---|---|---|
| `astraea_api_requests_total{transport,method,status}` | counter | requests; `status` is `success` or the error name the client got |
| `astraea_api_request_duration_seconds{method}` | histogram | time to answer |
| `astraea_api_response_bytes_total{method}` | counter | bytes of responses |
| `astraea_api_forwarded_total{method}` | counter | requests the node answered rather than our own data |
| `astraea_api_inflight{pool}` | gauge | requests being served now: `api` (32 slots) and `proof` (4 slots, refused with `tooBusy` when full) |
| `astraea_api_ws_sessions`, `_ws_sessions_total` | gauge, counter | WebSocket sessions open, and opened since start |
| `astraea_api_subscribers{stream}` | gauge | sessions subscribed to `ledger`, `transactions`, or to at least one account (`accounts`) |
| `astraea_api_subscribed_accounts` | gauge | accounts subscribed to, over all sessions |
| `astraea_api_ws_dropped_total` | counter | sessions disconnected for not reading their messages |

Method names a client made up are counted as `other`, so the series stay few.

## Loading

| Metric | Type | Meaning |
|---|---|---|
| `astraea_ingest_tip_ledger`, `_last_ledger` | gauge | the node's validated ledger, and the last one written |
| `astraea_ingest_last_ledger_close_timestamp_seconds` | gauge | when the network closed the last written ledger |
| `astraea_ingest_ledgers_total`, `_transactions_total`, `_state_changes_total` | counter | written since start |
| `astraea_ingest_commit_seconds_total` | counter | time spent writing ledgers: root checks, state, tree, blocks |
| `astraea_ingest_source_errors_total`, `_missing_retries_total` | counter | failed requests to the node, and retries for a ledger it does not have |

## History and storage

Refreshed every minute.

| Metric | Type | Meaning |
|---|---|---|
| `astraea_history_first_ledger`, `_last_ledger` | gauge | the range the API serves |
| `astraea_state_first_ledger` | gauge | the state snapshot: state methods start here |
| `astraea_tree_history_first_ledger` | gauge | first ledger with tree history: `proof_entry` starts here |
| `astraea_cold_segments`, `astraea_cold_transactions` | gauge | cold history segments and the transactions in them |
| `astraea_storage_bytes{part}` | gauge | bytes on disk: `state` (the state store, with its indexes and tree history), `hot_history`, `cold_segments`, `cold_indexes`, and inside the state store `index_tx`, `index_ledger_hash`, `index_account_tx`, `tree_history` |

Cold bytes per transaction with all indexes:
`(astraea_storage_bytes{part="cold_segments"} + on(instance) astraea_storage_bytes{part="cold_indexes"}) / on(instance) astraea_cold_transactions`.

## Process

The standard `process_cpu_seconds_total`, `process_resident_memory_bytes`, `process_open_fds`, `process_threads` and `process_start_time_seconds`, read from `/proc/self` (Linux only).
