# Changelog

## Unreleased

- Licensed under ISC, like xrpld. `SECURITY.md` says how to report a vulnerability, `CONTRIBUTING.md` how to contribute.
- `cargo deny check` in CI: permissive licenses only, crates.io only, no known RustSec advisories. It found four: three in zstd (RUSTSEC-2026-0391, -0398, -0403), fixed by moving to zstd 0.14.3, and one in crypto-bigint (RUSTSEC-2026-0387), fixed by moving to k256 0.14. The new k256 returns the normalized signature instead of an option; a high-S signature is still refused where canonical signatures are required.
- `ledger_entry` and `proof_entry` take every selector of Clio 2.8. New: `amm`, `bridge`, `credential`, `delegate`, `did`, `loan`, `loan_broker`, `mpt_issuance`, `mptoken`, `oracle`, `permissioned_domain`, `vault`, the two cross-chain claim IDs, `deposit_preauth` by `authorized_credentials`, and a hex key under `amendments`, `fee`, `hashes`, `nft_offer`, `nunl` or `signer_list`. Keys are derived as in xrpld and match the keys xrpld 3.4.1 returns for the same params. Errors use Clio's codes (`malformedOwner`, `malformedAddress`, `malformedDocumentID`, `malformedAuthorizedCredentials`).
- `ledger_entry` takes `include_deleted`, as in Clio.
- Each request has 10 seconds. Handlers run on blocking threads that cannot be stopped from outside, so the loops whose length the client controls check a per-thread deadline, and a request past it ends with `tooBusy` and frees its slot.
- `book_changes` and the `book_changes` stream. Rates and volumes follow xrpld's amount arithmetic (16-digit division, sums through `Number`, rounding to nearest with ties to even) and matched xrpld 3.4.1 on all 5889 order books in 4464 random mainnet ledgers, 1101 of them with several crossings.

## 0.2.0

- The tree history rebuild replays each of the 4096 subtrees on its own, in memory, from its key range of object versions, on 8 threads; a second pass puts the top of the tree together for every ledger and checks it against `AccountHash`. On mainnet 56 thousand ledgers took 99 seconds instead of about two and a half hours, with records byte for byte the same. After a stop, subtrees already replayed are not read again.
- Metrics on how far the data can be trusted and what is served ([docs/metrics.md](docs/metrics.md)): signers and quorum of the last confirmed ledger, each publisher's latest UNL list and its expiry, evidence bundles by how the target was confirmed, the served range with the first ledgers with state and with tree history, cold history size and transactions, bytes on disk by part. The API adds response bytes, answers from the node, requests in progress, subscribers per stream and dropped sessions; the process adds the standard `process_*` metrics.
- `proof_entry` at earlier ledgers (`ledger_index` or `ledger_hash`). Each ledger now records the state subtrees at depth 3 it changed (a full set of 4096 every 256 ledgers) in a `levels` keyspace; a path at an earlier ledger is rebuilt from those and the object versions, and must reproduce both the recorded subtree and the header's `AccountHash`. A store that started keeping the history later rebuilds it in the background, down to the state snapshot: every ledger's root is checked against the header, and `proof_entry` reaches the snapshot once the rebuild is complete.
- Proofs for all of history. `proof_ledger` and `proof_tx` no longer need an anchor within 512 ledgers: an older target is reached through the long skip list in the latest state, which holds the hash of every 256th ledger since the start of history. The package (`xrpl-witness/evidence/4`) proves that list in the state of the latest tree ledger, anchors that ledger by quorum as before, and adds the headers from the target up to the next multiple of 256. `proof_tx` finds transactions in cold history too. `witness-verify evidence` checks the new `skips` field.
- `account_tx` over cold history reads only headers and transactions, not state changes, and prepares the blocks a page needs in parallel. In the Clio comparison benchmark p99 for a 200-transaction page went from 4.2 s to 660 ms.
- Cold segments carry a seal (`cold-F.seal`): each block gets its full check once, when the segment is written, instead of on every load. `astraea-state history-cold-seal` seals older segments. With it, account_tx p99 is 383 ms and 16 clients get 234 requests per second, up from 39.
- `server_info` no longer waits for the node: the node's `load_factor` and version are refreshed in the background.
- One byte budget for the whole cold block cache instead of a fixed share per segment, and `TransactionIndex` read straight from the metadata header. On a real client's traffic `account_tx` p99 went from 16.7 ms to 5.3 ms (Clio: 7.2 to 8.8 ms).
- Cold segments are written as ASTJ6: ASTJ5 blocks cut into parts of up to 1 MiB that decode on their own, each with its own dictionary and zstd frame. `account_tx` decodes one part per transaction instead of the whole block: a single cold transaction takes 2.0 ms instead of 7.0 on recent history. Archives grow by 8% on recent history and 17% around ledger 98 million. Seals cover a block's head and each part, so a read hashes only what it decodes. `astraea-state history-cold-recode` rewrites ASTJ5 segments in place while the server runs; with parts off, blocks are written byte for byte as before. On the Clio comparison range recoded to ASTJ6, account_tx p99 for a 200-transaction page went from 465 ms to 128 ms (Clio: 106 ms), and 16 clients get 433 requests per second instead of 298 (Clio: 453).
- The XRPLA client retries dropped connections and 5xx answers with a growing pause.
- The full-history loader locks each chunk, gives each process its own temporary archive, and refuses a chunk with fewer ledgers than asked.
- WebSocket sessions answer a client's close frame before disconnecting. Without the reply xrpl.js saw an abnormal close and reconnected clients it had just disconnected, which then pinged forever: a few hundred idle sessions within the first quarter hour of real client traffic.
- `--api-addr` takes several addresses. One that is busy is retried every 10 seconds, so Astraea takes over a port as soon as the server holding it stops.
- API metrics on the metrics port: `astraea_api_requests_total` by transport, method and status (`success` or the error name), `astraea_api_request_duration_seconds` by method, and open WebSocket sessions.

## 0.1.0

First version in this repository.

- Clio-compatible API: `server_info`, `ping`, `ledger`, `tx` (hash and CTID), `account_tx`, `account_info`, `account_lines`, `account_objects`, `account_offers`, `ledger_entry`, `ledger_data`, `mpt_holders`.
- WebSocket subscriptions to the `ledger` and `transactions` streams and to accounts.
- Forwarding of node-only methods (`fee`, `server_state`, `ledger_current`, `server_definitions`) and of public read methods asked about the open ledger. Nothing else reaches the node.
- Proof API: `proof_ledger`, `proof_tx`, `proof_entry`, with offline checking in `witness-verify evidence`.
- Hot store with state at every ledger since the snapshot; cold store in ASTJ5 with on-disk indexes; new cold history becomes visible without a restart.
- Loader for the XRPLA archive with signature, digest, tree-root and chain checks, and scripts for loading and publishing full history.
- UNL list collector, validation archiver with sealed segments, and an independent archive verifier.
