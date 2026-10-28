# Changelog

## Unreleased

- `account_tx` over cold history reads only headers and transactions, not state changes, and prepares the blocks a page needs in parallel. In the Clio comparison benchmark p99 for a 200-transaction page went from 4.2 s to 660 ms.
- Cold segments carry a seal (`cold-F.seal`): each block gets its full check once, when the segment is written, instead of on every load. `astraea-state history-cold-seal` seals older segments. With it, account_tx p99 is 383 ms and 16 clients get 234 requests per second, up from 39.
- `server_info` no longer waits for the node: the node's `load_factor` and version are refreshed in the background.
- One byte budget for the whole cold block cache instead of a fixed share per segment, and `TransactionIndex` read straight from the metadata header. On a real client's traffic `account_tx` p99 went from 16.7 ms to 5.3 ms (Clio: 7.2 to 8.8 ms).
- The XRPLA client retries dropped connections and 5xx answers with a growing pause.
- The full-history loader locks each chunk, gives each process its own temporary archive, and refuses a chunk with fewer ledgers than asked.

## 0.1.0

First version in this repository.

- Clio-compatible API: `server_info`, `ping`, `ledger`, `tx` (hash and CTID), `account_tx`, `account_info`, `account_lines`, `account_objects`, `account_offers`, `ledger_entry`, `ledger_data`, `mpt_holders`.
- WebSocket subscriptions to the `ledger` and `transactions` streams and to accounts.
- Forwarding of node-only methods (`fee`, `server_state`, `ledger_current`, `server_definitions`) and of public read methods asked about the open ledger. Nothing else reaches the node.
- Proof API: `proof_ledger`, `proof_tx`, `proof_entry`, with offline checking in `witness-verify evidence`.
- Hot store with state at every ledger since the snapshot; cold store in ASTJ5 with on-disk indexes; new cold history becomes visible without a restart.
- Loader for the XRPLA archive with signature, digest, tree-root and chain checks, and scripts for loading and publishing full history.
- UNL list collector, validation archiver with sealed segments, and an independent archive verifier.
