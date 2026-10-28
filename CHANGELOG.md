# Changelog

## 0.1.0

First version in this repository.

- Clio-compatible API: `server_info`, `ping`, `ledger`, `tx` (hash and CTID), `account_tx`, `account_info`, `account_lines`, `account_objects`, `account_offers`, `ledger_entry`, `ledger_data`, `mpt_holders`.
- WebSocket subscriptions to the `ledger` and `transactions` streams and to accounts.
- Forwarding of node-only methods (`fee`, `server_state`, `ledger_current`, `server_definitions`) and of public read methods asked about the open ledger. Nothing else reaches the node.
- Proof API: `proof_ledger`, `proof_tx`, `proof_entry`, with offline checking in `witness-verify evidence`.
- Hot store with state at every ledger since the snapshot; cold store in ASTJ5 with on-disk indexes; new cold history becomes visible without a restart.
- Loader for the XRPLA archive with signature, digest, tree-root and chain checks, and scripts for loading and publishing full history.
- UNL list collector, validation archiver with sealed segments, and an independent archive verifier.
