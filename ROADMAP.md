# Roadmap

Astraea is general infrastructure for the XRP Ledger. It is not tied to any one application, and the plan below only covers what any client of a history server could use.

## 0.1: a Clio replacement with proofs

Done or in progress now.

- Clio-compatible JSON-RPC and WebSocket API for history and state, compared with Clio request by request on recorded production traffic.
- Ledgers loaded from xrpld and checked before writing: transaction root, parent chain, state root.
- Confirmation by validator quorum from archived signatures and UNL lists, independent of the source node.
- Evidence packages for ledgers, transactions and state objects, checkable offline with `witness-verify`.
- Cold history in ASTJ6 at about 260 bytes per transaction with indexes, measured on the history loaded so far.
- Full mainnet history from ledger 32571, loaded from the XRPLA archive (loading now).

## 0.2: proofs for all of history

- Done: prove an old ledger through the ledger's own skip lists (the `LedgerHashes` objects) from a confirmed anchor, so a proof no longer needs an anchor within 512 ledgers.
- Done: `proof_tx` for transactions in the cold store.
- Done: `proof_entry` for state at earlier ledgers, from the start of the tree history.
- Tree history back to the state snapshot, rebuilt from the stored state changes, so `proof_entry` covers every ledger that has state.
- A public endpoint with TLS, rate limits and edge caching of answers about closed ledgers, which never change.

## Later

- State at any historical ledger, not only from the snapshot onward.
- More of Clio's surface: NFT methods (`nft_info`, `nft_history`, `nfts_by_issuer`), `book_changes`, the remaining `ledger_entry` selectors, and the `book_changes` and `validations` streams.
- Smaller cold history (a target of under 217 bytes per transaction across all of history).
- Public benchmarks against Clio and the XRPLA archive: disk, memory, latency.
- Packaging: container images, a systemd example, and a release pipeline with reproducible binaries.
- A license and contribution guide before the repository opens.
