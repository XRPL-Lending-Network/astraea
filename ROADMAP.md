# Roadmap

Astraea is general infrastructure for the XRP Ledger. It is not tied to any one application, and the plan below only covers what any client of a history server could use.

## 0.1: a Clio replacement with proofs

Done or in progress now.

- Clio-compatible JSON-RPC and WebSocket API for history and state, compared with Clio request by request on recorded production traffic.
- Ledgers loaded from xrpld and checked before writing: transaction root, parent chain, state root.
- Confirmation by validator quorum from archived signatures and UNL lists, independent of the source node.
- Evidence packages for ledgers, transactions and state objects, checkable offline with `witness-verify`.
- Cold history in ASTJ6 at about 251 bytes per transaction with indexes, measured on the whole mainnet history.
- Full mainnet history from ledger 32571, loaded from the XRPLA archive.

## 0.2: proofs for all of history

Released.

- Prove an old ledger through the ledger's own skip lists (the `LedgerHashes` objects) from a confirmed anchor, so a proof no longer needs an anchor within 512 ledgers.
- `proof_tx` for transactions in the cold store.
- `proof_entry` for state at earlier ledgers, back to the state snapshot.
- Metrics on how far the data can be trusted: quorum margin, UNL lists and their expiry, how each proof was confirmed, and what part of history is served with state and with proofs.

## 0.3: a public endpoint

- TLS, rate limits and edge caching of answers about closed ledgers, which never change.

## Later

- State at any historical ledger, not only from the snapshot onward.
- More of Clio's surface: the `validations` stream.
- Smaller cold history (a target of under 217 bytes per transaction across all of history).
- Public benchmarks against Clio and the XRPLA archive: disk, memory, latency.
- Packaging: container images, a systemd example, and a release pipeline with reproducible binaries.
