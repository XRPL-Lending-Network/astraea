# Roadmap

Astraea is general infrastructure for the XRP Ledger. It is not tied to any one application, and the plan below only covers what any client of a history server could use.

## 0.1: a Clio replacement with proofs

Released.

- Clio-compatible JSON-RPC and WebSocket API for history and state, compared with Clio request by request.
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

## 0.3: ready for public traffic

Released.

- Limits per client, like Clio's DOS guard, with the client's address taken from a trusted proxy or tunnel.
- Answers that never change marked for an edge cache.
- A time limit for every request.
- The rest of Clio's surface: `book_changes`, the NFT methods, and the `validations` and `manifests` streams.

## 0.4: smaller and simpler

Released.

- Smaller cold history: about 208 bytes per transaction with indexes across all of history, below the target of 217.
- A fifth less code: research code and finished benchmarks that were never part of the server are gone, and the codec follows the same lint rules as everything else.
- A comparison with Clio, including where Clio is ahead: [docs/compared-with-clio.md](docs/compared-with-clio.md).

## 0.5: stable

Released. The first stable release, and the point where the repository opens to everyone.

- Public listeners with request slots and limits of their own, so that public load can't take the slots your own services need.
- `submit` and `simulate` forwarded for your own services, off by default and never on a public listener.
- Forwarding with one deadline over all nodes, and a `server_info` that no longer waits for nodes that stopped answering.
- `GET /health` for load balancers and monitors.
- Repeated `account_tx` pages that no longer evict their own blocks, and markers past the last ledger refused instead of read as the end of history.

## Next

- A public endpoint behind a tunnel that terminates TLS, with an edge cache keyed on the request body.
- State at any historical ledger, not only from the snapshot onward. In progress: the state patches of the cold history are being checked against every ledger's state root.
- Reading deep pages of old history at least as fast as Clio.
- Public benchmarks against Clio and the XRPLA archive: disk, memory, latency.
- Packaging: container images, a systemd example, and a release pipeline with reproducible binaries.
