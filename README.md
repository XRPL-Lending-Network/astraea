<p align="center">
  <img src="assets/hero.svg" alt="Astraea: XRPL history you can check yourself" width="100%">
</p>

Astraea is a history server for the XRP Ledger. It speaks the same JSON-RPC and WebSocket API as [Clio](https://github.com/XRPLF/clio), so an existing client can point at it without changes. It stores the whole public history, back to ledger 32571, in a compact format of its own. It can also hand you a package of evidence for any ledger, transaction or state object, which you can check on your own machine without trusting Astraea or any node.

The project is at version 0.1. Its answers have been compared with Clio on recorded production traffic, request by request, and loading the full history is in progress. Expect rough edges in the docs and tooling more than in the data path.

## Why another history server

A Clio or rippled node answers questions about the ledger, and you take its word for it. That is fine most of the time. It stops being fine when the answer matters to someone who doesn't run the node, like an auditor or a lender checking that a repayment really landed.

Astraea keeps the same answers but also keeps the reasons. Every ledger it stores has passed three checks before it is written:

- the transaction tree rebuilt from the stored transactions matches the root in the ledger header;
- the header's parent hash matches the previous ledger;
- validators from the UNL that was in force at the time signed that ledger, with at least 80% of the full list agreeing.

The signatures and the UNL lists are archived next to the data, byte for byte as the network and the list publishers sent them. That is what lets Astraea build a proof later, and not only for the newest ledger.

## How it fits together

<p align="center">
  <img src="assets/architecture.svg" alt="Sources feed the Ledger Engine and the Proof Engine, which serve the Clio-compatible API and the Proof API" width="100%">
</p>

The **Ledger Engine** loads validated ledgers from xrpld over gRPC, the same way Clio does. Recent ledgers live in a hot store together with the full account state at every ledger. Older history is packed into cold ASTJ5 segments. With all of its indexes (transaction by hash, ledger by hash, account history) it takes roughly 240 bytes per transaction.

The **Proof Engine** listens to the validations stream, checks each signature as it arrives, and decides whether a ledger reached quorum using the UNL lists that were valid for that ledger's close time. It doesn't take the node's word for "validated".

Both feed the API. More detail in [docs/architecture.md](docs/architecture.md).

## What you can ask it

Clio-compatible methods, answered from Astraea's own data:

`server_info`, `ping`, `ledger`, `tx` (by hash or CTID), `account_tx`, `account_info`, `account_lines`, `account_objects`, `account_offers`, `ledger_entry`, `ledger_data`, `mpt_holders`, and WebSocket `subscribe` for the `ledger` and `transactions` streams and for accounts.

Methods that Clio forwards to a node (`fee`, `server_state`, `ledger_current`, `server_definitions`, and read-only queries against the open ledger) are forwarded the same way. Submitting transactions is not supported.

Proof methods: `proof_ledger`, `proof_tx` and `proof_entry` return an evidence package. The package format is described in [docs/evidence-format.md](docs/evidence-format.md), and `witness-verify evidence` checks one offline. In 0.1 a package can be built for ledgers within 512 ledgers of an archived quorum, which means the period since the validation archive started; `proof_tx` covers the hot store and `proof_entry` the latest state. Reaching older history through the ledger's own skip lists is the next step (see the roadmap).

See [docs/api.md](docs/api.md) for parameters, differences from Clio and error behaviour.

## What a proof shows

<p align="center">
  <img src="assets/proof.svg" alt="Quorum on an anchor ledger, a parent-hash chain to the target ledger, and a path in the transaction tree" width="100%">
</p>

A package for a transaction carries the validations that put an anchor ledger over quorum, the UNL lists and manifests that say who was allowed to vote, the chain of headers from the target ledger up to the anchor, and the path of sibling hashes from the transaction to the tree root in the target header. Each step is plain hashing and signature checks. The package also says what it does not prove; for example, it can show a transaction is in the ledger, but not that an account's history is complete.

## Repository layout

| Crate | What it is |
|---|---|
| `crates/ledger-engine` | Loader, hot and cold history, indexes, the API server (`astraea-ingest`), maintenance tools (`astraea-state`, `astraea-xrpla`) |
| `crates/astj5` | ASTJ5, the cold-history codec: segment format, block pool, ASIX indexes |
| `crates/witness-core` | XRPL primitives with no I/O: hashing, STObject parsing, keys and signatures, manifests, UNL lists, SHAMap proofs, quorum rules, evidence packages |
| `crates/witness-archiver` | Archives raw signed validations from a node into sealed segments |
| `crates/witness-unl` | Polls UNL publishers and keeps every signed list it has seen |
| `crates/witness-store` | Append-only segment store with a hash chain of seals |
| `crates/witness-verify` | Independent checker for the archive and for evidence packages |

`scripts/` has the tools used to load the full history and to compare Astraea with Clio request by request.

## Building

Rust 1.99.1 is pinned in `rust-toolchain.toml`. Protobuf definitions are compiled in-process, so you don't need `protoc`.

```bash
cargo build --release
```

```bash
cargo test --workspace
```

Running a node of your own is covered in [docs/running.md](docs/running.md). The short version: point `astraea-ingest` at an xrpld gRPC port and at one or more validation streams, give it a data directory and an API address, and it starts filling history from the moment it connects. Older history comes from the XRPLA archive with `astraea-xrpla` and `astraea-state history-cold`.

## Status and plans

Version 0.1 covers what a Clio replacement needs plus proofs. What comes next is in [ROADMAP.md](ROADMAP.md).

## License

No license has been chosen yet. Until one is added, all rights are reserved.
