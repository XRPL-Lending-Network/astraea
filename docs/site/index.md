# Astraea API Server

## Introduction

Astraea is an XRP Ledger API server. It answers the same JSON-RPC and WebSocket API as Clio, field for field, so an existing client can point at it without changes.

It stores the whole public history, from ledger 32571 to the current ledger, in files of its own format rather than in a database server. With every index it takes about 208 bytes per transaction, about a third of the disk Clio needs for the same ledgers, and no database runs next to it.

Astraea checks every ledger before it writes it: the transaction tree, the state tree and the parent-hash chain are rebuilt from the data, and a ledger counts as validated only when validators from the UNL in force at the time signed it. The signatures and UNL lists are archived next to the history. From them Astraea builds evidence packages: proof that a ledger, transaction or state object is what it says, which anyone can check offline without trusting Astraea or any node.

- [API](api.md): methods, parameters, differences from Clio and errors.
- [Running](running.md): building, configuring and operating a server.
- [Architecture](architecture.md): how the parts fit together.
- [Compared with Clio](compared-with-clio.md): how they are built and measured.

## Develop

Before you write code for Astraea, read the [contribution guidelines](contributing.md).

Read about the [RPC subsystem](rpc.md) to learn how requests reach a handler and how to add a method of your own. The other parts are described in [Related Pages](pages.md), and the code itself in the [crate reference](crates.md).
