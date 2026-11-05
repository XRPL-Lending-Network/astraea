# Astraea and Clio

Astraea answers like [Clio](https://github.com/XRPLF/clio) 2.8, field for field, and it can stand in for it. Inside they are built differently. This page says how, and what each difference costs, including where Clio is still ahead.

## How they are built

| | Clio | Astraea |
|---|---|---|
| Language | C++ | Rust, with `unsafe` forbidden across the workspace |
| Storage | A separate database server (Cassandra or ScyllaDB) | Files on disk, read by the server itself |
| Transactions | One row per transaction, compressed by the database | Blocks in a codec built for XRPL binary objects |
| State | A row per object version, plus tables to walk keys in order | An embedded LSM store, kept only from a chosen snapshot onward |
| Trust in the node | The node's word for what was validated | Trees and hash chain rebuilt before writing, validator quorum checked independently |
| What you can take away | An answer | An answer, or a package of evidence you can check offline |

The columnar codec is what makes the history small. A ledger's fields are split into streams of similar values, repeated values go to a dictionary shared by the block, hashes that can be derived from other data are not stored, and state changes that the metadata already gives are rebuilt on reading instead of being kept. The result has to come back byte for byte: a segment is decoded and compared with its input before it is kept.

## Measurements

Sizes were measured on one host with the same mainnet data. Clio 2.8.0 held ledgers 107,245,125 to 107,971,338 in ScyllaDB.

| | Clio | Astraea | Notes |
|---|---|---|---|
| History per ledger on disk | 99 KB | 31 KB | See below |
| Main binary | 44.8 MB | 10.7 MB | Clio also needs its database server |
| Source, with tests | 5.9 MB of C++ | 1.4 MB of Rust | Not the same features: Astraea adds proofs, Clio has more storage backends |

**History per ledger.** For Clio this is everything it keeps for transactions and ledgers (`transactions`, `ledger_transactions`, `account_tx`, `ledgers`, `ledger_hashes`), 72.2 GB over 726,214 ledgers, after the database's compression. For Astraea it is the cold segments that lie fully inside the same range, 18.6 GB over 629,058 ledgers, plus about 9 bytes per transaction for indexes. The two ranges are not identical, and the Astraea figure also includes the state patches that Clio keeps in other tables, so the comparison is on the cautious side, but it is an estimate of about three times, not a benchmark.

Astraea's whole history, 5.18 billion transactions from ledger 32571, takes 1.08 TB.

### Where Clio is ahead or even

Speed depends on what is being read. These runs are from version 0.2, on one machine, and are recorded in [the changelog](../CHANGELOG.md). The denser blocks of `astraea-cold/2` have since added about 7% to reading one uncached transaction.

| Test | Clio | Astraea |
|---|---|---|
| `account_tx`, p99, a real client's traffic | 7.2 to 8.8 ms | 5.3 ms |
| `account_tx`, p99, pages of 200 from cold history | 106 ms | 128 ms |
| Requests per second, 16 clients, same pages | 453 | 433 |

So Astraea is not simply faster. Deep pages of old history cost more, because blocks have to be decoded, and that is the price of the smaller disk. Clio also has years of production behind it and scales out with its database. Astraea runs on one host, with one store.

## What 0.4 removed

Version 0.4 brings the smaller segment format described in [the changelog](../CHANGELOG.md), and it takes out what production never used. The cleanup itself changes no format and no answer. The figures below compare the code just before and just after it.

| | Before | After |
|---|---|---|
| Rust, lines including tests | 46,716 | 37,092 |
| Binaries built by `cargo build` | 25 | 7 |
| Packages in `Cargo.lock` | 282 | 277 |
| Duplicated packages | 26 | 20 |

The codec arrived as a copy of a research package, with experiments and measuring tools that were never connected to the server. They are gone, and the codec now follows the same lint rules as the rest of the code.

To check that the cleanup changed nothing, builds from before and after it read seven mainnet segments from different years, 2.42 million transactions, ledger by ledger, and rewrote them. The digests of what each build read were identical, and each rewritten segment came out byte for byte the same as the file on disk. This was a one-off check on a sample: the program is not in this repository, and the rest of the history was not compared. The live gRPC and WebSocket paths, whose libraries were updated in the same release, are covered by unit tests only.

## How to repeat this

`scripts/astraea-clio-bench.py` measures latency and throughput of both servers on the same requests, and [running.md](running.md) lists the other comparison scripts. Sizes come from `du` on the database's table directories and from the `bytes` fields in the cold segment manifests.
