# Crates

rustdoc builds this reference from the source, one page per crate. The command-line binaries of `ledger-engine` (`astraea-ingest`, `astraea-state`, `astraea-xrpla`, `astraea-snapshot`) are described in [Running](running.md) and [Maintenance tools](tools.md) instead.

| Crate | What it is |
|---|---|
| [ledger_engine](reference/ledger_engine/index.html) | Loader, hot and cold history, indexes, the API server (`astraea-ingest`), maintenance tools (`astraea-state`, `astraea-xrpla`) |
| [astraea_journal_codec](reference/astraea_journal_codec/index.html) (`crates/astj5`) | ASTJ, the cold-history codec: segment format and block pool |
| [witness_core](reference/witness_core/index.html) | XRPL primitives with no I/O: hashing, STObject parsing, keys and signatures, manifests, UNL lists, SHAMap proofs, quorum rules, evidence packages |
| [witness_archiver](reference/witness_archiver/index.html) | Archives raw signed validations from a node into sealed segments |
| [witness_unl](reference/witness_unl/index.html) | Polls UNL publishers and keeps every signed list it has seen |
| [witness_store](reference/witness_store/index.html) | Append-only segment store with a hash chain of seals |
| [witness_verify](reference/witness_verify/index.html) | Independent checker for the archive and for evidence packages |
