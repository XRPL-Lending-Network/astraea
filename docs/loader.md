# Loader

`astraea-ingest` pulls validated ledgers from one xrpld node over gRPC (`GetLedger` with transactions and state changes, the same call Clio uses). The node is a convenient source, not an authority. Before anything is written:

- the transaction tree is rebuilt from the transactions and metadata, and its root must equal `transaction_hash` in the header;
- the header hash is recomputed, and the header's `parent_hash` must equal the hash of the ledger before it;
- the account-state tree is updated with the ledger's changes, and its root must equal `account_hash` in the header.

A ledger that fails any of these is rejected and the loader retries it. A node that lies can stall Astraea, but it can't put wrong data into it.

## Publishing history without a restart

The server re-reads the history directory in the background. A new cold group becomes visible in a fixed order: data files, segment manifests, index files, and the index manifest last. The API extends its range downward only through index manifests, and it reads index manifests before segments, so the advertised range never runs ahead of the data. `scripts/astraea-full-publish.py` follows this order when it publishes groups loaded from the archive.

## Full history from the XRPLA archive

A node can't serve ledgers it never had, so the deep past comes from the [XRPLA](https://xrpla-data.firstledger.net) publication. `astraea-xrpla fetch` downloads a range and checks it: the catalog signature (Ed25519, the key is pinned in the binary), digests of every directory and segment, transaction-tree roots against headers, and an unbroken parent-hash chain over the whole requested range. Then `astraea-state history-cold` writes cold segments, decoding every ledger back and comparing it with the input before keeping it, and `astraea-state history-cold-index` builds the indexes, checking the header chain again.

The archive doesn't carry state trees, so state changes in these segments aren't verified against `account_hash`. Nothing in the API serves them; only transactions and headers are used.

Where the loaded data is kept is described in [Storage](storage.md).
