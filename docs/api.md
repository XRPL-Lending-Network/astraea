# API

Astraea serves JSON-RPC over HTTP `POST /` and WebSocket on the same address, like Clio and rippled. Requests and responses follow Clio 2.x, including error tokens and codes, so existing client libraries work unchanged. Both API versions 1 and 2 are accepted (`api_version`), and version 2 is the default.

Every response carries a warning that Astraea serves validated data only:

```json
{"id": 2001, "message": "This is an Astraea server. It serves only validated data."}
```

## Ledger range

`server_info` reports `complete_ledgers` as one range. It goes down as far as there is cold history with indexes that joins up with the hot store without a gap, and up to the last ledger the Proof Engine has confirmed by quorum. A ledger that was loaded but isn't confirmed yet is not served.

Ledgers outside the range get `lgrNotFound`, as on any server that doesn't have them. For `account_tx` with explicit bounds outside the range, version 2 returns `lgrIdxMalformed` like Clio.

## Methods

### History

| Method | Notes |
|---|---|
| `ledger` | by `ledger_index` or `ledger_hash`, with `transactions`, `expand` and `binary` |
| `tx` | by hash or by `ctid`; `binary` supported |
| `account_tx` | full range, both directions, markers; `limit` defaults to 200, at most 1000 |
| `book_changes` | by `ledger_index` or `ledger_hash`, over the full range; volumes and rates match xrpld to the last digit |

These work over the whole range, hot and cold. Paging with markers is continuous across the hot/cold boundary and between cold partitions.

### State

| Method | Notes |
|---|---|
| `account_info` | `signer_lists` supported |
| `account_lines`, `account_objects`, `account_offers` | `limit` 10 to 400, default 200 |
| `ledger_entry` | every selector of Clio 2.8: `index`, `account_root`, `amendments`, `amm`, `bridge` with `bridge_account`, `check`, `credential`, `delegate`, `deposit_preauth` (with `authorized` or `authorized_credentials`), `did`, `directory`, `escrow`, `fee`, `hashes`, `loan`, `loan_broker`, `mpt_issuance`, `mptoken`, `nft_offer`, `nft_page`, `nunl`, `offer`, `oracle`, `payment_channel`, `permissioned_domain`, `ripple_state`, `signer_list`, `ticket`, `vault`, `xchain_owned_claim_id`, `xchain_owned_create_account_claim_id`. A hex string in any of them is the object key, and the object must be of that type. `include_deleted` returns a deleted object as it was before the deleting ledger, with `deleted_ledger_index` |
| `ledger_data` | up to 256 objects per page in JSON, 2048 in binary |
| `mpt_holders` | as in Clio |

State exists from the hot store's snapshot onward. A state query for an older ledger returns `lgrNotFound`.

### Server

`server_info` and `ping` are answered locally. `server_info` includes Clio's fields plus a few of Astraea's own:

| Field | Meaning |
|---|---|
| `astraea`, `astraea_version` | server identification |
| `confirmed_ledger` | newest ledger confirmed by validator quorum |
| `loaded_ledger` | newest ledger loaded and checked, possibly not confirmed yet |
| `confirmation_rule` | the quorum rule in force |
| `state_root_checked` | whether the state root is checked on every ledger |

`load_factor` and `rippled_version` are taken from a node when forwarding is configured.

### Forwarded to a node

When the server is started with `--forward-rpc`, these go to the node the way Clio sends them:

- `fee`, `server_state`, `ledger_current`, `server_definitions`;
- public read methods asked about the open ledger (`ledger_index` of `"current"` or `"closed"`): `account_info`, `account_lines`, `account_objects`, `account_offers`, `account_channels`, `account_currencies`, `account_nfts`, `amm_info`, `book_offers`, `book_changes`, `deposit_authorized`, `gateway_balances`, `ledger`, `ledger_data`, `ledger_entry`, `nft_buy_offers`, `nft_sell_offers`, `noripple_check`, `ripple_path_find`, `vault_info`;
- `account_info` and `ledger` with `"queue": true`.

Nothing else is forwarded, whatever its parameters say. Transaction submission and admin methods return `unknownCmd`. Forwarded answers carry `"forwarded": true`. If all nodes fail, the server answers `failedToForward` at once for the next 5 seconds instead of waiting on a dead node.

### Subscriptions (WebSocket)

`subscribe` and `unsubscribe` support the `ledger`, `transactions` and `book_changes` streams and `accounts`. A ledger's `bookChanges` message comes after its transactions, as in Clio. The streams Clio offers that Astraea doesn't (`validations`, `manifests`, `transactions_proposed`, `accounts_proposed`, `books`) return `notSupported` instead of a silent subscription.

- Each confirmed ledger is published once, in order: `ledgerClosed` first, then its transactions by `TransactionIndex`.
- After subscribing to `ledger`, the first `ledgerClosed` is for the ledger right after the one in the subscribe response.
- An account receives a transaction if the account is affected by it, the same set that `account_tx` uses.
- One subscribe can name at most 10,000 accounts.
- A session that falls 1500 messages behind is disconnected, like Clio's `ws_max_sending_queue_size`.

## Limits

Each request has 10 seconds. The loops whose length depends on the request (owner directory pages, `ledger_data` objects, cold index partitions, the transactions of a page or a ledger) check the time, and a request past it ends with `tooBusy` instead of holding one of the request slots. On real traffic requests take well under a second; the slowest, a full binary `ledger_data` page, about 0.7 s.

## Proofs

| Method | Parameters | Proves |
|---|---|---|
| `proof_ledger` | `ledger_index` or `ledger_hash` | the header and its hash were validated by quorum |
| `proof_tx` | `transaction` (hash) | the transaction with this metadata is in a validated ledger |
| `proof_entry` | the same selectors as `ledger_entry`, and `ledger_index` or `ledger_hash` | the object exists with this content, or does not exist, in the state of that ledger (the latest by default) |

The response holds the package under `proof`, the anchor ledger, and two plain lists: what the package proves and what it does not (for example, a transaction proof says nothing about server-derived fields like `delivered_amount`).

`proof_ledger` and `proof_tx` work for any ledger the server holds, back to ledger 32570. A target within 512 ledgers of an anchor is linked to it by a header chain (`target_confirmed_by` is `quorum` or `hash-chain`). An older one is reached through a skip list (`skip-list`, package format `xrpl-witness/evidence/4`): the latest state holds the hash of every 256th ledger since the start of history, so the package proves that list in the state of a recent ledger and adds at most 256 headers from the target up to the ledger in the list. `proof_entry` works on the latest state and on earlier ledgers back to the state snapshot: the server keeps, per ledger, the hashes of the state subtrees at depth 3 that changed, and rebuilds the path from those and the object versions. A ledger before the snapshot has no state and gets `lgrNotFound`; while a server is still rebuilding its tree history, a ledger below the rebuilt part gets `noEvidence`.

Check a package offline. By default the verifier trusts the same two UNL publishers as xrpld's default configuration; `--publisher <hex key>` replaces them, `--threshold` sets how many lists must include a validator, and `--trust <n9… key>` adds a directly trusted validator.

```bash
witness-verify evidence package.json
```
