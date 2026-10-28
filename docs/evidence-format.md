# Evidence package: formats `xrpl-witness/evidence/1` and `/2`

An evidence package is a single JSON file about a single ledger. It lets
anyone check that the ledger was confirmed by a quorum under *their own*
trust policy, without trusting us, a node, or the network at the time of the
check.

The package holds only originals, that is, bytes signed by someone else.
Everything else is a note from whoever assembled the package, and the
verifier does not take those notes on faith.

## Fields

| Field | What it is | Protected by whose signatures |
|---|---|---|
| `format` | `xrpl-witness/evidence/1` | none |
| `ledger_index` | ledger index | validation signatures |
| `ledger_hash` | the hash the assembler considers confirmed | checked: it must reach quorum |
| `policy` | the policy the package was assembled under: `publishers`, `threshold`, `trusted_directly` | none; for reference only, the verifier supplies their own |
| `publisher_responses[]` | responses from UNL list publishers: `site`, `body` (base64, byte for byte), `first_seen_ms` | `body`: the publisher's signature and manifest; `first_seen_ms` is the assembler's word |
| `manifests[]` | validator manifests from the node, hex | the validator's master key and signing key |
| `negative_unl` | `flag_ledger`, `flag_ledger_hash`, `node_binary` (the NegativeUNL object in hex, or `null` if there is no object) | for now, the node's word; a proof of inclusion in the state tree is the next step |
| `validations[]` | `data`: the raw signed validation in hex; `received_ms` | the validator's signature |
| `provenance` | `source`: the collector; `exported_ms`; `seals`: seals of the archive segments holding these validations | the archive's seal chain |
| `transactions[]` (version 2) | inclusion proofs: `ledger_header` (118 bytes), `tx`, `meta`, `path` (inner nodes of the transaction tree from the root, 16 hashes each) | the header hash is the ledger hash signed by validators |

## Version 3

`xrpl-witness/evidence/3` adds two fields. Fields from versions 1 and 2 are
unchanged.

| Field | Contents |
|---|---|
| `chain` | headers (hex) from the target ledger up to and including the quorum-confirmed one (`ledger_index`), in order. Astraea includes a single header even when the target is the confirmed ledger itself, so the package always carries the header with its roots and close time. An empty chain is allowed in older packages; in that case only the hash is proven |
| `objects` | state object proofs in `xrpl-witness/state-proof/1` format: header, key, the object or proof of its absence (an empty slot, or a different leaf included in full), and the path in the state tree |

Checking the chain: ledger indexes are consecutive, each header's parent
hash is the hash of the previous header, and the last header is the ledger
that reached quorum. The target ledger is then **linked by hashes** to the
confirmed one (`via_chain`) rather than confirmed by quorum directly. A
transaction or object is proven (`in_confirmed_ledger`, `proven`) if its path
leads to the matching root in that ledger's header from the chain.

Absence of an object: in the last node of the path, the slot for the key is
all zeros, or it holds a different leaf, included in full, with the same key
prefix. Only one leaf can sit in that slot, so our key does not exist under
that prefix.

Version 3 packages are produced by Astraea (Proof API): `proof_ledger`,
`proof_tx`, `proof_entry`. The response carries a `guarantee` next to the
package, stating what is proven, how the target ledger was confirmed, and
what the package does not prove. Before returning a package, Astraea runs
the same verifier on it with its own publisher keys and returns it only if
the verifier reaches the same decision. Otherwise it returns an
`evidenceInvalid` error.

## Verification

1. Publisher responses: the publisher's manifest is signed and not revoked,
   its master key is one the **verifier** trusts, and the list is signed by
   the current key from the manifest. Lists from other publishers are not
   treated as tampering. They are someone else's policy: they do not count
   toward quorum and are listed in `untrusted_publishers`.
2. Manifests, both from the lists and from the package: both signatures
   check out. As in xrpld, only the manifest with the highest sequence
   counts for each master key. A rotated signing key no longer belongs to
   it, a revoked master key gets no signing key at all, and a signing key
   claimed by two master keys goes to neither. A publisher's lists count
   only if they are signed under its latest manifest.
3. Negative UNL comes from the last flag ledger *before* the ledger being
   checked, since changes recorded in a flag ledger apply to the ledgers
   after it. **It does not affect the verdict.** The package does not yet
   prove that the NegativeUNL object is included in the flag ledger's state,
   and the Negative UNL can only lower the threshold, so a substituted object
   could turn an insufficient set of signatures into a confirmation. The
   quorum computed with the claimed Negative UNL is reported for reference
   in `with_claimed_negative_unl`.
4. Each validation: it parses, the signature checks out, and the ledger
   index matches.
5. Time and policy. For each hash with full votes, the verifier takes a
   **window** of signed times: from the earliest to the latest signing time
   among full validations for that hash from validators known through the
   lists. Duplicate validations and their order do not change the window.
   The policies are every combination of lists that were in effect at any
   moment of the window, and the confirmation must hold under each of them.
   If any publisher configured by the verifier has no list in effect during
   the window, the policy is incomplete (`missing_publishers`, with the
   reason in `problems`) and there is no confirmation: without that list the
   UNL is smaller, and quorum would be computed from a smaller number of
   validators. A limitation: the package cannot prove that the assembler did
   not hide a newer list from the same publisher. The verifier only sees the
   lists that were presented.
6. Quorum follows the `full-unl` rule (the `rule` field of the report): 80%
   of the whole trusted list, counting only full validations. This is a
   separate policy, not a reproduction of xrpld's historical quorum with the
   Negative UNL. The network may have confirmed a ledger while some
   validators were disabled, and here that ledger will not reach the
   threshold. Conversely, votes from disabled validators do count here.
   The result is the hash confirmed under every policy in the window, and
   whether it matches the claimed one.
7. Version 2, for each transaction: the path from the leaf
   SHA-512Half(`SND\0`, VL(tx), VL(meta), transaction hash) through the inner
   nodes SHA-512Half(`MIN\0`, 16 children) leads to the transaction root in
   the header (`included`), and the header hash SHA-512Half(`LWR\0`, header)
   equals the hash that reached quorum (`in_confirmed_ledger`).

```bash
witness-verify evidence package.json
witness-verify evidence package.json --publisher ED2677AB... --trust n9...
```

## What the package does not claim

- A validation missing from the package means "we did not see it", not "the
  validator was silent".
- `first_seen_ms` and `negative_unl` are the assembler's observations. They
  do not affect the verdict.
- The exact list the network applied. v1 lists carry no signed publication
  time. So the verifier takes every list in effect at any moment of the
  window between the earliest and the latest signing time of validations from
  known validators (`policy_window` in the report), and quorum must hold for
  every combination of them (`policies`). The unsigned "when the assembler
  saw the list" has no effect on the choice.
- A single validator's signature does not prove consensus. Only a quorum
  under a named policy does.

## Export

```bash
witness-verify export <archive-dir> --ledger <index>
witness-verify export <archive-dir> --ledger <index> --tx <hash> --rpc <node-url>
```

The command assembles a package from the archive: validations from sealed
segments, the publisher responses in effect at the ledger time, manifests of
the signers, and the Negative UNL from the previous flag ledger. If the
ledger does not reach quorum, no package is produced.

With `--tx`, the transactions and the header are fetched from a node or a
Clio server, and the tree path is built locally. The node is not trusted: if
its header is not the ledger that reached quorum, no package is produced.
