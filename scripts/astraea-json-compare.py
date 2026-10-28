"""Compares Astraea transaction and object JSON with Clio.

Input is `astraea-state json` lines on stdin. A transaction is compared with Clio's
`tx` response, an object with `ledger_entry` at the same ledger. Clio answers in
API v2 and adds response fields to the transaction (date, ctid, ledger_index,
DeliverMax instead of Amount for Payment), and computed fields to the metadata
(delivered_amount, synthetic NFT fields, mpt_issuance_id). These are
stripped here, so only the binary-to-JSON conversion is compared. Response
fields are the API's job.

    astraea-state --db x json engine/blocks --from N --to M | python3 astraea-json-compare.py
"""
import collections, json, sys, urllib.request

TX_EXTRA = ("date", "ctid", "ledger_index")
META_EXTRA = ("delivered_amount", "nftoken_id", "nftoken_ids", "offer_id", "mpt_issuance_id")


def clio(method, **params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request("http://127.0.0.1:51233", data=body,
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))["result"]


def diff(a, b, path=""):
    """Paths where two JSON values differ."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: {'missing in ours' if k not in a else 'missing in Clio'}")
            else:
                out += diff(a[k], b[k], f"{path}/{k}")
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path}: length {len(a)} vs {len(b)}"]
        return [d for x, y in zip(a, b) for d in diff(x, y, path + "[]")]
    return [] if a == b else [f"{path}: {json.dumps(a)[:80]} vs {json.dumps(b)[:80]}"]


stats = collections.Counter()
kinds = collections.Counter()
examples = {}
for line in sys.stdin:
    item = json.loads(line)
    if item["kind"] == "tx":
        ours_tx, ours_meta = dict(item["tx"]), item["meta"]
        h = ours_tx.pop("hash")
        r = clio("tx", transaction=h)
        if "tx_json" not in r:
            stats["tx: missing in Clio"] += 1
            continue
        theirs_tx = {k: v for k, v in r["tx_json"].items() if k not in TX_EXTRA}
        if theirs_tx.get("TransactionType") == "Payment" and "DeliverMax" in theirs_tx:
            theirs_tx["Amount"] = theirs_tx.pop("DeliverMax")
        theirs_meta = {k: v for k, v in r["meta"].items() if k not in META_EXTRA}
        d = diff(ours_tx, theirs_tx, "tx") + diff(ours_meta, theirs_meta, "meta")
        kind = "tx"
        ident = h
    else:
        node = item["node"]
        r = clio("ledger_entry", index=node["index"], ledger_index=item["ledger"])
        if "node" not in r:
            stats["object: missing in Clio"] += 1
            continue
        d = diff(node, r["node"], node.get("LedgerEntryType", "?"))
        kind = "object"
        ident = f'{node["index"]} @ {item["ledger"]}'
    kinds[kind] += 1
    if d:
        stats[f"{kind}: mismatch"] += 1
        for p in d:
            key = p.split(":")[0]
            if key not in examples:
                examples[key] = (ident, p)
            stats["path " + key] += 1
    else:
        stats[f"{kind}: match"] += 1

print(f"compared: {dict(kinds)}")
for k, v in stats.most_common():
    print(f"  {v:>7}  {k}")
for key, (ident, p) in list(examples.items())[:40]:
    print(f"example {ident}: {p}")
