"""Compares Astraea ledgers with Clio: hash and transaction count.

Input is JSON lines from `astraea-state ledgers` on stdin; Clio is JSON-RPC on
127.0.0.1:51233 on the same machine:

    astraea-state --db <data>/state ledgers <data>/blocks | python3 astraea-clio-compare.py
"""
import json, sys, urllib.request

def clio(seq):
    body = json.dumps({"method": "ledger", "params": [{"ledger_index": seq, "transactions": True}]}).encode()
    r = json.load(urllib.request.urlopen(urllib.request.Request(
        "http://127.0.0.1:51233", data=body, headers={"Content-Type": "application/json"}), timeout=30))["result"]
    if "ledger_hash" not in r:
        return None, None  # Clio does not have this ledger
    return r["ledger_hash"], len(r["ledger"]["transactions"])

ok = bad = absent = 0; seqs = []; txs = changes = 0
for line in sys.stdin:
    l = json.loads(line)
    seqs.append(l["seq"]); txs += l["transactions"]; changes += l.get("changes", 0)
    ch, cn = clio(l["seq"])
    if ch is None:
        absent += 1
    elif ch == l["hash"] and cn == l["transactions"]:
        ok += 1
    else:
        bad += 1; print("mismatch", l["seq"], ch, l["hash"], cn, l["transactions"])
print(f"{len(seqs)} ledgers: {seqs[0]}…{seqs[-1]}, contiguous: {seqs == list(range(seqs[0], seqs[-1] + 1))}")
print(f"{ok} match Clio, {bad} differ, {absent} missing in Clio; {txs} transactions, {changes} state changes")
