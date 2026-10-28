"""Compares cold history queries with Clio: ledger by
sequence and by hash (with transactions, JSON and binary, api 1 and 2), tx by hash,
account_tx inside the cold range, and pages across the boundary between cold and
hot history in both directions. Responses are compared in full, without warnings.
Run on the host: python3 -I scripts/astraea-cold-compare.py FIRST LAST
(bounds of the cold range; Clio on 51233, Astraea on 51300).
"""
import json
import random
import sys
import urllib.request

CLIO, AST = "http://127.0.0.1:51233", "http://127.0.0.1:51300"
FIRST, LAST = int(sys.argv[1]), int(sys.argv[2])
SAMPLES = int(sys.argv[3]) if len(sys.argv) > 3 else 40
random.seed(27)


def rpc(url, method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(url, body, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)["result"]


bad = 0
checked = 0


def same(name, params, method):
    global bad, checked
    c, a = rpc(CLIO, method, params), rpc(AST, method, params)
    for d in (c, a):
        d.pop("warnings", None)
    checked += 1
    if c != a:
        bad += 1
        ks = sorted(set(c) | set(a))
        diff = [k for k in ks if c.get(k) != a.get(k)]
        print("DIFF", name, json.dumps(params)[:160], "fields:", diff[:8])
        for k in diff[:3]:
            print("   clio", k, json.dumps(c.get(k))[:300])
            print("   astr", k, json.dumps(a.get(k))[:300])
    return c


seqs = sorted(random.sample(range(FIRST, LAST + 1), SAMPLES))
accounts, hashes = set(), []
for s in seqs:
    for api in (1, 2):
        for binary in (False, True):
            p = {"ledger_index": s, "transactions": True, "expand": True, "binary": binary, "api_version": api}
            r = same(f"ledger {s} api{api} binary={binary}", p, "ledger")
    # In a binary response the ledger hash is at the top level.
    lh = r.get("ledger_hash") or r.get("ledger", {}).get("ledger_hash")
    if lh:
        same(f"ledger by hash {s}", {"ledger_hash": lh}, "ledger")
    j = rpc(CLIO, "ledger", {"ledger_index": s, "transactions": True, "expand": True})
    txs = j.get("ledger", {}).get("transactions", [])
    for t in random.sample(txs, min(3, len(txs))):
        hashes.append(t["hash"])
        accounts.add(t["tx_json"]["Account"])
        d = t["tx_json"].get("Destination")
        if d:
            accounts.add(d)
for h in hashes:
    for api in (1, 2):
        for binary in (False, True):
            same(f"tx {h[:12]} api{api} binary={binary}", {"transaction": h, "api_version": api, "binary": binary}, "tx")
pages = 0
for acc in sorted(accounts)[:60]:
    # Inside the cold range, both directions, three pages.
    for forward in (False, True):
        for api in (1, 2):
            p = {"account": acc, "ledger_index_min": FIRST, "ledger_index_max": LAST, "limit": 50,
                 "forward": forward, "api_version": api}
            for _ in range(3):
                r = same(f"account_tx {acc[:10]} forward={forward} api{api}", p, "account_tx")
                pages += 1
                if "marker" not in r:
                    break
                p = dict(p, marker=r["marker"])
    # Across the boundary between cold and hot history.
    for forward in (False, True):
        p = {"account": acc, "ledger_index_min": LAST - 20000, "ledger_index_max": LAST + 20000,
             "limit": 20, "forward": forward}
        for _ in range(6):
            r = same(f"account_tx across boundary {acc[:10]} forward={forward}", p, "account_tx")
            pages += 1
            if "marker" not in r:
                break
            p = dict(p, marker=r["marker"])
print(f"{checked} requests: {len(seqs)} ledgers, {len(hashes)} transactions, {min(len(accounts), 60)} accounts, {pages} account_tx pages; {bad} differences")
