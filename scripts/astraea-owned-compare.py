"""Compares account objects and ledger_data with Clio: account_objects,
account_lines, account_offers, ledger_data.

Accounts come from transactions in random ledgers of the Astraea range (senders,
destinations, amount issuers), queried at a random ledger. Pages are followed by the
marker from Clio's response, and each page goes to both systems.

    python3 astraea-owned-compare.py --astraea http://127.0.0.1:51300 --clio http://127.0.0.1:51233
"""
import argparse, collections, json, random, sys, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--astraea", default="http://127.0.0.1:51300")
ap.add_argument("--clio", default="http://127.0.0.1:51233")
ap.add_argument("--ledgers", type=int, default=10)
ap.add_argument("--accounts", type=int, default=80)
ap.add_argument("--pages", type=int, default=5, help="maximum pages per request")
ap.add_argument("--seed", type=int, default=1)
args = ap.parse_args()
rng = random.Random(args.seed)


def rpc(url, method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=120))["result"]


def diff(a, b, path=""):
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
    return [] if a == b else [f"{path}: {json.dumps(a)[:70]} vs {json.dumps(b)[:70]}"]


def issuers(v, out):
    if isinstance(v, dict):
        if "issuer" in v:
            out.add(v["issuer"])
        for x in v.values():
            issuers(x, out)
    elif isinstance(v, list):
        for x in v:
            issuers(x, out)


info = rpc(args.astraea, "server_info", {})["info"]
lo, hi = map(int, info["complete_ledgers"].split("-"))
hi -= 5  # Clio can lag by a ledger or two
print(f"Astraea range {lo}..{hi}")

accounts, seqs = set(), sorted(rng.sample(range(lo, hi), args.ledgers))
for seq in seqs:
    led = rpc(args.clio, "ledger", {"ledger_index": seq, "transactions": True, "expand": True})
    for t in led["ledger"]["transactions"]:
        tx = t["tx_json"]
        accounts.add(tx["Account"])
        if "Destination" in tx:
            accounts.add(tx["Destination"])
        issuers(tx, accounts)
accounts = sorted(accounts)
rng.shuffle(accounts)

requests = []
for a in accounts[: args.accounts]:
    seq = rng.randint(lo, hi)
    requests += [
        ("account_objects", {"account": a, "ledger_index": seq}),
        ("account_objects", {"account": a, "ledger_index": seq, "limit": 10}),
        ("account_objects", {"account": a, "ledger_index": seq, "type": "state", "limit": 20}),
        ("account_objects", {"account": a, "ledger_index": seq, "deletion_blockers_only": True}),
        ("account_lines", {"account": a, "ledger_index": seq, "limit": 15}),
        ("account_lines", {"account": a, "ledger_index": seq, "ignore_default": True}),
        ("account_offers", {"account": a, "ledger_index": seq, "limit": 10}),
    ]
for seq in seqs[:5]:
    requests += [
        ("ledger_data", {"ledger_index": seq, "limit": 50}),
        ("ledger_data", {"ledger_index": seq, "limit": 200, "binary": True}),
        ("ledger_data", {"ledger_index": seq, "limit": 100, "type": "offer"}),
        ("ledger_data", {"ledger_index": seq, "limit": 5, "api_version": 1}),
        ("ledger_data", {"ledger_index": seq, "limit": 5, "binary": True, "api_version": 1}),
    ]
# Errors and edge cases. The ledger is pinned: without it the two systems can be at
# different tips.
a = accounts[0]
errors = [
    ("account_objects", {"account": a, "type": "fee"}),
    ("account_objects", {"account": a, "type": "nope"}),
    ("account_objects", {"account": a, "marker": "zz"}),
    ("account_objects", {"account": a, "marker": "00" * 32 + ",5"}),
    ("account_objects", {"account": a, "marker": "00" * 32 + ",4294967295"}),
    ("account_objects", {"account": a, "marker": "AB" * 32 + ",0"}),
    ("account_lines", {"account": a, "marker": "AB" * 32 + ",0"}),
    ("account_lines", {"account": a, "peer": "rBadAddress"}),
    ("account_objects", {"account": a, "limit": "x"}),
    ("account_lines", {"account": a, "marker": 7}),
    ("account_lines", {"account": "rrrrrrrrrrrrrrrrrrrrBZbvji"}),
    ("account_offers", {"account": a, "limit": 0}),
    ("ledger_data", {"marker": "11" * 32}),
    ("ledger_data", {"ledger_index": hi, "limit": 0}),
]
requests += [(m, dict({"ledger_index": hi}, **p)) for m, p in errors]

stats, examples = collections.Counter(), {}


def check(method, params, tag):
    ours, theirs = rpc(args.astraea, method, params), rpc(args.clio, method, params)
    for r in (ours, theirs):
        r.pop("request", None) if r.get("status") == "error" else None
    d = diff(ours, theirs, method)
    stats[f"{method} {tag}" + (": mismatch" if d else ": match")] += 1
    for p in d:
        examples.setdefault(p.split(":")[0], (method, params, p))
    return theirs


for method, params in requests:
    theirs = check(method, params, "")
    for page in range(2, args.pages + 1):
        if "marker" not in theirs:
            break
        params = dict(params, marker=theirs["marker"])
        theirs = check(method, params, "page2+")

print("HTTP:")
for k, v in sorted(stats.items()):
    print(f"  {v:>5}  {k}")
for key, (method, params, p) in list(examples.items())[:40]:
    print(f"example {method} {json.dumps(params)[:200]}\n    {p}")
sys.exit(1 if any("mismatch" in k for k in stats) else 0)
