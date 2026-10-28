"""Real account_tx pages for astraea-layoutbench.

Accounts are taken from random transactions in the range (sender and
destination); pages come from account_tx requests to the Astraea API in the same
range, 200 transactions each, going back from the end. Output is one JSON line per
page: [[ledger, TransactionIndex], …].

    python3 astraea-pages.py --api http://127.0.0.1:51300 --min N --max M > pages.jsonl
"""
import argparse, json, random, sys, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--api", default="http://127.0.0.1:51300")
ap.add_argument("--min", type=int, required=True)
ap.add_argument("--max", type=int, required=True)
ap.add_argument("--accounts", type=int, default=200)
ap.add_argument("--seed", type=int, default=7)
args = ap.parse_args()
rng = random.Random(args.seed)


def rpc(method, **params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(args.api, data=body, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))["result"]


accounts, tries = set(), 0
while len(accounts) < args.accounts and tries < 20 * args.accounts:
    tries += 1
    led = rpc("ledger", ledger_index=rng.randint(args.min, args.max), transactions=True, expand=True)
    txs = led["ledger"]["transactions"]
    if txs:
        t = rng.choice(txs)["tx_json"]
        accounts.add(t["Account"])
        if "Destination" in t:
            accounts.add(t["Destination"])
written = 0
for a in sorted(accounts):
    r = rpc("account_tx", account=a, ledger_index_min=args.min, ledger_index_max=args.max, limit=200)
    page = [[t["ledger_index"], t["meta"]["TransactionIndex"]] for t in r.get("transactions", [])]
    if page:
        print(json.dumps(page))
        written += 1
print(f"pages: {written} from {len(accounts)} accounts", file=sys.stderr)
