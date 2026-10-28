"""Compares Astraea account history (account_tx) with Clio.

Accounts are taken from random transactions in a ledger range: sender,
destination and accounts from the metadata. For each one the hash lists are compared,
up to the `--depth` latest transactions, including order. Clio is JSON-RPC on
127.0.0.1:51233 on the same machine; the Astraea store is opened read-only
by the astraea-state tool, so the loader must be stopped during the comparison.

    python3 astraea-account-compare.py --state-bin ~/astraea-state \\
        --db ~/engine/state --blocks ~/engine/blocks --min 107874183 --max 107876000
"""
import argparse, json, random, subprocess, sys, time, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--state-bin", required=True)
ap.add_argument("--db", required=True)
ap.add_argument("--blocks", required=True)
ap.add_argument("--min", type=int, required=True)
ap.add_argument("--max", type=int, required=True)
ap.add_argument("--accounts", type=int, default=200)
ap.add_argument("--depth", type=int, default=1000)
ap.add_argument("--seed", type=int, default=1)
args = ap.parse_args()


def clio(method, **params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request("http://127.0.0.1:51233", data=body,
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))["result"]


def accounts_of(t):
    # Clio answers in API v2 format (tx_json and meta), xrpld defaults to v1.
    tx = t.get("tx_json", t)
    meta = t.get("meta") or t.get("metaData") or {}
    out = {tx.get("Account"), tx.get("Destination")}
    for n in meta.get("AffectedNodes", []):
        node = next(iter(n.values()))
        for part in ("FinalFields", "NewFields"):
            for k, v in node.get(part, {}).items():
                if isinstance(v, str) and v.startswith("r") and k in ("Account", "Owner", "Destination", "Issuer"):
                    out.add(v)
                if k in ("LowLimit", "HighLimit") and isinstance(v, dict):
                    out.add(v.get("issuer"))
    return {a for a in out if a}


rng = random.Random(args.seed)
sample, tries = set(), 0
while len(sample) < args.accounts:
    tries += 1
    if tries > 20 * args.accounts:
        sys.exit("cannot collect enough accounts: did the Clio response format change?")
    seq = rng.randint(args.min, args.max)
    txs = clio("ledger", ledger_index=seq, transactions=True, expand=True)["ledger"]["transactions"]
    if txs:
        sample |= accounts_of(rng.choice(txs))
sample = sorted(sample)[: args.accounts]


def clio_history(account):
    out, marker, pages = [], None, 0
    while len(out) < args.depth:
        # Guard against endless paging: a page with no transactions but the
        # same marker is a reason to stop and report rather than loop forever.
        pages += 1
        if pages > 4 * args.depth // 400 + 10:
            raise RuntimeError(f"{account}: Clio keeps paging, marker {marker}")
        p = dict(account=account, ledger_index_min=args.min, ledger_index_max=args.max,
                 forward=False, limit=min(400, args.depth - len(out)))
        if marker:
            p["marker"] = marker
        r = clio("account_tx", **p)
        out += [t["tx"]["hash"] if "tx" in t else t["hash"] for t in r["transactions"]]
        if marker and r.get("marker") == marker:
            raise RuntimeError(f"{account}: Clio returned the same marker {marker}")
        marker = r.get("marker")
        if not marker:
            break
    return out


def our_history(account):
    r = subprocess.run([args.state_bin, "--db", args.db, "account-tx", account,
                        "--min", str(args.min), "--max", str(args.max),
                        "--limit", str(args.depth), "--blocks", args.blocks],
                       capture_output=True, text=True, check=True)
    return [j["hash"] for j in map(json.loads, r.stdout.splitlines()) if "hash" in j]


same = diff = txs = 0
for i, a in enumerate(sample):
    t = time.time()
    try:
        ours, theirs = our_history(a), clio_history(a)
    except RuntimeError as e:
        print("skipped:", e, flush=True)
        continue
    print(f"{i + 1}/{len(sample)} {a}: ours {len(ours)}, Clio {len(theirs)}, {time.time() - t:.1f} s",
          file=sys.stderr, flush=True)
    txs += len(theirs)
    if ours == theirs:
        same += 1
    else:
        diff += 1
        only_ours = set(ours) - set(theirs)
        only_clio = set(theirs) - set(ours)
        print(f"mismatch {a}: ours {len(ours)}, Clio {len(theirs)}; "
              f"only ours {sorted(only_ours)[:3]}, only Clio {sorted(only_clio)[:3]}")
print(f"{len(sample)} accounts: {same} match, {diff} differ; {txs} transactions compared")
