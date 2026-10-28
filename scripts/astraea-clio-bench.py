"""Latency and throughput of Astraea against Clio on the same history.

Both servers get the same requests, sampled from the ledger range they share:
ledger with expanded transactions, tx by hash, the first two pages of
account_tx, and account_info / account_lines / account_objects on the
validated ledger. Requests go to the two servers in random order, one at a
time, so neither gets a warmer machine. The sample runs twice: the first pass
mostly misses the caches, the second pass repeats the same requests.

Then each server takes 16 parallel clients sending account_tx for random
accounts for a fixed time, and the script reports requests per second.

Answers are not compared here (astraea-cold-compare.py and
astraea-client-replay.py do that); a request that errors on one side is
reported and left out of the timings.

Run on a host that sees both servers:
  python3 -I scripts/astraea-clio-bench.py FIRST LAST [SAMPLES] [SECONDS]
FIRST and LAST bound the shared range. Clio is expected on 127.0.0.1:51233
and Astraea on 127.0.0.1:51300; override with CLIO and ASTRAEA.
"""
import json
import os
import random
import statistics
import sys
import threading
import time
import urllib.request

CLIO = os.environ.get("CLIO", "http://127.0.0.1:51233")
AST = os.environ.get("ASTRAEA", "http://127.0.0.1:51300")
FIRST, LAST = int(sys.argv[1]), int(sys.argv[2])
SAMPLES = int(sys.argv[3]) if len(sys.argv) > 3 else 60
SECONDS = int(sys.argv[4]) if len(sys.argv) > 4 else 30
random.seed(206)


def rpc(url, method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(url, body, {"content-type": "application/json"})
    t = time.perf_counter()
    with urllib.request.urlopen(req, timeout=120) as r:
        out = json.load(r)["result"]
    return out, (time.perf_counter() - t) * 1e3


def requests():
    """Request sample: (method, params), built from Astraea's answers."""
    out, accounts = [], []
    for seq in sorted(random.sample(range(FIRST, LAST + 1), SAMPLES)):
        out.append(("ledger", {"ledger_index": seq, "transactions": True, "expand": True}))
        led, _ = rpc(AST, "ledger", {"ledger_index": seq, "transactions": True, "expand": True})
        txs = led.get("ledger", {}).get("transactions", [])
        for t in random.sample(txs, min(2, len(txs))):
            out.append(("tx", {"transaction": t["hash"]}))
            accounts.append((t.get("tx_json") or t)["Account"])
    for acc in accounts[:SAMPLES]:
        out.append(("account_tx", {"account": acc, "ledger_index_min": FIRST, "ledger_index_max": LAST, "limit": 200}))
        out.append(("account_tx+marker", {"account": acc, "ledger_index_min": FIRST, "ledger_index_max": LAST, "limit": 200}))
        for m in ("account_info", "account_lines", "account_objects"):
            out.append((m, {"account": acc, "ledger_index": "validated"}))
    return out, accounts


def call(url, method, params):
    if method == "account_tx+marker":
        first, _ = rpc(url, "account_tx", params)
        if "marker" not in first:
            return None
        return rpc(url, "account_tx", dict(params, marker=first["marker"]))
    return rpc(url, method, params)


def timings(sample):
    t = {"clio": {}, "astraea": {}}
    errors = 0
    for method, params in sample:
        order = [("clio", CLIO), ("astraea", AST)]
        random.shuffle(order)
        got = {}
        for name, url in order:
            r = call(url, method, params)
            got[name] = r
        if any(v is None for v in got.values()):
            continue
        if any("error" in v[0] for v in got.values()):
            errors += 1
            continue
        for name, (_, ms) in got.items():
            t[name].setdefault(method, []).append(ms)
    return t, errors


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def report(title, t):
    print(f"\n{title}")
    print(f"{'method':<20}{'n':>5}  {'Clio p50':>9}{'p90':>8}{'p99':>8}  {'Astraea p50':>12}{'p90':>8}{'p99':>8}")
    for m in sorted(set(t["clio"]) | set(t["astraea"])):
        c, a = t["clio"].get(m, []), t["astraea"].get(m, [])
        if not c or not a:
            continue
        print(f"{m:<20}{len(c):>5}  {statistics.median(c):>9.1f}{pct(c, 90):>8.1f}{pct(c, 99):>8.1f}"
              f"  {statistics.median(a):>12.1f}{pct(a, 90):>8.1f}{pct(a, 99):>8.1f}")


def load(url, accounts, seconds, clients=16):
    done, lat, errs = [0], [], [0]
    stop = time.time() + seconds
    lock = threading.Lock()

    def worker(seed):
        rnd = random.Random(seed)
        while time.time() < stop:
            acc = rnd.choice(accounts)
            try:
                r, ms = rpc(url, "account_tx", {"account": acc, "limit": 50,
                                                  "ledger_index_min": FIRST, "ledger_index_max": LAST})
                with lock:
                    if "error" in r:
                        errs[0] += 1
                    else:
                        done[0] += 1
                        lat.append(ms)
            except Exception:
                with lock:
                    errs[0] += 1

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(clients)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    return done[0] / seconds, statistics.median(lat) if lat else 0, pct(lat, 99) if lat else 0, errs[0]


sample, accounts = requests()
print(f"range {FIRST}..{LAST}: {len(sample)} requests, {len(accounts)} accounts")
first, e1 = timings(sample)
report(f"first pass, ms (requests with an error on either side: {e1})", first)
second, e2 = timings(sample)
report(f"second pass, same requests, ms (errors: {e2})", second)
print(f"\naccount_tx, 16 clients, {SECONDS} s each")
for name, url in (("Clio", CLIO), ("Astraea", AST)):
    rps, p50, p99, errs = load(url, accounts, SECONDS)
    print(f"{name:<8} {rps:8.1f} req/s   p50 {p50:6.1f} ms   p99 {p99:6.1f} ms   errors {errs}")
