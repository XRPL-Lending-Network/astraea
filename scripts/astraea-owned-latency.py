"""Latency of the new methods: Astraea vs Clio, over HTTP, identical requests."""
import json, time, urllib.request, random, statistics
A, C = "http://127.0.0.1:51300", "http://127.0.0.1:51233"
def rpc(u, m, p):
    b = json.dumps({"method": m, "params": [p]}).encode()
    r = urllib.request.Request(u, data=b, headers={"Content-Type": "application/json"})
    t0 = time.time(); json.load(urllib.request.urlopen(r, timeout=60)); return (time.time() - t0) * 1000
def info():
    b = json.dumps({"method": "server_info", "params": [{}]}).encode()
    return json.load(urllib.request.urlopen(urllib.request.Request(A, data=b, headers={"Content-Type": "application/json"})))["result"]["info"]
lo, hi = map(int, info()["complete_ledgers"].split("-")); hi -= 5
rng = random.Random(7)
accts = set()
for seq in rng.sample(range(lo, hi), 8):
    b = json.dumps({"method": "ledger", "params": [{"ledger_index": seq, "transactions": True, "expand": True}]}).encode()
    l = json.load(urllib.request.urlopen(urllib.request.Request(C, data=b, headers={"Content-Type": "application/json"})))["result"]
    for t in l["ledger"]["transactions"]:
        accts.add(t["tx_json"]["Account"])
accts = sorted(accts); rng.shuffle(accts)
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(q * len(x)))]
print("method           count   Astraea p50/p95/p99, ms        Clio p50/p95/p99, ms")
for m, mk in (("account_objects", lambda a: {"account": a, "ledger_index": rng.randint(lo, hi)}),
              ("account_lines", lambda a: {"account": a, "ledger_index": rng.randint(lo, hi)}),
              ("account_offers", lambda a: {"account": a, "ledger_index": rng.randint(lo, hi)}),
              ("ledger_data", lambda a: {"ledger_index": rng.randint(lo, hi), "limit": 256})):
    xs, ys = [], []
    for a in accts[:150]:
        p = mk(a)
        xs.append(rpc(A, m, p)); ys.append(rpc(C, m, p))
    print(f"{m:<16} {len(xs):>5}   " + "  ".join(f"{pct(xs, q):6.1f}" for q in (.5, .95, .99)) + "      " + "  ".join(f"{pct(ys, q):6.1f}" for q in (.5, .95, .99)))
