"""proof_entry/proof_tx/proof_ledger in sequence: success rate, time, size, witness-verify check."""
import json, subprocess, sys, time, urllib.request, random, statistics, os, tempfile
A = "http://127.0.0.1:51300"
VERIFY = sys.argv[1]
def rpc(m, p):
    b = json.dumps({"method": m, "params": [p]}).encode()
    r = urllib.request.Request(A, data=b, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r, timeout=60))["result"]
info = rpc("server_info", {})["info"]
lo, hi = map(int, info["complete_ledgers"].split("-"))
led = rpc("ledger", {"ledger_index": hi - 3, "transactions": True, "expand": True})
accts = sorted({t["tx_json"]["Account"] for t in led["ledger"]["transactions"]})[:40]
txs = [t["hash"] for t in led["ledger"]["transactions"]][:5]
res = {"ok": 0, "err": {}, "ms": [], "bytes": [], "verified": 0, "verify_fail": []}
def one(m, p, verify):
    t0 = time.time(); r = rpc(m, p); ms = (time.time() - t0) * 1000
    if r.get("status") == "error":
        res["err"][r.get("error")] = res["err"].get(r.get("error"), 0) + 1; return
    res["ok"] += 1; res["ms"].append(ms)
    body = json.dumps(r["proof"]); res["bytes"].append(len(body))
    if verify:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(body); path = f.name
        out = subprocess.run([VERIFY, "evidence", path], capture_output=True, text=True)
        os.unlink(path)
        if out.returncode == 0: res["verified"] += 1
        else: res["verify_fail"].append((m, out.stdout[-300:] + out.stderr[-300:]))
for i, a in enumerate(accts[:30]):
    one("proof_entry", {"account_root": a}, i % 3 == 0)
    time.sleep(1.2)
print("proof_entry", res["ok"], "of 30, errors", res["err"], "ms p50/max %.0f/%.0f" % (statistics.median(res["ms"]), max(res["ms"])) if res["ms"] else "",
      "bytes p50 %d" % statistics.median(res["bytes"]) if res["bytes"] else "", "verified", res["verified"], res["verify_fail"][:2])
for name, calls in (("proof_tx", [("proof_tx", {"transaction": h}) for h in txs]),
                    ("proof_ledger recent/old", [("proof_ledger", {"ledger_index": hi - 2}), ("proof_ledger", {"ledger_index": hi - 300}), ("proof_ledger", {"ledger_index": lo + 10})])):
    res.update(ok=0, err={}, ms=[], bytes=[], verified=0, verify_fail=[])
    for m, p in calls: one(m, p, True)
    print(name, res["ok"], "of", len(calls), "errors", res["err"], "ms", [round(x) for x in res["ms"]], "bytes", res["bytes"], "verified", res["verified"], res["verify_fail"][:2])
