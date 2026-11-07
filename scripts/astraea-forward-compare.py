"""Compares forwarded methods, server_info and mpt_holders with Clio.
Forwarding to a node (fee, server_state, ledger_current, server_definitions):
response shape and the forwarded flag; server_info: fields that mean the same on both; mpt_holders:
the whole response on one ledger, including errors. Run on the host:
python3 -I scripts/astraea-forward-compare.py (Clio on 51233, Astraea on 51300).
"""
import json, sys, urllib.request, time
CLIO, AST = "http://127.0.0.1:51233", "http://127.0.0.1:51300"
def rpc(url, method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {"content-type": "application/json"}), timeout=15) as r:
        return json.load(r)
def shape(o):
    if isinstance(o, dict): return {k: shape(v) for k, v in o.items()}
    if isinstance(o, list): return [shape(o[0])] if o else []
    return type(o).__name__
def drop(d, keys):
    return {k: v for k, v in d.items() if k not in keys}
bad = 0
def same(name, a, b):
    global bad
    ok = a == b
    bad += not ok
    print(("OK  " if ok else "DIFF"), name)
    if not ok:
        print("   clio:", json.dumps(a)[:400]); print("   astr:", json.dumps(b)[:400])
# Forwarding: the whole response shape, since values change from ledger to ledger.
for m in ["fee", "server_state", "ledger_current", "server_definitions"]:
    c, a = rpc(CLIO, m, {}), rpc(AST, m, {})
    same(f"{m}: top level", sorted(drop(c, ["warnings"])), sorted(drop(a, ["warnings"])))
    same(f"{m}: forwarded", c.get("forwarded"), a.get("forwarded"))
    same(f"{m}: result shape", shape(c["result"]) if m != "server_state" else sorted(c["result"]["state"]), shape(a["result"]) if m != "server_state" else sorted(a["result"]["state"]))
c, a = rpc(CLIO, "server_definitions", {}), rpc(AST, "server_definitions", {})
same("server_definitions: values", drop(c["result"], ["hash"]), drop(a["result"], ["hash"]))
# server_info: fields that mean the same on both.
c, a = rpc(CLIO, "server_info", {})["result"], rpc(AST, "server_info", {})["result"]
for k in ["validated", "status"]:
    same(f"server_info.{k}", c.get(k), a.get(k))
ci, ai = c["info"], a["info"]
for k in ["load_factor", "network_id", "validation_quorum"]:
    same(f"server_info.info.{k}", ci.get(k), ai.get(k))
same("server_info.info.validated_ledger: fields", sorted(ci["validated_ledger"]), sorted(ai["validated_ledger"]))
same("server_info.info.time: format", len(ci["time"]), len(ai["time"]))
print("   complete_ledgers clio", ci["complete_ledgers"], "astraea", ai["complete_ledgers"])
# mpt_holders: on the same ledger.
seq = min(rpc(CLIO, "ledger", {})["result"]["ledger_index"], rpc(AST, "ledger", {})["result"]["ledger_index"])
ids = ["06683217C8B4CC998DC684466B3EE24E3030DEC2797803F5", "06683B32BFC43C52B501BBACF1E46D66D0B79C00EC806430"]
cases = []
for i in ids:
    cases += [{"mpt_issuance_id": i}, {"mpt_issuance_id": i, "limit": 1}, {"mpt_issuance_id": i, "limit": 1000}]
cases += [{"mpt_issuance_id": ids[0], "limit": 1, "marker": "D45074F9A73271C1A076B21E8E966FC71B206D2D"},
          {"mpt_issuance_id": "XYZ"}, {}, {"mpt_issuance_id": ids[0], "marker": "zz"}, {"mpt_issuance_id": ids[0], "limit": 0},
          {"mpt_issuance_id": "0000000000000000000000000000000000000000000000AA"}]
for p in cases:
    q = dict(p, ledger_index=seq)
    c, a = rpc(CLIO, "mpt_holders", q)["result"], rpc(AST, "mpt_holders", q)["result"]
    same(f"mpt_holders {json.dumps(p)[:90]}", drop(c, ["request"]), drop(a, ["request"]))
print("differences:", bad)
