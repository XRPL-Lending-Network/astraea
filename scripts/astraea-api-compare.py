"""Astraea vs Clio API comparison: identical requests must get identical responses.

Requests are built from live data in the Astraea range: random ledgers,
their transactions, accounts and objects. Each one goes to both systems over HTTP
JSON-RPC; the whole `result` is compared, except fields that are naturally
server-specific (server_info). Some requests are repeated over
WebSocket, which also checks the response envelope.

    python3 astraea-api-compare.py --astraea http://127.0.0.1:51300 --clio http://127.0.0.1:51233
"""
import argparse, base64, collections, json, os, random, socket, sys, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--astraea", default="http://127.0.0.1:51300")
ap.add_argument("--clio", default="http://127.0.0.1:51233")
ap.add_argument("--ledgers", type=int, default=20)
ap.add_argument("--seed", type=int, default=1)
args = ap.parse_args()
rng = random.Random(args.seed)


def rpc(url, method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))


def ws(url, request):
    """A single WebSocket request: a minimal client without libraries."""
    host, port = url.split("//")[1].split(":")
    s = socket.create_connection((host, int(port)), timeout=60)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    rest = buf.split(b"\r\n\r\n", 1)[1]
    payload = json.dumps(request).encode()
    mask = os.urandom(4)
    head = bytes([0x81])
    n = len(payload)
    head += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + n.to_bytes(2, "big")
    s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def need(k):
        nonlocal rest
        while len(rest) < k:
            chunk = s.recv(65536)
            if not chunk:
                raise ConnectionError("WebSocket closed")
            rest += chunk

    # A large response arrives in several frames: collect until FIN.
    message = b""
    while True:
        need(2)
        fin, n, at = rest[0] & 0x80, rest[1] & 0x7F, 2
        if n == 126:
            need(4); n = int.from_bytes(rest[2:4], "big"); at = 4
        elif n == 127:
            need(10); n = int.from_bytes(rest[2:10], "big"); at = 10
        need(at + n)
        message += rest[at:at + n]
        rest = rest[at + n:]
        if fin:
            break
    s.close()
    return json.loads(message)


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


info = rpc(args.astraea, "server_info", {})["result"]["info"]
lo, hi = map(int, info["complete_ledgers"].split("-"))
hi -= 5  # Clio can lag by a ledger or two
print(f"Astraea range {lo}..{hi}")

requests = []
txs, accounts, objects = [], set(), []
for seq in sorted(rng.sample(range(lo, hi), args.ledgers)):
    for api in (1, 2):
        requests.append(("ledger", {"ledger_index": seq, "api_version": api}))
        requests.append(("ledger", {"ledger_index": seq, "transactions": True, "api_version": api}))
        requests.append(("ledger", {"ledger_index": seq, "transactions": True, "expand": True, "api_version": api}))
    requests.append(("ledger", {"ledger_index": seq, "transactions": True, "expand": True, "binary": True}))
    requests.append(("ledger", {"ledger_index": str(seq), "binary": True}))
    led = rpc(args.clio, "ledger", {"ledger_index": seq, "transactions": True, "expand": True})["result"]
    requests.append(("ledger", {"ledger_hash": led["ledger_hash"]}))
    for t in rng.sample(led["ledger"]["transactions"], min(5, len(led["ledger"]["transactions"]))):
        txs.append(t["hash"])
        accounts.add(t["tx_json"]["Account"])
        if "Destination" in t["tx_json"]:
            accounts.add(t["tx_json"]["Destination"])
        for n in t["meta"]["AffectedNodes"]:
            node = next(iter(n.values()))
            if "LedgerIndex" in node and "DeletedNode" not in n:
                objects.append((node["LedgerIndex"], seq))

for h in txs:
    requests.append(("tx", {"transaction": h}))
    requests.append(("tx", {"transaction": h, "api_version": 1}))
    requests.append(("tx", {"transaction": h, "binary": True}))
for a in sorted(accounts)[:60]:
    seq = rng.randint(lo, hi)
    requests.append(("account_info", {"account": a, "ledger_index": seq}))
    requests.append(("account_info", {"account": a, "ledger_index": seq, "signer_lists": True, "api_version": 1}))
    requests.append(("account_info", {"account": a, "ledger_index": seq, "signer_lists": True}))
    requests.append(("account_tx", {"account": a, "ledger_index_min": lo, "ledger_index_max": hi, "limit": 20}))
    requests.append(("account_tx", {"account": a, "ledger_index_min": lo, "ledger_index_max": hi, "limit": 10,
                                    "forward": True, "api_version": 1}))
    requests.append(("account_tx", {"account": a, "ledger_index_min": lo, "ledger_index_max": hi, "limit": 5,
                                    "binary": True}))
for idx, seq in objects[:150]:
    requests.append(("ledger_entry", {"index": idx, "ledger_index": seq}))
    requests.append(("ledger_entry", {"index": idx, "ledger_index": seq, "binary": True}))
for a in sorted(accounts)[:20]:
    requests.append(("ledger_entry", {"account_root": a, "ledger_index": hi}))
    requests.append(("ledger_entry", {"directory": {"owner": a}, "ledger_index": hi}))
# Errors.
requests += [
    ("tx", {"transaction": "00" * 32}),
    ("account_info", {"account": "rBadAddress", "ledger_index": hi}),
    ("account_info", {"account": "rrrrrrrrrrrrrrrrrrrrBZbvji", "ledger_index": hi}),
    ("ledger", {"ledger_index": hi + 1000}),
    ("ledger_entry", {"index": "00" * 32, "ledger_index": hi}),
    ("nonexistent_method", {}),
]

stats, examples = collections.Counter(), {}
pages = 0
for method, params in requests:
    ours, theirs = rpc(args.astraea, method, params)["result"], rpc(args.clio, method, params)["result"]
    for r in (ours, theirs):
        r.pop("request", None) if r.get("status") == "error" else None
    d = diff(ours, theirs, method)
    key = f"{method} v{params.get('api_version', 2)}{' binary' if params.get('binary') else ''}"
    stats[key + (": mismatch" if d else ": match")] += 1
    for p in d:
        examples.setdefault(p.split(":")[0], (method, params, p))
    # Second account_tx page, using the marker from Clio's response, sent to both systems.
    if method == "account_tx" and "marker" in theirs and pages < 60:
        pages += 1
        nxt = dict(params, marker=theirs["marker"])
        o2, t2 = rpc(args.astraea, method, nxt)["result"], rpc(args.clio, method, nxt)["result"]
        d2 = diff(o2, t2, "account_tx/page2")
        stats["account_tx: second page" + (": mismatch" if d2 else ": match")] += 1
        for p in d2:
            examples.setdefault(p.split(":")[0], (method, nxt, p))

def report(title):
    print(title)
    for k, v in sorted(stats.items()):
        print(f"  {v:>5}  {k}")
    for key, (method, params, p) in list(examples.items())[:40]:
        print(f"example {method} {json.dumps(params)[:160]}\n    {p}")
    sys.stdout.flush()


report("HTTP:")
stats, examples = collections.Counter(), {}

# WebSocket: the response envelope and a request with id.
for i, (method, params) in enumerate(requests[:: max(1, len(requests) // 15)]):
    req = dict(params, command=method, id=i)
    o, t = ws(args.astraea, req), ws(args.clio, req)
    for r in (o, t):
        r.pop("warnings", None)
        r.pop("request", None)
    d = diff(o, t, f"ws/{method}")
    stats["ws" + (": mismatch" if d else ": match")] += 1
    for p in d:
        examples.setdefault(p.split(":")[0], (method, req, p))

report("WebSocket:")
