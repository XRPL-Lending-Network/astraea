"""Live comparison of subscriptions with Clio: both systems subscribe to
ledger and the 30 most active accounts (api 2), and to transactions (api 1 and 2);
messages are compared in full for the ledgers both have published, along with
message order. Run on the host: python3 -I
scripts/astraea-subs-compare.py [seconds].
"""
import base64, json, os, socket, struct
def ws(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
    return s, buf.split(b"\r\n\r\n", 1)[1]
def send(s, obj):
    d = json.dumps(obj).encode(); m = os.urandom(4)
    h = bytes([0x81]) + (bytes([0x80 | len(d)]) if len(d) < 126 else bytes([0x80 | 126]) + struct.pack(">H", len(d)))
    s.sendall(h + m + bytes(b ^ m[i % 4] for i, b in enumerate(d)))
def recv(s, rest):
    buf, data = rest, b""
    def need(n):
        nonlocal buf
        while len(buf) < n: buf += s.recv(65536)
    while True:
        need(2); fin = buf[0] & 0x80; n = buf[1] & 0x7F; at = 2
        if n == 126: need(4); n = struct.unpack(">H", buf[2:4])[0]; at = 4
        elif n == 127: need(10); n = struct.unpack(">Q", buf[2:10])[0]; at = 10
        need(at + n); data += buf[at:at + n]; buf = buf[at + n:]
        if fin: return json.loads(data), buf
import json, time, threading, urllib.request, collections, sys
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 90
def rpc(m, p):
    b = json.dumps({"method": m, "params": [p]}).encode()
    return json.load(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:51233", b), timeout=10))["result"]
c = collections.Counter()
top = rpc("ledger", {})["ledger_index"]
for i in range(5):
    for t in rpc("ledger", {"ledger_index": top - i, "transactions": True, "expand": True})["ledger"]["transactions"]:
        c[t["tx_json"]["Account"]] += 1
accounts = [a for a, _ in c.most_common(30)]
got = {}
def listen(name, port, req):
    s, rest = ws(port); send(s, req); s.settimeout(1); msgs = []
    t0 = time.time()
    while time.time() - t0 < DUR:
        try:
            r, rest = recv(s, rest); msgs.append(r)
        except Exception:
            pass
    s.close(); got[name] = msgs
reqs = {
    "ledger+accounts v2": {"id": 1, "command": "subscribe", "streams": ["ledger"], "accounts": accounts},
    "transactions v1": {"id": 2, "command": "subscribe", "streams": ["transactions"], "api_version": 1},
    "transactions v2": {"id": 3, "command": "subscribe", "streams": ["transactions"], "api_version": 2},
}
th = []
for n, r in reqs.items():
    for sys_, port in (("clio", 51233), ("astraea", 51300)):
        t = threading.Thread(target=listen, args=(f"{n}|{sys_}", port, r)); t.start(); th.append(t)
for t in th: t.join()
def key(m):
    if m.get("type") == "ledgerClosed": return ("L", m["ledger_index"])
    if m.get("type") == "transaction": return ("T", m["ledger_index"], m.get("hash") or m["transaction"]["hash"])
    return ("R",)
bad = 0
for n in reqs:
    cm = {key(m): m for m in got[f"{n}|clio"]}; am = {key(m): m for m in got[f"{n}|astraea"]}
    cr, ar = cm.pop(("R",), {}), am.pop(("R",), {})
    for d in (cr, ar): d.pop("warnings", None)
    if isinstance(cr.get("result"), dict) and cr["result"]: cr["result"] = sorted(cr["result"]); ar["result"] = sorted(ar.get("result", {}))
    print(f"== {n}: subscribe response {'OK' if cr == ar else 'DIFF'}")
    if cr != ar: bad += 1; print("   clio", json.dumps(cr)[:300]); print("   astr", json.dumps(ar)[:300])
    # Compare the ledgers both systems managed to publish.
    lc = {k[1] for k in cm if k[0] == "L"} | {k[1] for k in cm if k[0] == "T"}
    la = {k[1] for k in am if k[0] == "L"} | {k[1] for k in am if k[0] == "T"}
    both = lc & la
    if both:
        both -= {min(both), max(both)}   # the first and last may be incomplete
    ck = {k for k in cm if k[1] in both}; ak = {k for k in am if k[1] in both}
    diffs = 0
    for k in sorted(ck & ak):
        a, b = dict(cm[k]), dict(am[k])
        if k[0] == "L":
            a.pop("validated_ledgers"); b.pop("validated_ledgers")
        if a != b:
            diffs += 1
            if diffs <= 3:
                ks = sorted(set(a) | set(b))
                print("   DIFF", k, [x for x in ks if a.get(x) != b.get(x)])
                for x in ks:
                    if a.get(x) != b.get(x): print("     ", x, "clio:", json.dumps(a.get(x))[:250], "| astr:", json.dumps(b.get(x))[:250])
    only_c, only_a = len(ck - ak), len(ak - ck)
    bad += diffs + only_c + only_a
    print(f"   ledgers in both: {len(both)}, messages: {len(ck & ak)} shared, differences {diffs}, only in Clio {only_c}, only in Astraea {only_a}")
    order_c = [k for k in (key(m) for m in got[f'{n}|clio']) if len(k) > 1 and k[1] in both]
    order_a = [k for k in (key(m) for m in got[f'{n}|astraea']) if len(k) > 1 and k[1] in both]
    print("   message order", "matches" if order_c == order_a else "DIFFERS")
    bad += order_c != order_a
print("total differences:", bad)
