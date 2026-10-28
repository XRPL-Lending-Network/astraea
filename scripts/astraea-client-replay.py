"""Acceptance test: client backend requests from the Clio log are replayed
against Clio and Astraea and the responses are compared. Each unique request
(without id) is sent over WebSocket to both systems almost simultaneously; if the responses refer to different ledgers
(validated/current moved between them), the request is retried. Responses
are compared in full, without warnings; for server state methods (server_info,
server_state, fee, ping, ledger_current) only the structure: field paths and types.
Astraea's own fields in server_info (astraea, astraea_version) are
additions, not counted as differences, but they are printed.
submit is not replayed (client transactions are not resubmitted to the network).
Subscriptions are a separate run: with SUBS=<seconds> each unique subscription
is opened in both systems at once, and the subscribe response, the messages for
shared ledgers (the first and last may be incomplete) and their order are compared.
Run on the host: CLIO_HOST=<external host address> python3 -I
scripts/astraea-client-replay.py LOG IP [IP ...], where IP are the clients whose requests
are replayed. Clio answers 127.0.0.1 as an admin (counters, ETL),
so it has to be queried from the same address the client is seen from. Clio is on
51233, Astraea on 127.0.0.1:51300.
"""
import base64
import collections
import json
import os
import random
import re
import socket
import struct
import sys
import threading
import time

CLIO, AST = 51233, 51300
LOG = sys.argv[1]
IPS = set(sys.argv[2:])
CLIO_HOST = os.environ.get("CLIO_HOST", "127.0.0.1")
PER_METHOD = int(os.environ.get("PER_METHOD", "400"))
SKIP = {"submit", "subscribe", "unsubscribe"}
SHAPE = {"server_info", "server_state", "fee", "ping", "ledger_current"}
random.seed(252)

pat = re.compile(r"received request from work queue: (\{.*\}) ip = (\S+)\s*$")


def requests():
    seen = collections.defaultdict(dict)
    total = collections.Counter()
    for line in open(LOG, errors="replace"):
        if "received request" not in line:
            continue
        m = pat.search(line)
        if not m or m.group(2) not in IPS:
            continue
        try:
            r = json.loads(m.group(1))
        except ValueError:
            continue
        if "method" in r:
            p = (r.get("params") or [{}])[0]
            r = dict(p if isinstance(p, dict) else {}, command=r["method"])
        r.pop("id", None)
        meth = r.get("command")
        total[meth] += 1
        seen[meth][json.dumps(r, sort_keys=True)] = r
    return seen, total


def ws(host, port):
    s = socket.create_connection((host, port), timeout=120)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(
        f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return [s, buf.split(b"\r\n\r\n", 1)[1]]


def frame(c, op, d):
    m = os.urandom(4)
    n = len(d)
    if n < 126:
        h = bytes([0x80 | op, 0x80 | n])
    elif n < 65536:
        h = bytes([0x80 | op, 0x80 | 126]) + struct.pack(">H", n)
    else:
        h = bytes([0x80 | op, 0x80 | 127]) + struct.pack(">Q", n)
    c[0].sendall(h + m + bytes(b ^ m[i % 4] for i, b in enumerate(d)))


def send(c, obj):
    frame(c, 0x1, json.dumps(obj).encode())


def recv(c):
    s = c[0]
    data = b""
    while True:
        while len(c[1]) < 2:
            c[1] += s.recv(65536)
        fin = c[1][0] & 0x80
        op = c[1][0] & 0x0F
        n = c[1][1] & 0x7F
        at = 2
        if n == 126:
            while len(c[1]) < 4:
                c[1] += s.recv(65536)
            n = struct.unpack(">H", c[1][2:4])[0]
            at = 4
        elif n == 127:
            while len(c[1]) < 10:
                c[1] += s.recv(65536)
            n = struct.unpack(">Q", c[1][2:10])[0]
            at = 10
        while len(c[1]) < at + n:
            c[1] += s.recv(1 << 20)
        payload = c[1][at:at + n]
        c[1] = c[1][at + n:]
        # Control frames: answer ping with pong, skip pong.
        if op == 0x9:
            frame(c, 0xA, payload)
            continue
        if op == 0xA:
            continue
        if op == 0x8:
            raise ConnectionError("server closed the WebSocket")
        data += payload
        if fin:
            return json.loads(data)


conns = {CLIO: ws(CLIO_HOST, CLIO), AST: ws("127.0.0.1", AST)}


def ask(req):
    out = {}
    for p in (CLIO, AST):
        send(conns[p], dict(req, id=1))
    for p in (CLIO, AST):
        r = recv(conns[p])
        r.pop("warnings", None)
        r.pop("id", None)
        if isinstance(r.get("result"), dict):
            r["result"].pop("warnings", None)
        out[p] = r
    return out[CLIO], out[AST]


def at(r):
    res = r.get("result", {})
    return tuple(res.get(k) for k in ("ledger_index", "ledger_current_index", "ledger_index_max", "ledger_hash"))


def shape(v, path=""):
    if isinstance(v, dict):
        out = {path or "/": "object"}
        for k, x in v.items():
            out.update(shape(x, f"{path}/{k}"))
        return out
    if isinstance(v, list):
        out = {path: "array"}
        if v:
            out.update(shape(v[0], path + "[]"))
        return out
    return {path: type(v).__name__}


def diff(a, b, path=""):
    if type(a) is not type(b):
        return [(path, a, b)]
    if isinstance(a, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append((f"{path}/{k}", a.get(k, "<missing>"), b.get(k, "<missing>")))
            else:
                out += diff(a[k], b[k], f"{path}/{k}")
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [(path + "#len", len(a), len(b))]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, f"{path}[{i}]")
        return out
    return [] if a == b else [(path, a, b)]


def key(m):
    if m.get("type") == "ledgerClosed":
        return ("L", m["ledger_index"])
    if m.get("type") == "transaction":
        return ("T", m["ledger_index"], m.get("hash") or m["transaction"]["hash"])
    return ("R",)


def subscriptions(reqs, seconds):
    got = {}

    def listen(name, host, port, req):
        c = ws(host, port)
        send(c, dict(req, id=1))
        c[0].settimeout(1)
        msgs = []
        t0 = time.time()
        while time.time() - t0 < seconds:
            try:
                msgs.append(recv(c))
            except (socket.timeout, TimeoutError):
                pass
        c[0].close()
        got[name] = msgs

    th = []
    for n, req in enumerate(reqs):
        for side, host, port in (("clio", CLIO_HOST, CLIO), ("astraea", "127.0.0.1", AST)):
            t = threading.Thread(target=listen, args=((n, side), host, port, req))
            t.start()
            th.append(t)
    for t in th:
        t.join()
    bad = 0
    for n, req in enumerate(reqs):
        cm = {key(m): m for m in got[(n, "clio")]}
        am = {key(m): m for m in got[(n, "astraea")]}
        cr, ar = cm.pop(("R",), {}), am.pop(("R",), {})
        for d in (cr, ar):
            d.pop("warnings", None)
            d.pop("id", None)
        brief = {k: (len(v) if isinstance(v, list) else v) for k, v in req.items() if k != "command"}
        print(f"subscribe {json.dumps(brief)}: response {'matches' if cr == ar else 'DIFFERS'}")
        if cr != ar:
            bad += 1
            print("   clio", json.dumps(cr)[:300])
            print("   astr", json.dumps(ar)[:300])
        both = {k[1] for k in cm} & {k[1] for k in am}
        if both:
            both -= {min(both), max(both)}
        ck = {k for k in cm if k[1] in both}
        ak = {k for k in am if k[1] in both}
        diffs = 0
        for k in sorted(ck & ak):
            d = diff(cm[k], am[k])
            if d:
                diffs += 1
                if diffs <= 3:
                    print("   DIFF", k, [(p, json.dumps(x)[:120], json.dumps(y)[:120]) for p, x, y in d[:4]])
        oc = [k for k in map(key, got[(n, "clio")]) if len(k) > 1 and k[1] in both]
        oa = [k for k in map(key, got[(n, "astraea")]) if len(k) > 1 and k[1] in both]
        bad += diffs + len(ck - ak) + len(ak - ck) + (oc != oa)
        print(
            f"   ledgers in both {len(both)}, shared messages {len(ck & ak)}, differences {diffs}, "
            f"only in Clio {len(ck - ak)}, only in Astraea {len(ak - ck)}, order {'matches' if oc == oa else 'DIFFERS'}"
        )
    print("total differences in subscriptions:", bad)


seen, total = requests()
print("client requests in the log:", sum(total.values()), dict(total.most_common()))
if os.environ.get("SUBS"):
    subscriptions(list(seen.get("subscribe", {}).values()), int(os.environ["SUBS"]))
    sys.exit(0)
ADDED = ("/result/info/astraea",)
added = {}
stats = collections.defaultdict(lambda: [0, 0])
examples = collections.defaultdict(list)
for meth, reqs in sorted(seen.items(), key=lambda x: -total[x[0]]):
    if meth in SKIP:
        print(f"{meth}: {len(reqs)} unique, not replayed")
        continue
    sample = list(reqs.values())
    random.shuffle(sample)
    for req in sample[:PER_METHOD]:
        # Astraea confirms a ledger by quorum and can be one ledger behind Clio:
        # wait until both are on the same one.
        for _ in range(40):
            c, a = ask(req)
            if meth in SHAPE or at(c) == at(a):
                break
            time.sleep(0.25)
        if meth in SHAPE:
            sc, sa = shape(c), shape(a)
            d = [(k, sc.get(k, "<missing>"), sa.get(k, "<missing>")) for k in sorted(set(sc) | set(sa)) if sc.get(k) != sa.get(k)]
            own = [k for k, x, _ in d if x == "<missing>" and k.startswith(ADDED)]
            if own and meth not in added:
                added[meth] = own
            d = [x for x in d if x[0] not in own]
        else:
            d = diff(c, a)
        stats[meth][0] += 1
        if d:
            stats[meth][1] += 1
            if len(examples[meth]) < 3:
                examples[meth].append((req, d))
for meth, (n, bad) in stats.items():
    print(f"{meth}: {len(seen[meth])} unique, {n} replayed, {bad} differences")
    for req, d in examples[meth]:
        print("   request", json.dumps(req)[:300])
        for path, x, y in d[:6]:
            print("     ", path, "| clio", json.dumps(x)[:200], "| astraea", json.dumps(y)[:200])
for meth, ks in added.items():
    print(f"{meth}: fields only in Astraea (additions): {', '.join(ks)}")
print("total differences:", sum(b for _, b in stats.values()))
