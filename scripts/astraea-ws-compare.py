"""Compares the shape of WebSocket responses with Clio: top-level fields for
forwarded and native methods. No dependencies, it uses its own minimal
WebSocket client. Run on the host: python3 -I scripts/astraea-ws-compare.py.
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
bad = 0
for m in ["fee", "server_state", "ledger_current", "server_info", "ping"]:
    out = []
    for port in (51233, 51300):
        s, rest = ws(port); send(s, {"command": m, "id": 7, "api_version": 2}); r, _ = recv(s, rest); s.close()
        out.append(sorted(k for k in r if k != "warnings"))
    ok = out[0] == out[1]; bad += not ok
    print("OK  " if ok else "DIFF", m, "" if ok else f"clio {out[0]} astraea {out[1]}")
print("differences:", bad)
