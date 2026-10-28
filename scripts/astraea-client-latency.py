"""Latency of Astraea against Clio on a client's real requests.

Takes the requests a client sent to Clio from the Clio log, keeping their
real mix: a random sample of the log lines, so a request the client sends
often is timed often. Each request goes to both servers over JSON-RPC, one
at a time and in random order. Then each server gets the same sample from 8
parallel clients for a fixed time, and the script reports requests per
second.

submit, subscribe and unsubscribe are left out. Answers are not compared
here (astraea-client-replay.py does that); a request that errors on one side
only is counted and left out of the timings.

Run on the host:
  python3 -I scripts/astraea-client-latency.py LOG SAMPLES SECONDS IP [IP ...]
Clio is queried at 127.0.0.1:51233 (override with CLIO_HOST). From any other
address its DOS guard throttles the load test with 503s; as an admin it adds
a few fields to some answers, which doesn't change the timings. Astraea is
at 127.0.0.1:51300. An HTTP error counts as an error answer.
"""
import collections
import json
import os
import random
import re
import statistics
import sys
import threading
import time
import urllib.request

LOG, SAMPLES, SECONDS = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
IPS = set(sys.argv[4:])
CLIO = f"http://{os.environ.get('CLIO_HOST', '127.0.0.1')}:51233"
AST = "http://127.0.0.1:51300"
SKIP = {"submit", "subscribe", "unsubscribe"}
random.seed(206)
pat = re.compile(r"received request from work queue: (\{.*\}) ip = (\S+)\s*$")


def sample():
    """Reservoir sample of the client's requests, as (method, params)."""
    out, seen, total = [], 0, collections.Counter()
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
            method, params = r["method"], dict(p if isinstance(p, dict) else {})
        else:
            method = r.pop("command", None)
            params = r
        params.pop("id", None)
        if not method or method in SKIP:
            continue
        total[method] += 1
        seen += 1
        if len(out) < SAMPLES:
            out.append((method, params))
        else:
            k = random.randrange(seen)
            if k < SAMPLES:
                out[k] = (method, params)
    return out, total


def rpc(url, method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(url, body, {"content-type": "application/json"})
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            out = json.load(r).get("result", {})
    except urllib.error.HTTPError as e:
        out = {"error": f"http {e.code}"}
    return out, (time.perf_counter() - t) * 1e3


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def failed(r):
    return r.get("status") == "error" or "error" in r


reqs, total = sample()
print(f"{sum(total.values())} client requests in the log; {len(reqs)} sampled")
times = {"clio": collections.defaultdict(list), "astraea": collections.defaultdict(list)}
one_sided = collections.Counter()
both_failed = collections.Counter()
for method, params in reqs:
    order = [("clio", CLIO), ("astraea", AST)]
    random.shuffle(order)
    got = {name: rpc(url, method, params) for name, url in order}
    bad = {name for name, (r, _) in got.items() if failed(r)}
    if len(bad) == 1:
        one_sided[(method, next(iter(bad)))] += 1
        continue
    if bad:
        both_failed[method] += 1
    for name, (_, ms) in got.items():
        times[name][method].append(ms)

print(f"\n{'method':<18}{'share':>7}{'n':>6}  {'Clio p50':>9}{'p90':>8}{'p99':>8}  {'Astraea p50':>12}{'p90':>8}{'p99':>8}")
allc, alla = [], []
for m, count in total.most_common():
    c, a = times["clio"].get(m, []), times["astraea"].get(m, [])
    allc += c
    alla += a
    if not c:
        continue
    share = 100 * count / sum(total.values())
    print(f"{m:<18}{share:>6.1f}%{len(c):>6}  {statistics.median(c):>9.1f}{pct(c, 90):>8.1f}{pct(c, 99):>8.1f}"
          f"  {statistics.median(a):>12.1f}{pct(a, 90):>8.1f}{pct(a, 99):>8.1f}")
print(f"{'all':<18}{'':>7}{len(allc):>6}  {statistics.median(allc):>9.1f}{pct(allc, 90):>8.1f}{pct(allc, 99):>8.1f}"
      f"  {statistics.median(alla):>12.1f}{pct(alla, 90):>8.1f}{pct(alla, 99):>8.1f}")
if one_sided:
    print("\nerror on one side only (left out):", dict(one_sided))
if both_failed:
    print("error on both sides (timed):", dict(both_failed))


def load(url, seconds, clients=8):
    done, lat, errs = [0], [], [0]
    stop = time.time() + seconds
    lock = threading.Lock()

    def worker(seed):
        rnd = random.Random(seed)
        while time.time() < stop:
            method, params = rnd.choice(reqs)
            try:
                r, ms = rpc(url, method, params)
                with lock:
                    done[0] += 1
                    lat.append(ms)
                    errs[0] += failed(r)
            except Exception:
                with lock:
                    errs[0] += 1

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(clients)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    return done[0] / seconds, statistics.median(lat), pct(lat, 99), errs[0]


print(f"\nsame mix, 8 clients, {SECONDS} s each")
for name, url in (("Clio", CLIO), ("Astraea", AST)):
    rps, p50, p99, errs = load(url, SECONDS)
    print(f"{name:<8} {rps:8.1f} req/s   p50 {p50:6.1f} ms   p99 {p99:6.1f} ms   errors {errs}")
