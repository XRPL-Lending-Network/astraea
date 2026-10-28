"""Full Astraea history: publishes the chunks made by scripts/astraea-full-history.sh
into the live history, in groups, top down.

Chunks are taken strictly in order (each one directly below the previous) and
moved into the group directory groups/G. A group is closed once it has
GROUP_TX transactions or GROUP_LEDGERS ledgers, or reaches the bottom. A closed
group gets indexes (`history-cold-index`: header chain, every transaction and
every account history checked), an adjacency check against the published
history (the hash of the group's last ledger from its index must be the parent
of the next ledger according to the Astraea API; `history-anchor` will not do,
because opening the live directory finishes ingest's pending file swaps), and then
symlinks in the live history directory: segment data, their manifests, index
files and, last, the index manifest. The API extends its range downward only
through indexes, so the group stays invisible until the last link is in place.
Published groups are recorded in published.json. If free space on the data disk
drops below MIN_FREE, a STOP file is written and no new chunks are started.
Run on the host: python3 -I scripts/astraea-full-publish.py (paths as in
astraea-full-history.sh, same environment variables).
"""
import json
import os
import struct
import subprocess
import sys
import time
import urllib.request

HOME = os.environ.get("ASTRAEA_HOME", "/var/lib/astraea")
B = os.environ.get("B", f"{HOME}/src/target/release")
R = os.environ.get("R", f"{HOME}/history-full")
LIVE = os.environ.get("LIVE", f"{HOME}/engine/history")
TOP = int(os.environ["TOP"])  # the ledger just below the history already served
BOTTOM = int(os.environ.get("BOTTOM", "32571"))
CHUNK = 32768
GROUP_TX = int(os.environ.get("GROUP_TX", "40000000"))
GROUP_LEDGERS = int(os.environ.get("GROUP_LEDGERS", "4000000"))
MIN_FREE = 300 << 30
API = "http://127.0.0.1:51300"
STATE = os.path.join(R, "published.json")


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def chunks():
    e = TOP
    while e >= BOTTOM:
        yield max(BOTTOM, e - CHUNK + 1), e
        e -= CHUNK


def run(*args):
    p = subprocess.run([f"{B}/astraea-state", "--db", "/nonexistent", *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{args[0]}: {(p.stderr or p.stdout).strip()[-500:]}")
    return p.stdout.strip()


def rpc(method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(API, body, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["result"]


def complete_ledgers():
    return rpc("server_info", {})["info"]["complete_ledgers"]


def anchor(gd, first, last):
    """Hash of the group's last ledger (from its index .lgr) is the parent
    of the next, already published, ledger."""
    b = open(os.path.join(gd, f"coldidx-{first:010}.lgr"), "rb").read()
    mine = next((h.hex().upper() for h, q in struct.iter_unpack("<32sI", b[10:]) if q == last), None)
    nxt = rpc("ledger", {"ledger_index": last + 1})["ledger"]["parent_hash"]
    if mine is None or mine != nxt:
        raise RuntimeError(f"group does not adjoin: hash of {last} {mine}, parent of {last + 1} {nxt}")
    return f"hash of {last} = parent of {last + 1} ({nxt[:16]}…)"


def space():
    st = os.statvfs(R)
    free = st.f_bavail * st.f_frsize
    stop = os.path.join(R, "STOP")
    if free < MIN_FREE and not os.path.exists(stop):
        open(stop, "w").write(f"{free >> 30} GB free\n")
        log(f"ONLY {free >> 30} GB FREE: STOP, no new chunks will start")
    return free


def publish(g, first, last, tx):
    gd = os.path.join(R, "groups", str(g))
    # Retry after a failure: links to the group's previous indexes are removed before
    # the files themselves (manifest first), otherwise the live directory would be left
    # with a dangling link or a partition overlapping the new one.
    old = sorted((n for n in os.listdir(gd) if n.startswith("coldidx-")), key=lambda n: not n.endswith(".json"))
    for n in old:
        dst = os.path.join(LIVE, n)
        if os.path.islink(dst) and os.readlink(dst) == os.path.join(gd, n):
            os.remove(dst)
    for n in old:
        os.remove(os.path.join(gd, n))
    t0 = time.time()
    log(f"group {g}: indexes {first}..{last}, {tx} transactions")
    out = run("history-cold-index", gd)
    log(f"group {g}: {out} ({time.time() - t0:.0f} s)")
    log(f"group {g}: {anchor(gd, first, last)}")
    names = sorted(os.listdir(gd))
    order = [n for n in names if n.startswith("cold-") and not n.endswith(".json")]
    order += [n for n in names if n.startswith("cold-") and n.endswith(".json")]
    order += [n for n in names if n.startswith("coldidx-") and not n.endswith(".json")]
    order += [n for n in names if n.startswith("coldidx-") and n.endswith(".json")]
    # After a restart some of the group's links may already be in place.
    for n in order:
        dst = os.path.join(LIVE, n)
        if os.path.lexists(dst) and os.readlink(dst) != os.path.join(gd, n):
            raise RuntimeError(f"{n} already exists in live history")
    for n in order:
        if not os.path.lexists(os.path.join(LIVE, n)):
            os.symlink(os.path.join(gd, n), os.path.join(LIVE, n))
    # The API re-reads the directory in the background every 15 s.
    for _ in range(12):
        time.sleep(10)
        cl = complete_ledgers()
        if cl.startswith(f"{first}-"):
            break
    else:
        raise RuntimeError(f"after publishing group {g} the API reports {cl}, expected it to start at {first}")
    log(f"group {g} published: {first}..{last}; complete_ledgers {cl}")


def save(done):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(done, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE)
    d = os.open(R, os.O_RDONLY)
    try:
        os.fsync(d)
    finally:
        os.close(d)


def full(group):
    return group["tx"] >= GROUP_TX or group["last"] - group["first"] + 1 >= GROUP_LEDGERS or group["first"] == BOTTOM


def main():
    os.makedirs(os.path.join(R, "groups"), exist_ok=True)
    done = json.load(open(STATE)) if os.path.exists(STATE) else []
    floor = min((x["first"] for x in done), default=TOP + 1)
    g = len(done)
    group = {"first": None, "last": None, "tx": 0}
    # Chunks already moved into an unpublished group, after a restart.
    gd = os.path.join(R, "groups", str(g))
    for s, e in chunks():
        if e >= floor:
            continue
        mark = os.path.join(R, "chunks", f"{s}.moved")
        if not os.path.exists(mark):
            break
        tx = int(open(mark).read().split()[2])
        group = {"first": s, "last": group["last"] or e, "tx": group["tx"] + tx}
    if group["first"] is not None:
        log(f"continuing group {g}: {group['first']}..{group['last']}")
    def close():
        nonlocal g, gd, group, floor
        publish(g, group["first"], group["last"], group["tx"])
        floor = group["first"]
        done.append({"group": g, **group, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        save(done)
        g += 1
        gd = os.path.join(R, "groups", str(g))
        group = {"first": None, "last": None, "tx": 0}
        log(f"{space() >> 30} GB free on disk; {len(done)} groups published")
    # A group assembled before a restart may already be full (publishing failed).
    if group["first"] is not None and full(group):
        close()
    for s, e in chunks():
        if e >= floor or (group["first"] is not None and s >= group["first"]):
            continue
        ok = os.path.join(R, "chunks", f"{s}.ok")
        fail = os.path.join(R, "chunks", f"{s}.fail")
        waited = 0
        while not os.path.exists(ok):
            if os.path.exists(fail) and waited % 600 == 0:
                log(f"chunk {s}: failed: {open(fail).read().strip()}; waiting for the download to be restarted")
            space()
            time.sleep(30)
            waited += 30
        tx = int(open(ok).read().split()[2])
        cd = os.path.join(R, "chunks", str(s))
        os.makedirs(gd, exist_ok=True)
        # Restart in the middle of a move: some files are already in the group.
        for n in os.listdir(cd) if os.path.isdir(cd) else []:
            os.rename(os.path.join(cd, n), os.path.join(gd, n))
        os.rename(ok, os.path.join(R, "chunks", f"{s}.moved"))
        if os.path.isdir(cd):
            os.rmdir(cd)
        group = {"first": s, "last": group["last"] or e, "tx": group["tx"] + tx}
        if full(group):
            close()
    log("== full history published")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"STOPPED: {e}")
        sys.exit(1)
