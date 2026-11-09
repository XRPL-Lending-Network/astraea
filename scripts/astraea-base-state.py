#!/usr/bin/env python3
"""Write the whole state of one ledger as an XWLS snapshot, from a public server.

A node that doesn't keep history can't give the state of an old ledger over gRPC,
so `astraea-snapshot` can't reach it. This takes it over JSON-RPC from any
full-history server. The server is not trusted: `astraea-state history-state-replay`
requires the rebuilt root to match the header's AccountHash, and the header's hash
to be the parent hash of the first cold ledger.

Usage: astraea-base-state.py --url https://<server>/ --ledger 32570 --out base.xwls.zst
Needs the `zstd` command.
"""

import argparse
import json
import struct
import subprocess
import time
import urllib.error
import urllib.request

HEADER_LEN = 118
MAGIC = b"XWLS\x00\x01"


def call(url, params):
    body = json.dumps({"method": "ledger_data", "params": [params]}).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "astraea-base-state"},
    )
    for attempt in range(8):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                result = json.load(response)["result"]
                if result.get("status") == "success" or "ledger_index" in result:
                    if "error" not in result:
                        return result
                raise RuntimeError(f"server answered: {result.get('error')}")
        except (urllib.error.URLError, TimeoutError, RuntimeError) as e:
            wait = 2**attempt
            print(f"attempt {attempt + 1}: {e}; waiting {wait} s", flush=True)
            time.sleep(wait)
    raise SystemExit("the server keeps failing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ledger", type=int, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--pause", type=float, default=0.2, help="seconds between pages")
    args = parser.parse_args()

    compress = subprocess.Popen(["zstd", "-q", "-3", "-f", "-o", args.out], stdin=subprocess.PIPE)
    params = {"ledger_index": args.ledger, "binary": True, "limit": 2048}
    objects, pages, seen = 0, 0, None
    while True:
        page = call(args.url, params)
        if seen is None:
            header = bytes.fromhex(page["ledger"]["ledger_data"])
            if len(header) != HEADER_LEN:
                raise SystemExit(f"header is {len(header)} bytes")
            compress.stdin.write(MAGIC + header)
            seen = page["ledger_hash"]
        elif page["ledger_hash"] != seen:
            raise SystemExit("the server changed ledgers between pages")
        for item in page["state"]:
            data = bytes.fromhex(item["data"])
            compress.stdin.write(bytes.fromhex(item["index"]))
            compress.stdin.write(struct.pack("<I", len(data)))
            compress.stdin.write(data)
            objects += 1
        pages += 1
        if pages % 50 == 0:
            print(f"{pages} pages, {objects} objects", flush=True)
        marker = page.get("marker")
        if not marker:
            break
        params["marker"] = marker
        time.sleep(args.pause)
    compress.stdin.close()
    if compress.wait() != 0:
        raise SystemExit("zstd failed")
    print(f"ledger {args.ledger}, hash {seen}: {objects} objects in {pages} pages")


if __name__ == "__main__":
    main()
