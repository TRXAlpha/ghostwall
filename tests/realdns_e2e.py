#!/usr/bin/env python3
"""End to end against a real AdGuard Home or Pi-hole (CI starts the container): does
Ghostwall read the answer codes they really log, and does nx_burst fire on a storm of
made-up domains while a normal lookup, a missing name under a real domain and a name the
DNS server itself blocks (answered NXDOMAIN) never count?

    tests/realdns_e2e.py query --port 5354
    tests/realdns_e2e.py check --format adguard --log work/data/querylog.json

The made-up names are four dictionary words glued together under .com, picked at random
each run (word-like on purpose: they must not trip the "random-looking" rules, which
would raise dga_burst instead and hide what this tests).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GD = os.path.join(ROOT, "agents", "ghost_dns")
sys.path.insert(0, GD)

WORDS = ("amber anchor apple basket beacon birch blanket bottle bramble breeze bucket candle canyon "
         "castle cedar copper cotton crystal falcon feather forest garden harbor hazel honey island "
         "lantern maple marble meadow mirror needle orchard pebble pepper pillow quarry ribbon saddle "
         "silver timber velvet willow").split()
STATE = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "realdns_names.json")
REAL = "example.com"                               # resolves (A and AAAA)
MISSING_SUB = "ghostwall-ci-missing.example.com"   # a missing name under a real domain
BLOCKED = "blockedtest-ghostwall.example"          # the DNS server blocks it itself


def made_up(n: int) -> list[str]:
    rng = random.SystemRandom()
    return ["".join(rng.sample(WORDS, 4)) + ".com" for _ in range(n)]


def ask(name: str, qtype: int, port: int) -> str:
    """Send one query to 127.0.0.1:port; what the reply says (dnsmsg.reply_status)."""
    import dnsmsg
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        for _ in range(3):
            s.sendto(q, ("127.0.0.1", port))
            try:
                return dnsmsg.reply_status(s.recv(4096))
            except socket.timeout:
                continue
        raise SystemExit(f"no answer for {name} from 127.0.0.1:{port}")
    finally:
        s.close()


def cmd_query(a) -> int:
    for _ in range(60):                            # wait until the server answers
        try:
            ask(REAL, 1, a.port)
            break
        except SystemExit:
            time.sleep(2)
    names = made_up(12)
    print("made-up names:", ", ".join(names))
    got = {}
    for name in [REAL, MISSING_SUB, BLOCKED] + names:
        for qtype in (1, 28):                      # A and AAAA, as getaddrinfo does
            qt = "A" if qtype == 1 else "AAAA"
            got[f"{name} {qt}"] = ask(name, qtype, a.port)
            print(f"{name} {qt} -> {got[f'{name} {qt}']}")
        time.sleep(0.5)
    with open(STATE, "w") as f:
        json.dump({"names": names, "client_saw": got}, f)
    return 0


def cmd_check(a) -> int:
    from shadow import parse_adguard_entry, parse_pihole_line, pihole_blocked_host, pihole_reply
    with open(STATE) as f:
        st = json.load(f)
    names, client = st["names"], st["client_saw"]
    with open(a.log, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    print(f"{a.log}: {len(lines)} lines")
    seen: dict[tuple[str, str], tuple] = {}        # (name, qtype) -> what Ghostwall reads
    if a.format == "adguard":
        for line in lines:
            p = parse_adguard_entry(line)
            if p:
                seen[(p[1], p[2])] = (p[3], p[4], p[5])          # blocked, rcode, zone
    else:
        last: dict[str, str] = {}
        for line in lines:
            q = parse_pihole_line(line)
            if q:
                last[q[1]] = q[2]
                seen.setdefault((q[1], q[2]), (False, None, None))
                continue
            host = pihole_blocked_host(line)
            if host and host in last:
                seen[(host, last[host])] = (True, None, None)
                continue
            rep = pihole_reply(line)
            if rep and rep[0] in last and seen.get((rep[0], last[rep[0]]), (False,))[0] is False:
                seen[(rep[0], last[rep[0]])] = (False, rep[1], None)
    for k, v in sorted(seen.items()):
        print("  ", k, v)
    bad, odd = [], []
    raw = {}
    if a.format == "adguard":                      # for the report on a mismatch
        for line in lines:
            try:
                j = json.loads(line)
                raw[(j.get("QH", "").rstrip(".").lower(), j.get("QT"))] = line
            except ValueError:
                pass
    for key, saw in client.items():
        name, qt = key.split()
        got = seen.get((name, qt))
        if name == BLOCKED:
            if not got or not got[0] or got[1] is not None:
                bad.append(f"{key}: the server blocked it; Ghostwall must see it as blocked, read {got}")
        elif got is None:
            bad.append(f"{key}: not in the log")
        elif got[1] != saw:
            # What the server logged differs from what it sent: report it with the raw entry.
            odd.append(f"{key}: the client got {saw}, Ghostwall read {got[1]} from the log\n      "
                       + raw.get((name, qt), "")[:600])
    nx_names = [n for n in names if client.get(f"{n} A") == "NXDOMAIN"]
    if len(nx_names) < 11:
        bad.append(f"only {len(nx_names)} of the made-up names came back NXDOMAIN to the client: {client}")
    if odd:
        print("MISMATCH between what the server sent and what it logged:\n  " + "\n  ".join(odd))
        if len(odd) > 2:
            bad.append(f"{len(odd)} mismatches")
    if bad:
        print("FAIL:\n  " + "\n  ".join(bad))
        return 1

    # The whole pipeline over the real log: one nx_burst, for the storm, and nothing else.
    out = subprocess.run([sys.executable, os.path.join(GD, "replay_querylog.py"), "--querylog", a.log,
                          "--feed", "", "--popular", ""], capture_output=True, text=True, timeout=600)
    print(out.stdout[-3000:], out.stderr[-2000:])
    if out.returncode != 0:
        print("FAIL: replay exited", out.returncode)
        return 1
    alerts = [ln.split() for ln in out.stdout.splitlines() if ln.startswith("  ") and len(ln.split()) == 2]
    counts = {r: int(c) for r, c in alerts if c.isdigit()}
    if counts != {"nx_burst": 1}:
        print(f"FAIL: expected exactly one nx_burst alert, got {counts}")
        return 1
    print("OK: real", a.format, "log read correctly; one nx_burst for the storm, nothing else")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("query")
    q.add_argument("--port", type=int, required=True)
    c = sub.add_parser("check")
    c.add_argument("--format", choices=["adguard", "pihole"], required=True)
    c.add_argument("--log", required=True)
    a = ap.parse_args(argv)
    return cmd_query(a) if a.cmd == "query" else cmd_check(a)


if __name__ == "__main__":
    sys.exit(main())
