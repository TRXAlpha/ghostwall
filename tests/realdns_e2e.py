#!/usr/bin/env python3
"""End to end against a real AdGuard Home or Pi-hole (CI starts the container): does
Ghostwall read the answer codes they really log, and does nx_burst fire on a storm of
made-up domains while a normal lookup, a missing name under a real domain and a name the
DNS server itself blocks (answered NXDOMAIN) never count?

    tests/realdns_e2e.py block --server adguard --port 5354 --api http://127.0.0.1:3000 --user ci --password ...
    tests/realdns_e2e.py query --port 5354
    tests/realdns_e2e.py check --format adguard --log work/data/querylog.json

`block` is the DNS-server blocking feature (agents/ghost_dns/dns_block.py) against the real server:
with dns_block_feed on, a name in a test feed is refused (the CI servers answer blocked names
NXDOMAIN) and a Trusted name in the same feed is not; a second pass registers nothing twice;
`ghostwall unblock` lets the refused name through. `check` then confirms Ghostwall reads those
blocks from the real log and says "blocked by your DNS server" in the threat_feed alert.

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
STATE_BLOCK = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "realdns_block.json")
FEED_BAD = "example.org"        # in the test feed: must be refused
FEED_TRUSTED = "example.net"    # in the test feed and Trusted in Ghostwall: must resolve
CANARY = "use-application-dns.net"
REAL = "example.com"                               # resolves (A and AAAA)
MISSING_SUB = "ghostwall-ci-missing.example.com"   # a missing name under a real domain
BLOCKED = "blockedtest-ghostwall.example"          # the DNS server blocks it itself


def made_up(n: int) -> list[str]:
    rng = random.SystemRandom()
    return ["".join(rng.sample(WORDS, 4)) + ".com" for _ in range(n)]


def ask(name: str, qtype: int, port: int) -> str:
    """Send one query to 127.0.0.1:port; what the reply says (dnsmsg.reply_status), or
    "BLOCKED" for a null answer (0.0.0.0 / ::, Pi-hole's and AdGuard's default blocking)."""
    import dnsmsg
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        for _ in range(3):
            s.sendto(q, ("127.0.0.1", port))
            try:
                reply = s.recv(4096)
                ips = dnsmsg.extract_answer_ips(reply)
                if ips and all(ip in ("0.0.0.0", "::") for ip in ips):
                    return "BLOCKED"
                return dnsmsg.reply_status(reply)
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


def wait_for(name: str, want: str, port: int, tries: int = 15) -> str:
    """The server needs a moment to load a changed list: ask until the answer is `want`.
    want="REFUSED" accepts either way a DNS server blocks: NXDOMAIN or a null answer."""
    got = ""
    for _ in range(tries):
        got = ask(name, 1, port)
        if got == want or (want == "REFUSED" and got in ("NXDOMAIN", "BLOCKED")):
            break
        time.sleep(1)
    return got


def cmd_block(a) -> int:
    import tempfile
    import dns_block
    from state import GhostState
    d = tempfile.mkdtemp(prefix="gw-block-")
    feed = os.path.join(d, "threat_feed.txt")
    with open(feed, "w") as f:
        f.write(f"#@source\thttps://feed.example/test\t2026-11-07\tTest feed\tmalware\n{FEED_BAD}\n{FEED_TRUSTED}\n")
    cfg = os.path.join(d, "ghost_dns.json")
    with open(cfg, "w") as f:
        json.dump({"state_path": os.path.join(d, "state.json"), "threat_feed_path": feed,
                   "events_path": os.path.join(d, "events.jsonl"), "allowlist_path": None}, f)
    st = GhostState(os.path.join(d, "state.json"))
    st.allow(FEED_TRUSTED)                         # `ghostwall allow example.net`
    env = dict(os.environ, DNS_SOURCE=a.server, DNS_BLOCK_FEED="on", DNS_BLOCK_ADS="off", DNS_BLOCK_BYPASS="off",
               DNS_BLOCK_BIND="0.0.0.0", DNS_BLOCK_PORT="5382",
               # AdGuard resolves a list's URL with its own DNS (not the container's hosts
               # file), so the URL holds an address: the DNS container's gateway (CI sets it).
               DNS_BLOCK_URL=f"http://{os.environ.get('BLOCK_HOST', '127.0.0.1')}:5382/ghostwall-blocklist.txt",
               ADGUARD_URL=a.api, ADGUARD_USER=a.user, ADGUARD_PASSWORD=a.password,
               PIHOLE_URL=a.api, PIHOLE_PASSWORD=a.password,
               DNS_BLOCK_CANARIES="on" if a.server == "adguard" else "off")

    def once(label: str) -> str:
        r = subprocess.run([sys.executable, os.path.join(GD, "dns_block.py"), "once", "--config", cfg],
                           capture_output=True, text=True, timeout=1200, env=env)
        out = r.stdout + r.stderr
        print(f"--- dns_block once ({label}) rc={r.returncode}\n{out}")
        if r.returncode != 0:
            raise SystemExit(f"FAIL: dns_block once ({label}) exited {r.returncode}")
        if a.password in out:
            raise SystemExit("FAIL: the DNS server password is in dns_block's output")
        return out

    def registered() -> int:
        s = dns_block.load_settings(env, cfg)
        cl = dns_block.AdGuard(s, dns_block.Http()) if a.server == "adguard" else dns_block.PiHole(s, dns_block.Http())
        if a.server == "adguard":
            return sum(1 for u in cl.lists(cl.status()) if u == s["url"])
        cl.login()
        try:
            return sum(1 for u in cl.lists() if u == s["url"])
        finally:
            cl.logout()

    bad = []
    once("register")
    if wait_for(FEED_BAD, "REFUSED", a.port) not in ("NXDOMAIN", "BLOCKED"):
        bad.append(f"{FEED_BAD} is in the registered feed but was not refused")
    for name in (FEED_TRUSTED, REAL):
        if wait_for(name, "NOERROR", a.port, tries=3) != "NOERROR":
            bad.append(f"{name} should resolve (Trusted / not listed) but did not")
    if a.server == "adguard" and wait_for(CANARY, "NXDOMAIN", a.port) != "NXDOMAIN":
        bad.append(f"{CANARY} (Firefox canary) should be NXDOMAIN")
    n = registered()
    if n != 1:
        bad.append(f"expected the list registered once, found {n}")
    second = once("again, nothing changed")
    if "added" in second:
        bad.append("a second pass registered something again")
    n = registered()
    if n != 1:
        bad.append(f"after a second pass the list is registered {n} times")
    st.set_dns_exception(FEED_BAD)                 # `ghostwall unblock example.org`
    once("unblock")
    if wait_for(FEED_BAD, "NOERROR", a.port) != "NOERROR":
        bad.append(f"{FEED_BAD} should resolve after `ghostwall unblock` but is still refused")
    st.set_dns_exception(FEED_BAD, False)          # `ghostwall unblock --undo`
    once("undo")
    if wait_for(FEED_BAD, "REFUSED", a.port) not in ("NXDOMAIN", "BLOCKED"):
        bad.append(f"{FEED_BAD} should be refused again after `unblock --undo`")
    if bad:
        print("FAIL:\n  " + "\n  ".join(bad))
        return 1
    with open(STATE_BLOCK, "w") as f:
        json.dump({"feed": feed, "bad": FEED_BAD}, f)
    print("OK: the real", a.server, "refuses the feed name, lets the Trusted one through, registers once, "
          "and follows unblock and undo")
    return 0


def check_block(log: str) -> int:
    """The threat_feed alert for the refused name says the DNS server blocked it."""
    if not os.path.exists(STATE_BLOCK):
        return 0
    with open(STATE_BLOCK) as f:
        info = json.load(f)
    ev = os.path.join(os.path.dirname(STATE_BLOCK), "realdns_block_events.jsonl")
    if os.path.exists(ev):
        os.remove(ev)
    out = subprocess.run([sys.executable, os.path.join(GD, "replay_querylog.py"), "--querylog", log,
                          "--feed", info["feed"], "--popular", "", "--events-out", ev],
                         capture_output=True, text=True, timeout=600)
    print(out.stdout[-2000:], out.stderr[-1000:])
    alerts = []
    if os.path.exists(ev):
        with open(ev) as f:
            alerts = [json.loads(ln) for ln in f if ln.strip()]
    feed_alerts = [e for e in alerts if e.get("rule") == "threat_feed" and e.get("domain") == info["bad"]]
    if not any("blocked by your DNS server" in " ".join(e.get("reasons") or []) for e in feed_alerts):
        print(f"FAIL: no threat_feed alert for {info['bad']} saying it was blocked by the DNS server: {feed_alerts}")
        return 1
    print("OK: the threat_feed alert says the name was blocked by the DNS server")
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
    return check_block(a.log)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("block")
    b.add_argument("--server", choices=["adguard", "pihole"], required=True)
    b.add_argument("--port", type=int, required=True, help="the DNS port to ask")
    b.add_argument("--api", required=True, help="the DNS server's web address, e.g. http://127.0.0.1:3000")
    b.add_argument("--user", default="")
    b.add_argument("--password", required=True)
    q = sub.add_parser("query")
    q.add_argument("--port", type=int, required=True)
    c = sub.add_parser("check")
    c.add_argument("--format", choices=["adguard", "pihole"], required=True)
    c.add_argument("--log", required=True)
    a = ap.parse_args(argv)
    return {"query": cmd_query, "check": cmd_check, "block": cmd_block}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
