#!/usr/bin/env python3
"""Download IP reputation lists into ip_blocklist.txt (gateway mode drops LAN traffic to them).

    python update_ipfeed.py [--out ip_blocklist.txt] [--min 500]

Only high-confidence lists (agents/dga_eval research notes): Spamhaus DROP and DROPv6
(networks run by criminals, hijacked or leased to spammers and botnet operators; "Don't
Route Or Peer"), abuse.ch SSLBL botnet C2 addresses and Feodo Tracker botnet C2 addresses
(often empty after takedowns: that is fine). FireHOL level1 is deliberately not used: it
holds private and bogon ranges that break outbound use.

Each source is written under a "#@source" line. A source that fails keeps its previous
contents; the file is written atomically and only when at least --min networks remain.
Anything that isn't a public network, or is wider than a /8 (IPv4) or /19 (IPv6), is
dropped: a typo or a poisoned list must not cut the house off the internet.
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BYTES = 8 * 1024 * 1024
MIN_PREFIX = {4: 8, 6: 19}

SOURCES = [
    ("Spamhaus DROP", "https://www.spamhaus.org/drop/drop_v4.json"),
    ("Spamhaus DROPv6", "https://www.spamhaus.org/drop/drop_v6.json"),
    ("abuse.ch SSLBL", "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"),
    ("abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
]


def fetch(url: str, timeout: float = 60.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ghostwall-ipfeed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url}: larger than {MAX_BYTES // (1024 * 1024)} MB, refusing")
    return data.decode("utf-8", "replace")


def net_ok(net) -> bool:
    """A public network no wider than MIN_PREFIX for its family."""
    return net.prefixlen >= MIN_PREFIX[net.version] and net.network_address.is_global and \
        net.broadcast_address.is_global


def parse_nets(text: str) -> tuple[set[str], int]:
    """(networks, refused count) from Spamhaus NDJSON ({"cidr": ...} lines) or plain
    address / CIDR lines ('#' comments, extra columns ignored)."""
    out, refused = set(), 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("{"):
            try:
                cidr = json.loads(line).get("cidr")
            except ValueError:
                continue
            if not cidr:
                continue                 # Spamhaus' trailing metadata record
        else:
            cidr = line.split("#", 1)[0].replace(",", " ").split()[0]
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            refused += 1
            continue
        if net_ok(net):
            out.add(str(net))
        else:
            refused += 1
    return out, refused


def read_sections(path: str) -> dict[str, tuple[str, list[str]]]:
    """{source name: (fetched date, networks)} from a file this script wrote."""
    out: dict[str, tuple[str, list[str]]] = {}
    name = None
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#@source\t"):
                    parts = (line.split("\t") + ["", ""])[1:3]
                    name = parts[0]
                    out[name] = (parts[1], [])
                elif name and line and not line.startswith("#"):
                    out[name][1].append(line)
    except OSError:
        pass
    return out


def read_networks(path: str) -> tuple[list[str], list[str]]:
    """(IPv4, IPv6) networks from ip_blocklist.txt, each checked again (the file is the
    input to a firewall rule)."""
    v4, v6 = [], []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                if net_ok(net):
                    (v4 if net.version == 4 else v6).append(str(net))
    except OSError:
        pass
    return v4, v6


def _write_atomic(path: str, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".ipfeed-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="update the Ghostwall IP reputation list")
    ap.add_argument("--out", default=os.path.join(HERE, "ip_blocklist.txt"))
    ap.add_argument("--min", type=int, default=500, help="refuse to write fewer networks than this")
    args = ap.parse_args(argv)

    previous = read_sections(args.out)
    today = datetime.date.today().isoformat()
    sections, fresh, failed = [], 0, 0
    for name, url in SOURCES:
        try:
            nets, refused = parse_nets(fetch(url))
            fresh += 1
            print(f"[ipfeed] {name}: {len(nets)} networks" + (f", {refused} refused" if refused else ""))
            sections.append((name, today, sorted(nets)))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            if name in previous:
                fetched, nets = previous[name]
                print(f"[ipfeed] FAILED {name}: {exc}; keeping its {len(nets)} networks from {fetched}",
                      file=sys.stderr)
                sections.append((name, fetched, nets))
            else:
                print(f"[ipfeed] FAILED {name}: {exc}; nothing to keep", file=sys.stderr)
    total = len({n for _, _, nets in sections for n in nets})
    if not fresh or total < args.min:
        print(f"[ipfeed] only {total} networks or nothing downloaded; keeping the existing file", file=sys.stderr)
        return 1
    body = [f"# Ghostwall IP reputation list, {total} networks. Generated by update_ipfeed.py."]
    for name, fetched, nets in sections:
        body.append(f"#@source\t{name}\t{fetched}")
        body.extend(nets)
    _write_atomic(args.out, "\n".join(body) + "\n")
    print(f"[ipfeed] wrote {total} networks to {args.out}")
    if failed:
        print(f"[ipfeed] WARNING: {failed} source(s) failed; the others were updated", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
