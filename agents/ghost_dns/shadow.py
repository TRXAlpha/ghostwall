"""Shadow mode: score the queries AdGuard Home or Pi-hole already answered.

The firewall stays OUT of the DNS path. The DNS server keeps port 53, so if
anything in Ghostwall crashes or misbehaves, DNS is untouched. This follower
tails the DNS server's query log and feeds each query to the same
Resolver.decide() policy, so events, the dashboard and Telegram alerts work
exactly as in inline mode.

Two log formats:
  - AdGuard Home querylog.json: one JSON object per line. AdGuard buffers
    `querylog.size_memory` entries (1000 by default) before writing, so
    go_shadow.sh lowers that; otherwise alerts can lag by hours.
  - Pi-hole pihole.log (dnsmasq/FTL): one text line per event, written at once.

Nothing can be blocked, which is the point: this is the safe way to prove the
models and the allowlist before ever going inline.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time


def parse_adguard_line(line: str):
    """AdGuard querylog line -> (client_ip, host, qtype) or None."""
    try:
        j = json.loads(line)
    except ValueError:
        return None
    if not isinstance(j, dict):
        return None
    host = j.get("QH")
    ip = j.get("IP")
    if not host or not ip:
        return None
    return str(ip), str(host).rstrip(".").lower(), str(j.get("QT") or "A")


parse_line = parse_adguard_line  # older name, used by replay_querylog and tests

# `Oct 31 12:00:00 dnsmasq[123]: query[A] example.com from 192.168.1.10`, and the
# log-queries=extra form with a serial and client/port before `query`.
_PIHOLE_QUERY = re.compile(r"\bquery\[(?P<qt>[A-Za-z0-9]+)\]\s+(?P<host>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)")


def parse_pihole_line(line: str):
    """Pi-hole log line -> (client_ip, host, qtype) or None (replies, forwards, blocks)."""
    m = _PIHOLE_QUERY.search(line)
    if not m:
        return None
    return m["ip"], m["host"].rstrip(".").lower(), m["qt"].upper()


PARSERS = {"adguard": parse_adguard_line, "pihole": parse_pihole_line}


def detect_format(path: str) -> str:
    """'adguard' or 'pihole', from the first line of the log, else from its name."""
    try:
        with open(path, "rb") as f:
            for raw in f.read(8192).splitlines():
                line = raw.decode("utf-8", "replace").strip()
                if line.startswith("{"):
                    return "adguard"
                if "dnsmasq" in line or "query[" in line:
                    return "pihole"
    except OSError:
        pass
    return "adguard" if path.endswith(".json") or "pihole" not in path.lower() else "pihole"


class QueryLogFollower:
    """Tail a query log. Starts at the current end (no history replay)."""

    def __init__(self, resolver, path: str, poll_seconds: float = 2.0, fmt: str = "auto"):
        self.resolver = resolver
        self.path = path
        self.fmt = detect_format(path) if fmt in (None, "", "auto") else fmt
        if self.fmt not in PARSERS:
            raise ValueError(f"querylog_format must be adguard, pihole or auto, not {fmt!r}")
        self.parse = PARSERS[self.fmt]
        self.poll = poll_seconds
        self.offset = os.path.getsize(path) if os.path.exists(path) else 0
        self._head = self._read_head()
        self._stop = threading.Event()
        self.seen = 0
        self.missing = False  # True while the querylog can't be seen; warned once per outage

    def _read_head(self) -> bytes:
        try:
            with open(self.path, "rb") as f:
                return f.read(64)
        except OSError:
            return b""

    def _rotated(self, size: int) -> bool:
        """The file was replaced/truncated. A size check alone misses a new file
        that has already grown past our old offset, so also compare its first bytes."""
        if size < self.offset:
            return True
        head = self._read_head()
        known = self._head
        if known and head[:len(known)] != known:
            return True
        if len(head) > len(known):
            self._head = head  # remember more of the header as the file grows
        return False

    def poll_once(self) -> int:
        """Process any new complete lines. Returns how many queries were scored."""
        if not os.path.exists(self.path):
            # A missing log means the firewall is blind (wrong path, or systemd ProtectHome
            # hiding it). Say so once instead of silently scoring nothing.
            if not self.missing:
                print(f"[ghost-dns:shadow] WARNING querylog not found: {self.path} -- nothing is being scored",
                      file=sys.stderr, flush=True)
                self.missing = True
            return 0
        if self.missing:
            print(f"[ghost-dns:shadow] querylog is back: {self.path}", file=sys.stderr, flush=True)
            self.missing = False
        size = os.path.getsize(self.path)
        if self._rotated(size):
            self.offset = 0  # AdGuard rotated/truncated the log
            self._head = self._read_head()
        done = 0
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            for raw in f:
                if not raw.endswith(b"\n"):
                    break  # partial line: wait for the rest
                self.offset += len(raw)
                parsed = self.parse(raw.decode("utf-8", "replace").strip())
                if not parsed:
                    continue
                ip, host, qtype = parsed
                try:
                    self.resolver.decide(ip, host, qtype)
                except Exception as exc:  # noqa: BLE001 - never die on one bad line
                    print(f"[ghost-dns:shadow] decide failed for {host}: {exc!r}", file=sys.stderr, flush=True)
                self.resolver.stats["queries"] += 1
                done += 1
        self.seen += done
        return done

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except OSError as exc:
                print(f"[ghost-dns:shadow] read error: {exc}", file=sys.stderr, flush=True)
            time.sleep(self.poll)

    def stop(self) -> None:
        self._stop.set()
