"""A view of which destination IPs were recently handed out by ghost-dns.

ghost-dns appends every A/AAAA answer it forwards to resolved_ips.jsonl. This
class tails that file (incremental byte offset) into an ip -> last-seen-epoch
map with a TTL, so ghost-flow can tell a DNS-driven connection from a raw-IP
one. If the file is absent (ghost-dns not running) every IP is simply unknown.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone


def _iso_to_epoch(s: str) -> float:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return time.time()


class ResolvedIPs:
    def __init__(self, path: str, ttl_seconds: int = 3600):
        self.path = path
        self.ttl = ttl_seconds
        self._ips: dict[str, float] = {}
        self._dom: dict[str, str] = {}
        self._offset = 0

    def add(self, ip: str, domain: str | None = None, when: float | None = None) -> None:
        self._ips[ip] = when if when is not None else time.time()
        if domain:
            self._dom[ip] = domain

    def refresh(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, "rb") as f:
                f.seek(self._offset)
                for raw in f:
                    self._offset += len(raw)
                    try:
                        rec = json.loads(raw.decode("utf-8", "replace"))
                    except ValueError:
                        continue
                    ip = rec.get("ip")
                    if ip:
                        self._ips[ip] = _iso_to_epoch(rec.get("time", ""))
                        if rec.get("domain"):
                            self._dom[ip] = rec["domain"]
        except OSError:
            return

    def _purge(self) -> None:
        cutoff = time.time() - self.ttl
        for ip in [k for k, v in self._ips.items() if v < cutoff]:
            del self._ips[ip]
            self._dom.pop(ip, None)

    def knows(self, ip: str) -> bool:
        self.refresh()
        self._purge()
        return ip in self._ips

    def domain_for(self, ip: str) -> str | None:
        return self._dom.get(ip)
