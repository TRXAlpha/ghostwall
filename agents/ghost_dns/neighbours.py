"""Which MAC address has an IPv4 address right now, from the kernel's neighbour (ARP)
table in /proc/net/arp. A device that just sent this box a DNS query is in it: the box
needed its MAC to answer, or learnt it from the device's own ARP request.

Used to keep a device's name on the device rather than on an address: DHCP can give
the laptop's old address to the TV. IPv6 addresses are not in this table (their
neighbours are only on netlink), so IPv6 clients keep being known by address.
"""
from __future__ import annotations

import re
import time

ARP_PATH = "/proc/net/arp"
ATF_COM = 0x2                       # entry complete: the MAC is known
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def normalize_mac(mac) -> str | None:
    """aa:bb:cc:dd:ee:ff, or None for anything that isn't a usable MAC."""
    m = str(mac or "").strip().lower().replace("-", ":")
    if not MAC_RE.match(m) or m == "00:00:00:00:00:00":
        return None
    return m


def read_arp(path: str = ARP_PATH) -> dict[str, str]:
    """{ip: mac} for the complete entries of an /proc/net/arp style file."""
    out: dict[str, str] = {}
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            next(f, None)                                   # header line
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                try:
                    flags = int(parts[2], 16)
                except ValueError:
                    continue
                mac = normalize_mac(parts[3])
                if flags & ATF_COM and mac:
                    out[parts[0]] = mac
    except OSError:
        return {}
    return out


class Neighbours:
    """Cached view of the ARP table: re-read at most every `ttl` seconds, and sooner
    (at most every `miss_ttl`) when asked about an address it doesn't know yet, so a
    device's first query already finds its MAC."""

    def __init__(self, path: str = ARP_PATH, ttl: float = 30.0, miss_ttl: float = 2.0,
                 clock=time.monotonic):
        self.path, self.ttl, self.miss_ttl, self.clock = path, ttl, miss_ttl, clock
        self._table: dict[str, str] = {}
        self._read_at = -1e18

    def _refresh(self) -> None:
        self._table = read_arp(self.path)
        self._read_at = self.clock()

    def mac(self, ip: str) -> str | None:
        now = self.clock()
        if now - self._read_at >= self.ttl:
            self._refresh()
        elif ip not in self._table and now - self._read_at >= self.miss_ttl:
            self._refresh()
        return self._table.get(ip)
