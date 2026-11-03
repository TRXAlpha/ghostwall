"""Which MAC address has an IP address right now, from the kernel's neighbour table
(ARP for IPv4, NDP for IPv6), read over netlink, the way `ip neigh` does; /proc/net/arp
(IPv4 only) if netlink can't be used. A device that just sent this box a DNS query is in
it: the box needed its MAC to answer.

Used to keep a device's name on the device rather than on an address: DHCP can give the
laptop's old address to the TV, and a phone's IPv6 privacy addresses change every day.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import struct
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


# netlink: rtnetlink neighbour dump (linux/neighbour.h)
_RTM_NEWNEIGH, _RTM_GETNEIGH = 28, 30
_NLM_F_REQUEST, _NLM_F_DUMP = 0x1, 0x300
_NLMSG_ERROR, _NLMSG_DONE = 2, 3
_NDA_DST, _NDA_LLADDR = 1, 2
# REACHABLE, STALE, DELAY, PROBE, PERMANENT: the MAC is known (not INCOMPLETE/FAILED/NOARP)
_NUD_KNOWN = 0x02 | 0x04 | 0x08 | 0x10 | 0x80
_NL_HDR = struct.Struct("=LHHLL")
_ND_MSG = struct.Struct("=BxxxiHBB")


def parse_neigh_dump(data: bytes) -> tuple[dict[str, str], bool]:
    """({ip: mac}, done) from one buffer of an RTM_GETNEIGH dump."""
    out: dict[str, str] = {}
    off = 0
    while off + _NL_HDR.size <= len(data):
        length, typ = _NL_HDR.unpack_from(data, off)[:2]
        if length < _NL_HDR.size:
            break
        if typ == _NLMSG_DONE:
            return out, True
        if typ == _NLMSG_ERROR:
            raise OSError("netlink neighbour dump refused")
        if typ == _RTM_NEWNEIGH and length >= _NL_HDR.size + _ND_MSG.size:
            family, _ifindex, state = _ND_MSG.unpack_from(data, off + _NL_HDR.size)[:3]
            dst = ll = None
            a, end = off + _NL_HDR.size + _ND_MSG.size, off + length
            while a + 4 <= end:
                alen, atype = struct.unpack_from("=HH", data, a)
                if alen < 4:
                    break
                val = data[a + 4:a + alen]
                if atype == _NDA_DST and family in (socket.AF_INET, socket.AF_INET6):
                    try:
                        dst = socket.inet_ntop(family, val)
                    except (ValueError, OSError):
                        dst = None
                elif atype == _NDA_LLADDR and len(val) == 6:
                    ll = normalize_mac(":".join(f"{b:02x}" for b in val))
                a += (alen + 3) & ~3
            if dst and ll and state & _NUD_KNOWN:
                out[dst] = ll
        off += (length + 3) & ~3
    return out, False


def read_netlink(timeout: float = 2.0) -> dict[str, str]:
    """{ip: mac} for the IPv4 and IPv6 neighbours whose MAC is known. Raises OSError
    where netlink is not available."""
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)   # NETLINK_ROUTE
    try:
        s.settimeout(timeout)
        s.sendto(_NL_HDR.pack(_NL_HDR.size + _ND_MSG.size, _RTM_GETNEIGH, _NLM_F_REQUEST | _NLM_F_DUMP, 1, 0)
                 + _ND_MSG.pack(socket.AF_UNSPEC, 0, 0, 0, 0), (0, 0))
        out: dict[str, str] = {}
        while True:
            part, done = parse_neigh_dump(s.recv(1 << 16))
            out.update(part)
            if done:
                return out
    finally:
        s.close()


def read_neighbours(path: str = ARP_PATH) -> dict[str, str]:
    """The kernel's table (netlink, else /proc/net/arp) for the default path; a file in
    /proc/net/arp's format for any other path (tests, or a table you export)."""
    if path == ARP_PATH:
        try:
            return read_netlink()
        except (OSError, AttributeError):   # no AF_NETLINK (not Linux) or not allowed
            pass
    return read_arp(path)


def canonical_ip(ip: str) -> str:
    """One spelling per address: compressed IPv6, and IPv4 for an IPv4-mapped one."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return str(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return a.compressed


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
        self._table = {canonical_ip(k): v for k, v in read_neighbours(self.path).items()}
        self._read_at = self.clock()

    def mac(self, ip: str) -> str | None:
        ip = canonical_ip(ip)
        now = self.clock()
        if now - self._read_at >= self.ttl:
            self._refresh()
        elif ip not in self._table and now - self._read_at >= self.miss_ttl:
            self._refresh()
        return self._table.get(ip)
