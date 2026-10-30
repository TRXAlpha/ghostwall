"""Raw-IP-to-unknown-host detection.

A connection to a public IP that ghost-dns never resolved means the client
reached the address without a DNS lookup -- a classic sign of malware with a
hardcoded C2, or DNS bypass. Connections to private/loopback/link-local/
multicast addresses are ignored (LAN chatter), as are IPs on the static
exceptions list (NTP pools, update CDNs that clients reach by cached IP, etc.).
"""
from __future__ import annotations

import ipaddress


def is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> don't alert
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
            or a.is_reserved or a.is_unspecified)


class RawIPDetector:
    def __init__(self, resolved, exceptions: set[str] | None = None):
        self.resolved = resolved
        self.exceptions = exceptions or set()

    def check(self, dst_ip: str) -> str | None:
        """Return a reason string if this destination is a raw-IP connection,
        else None."""
        if is_local(dst_ip) or dst_ip in self.exceptions:
            return None
        if self.resolved.knows(dst_ip):
            return None
        return f"connection to {dst_ip} with no preceding DNS lookup"
