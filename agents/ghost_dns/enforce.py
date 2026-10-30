"""Enforcement bridge to the nftables `ghostwall` table (see
agents/netconf/out/ghostwall.nft).

Two backends:
  - NullBackend : records intent only, changes nothing on the host. The DEFAULT
                  everywhere except a Pi with enforcement explicitly enabled, and
                  the only backend used in tests / on the Windows dev box.
  - NftBackend  : shells out to `nft` to add/remove set elements and the
                  lockdown rule. Every IP is validated before it reaches the
                  command line, so a crafted device name or domain can never
                  inject shell/nft syntax.

Domain blocking is NOT done here -- that happens in the resolver (sinkhole /
NXDOMAIN). This bridge only handles the three things that need the kernel:
isolating a device, blackholing a destination IP, and LAN lockdown.
"""
from __future__ import annotations

import ipaddress
import subprocess
import threading

TABLE = "inet ghostwall"
SET_ISOLATED = "isolated_dev"
SET_BLOCKED_IP = "blocked_ip"
# A stable comment tag so the lockdown rule can be found and deleted again.
LOCKDOWN_TAG = "ghostwall_lockdown"


def _valid_ip(ip: str) -> str:
    """Return the normalised address or raise ValueError. Guards the nft CLI."""
    return str(ipaddress.ip_address(ip))


class NullBackend:
    """Records calls; touches nothing. Safe default."""

    def __init__(self):
        self.calls: list[tuple] = []

    def _run(self, *args: str) -> None:
        self.calls.append(args)

    def lockdown_on(self, pi_ip: str) -> None:
        self._run("insert", "rule", *TABLE.split(), "forward", "lockdown", pi_ip)

    def lockdown_off(self, pi_ip: str) -> None:
        self._run("delete", "rule", *TABLE.split(), "forward", "lockdown")

    @property
    def name(self) -> str:
        return "null"


class NftBackend:
    """Real nftables backend (Linux + root). Imported lazily by the app."""

    def __init__(self, nft: str = "nft"):
        self.nft = nft

    @property
    def name(self) -> str:
        return "nft"

    def _run(self, *args: str) -> None:
        subprocess.run([self.nft, *args], check=True,
                       capture_output=True, text=True, timeout=5)

    def lockdown_on(self, pi_ip: str) -> None:
        self._run("insert", "rule", "inet", "ghostwall", "forward", "position", "0",
                  "iifname", "!=", "tailscale0",
                  "ip", "daddr", "!=", pi_ip, "ip", "saddr", "!=", pi_ip,
                  "drop", "comment", f'"{LOCKDOWN_TAG}"')

    def lockdown_off(self, pi_ip: str) -> None:
        # nft can only delete a rule by handle, so find the lockdown rule's
        # handle from `nft -a list chain` and delete that.
        out = subprocess.run(
            [self.nft, "-a", "list", "chain", "inet", "ghostwall", "forward"],
            check=True, capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if LOCKDOWN_TAG in line and "handle" in line:
                handle = line.rsplit("handle", 1)[1].strip()
                self._run("delete", "rule", "inet", "ghostwall", "forward",
                          "handle", handle)
                return


class Enforcer:
    """Thread-safe facade over a backend. The resolver/control-API call these."""

    def __init__(self, backend=None):
        self.backend = backend or NullBackend()
        self._lock = threading.Lock()
        self.lockdown = False

    # -- device isolation -------------------------------------------------
    def isolate(self, ip: str) -> None:
        ip = _valid_ip(ip)
        with self._lock:
            self.backend._run("add", "element", *TABLE.split(), SET_ISOLATED,
                              "{", ip, "}")

    def release(self, ip: str) -> None:
        ip = _valid_ip(ip)
        with self._lock:
            self.backend._run("delete", "element", *TABLE.split(), SET_ISOLATED,
                              "{", ip, "}")

    # -- destination blackhole -------------------------------------------
    def block_ip(self, ip: str, timeout: str | None = "24h") -> None:
        ip = _valid_ip(ip)
        elem = [ip] + (["timeout", timeout] if timeout else [])
        with self._lock:
            self.backend._run("add", "element", *TABLE.split(), SET_BLOCKED_IP,
                              "{", *elem, "}")

    def unblock_ip(self, ip: str) -> None:
        ip = _valid_ip(ip)
        with self._lock:
            self.backend._run("delete", "element", *TABLE.split(), SET_BLOCKED_IP,
                              "{", ip, "}")

    # -- LAN lockdown -----------------------------------------------------
    def set_lockdown(self, on: bool, pi_ip: str = "192.168.1.20") -> bool:
        """Toggle the forward-chain lockdown rule. Returns the new state."""
        pi_ip = _valid_ip(pi_ip)
        with self._lock:
            if on and not self.lockdown:
                self.backend.lockdown_on(pi_ip)
                self.lockdown = True
            elif not on and self.lockdown:
                self.backend.lockdown_off(pi_ip)
                self.lockdown = False
            return self.lockdown
