"""Minimal IPv4/IPv6 + TCP/UDP parser (stdlib only).

Just enough to pull 5-tuples, TCP flags and the L4 payload out of a raw packet.
NFQUEUE hands us packets starting at the IP header; pcap frames may start at
Ethernet, so parse() auto-detects and skips an Ethernet header when present.
Never raises on malformed input -- returns None instead.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

PROTO_TCP = 6
PROTO_UDP = 17

# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class Packet:
    version: int           # 4 or 6
    proto: int             # 6 TCP, 17 UDP, or other
    src: str
    dst: str
    sport: int
    dport: int
    flags: int             # TCP flags (0 for UDP)
    payload: bytes         # L4 payload (after TCP/UDP header)

    @property
    def is_syn_only(self) -> bool:
        return self.proto == PROTO_TCP and (self.flags & SYN) and not (self.flags & ACK)


def _strip_ethernet(data: bytes) -> bytes:
    """If data looks like an Ethernet frame (not an IPv4/6 header), skip 14 bytes."""
    if len(data) < 14:
        return data
    v = data[0] >> 4
    if v in (4, 6):
        return data  # already an IP header
    ethertype = struct.unpack(">H", data[12:14])[0]
    if ethertype in (0x0800, 0x86DD):
        return data[14:]
    return data


def parse(data: bytes) -> Packet | None:
    try:
        data = _strip_ethernet(data)
        if not data:
            return None
        version = data[0] >> 4
        if version == 4:
            return _parse_v4(data)
        if version == 6:
            return _parse_v6(data)
    except Exception:  # noqa: BLE001 - untrusted bytes, never crash the loop
        return None
    return None


def _parse_l4(proto: int, l4: bytes):
    if proto == PROTO_TCP:
        if len(l4) < 20:
            return None
        sport, dport = struct.unpack(">HH", l4[0:4])
        data_off = (l4[12] >> 4) * 4
        flags = l4[13]
        return sport, dport, flags, l4[data_off:]
    if proto == PROTO_UDP:
        if len(l4) < 8:
            return None
        sport, dport = struct.unpack(">HH", l4[0:4])
        return sport, dport, 0, l4[8:]
    return 0, 0, 0, b""


def _parse_v4(data: bytes) -> Packet | None:
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    parsed = _parse_l4(proto, data[ihl:])
    if parsed is None:
        return Packet(4, proto, src, dst, 0, 0, 0, b"")
    sport, dport, flags, payload = parsed
    return Packet(4, proto, src, dst, sport, dport, flags, payload)


def _parse_v6(data: bytes) -> Packet | None:
    if len(data) < 40:
        return None
    proto = data[6]  # next header (no ext-header chasing: good enough for TCP/UDP)
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    parsed = _parse_l4(proto, data[40:])
    if parsed is None:
        return Packet(6, proto, src, dst, 0, 0, 0, b"")
    sport, dport, flags, payload = parsed
    return Packet(6, proto, src, dst, sport, dport, flags, payload)
