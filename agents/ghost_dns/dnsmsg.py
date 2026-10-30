"""Minimal DNS wire-format helpers (stdlib only).

Only what the resolver needs: parse the question (name + qtype) out of a UDP
query, and build three kinds of reply from the original query bytes --
NXDOMAIN, a sinkhole A/AAAA answer, and a verbatim pass-through of an upstream
reply. We never parse answer sections ourselves; forwarding copies upstream's
bytes unchanged.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
               16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 64: "SVCB"}


@dataclass
class Question:
    name: str          # lowercase, no trailing dot
    qtype: int
    qtype_name: str
    end: int           # byte offset just past the question (name+qtype+qclass)


def _parse_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Parse a (possibly compressed) QNAME. Returns (name, offset_after).

    For the question section there is no compression, but we handle a pointer
    defensively so a malformed packet cannot loop forever.
    """
    labels: list[str] = []
    jumped = False
    end_after = offset
    seen = 0
    while True:
        if offset >= len(packet):
            break
        length = packet[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end_after = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(packet):
                break
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                end_after = offset + 2
            jumped = True
            offset = ptr
            seen += 1
            if seen > 32:  # pointer-loop guard
                break
            continue
        offset += 1
        labels.append(packet[offset : offset + length].decode("latin-1"))
        offset += length
    return ".".join(labels).lower(), end_after


def parse_question(packet: bytes) -> Question | None:
    """Parse the first question. Returns None if the packet is too short or has
    no question."""
    if len(packet) < 12:
        return None
    qdcount = struct.unpack(">H", packet[4:6])[0]
    if qdcount < 1:
        return None
    name, after = _parse_name(packet, 12)
    if after + 4 > len(packet):
        return None
    qtype = struct.unpack(">H", packet[after : after + 2])[0]
    return Question(name=name, qtype=qtype,
                    qtype_name=QTYPE_NAMES.get(qtype, str(qtype)),
                    end=after + 4)


def _response_header(packet: bytes, rcode: int, ancount: int) -> bytes:
    tid = packet[:2]
    flags = struct.unpack(">H", packet[2:4])[0]
    rd = flags & 0x0100
    # QR=1, Opcode copied(0), AA=1, TC=0, RD copied, RA=1, Z=0, rcode
    resp_flags = 0x8000 | 0x0400 | rd | 0x0080 | (rcode & 0x0F)
    header = tid + struct.pack(">H", resp_flags)
    header += struct.pack(">HHHH", 1, ancount, 0, 0)
    return header


def build_nxdomain(packet: bytes, question_end: int) -> bytes:
    """NXDOMAIN (rcode 3) echoing the original question, no answers."""
    if len(packet) < 12:
        return packet
    return _response_header(packet, rcode=3, ancount=0) + packet[12:question_end]


def build_servfail(packet: bytes, question_end: int) -> bytes:
    """SERVFAIL (rcode 2) -- used when the upstream can't be reached, so clients
    retry rather than caching a bogus NXDOMAIN."""
    if len(packet) < 12:
        return packet
    return _response_header(packet, rcode=2, ancount=0) + packet[12:question_end]


def build_sinkhole(packet: bytes, q: Question, ipv4: str, ipv6: str | None = None,
                   ttl: int = 60) -> bytes:
    """Answer A/AAAA queries with a sinkhole address; NODATA for other qtypes.

    Pointing the client at a sinkhole (rather than NXDOMAIN) lets a local
    sinkhole/honeypot observe what the client tries to do, and gives cleaner
    behaviour for browsers than NXDOMAIN. Non-address queries get NOERROR with
    no answer (NODATA)."""
    if len(packet) < 12:
        return packet
    question = packet[12:q.end]
    if q.qtype == 1:  # A
        rdata = socket.inet_aton(ipv4)
        rtype = 1
    elif q.qtype == 28 and ipv6:  # AAAA
        rdata = socket.inet_pton(socket.AF_INET6, ipv6)
        rtype = 28
    else:
        # NODATA: NOERROR, no answer records.
        return _response_header(packet, rcode=0, ancount=0) + question
    header = _response_header(packet, rcode=0, ancount=1)
    # Answer: name pointer to the question (0xC00C), type, class IN, ttl, rdlen, rdata
    answer = struct.pack(">HHHIH", 0xC00C, rtype, 1, ttl, len(rdata)) + rdata
    return header + question + answer


def extract_answer_ips(packet: bytes) -> list[str]:
    """Best-effort pull of A/AAAA addresses from an upstream reply, so the
    resolver can record domain->ip mappings for ghost-flow's raw-IP check.

    Parsing is defensive: on any malformed record we stop and return what we
    have. Never raises."""
    ips: list[str] = []
    try:
        if len(packet) < 12:
            return ips
        qd, an = struct.unpack(">HH", packet[4:8])
        off = 12
        for _ in range(qd):
            _, off = _parse_name(packet, off)
            off += 4  # qtype + qclass
        for _ in range(an):
            _, off = _parse_name(packet, off)
            if off + 10 > len(packet):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", packet[off : off + 10])
            off += 10
            rdata = packet[off : off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    except Exception:  # noqa: BLE001 - parsing untrusted bytes, never crash
        return ips
    return ips
