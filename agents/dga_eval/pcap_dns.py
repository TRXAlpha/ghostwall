"""DNS queries and their replies out of a packet capture (pcap or pcapng), stdlib only.

Reads the capture as a stream (it can come straight from an HTTP download or a zip
member) and keeps only DNS over UDP or TCP port 53. Captures are untrusted data: every
length is checked and a malformed packet is skipped, never trusted.

    for q in dns_queries(stream):   # q: dict(t, client, server, name, qtype, reply)

`reply` is the raw bytes of the first answer to that query (same client address and
port, server, transaction id and question), or None when the capture has no answer.
"""
from __future__ import annotations

import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ghost_dns"))
import dnsmsg  # noqa: E402

MAX_PACKET = 1 << 18          # bigger "packets" mean a broken file
REPLY_WAIT = 10.0             # seconds a query waits for its answer


class CaptureError(ValueError):
    pass


def _read(f, n: int) -> bytes:
    b = f.read(n)
    while len(b) < n:
        more = f.read(n - len(b))
        if not more:
            break
        b += more
    return b


def packets(f):
    """(time, linktype, frame bytes) for each packet of a pcap or pcapng stream."""
    head = _read(f, 4)
    if len(head) < 4:
        return
    if head == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(f, head)
        return
    magic = head
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise CaptureError("not a pcap or pcapng file")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    rest = _read(f, 20)
    if len(rest) < 20:
        return
    linktype = struct.unpack(end + "I", rest[16:20])[0] & 0x0FFFFFFF
    div = 1e9 if nano else 1e6
    while True:
        h = _read(f, 16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(end + "IIII", h)
        if incl > MAX_PACKET:
            raise CaptureError("packet length out of range")
        data = _read(f, incl)
        if len(data) < incl:
            return
        yield sec + frac / div, linktype, data


def _pcapng(f, first4: bytes):
    end = "<"
    links: list[tuple[int, float]] = []   # per interface: (linktype, seconds per tick)
    block_type_raw = first4
    while True:
        lenb = _read(f, 4)
        if len(lenb) < 4:
            return
        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            bom = _read(f, 4)
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(end + "I", lenb)[0]
            if blen < 28 or blen > MAX_PACKET * 4:
                raise CaptureError("bad pcapng section")
            _read(f, blen - 12)
            links = []
        else:
            btype = struct.unpack(end + "I", block_type_raw)[0]
            blen = struct.unpack(end + "I", lenb)[0]
            if blen < 12 or blen > MAX_PACKET * 4:
                raise CaptureError("bad pcapng block")
            body = _read(f, blen - 8)
            if len(body) < blen - 8:
                return
            body = body[:-4]
            if btype == 1 and len(body) >= 8:              # interface description
                lt = struct.unpack(end + "H", body[:2])[0]
                res = 1e-6
                off = 8
                while off + 4 <= len(body):                # options: if_tsresol
                    code, olen = struct.unpack(end + "HH", body[off:off + 4])
                    if code == 0:
                        break
                    if code == 9 and olen >= 1:
                        v = body[off + 4]
                        res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                    off += 4 + ((olen + 3) & ~3)
                links.append((lt, res))
            elif btype == 6 and len(body) >= 20:           # enhanced packet
                iface, hi, lo, cap, _orig = struct.unpack(end + "IIIII", body[:20])
                if iface < len(links):
                    lt, res = links[iface]
                    yield ((hi << 32) | lo) * res, lt, body[20:20 + cap]
            elif btype == 3 and len(body) >= 4 and links:  # simple packet
                lt, _ = links[0]
                yield 0.0, lt, body[4:]
        block_type_raw = _read(f, 4)
        if len(block_type_raw) < 4:
            return


def _ip_payload(linktype: int, frame: bytes):
    """(ip version, packet bytes starting at the IP header) or None."""
    if linktype == 1:                    # Ethernet
        off, et = 14, struct.unpack(">H", frame[12:14])[0] if len(frame) >= 14 else 0
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
            et = struct.unpack(">H", frame[off + 2:off + 4])[0]
            off += 4
    elif linktype == 113:                # Linux cooked
        off, et = 16, struct.unpack(">H", frame[14:16])[0] if len(frame) >= 16 else 0
    elif linktype == 276:                # Linux cooked v2
        off, et = 20, struct.unpack(">H", frame[0:2])[0] if len(frame) >= 20 else 0
    elif linktype in (0, 108):           # BSD loopback
        off = 4
        et = 0x0800 if frame[off:off + 1] and frame[off] >> 4 == 4 else 0x86DD
    elif linktype in (12, 14, 101, 228, 229):   # raw IP
        off = 0
        et = 0x0800 if frame[:1] and frame[0] >> 4 == 4 else 0x86DD
    else:
        return None
    if et == 0x0800:
        return 4, frame[off:]
    if et == 0x86DD:
        return 6, frame[off:]
    return None


def _ip_text(b: bytes) -> str:
    if len(b) == 4:
        return ".".join(str(x) for x in b)
    import ipaddress
    return str(ipaddress.IPv6Address(b))


def _transport(ver: int, p: bytes):
    """(src, dst, proto, transport bytes) or None."""
    if ver == 4:
        if len(p) < 20:
            return None
        ihl = (p[0] & 0x0F) * 4
        total = struct.unpack(">H", p[2:4])[0]
        frag = struct.unpack(">H", p[6:8])[0]
        if frag & 0x1FFF:                # not the first fragment
            return None
        proto = p[9]
        body = p[ihl:total] if total >= ihl else p[ihl:]
        return _ip_text(p[12:16]), _ip_text(p[16:20]), proto, body
    if len(p) < 40:
        return None
    nxt = p[6]
    plen = struct.unpack(">H", p[4:6])[0]
    body = p[40:40 + plen]
    for _ in range(8):                   # skip extension headers
        if nxt in (0, 43, 60) and len(body) >= 8:
            nxt, body = body[0], body[(body[1] + 1) * 8:]
        elif nxt == 44:                  # fragment header
            if len(body) < 8 or struct.unpack(">H", body[2:4])[0] & 0xFFF8:
                return None
            nxt, body = body[0], body[8:]
        else:
            break
    return _ip_text(p[8:24]), _ip_text(p[24:40]), nxt, body


def dns_messages(f):
    """(time, src, sport, dst, dport, dns message bytes) for port-53 traffic."""
    for t, lt, frame in packets(f):
        ipp = _ip_payload(lt, frame)
        if not ipp:
            continue
        tr = _transport(*ipp)
        if not tr:
            continue
        src, dst, proto, body = tr
        if proto == 17 and len(body) >= 8:
            sport, dport = struct.unpack(">HH", body[:4])
            msg = body[8:]
        elif proto == 6 and len(body) >= 20:
            sport, dport = struct.unpack(">HH", body[:4])
            doff = (body[12] >> 4) * 4
            seg = body[doff:]
            if len(seg) < 14:            # handshake, ack, or too short for a message
                continue
            n = struct.unpack(">H", seg[:2])[0]
            msg = seg[2:2 + n]           # first message of the segment only
        else:
            continue
        if 53 not in (sport, dport) or len(msg) < 12:
            continue
        yield t, src, sport, dst, dport, msg


def dns_queries(f):
    """Each DNS query once, in capture order, with its answer when there is one.

    A query repeated with the same client, transaction id and question within
    REPLY_WAIT seconds (a retry, or the same query sent to a second server) is one
    query, as the device's DNS server would log it once."""
    pending: dict[tuple, dict] = {}
    order: list[dict] = []
    out_upto = 0
    for t, src, sport, dst, dport, msg in dns_messages(f):
        flags = struct.unpack(">H", msg[2:4])[0]
        q = dnsmsg.parse_question(msg)
        if q is None or not q.name:
            continue
        txid = msg[:2]
        if not flags & 0x8000:           # a query
            if dport != 53:
                continue
            key = (src, txid, q.name, q.qtype)
            old = pending.get(key)
            if old is not None and t - old["t"] <= REPLY_WAIT:
                continue
            rec = {"t": t, "client": src, "server": dst, "name": q.name,
                   "qtype": q.qtype_name, "reply": None}
            pending[key] = rec
            order.append(rec)
        else:                            # an answer: to the client that asked
            if sport != 53:
                continue
            rec = pending.get((dst, txid, q.name, q.qtype))
            if rec is not None and rec["reply"] is None and -1 <= t - rec["t"] <= REPLY_WAIT:
                rec["reply"] = bytes(msg)
        # hand out queries whose answer can no longer come
        while out_upto < len(order) and t - order[out_upto]["t"] > REPLY_WAIT:
            out_upto += 1
        if out_upto > 4096:
            done, order = order[:out_upto], order[out_upto:]
            out_upto = 0
            yield from done
            if len(pending) > 200000:
                pending = {k: v for k, v in pending.items() if t - v["t"] <= REPLY_WAIT}
    yield from order


def servers(records) -> set[str]:
    """Addresses that answered DNS in the capture (a resolver or forwarder)."""
    return {r["server"] for r in records if r["reply"] is not None}
