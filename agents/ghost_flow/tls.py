"""Minimal TLS ClientHello parser (stdlib only).

Extracts exactly the fields JA4 needs: legacy version, cipher suites,
extension types, SNI presence, ALPN values, supported_versions and
signature_algorithms. Returns None for anything that is not a TLS
ClientHello. Never raises.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

EXT_SNI = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_SIG_ALGS = 0x000D


@dataclass
class ClientHello:
    legacy_version: int                      # from the ClientHello body
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)   # in wire order
    sni: str | None = None
    alpns: list[str] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)


def parse_client_hello(payload: bytes) -> ClientHello | None:
    try:
        return _parse(payload)
    except Exception:  # noqa: BLE001
        return None


def _parse(p: bytes) -> ClientHello | None:
    # TLS record: type(22=handshake) | version(2) | length(2)
    if len(p) < 5 or p[0] != 0x16:
        return None
    rec_len = struct.unpack(">H", p[3:5])[0]
    body = p[5:5 + rec_len] if rec_len else p[5:]
    # Handshake: type(1=ClientHello) | length(3)
    if len(body) < 4 or body[0] != 0x01:
        return None
    hs_len = int.from_bytes(body[1:4], "big")
    ch = body[4:4 + hs_len] if hs_len else body[4:]
    off = 0
    if len(ch) < 2 + 32 + 1:
        return None
    legacy_version = struct.unpack(">H", ch[off:off + 2])[0]
    off += 2
    off += 32  # random
    sid_len = ch[off]; off += 1 + sid_len
    if off + 2 > len(ch):
        return None
    cs_len = struct.unpack(">H", ch[off:off + 2])[0]; off += 2
    ciphers = [struct.unpack(">H", ch[off + i:off + i + 2])[0]
               for i in range(0, cs_len, 2)]
    off += cs_len
    if off >= len(ch):
        return None
    comp_len = ch[off]; off += 1 + comp_len
    out = ClientHello(legacy_version=legacy_version, ciphers=ciphers)
    if off + 2 > len(ch):
        return out  # no extensions
    ext_total = struct.unpack(">H", ch[off:off + 2])[0]; off += 2
    end = min(len(ch), off + ext_total)
    while off + 4 <= end:
        etype, elen = struct.unpack(">HH", ch[off:off + 4])
        off += 4
        edata = ch[off:off + elen]
        off += elen
        out.extensions.append(etype)
        if etype == EXT_SNI:
            out.sni = _parse_sni(edata)
        elif etype == EXT_ALPN:
            out.alpns = _parse_alpn(edata)
        elif etype == EXT_SUPPORTED_VERSIONS:
            out.supported_versions = _parse_supported_versions(edata)
        elif etype == EXT_SIG_ALGS:
            out.sig_algs = _parse_u16_list(edata)
    return out


def _parse_sni(d: bytes) -> str | None:
    # server_name_list length(2) | name_type(1) | name_len(2) | name
    if len(d) < 5:
        return None
    ntype = d[2]
    nlen = struct.unpack(">H", d[3:5])[0]
    if ntype != 0:
        return None
    # SNI is sent as ASCII on the wire (punycode for IDNs), so ascii is correct
    # and the idna codec (which rejects the "ignore" handler) is wrong here.
    return d[5:5 + nlen].decode("ascii", "ignore").lower() if nlen else None


def _parse_alpn(d: bytes) -> list[str]:
    if len(d) < 2:
        return []
    off = 2  # ALPN protocol list length
    out = []
    while off < len(d):
        ln = d[off]; off += 1
        out.append(d[off:off + ln].decode("ascii", "ignore"))
        off += ln
    return out


def _parse_supported_versions(d: bytes) -> list[int]:
    if not d:
        return []
    ln = d[0]
    return [struct.unpack(">H", d[1 + i:3 + i])[0] for i in range(0, ln, 2)]


def _parse_u16_list(d: bytes) -> list[int]:
    if len(d) < 2:
        return []
    ln = struct.unpack(">H", d[0:2])[0]
    return [struct.unpack(">H", d[2 + i:4 + i])[0] for i in range(0, ln, 2)]
