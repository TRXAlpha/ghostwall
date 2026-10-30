"""JA4 TLS client fingerprint (FoxIO spec) from a parsed ClientHello.

JA4 = a_b_c
  a = <proto><tls_ver><sni d|i><n_ciphers 2d><n_exts 2d><alpn 2ch>
  b = sha256(sorted cipher-hex csv)[:12]            (GREASE removed)
  c = sha256(sorted ext-hex csv + "_" + sigalg-hex csv)[:12]
        extensions sorted, GREASE/SNI/ALPN removed; sig-algs in original order

Deterministic and widely documented, so a known ClientHello has a known JA4 we
can assert in tests. Only TCP is handled (proto "t"); QUIC would be "q".
"""
from __future__ import annotations

import hashlib

from tls import ClientHello

_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
        0x0300: "s3", 0x0002: "s2"}

EXT_SNI = 0x0000
EXT_ALPN = 0x0010


def _is_grease(v: int) -> bool:
    return v in _GREASE


def _hex12(values: list[int]) -> str:
    joined = ",".join(f"{v:04x}" for v in values)
    return hashlib.sha256(joined.encode()).hexdigest()[:12] if values else "000000000000"


def _version(ch: ClientHello) -> str:
    sv = [v for v in ch.supported_versions if not _is_grease(v)]
    best = max(sv) if sv else ch.legacy_version
    return _VER.get(best, "00")


def _alpn_code(ch: ClientHello) -> str:
    for a in ch.alpns:
        if a:
            return (a[0] + a[-1])
    return "00"


def ja4(ch: ClientHello, proto: str = "t") -> str:
    ciphers = [c for c in ch.ciphers if not _is_grease(c)]
    exts_all = [e for e in ch.extensions if not _is_grease(e)]
    sni = "d" if ch.sni is not None or EXT_SNI in ch.extensions else "i"
    n_cip = min(len(ciphers), 99)
    n_ext = min(len(exts_all), 99)
    a = f"{proto}{_version(ch)}{sni}{n_cip:02d}{n_ext:02d}{_alpn_code(ch)}"

    b = _hex12(sorted(ciphers))

    exts_for_c = sorted(e for e in exts_all if e not in (EXT_SNI, EXT_ALPN))
    sigs = [s for s in ch.sig_algs if not _is_grease(s)]
    ext_csv = ",".join(f"{e:04x}" for e in exts_for_c)
    if sigs:
        raw_c = ext_csv + "_" + ",".join(f"{s:04x}" for s in sigs)
    else:
        raw_c = ext_csv
    c = hashlib.sha256(raw_c.encode()).hexdigest()[:12] if exts_for_c else "000000000000"

    return f"{a}_{b}_{c}"
