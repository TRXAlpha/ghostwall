"""Domain tokenizer + registrable-part logic. numpy only, no model deps.

Must stay byte-for-byte compatible with:
  - trm/data.py          (the TRM training tokenizer: last 64 bytes, pad=0, unk=1)
  - research/dns_scorer/scorer.py (the first, standalone Pi inference copy)

Both the ONNX TRM model and the numpy logistic-regression scorer consume these
exact token ids, so do not change the vocab or the mapping without re-exporting
the models.
"""
from __future__ import annotations

import numpy as np

MAX_LEN = 64
VOCAB = "abcdefghijklmnopqrstuvwxyz0123456789-._"
PAD, UNK = 0, 1
N_TOKENS = len(VOCAB) + 2
DOT = VOCAB.index(".") + 2

# byte -> token id lookup table (A-Z fold to a-z, everything else -> UNK)
_LUT = bytearray([UNK]) * 256
for _i, _ch in enumerate(VOCAB):
    _LUT[ord(_ch)] = _i + 2
    if _ch.isalpha():
        _LUT[ord(_ch.upper())] = _i + 2

# Small built-in public-suffix list (same set as the Pi scorer). Incomplete by
# design: it covers the common TLDs and 2-level suffixes we actually see.
PUBLIC_SUFFIXES = frozenset("""
com net org edu gov mil int info biz xyz online site store tech app dev io
co uk co.uk org.uk ac.uk gov.uk me.uk net.uk sch.uk
com.au net.au org.au edu.au gov.au id.au
co.nz net.nz org.nz
co.jp ne.jp or.jp ac.jp go.jp
com.br com.mx com.ar com.co com.cn com.tw com.hk com.sg com.my com.tr com.ru
co.in co.za co.il co.kr co.id co.th
eu de fr it es nl se no fi dk pt pl cz at ch be gr hu ro ie bg hr sk si lt lv ee
ca us mx br ar cl pe za ng ke gh eg in pk bd lk np ir il sa ae qa kw om jo tr
ru ua by kz ge am az md cn jp kr hk tw mo sg my id th vn ph mm kh la mn
cat asia aero name pro museum travel jobs mobi tel xxx post shop club top wang win
me tv cc ws nu to ai sh ac st
""".split())


def registrable_part(host: str) -> str:
    """Drop the public suffix; return '<label>.<suffix>' (or the host if short)."""
    host = host.strip().rstrip(".").lower()
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def registrable_label(host: str) -> str:
    """The single DGA-relevant label: the registrable part with the suffix and
    any sub-labels removed (what the models were trained on -- dots stripped)."""
    reg = registrable_part(host)
    return reg.split(".")[0] if reg else ""


def encode(domains: list[str], max_len: int = MAX_LEN) -> np.ndarray:
    """list[str] -> int64 tokens [N, max_len]. Keeps the LAST max_len bytes,
    left-aligned with trailing pad -- identical layout to trm/data.py."""
    n = len(domains)
    out = np.zeros((n, max_len), dtype=np.int64)
    for i, d in enumerate(domains):
        b = d.encode("utf-8")[-max_len:]
        row = [_LUT[c] for c in b]
        out[i, : len(row)] = row
    return out


def strip_dot(tokens: np.ndarray) -> np.ndarray:
    """Zero out every token at or after the first '.' in each row (a copy).

    The DRIFT dataset leaks a shortcut (benign names keep dots, DGA labels do
    not), so both models were trained dot-stripped and must be fed the same."""
    t = np.array(tokens, copy=True)
    hit = t == DOT
    first = np.where(hit.any(1), hit.argmax(1), t.shape[1])
    t[np.arange(t.shape[1])[None, :] >= first[:, None]] = 0
    return t
