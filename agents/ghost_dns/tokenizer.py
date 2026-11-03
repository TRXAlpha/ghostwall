"""Domain tokenizer + registrable-part logic. numpy only, no model deps.

Must stay byte-for-byte compatible with trm/data.py (the TRM training tokenizer:
last 64 bytes, pad=0, unk=1).

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

# Small built-in public-suffix list. Incomplete by design: it covers the common
# TLDs and 2-level suffixes we actually see.
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

# Dynamic-DNS and free-subdomain providers: each name under them belongs to someone
# else, so the label to score is the one left of the provider. Without this every
# host of e.g. corebot (<random>.ddns.net) is scored as "ddns" and looks harmless.
# Hosting and CDN suffixes (cloudfront.net, herokuapp.com, ...) are deliberately not
# here: their machine-made host names would be scored and flood the alerts.
DYNAMIC_DNS_SUFFIXES = frozenset("""
ddns.net ddns.me ddnsking.com ddnsfree.com duckdns.org dynu.net dynv6.net dedyn.io
no-ip.biz no-ip.info no-ip.org no-ip.ca noip.me noip.us
hopto.org hopto.me zapto.org sytes.net myftp.biz myftp.org myvnc.com redirectme.net
bounceme.net serveftp.com servegame.com servehttp.com serveblog.net servebeer.com
servemp3.com servepics.com servequake.com serveminecraft.net servecounterstrike.com
servehalflife.com serveexchange.com servep2p.com gotdns.ch loginto.me onthewifi.com
3utilities.com webhop.me freeddns.org freedynamicdns.net freedynamicdns.org
dyndns.org dyndns.biz dyndns.info dyndns.tv dyndns.ws homeip.net homelinux.com
homelinux.net homelinux.org dynalias.com dynalias.net dynalias.org selfip.com
selfip.net selfip.org dnsalias.com dnsalias.net dnsalias.org gotdns.com gotdns.org
blogdns.com blogdns.net blogdns.org is-a-geek.com is-a-geek.net is-a-geek.org
mooo.com chickenkiller.com us.to crabdance.com strangled.net twilightparadox.com
ignorelist.com jumpingcrab.com dynserv.com yi.org dns-dynamic.net changeip.com
changeip.net changeip.org dnsdojo.com dnsdojo.net dnsdojo.org afraid.org
""".split())

# Second-level labels that countries use under their TLD (com.ua, gov.br, edu.cn,
# ac.id, or.jp, ...). The list above names only some of them.
_GENERIC_SLD = frozenset("com net org edu gov ac co or ne go mil gob nom lg ed gv sch ltd plc biz info".split())


def is_public_suffix(suffix: str) -> bool:
    """True if names directly under `suffix` belong to different owners."""
    if suffix in PUBLIC_SUFFIXES or suffix in DYNAMIC_DNS_SUFFIXES:
        return True
    sld, _, tld = suffix.partition(".")
    return len(tld) == 2 and tld.isalpha() and "." not in tld and sld in _GENERIC_SLD


def registrable_part(host: str) -> str:
    """Drop the public suffix; return '<label>.<suffix>' (or the host if short)."""
    host = host.strip().rstrip(".").lower()
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if is_public_suffix(last2):
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
