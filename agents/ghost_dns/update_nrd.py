#!/usr/bin/env python3
"""Download the newly-registered-domains (NRD) list into nrd_domains.bin (rule new_domain).

    python update_nrd.py [--out nrd_domains.bin] [--config ghost_dns.json] [--days 14]
                         [--force] [--check NAME]

Source: HaGeZi's NRD lists (https://github.com/hagezi/nrd, GPL-3.0; downloaded here and
never redistributed), built from Stamus Labs' registration data. Five non-overlapping
bands of 7 days: registered in the last 7 days, 8 to 14, 15 to 21, 22 to 28, 29 to 35.
nrd_days (ghost_dns.json; default 14) picks how many are fetched: 14 days is two files,
about 4.9 million names, 80 MB of text each day (about 25 MB on the wire, gzip), and 39 MiB
in the resolver (8 bytes a name, see nrdfile.py and detectors.NrdList).

Runs as part of the daily feed service (ghostwall-feed.service, ExecStartPost) and does
nothing, not even a download, while nrd_mode is "off" (it removes an old list then). It
reads nrd_mode and nrd_days from the same ghost_dns.json as ghost-dns (--config, else
GHOSTWALL_CONFIG, else /etc/ghostwall/ghost_dns.json). --force downloads whatever the mode.

Like update_feed.py: https only, streamed (never the whole text in memory: the names are
hashed as they arrive, about 8 bytes each), written atomically, and the old list is kept
when anything looks wrong: a band that cannot be fetched (raw.githubusercontent.com first,
then the jsDelivr mirror), is shorter than the header says it is (a cut-off download), is
tiny, or shrank to less than half of yesterday's. The bands are one rolling window, so
they are replaced together or not at all. Exit 1 means the file was not written. Popular
sites are not filtered out here: ghost-dns never calls a top-1M name new.
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import os
import re
import sys
import urllib.request
from array import array

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nrdfile  # noqa: E402

SOURCE = "HaGeZi NRD (Stamus Labs data)"
RAW = "https://raw.githubusercontent.com/hagezi/nrd/main/domains/{name}.txt"
MIRROR = "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/{name}.txt"
BAND_FILES = ("nrd7", "nrd14-8", "nrd21-15", "nrd28-22", "nrd35-29")   # band i covers 7*i+1 .. 7*(i+1) days ago
MAX_BYTES = 400 * 1024 * 1024    # decompressed, per band (the real one is about 45 MB)
MIN_BAND = 100_000               # a real band has more than 2 million names
SHRINK_RATIO = 0.5               # a band half its last size looks broken ...
SHRINK_DAYS = 3                  # ... while the old list is this fresh
MAX_BAD_LINES = 0.01             # more junk lines than this: not a domain list
DEFAULT_CONFIG = "/etc/ghostwall/ghost_dns.json"
_HOST = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_ENTRIES = re.compile(r"^#\s*Number of entries:\s*(\d+)", re.I)


def open_url(url: str, timeout: float = 120.0):
    """A readable byte stream of the response body, gunzipped when the server compressed it."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing {url}: only https://")
    req = urllib.request.Request(url, headers={"User-Agent": "ghostwall-nrd/1.0", "Accept-Encoding": "gzip"})
    resp = urllib.request.urlopen(req, timeout=timeout)
    if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
        return gzip.GzipFile(fileobj=resp)
    return resp


def hash_lines(lines) -> tuple[array, int, int]:
    """(hashes in list order, declared number of entries or 0, junk lines) of a domain list
    given as an iterable of text lines or bytes. Names are lowercased; comments, blank lines,
    IP addresses, single labels and anything that is not a hostname are skipped (junk counts
    the last of these)."""
    out = array("Q")
    declared = junk = 0
    for raw in lines:
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        line = line.strip().lower()
        if not line:
            continue
        if line.startswith("#"):
            m = _ENTRIES.match(line)
            if m:
                declared = int(m.group(1))
            continue
        if "." not in line or _IPV4.match(line) or not _HOST.match(line):
            junk += 1
            continue
        out.append(nrdfile.hash64(line))
    return out, declared, junk


def check_band(hashes: array, declared: int, junk: int, name: str) -> None:
    """Raise ValueError if a downloaded band cannot be the list it claims to be."""
    n = len(hashes)
    if n < MIN_BAND:
        raise ValueError(f"{name}: only {n} names")
    if junk > MAX_BAD_LINES * (n + junk):
        raise ValueError(f"{name}: {junk} of {n + junk} lines are not domain names")
    if declared and n < 0.95 * declared:
        raise ValueError(f"{name}: {n} names, its header says {declared} (cut off?)")


def fetch_band(name: str) -> tuple[array, int]:
    """(hashes, declared count) of one band: from GitHub, else from the jsDelivr mirror."""
    errors = []
    for template in (RAW, MIRROR):
        url = template.format(name=name)
        try:
            with open_url(url) as stream:
                seen = 0

                def capped():
                    nonlocal seen
                    for line in stream:
                        seen += len(line)
                        if seen > MAX_BYTES:
                            raise ValueError(f"larger than {MAX_BYTES // 2 ** 20} MB, refusing")
                        yield line

                hashes, declared, junk = hash_lines(capped())
            check_band(hashes, declared, junk, name)
            return hashes, declared
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url.split('/')[2]}: {exc}")
    raise ValueError("; ".join(errors))


def band_days(i: int) -> int:
    return nrdfile.BAND_DAYS * (i + 1)


def previous_counts(path: str) -> tuple[str, dict[int, int]]:
    """(built date, {band days: names}) of the list on disk, or ("", {}) if none is usable."""
    try:
        head = nrdfile.header(path)
    except (OSError, ValueError):
        return "", {}
    return head["built"], {b["days"]: b["count"] for b in head["bands"]}


def _age_days(built: str, today: datetime.date | None = None) -> int:
    try:
        return ((today or datetime.date.today()) - datetime.date.fromisoformat(built)).days
    except ValueError:
        return 10 ** 6


def update(out: str, days: int, fetch=fetch_band, today: datetime.date | None = None) -> int:
    """Fetch the bands for `days`, check them, write `out`. 0 = written, 1 = not (old file kept)."""
    n_bands = nrdfile.window_days(days) // nrdfile.BAND_DAYS
    built, old = previous_counts(out)
    day = (today or datetime.date.today()).isoformat()
    bands, meta = [], []
    for i in range(n_bands):
        name = BAND_FILES[i]
        try:
            hashes, declared = fetch(name)
        except Exception as exc:  # noqa: BLE001
            print(f"[nrd] FAILED {name}: {exc}; keeping the existing list"
                  + (f" (built {built})" if built else " (there is none)"), file=sys.stderr)
            return 1
        days_i = band_days(i)
        before = old.get(days_i)
        if before and len(hashes) < SHRINK_RATIO * before and _age_days(built, today) <= SHRINK_DAYS:
            print(f"[nrd] {name}: only {len(hashes)} names, {before} last time; looks broken, "
                  f"keeping the existing list (built {built})", file=sys.stderr)
            return 1
        print(f"[nrd] {name}: {len(hashes)} names (registered {_range_text(days_i)})")
        bands.append((days_i, hashes))
        meta.append({"file": name, "fetched": day})
    nrdfile.write(out, bands, day, SOURCE, meta)
    total = sum(len(h) for _, h in bands)
    print(f"[nrd] wrote {total} names ({nrdfile.window_days(days)} days, {total * 8 / 2 ** 20:.1f} MiB in memory) to {out}")
    return 0


def _range_text(days: int) -> str:
    return f"in the last {days} days" if days <= nrdfile.BAND_DAYS else \
        f"{days - nrdfile.BAND_DAYS + 1} to {days} days ago"


def check(path: str, name: str) -> int:
    """Say whether NAME is on the list at `path` and how young it is (for `--check`)."""
    try:
        head, bands = nrdfile.read(path)
    except (OSError, ValueError) as exc:
        print(f"[nrd] can't read {path}: {exc}", file=sys.stderr)
        return 1
    from tokenizer import registrable_part
    name = name.strip().lower().rstrip(".")
    for cand in dict.fromkeys((registrable_part(name), name)):
        h = nrdfile.hash64(cand)
        for days, hashes in bands:
            if h in hashes:
                print(f"{cand} is on the list: registered {_range_text(days)} (list built {head['built']})")
                return 0
    print(f"{name} is not on the list (built {head['built']}, {sum(len(h) for _, h in bands)} names)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="update the Ghostwall newly-registered-domains list")
    ap.add_argument("--out", default=None, help="the list to write (default: nrd_path from the config, "
                                                "else nrd_domains.bin next to this script)")
    ap.add_argument("--config", default=os.environ.get("GHOSTWALL_CONFIG") or (
        DEFAULT_CONFIG if os.path.exists(DEFAULT_CONFIG) else None), help="ghost_dns.json (nrd_mode, nrd_days)")
    ap.add_argument("--days", type=int, default=None, help="window in days (default: nrd_days, 14)")
    ap.add_argument("--force", action="store_true", help="download although nrd_mode is off")
    ap.add_argument("--check", metavar="NAME", help="say whether NAME is on the list on disk, and exit")
    args = ap.parse_args(argv)

    import config as config_mod
    try:
        cfg = config_mod.load_config(args.config)
    except (ValueError, OSError) as exc:
        print(f"[nrd] can't use {args.config}: {exc}", file=sys.stderr)
        return 1
    out = args.out or cfg.get("nrd_path") or os.path.join(HERE, "nrd_domains.bin")
    if args.check:
        return check(out, args.check)
    mode = cfg.get("nrd_mode", "off")
    if mode == "off" and not args.force:
        if os.path.exists(out):
            os.remove(out)
            print(f"[nrd] nrd_mode is off; removed {out}")
        else:
            print("[nrd] nrd_mode is off; nothing to do (set it to alert in ghost_dns.json to use the list)")
        return 0
    days = args.days or int(cfg.get("nrd_days", 14))
    if not 1 <= days <= nrdfile.MAX_BANDS * nrdfile.BAND_DAYS:
        print(f"[nrd] --days must be 1 to {nrdfile.MAX_BANDS * nrdfile.BAND_DAYS}", file=sys.stderr)
        return 1
    return update(out, days)


if __name__ == "__main__":
    sys.exit(main())
