"""The newly-registered-domains file (nrd_domains.bin): written by update_nrd.py, read by
ghost-dns. Stdlib only, so the updater needs no numpy.

Layout: a magic line, one JSON header line, then for each age band its names as 64-bit
hashes (little endian, 8 bytes each, in the order the list gave them: the reader sorts).

    GWNRD1\\n
    {"built": "2026-11-07", "source": "...", "bands": [{"days": 7, "count": 2183043, ...}, ...]}\\n
    <band 1 hashes><band 2 hashes>...

A band holds the domains registered up to `days` days ago and after the previous band's
`days` (7, then 8 to 14, 15 to 21...), the way HaGeZi's lists are cut, so a hit also says
how young the domain is. The hash is detectors._hash64 (blake2b, 8 bytes); a test keeps the
two the same. Hashes instead of names: 8 bytes a domain instead of about 60 in the file and
in memory, and the reader loads a million in a fraction of a second.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from array import array

MAGIC = b"GWNRD1\n"
BAND_DAYS = 7                  # width of one band, in days
MAX_BANDS = 5                  # 35 days: the longest window the source publishes
MAX_HEADER = 8192


def hash64(name: str) -> int:
    return int.from_bytes(hashlib.blake2b(name.encode("utf-8"), digest_size=8).digest(), "big")


def window_days(days) -> int:
    """nrd_days rounded up to whole bands (1..7 -> 7, 8..14 -> 14 ...), at most 35."""
    n = max(1, int(days))
    return min(MAX_BANDS, -(-n // BAND_DAYS)) * BAND_DAYS


def write(path: str, bands: list[tuple[int, array]], built: str, source: str,
          meta: list[dict] | None = None) -> None:
    """Write `bands` ([(days, hashes)] in ascending days) atomically: temporary file in the
    same folder, flushed to disk, then renamed over the old one, so a power cut on an SD
    card leaves the old list or the new one."""
    head = {"built": built, "source": source,
            "bands": [{"days": d, "count": len(h), **(meta[i] if meta else {})}
                      for i, (d, h) in enumerate(bands)]}
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".nrd-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(MAGIC)
            f.write(json.dumps(head, separators=(",", ":")).encode("utf-8") + b"\n")
            for _, h in bands:
                if sys.byteorder == "big":      # pragma: no cover - the file is little endian
                    h = array("Q", h)
                    h.byteswap()
                h.tofile(f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def read_header(f) -> dict:
    """The header of an open file; ValueError if it is not a file this module wrote or
    its size does not match what the header promises (a truncated copy)."""
    if f.read(len(MAGIC)) != MAGIC:
        raise ValueError("not a Ghostwall newly-registered-domains file")
    line = f.readline(MAX_HEADER)
    try:
        head = json.loads(line)
        bands = head["bands"]
        built = head["built"]
        if not isinstance(built, str) or not isinstance(bands, list) or not 1 <= len(bands) <= MAX_BANDS:
            raise ValueError
        last = 0
        for b in bands:
            if (isinstance(b["days"], bool) or not isinstance(b["days"], int) or b["days"] <= last
                    or isinstance(b["count"], bool) or not isinstance(b["count"], int) or b["count"] < 0):
                raise ValueError
            last = b["days"]
    except (ValueError, KeyError, TypeError):
        raise ValueError("unreadable header") from None
    start = f.tell()
    f.seek(0, os.SEEK_END)
    end = f.tell()
    f.seek(start)
    want = sum(b["count"] for b in bands) * 8
    if end - start != want:
        raise ValueError(f"size {end - start} bytes, the header says {want}")
    return head


def header(path: str) -> dict:
    with open(path, "rb") as f:
        return read_header(f)


def read(path: str, max_days: int = MAX_BANDS * BAND_DAYS) -> tuple[dict, list[tuple[int, array]]]:
    """(header, [(days, hashes)]) for the bands up to `max_days`; later bands are not read.
    The hashes are in file order: sort them (detectors._sorted_index) before searching."""
    with open(path, "rb") as f:
        head = read_header(f)
        out = []
        for b in head["bands"]:
            if b["days"] > max_days:
                break
            a = array("Q")
            if b["count"]:
                a.fromfile(f, b["count"])
            if sys.byteorder == "big":          # pragma: no cover
                a.byteswap()
            out.append((b["days"], a))
    return head, out
