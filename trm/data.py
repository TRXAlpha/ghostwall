"""DRIFT (DSN'26) eSLD dataset -> fixed-width uint8 token matrices, cached as .npy.

Token ids: 0 = pad, 1 = unknown char, 2.. = vocabulary below.
"""
import os

import numpy as np
import pyarrow.parquet as pq

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
RAW = os.path.join(ROOT, "drift")
CACHE = os.path.join(ROOT, "cache")
MAX_LEN = 64
VOCAB = "abcdefghijklmnopqrstuvwxyz0123456789-._"
PAD, UNK = 0, 1
N_TOKENS = len(VOCAB) + 2

_LUT = np.full(256, UNK, dtype=np.uint8)
for i, ch in enumerate(VOCAB):
    _LUT[ord(ch)] = i + 2
    if ch.isalpha():
        _LUT[ord(ch.upper())] = i + 2


def encode_strings(strings, max_len=MAX_LEN):
    """list/array of str -> (tokens [N, max_len] uint8, lengths [N] uint8). Keeps the
    LAST max_len chars of longer names (the registrable part is at the end)."""
    import pyarrow as pa
    arr = pa.array(strings, type=pa.large_string()) if not isinstance(strings, pa.Array) else strings
    return _encode_arrow(arr.cast(pa.large_string()), max_len)


def _encode_arrow(arr, max_len):
    n = len(arr)
    bufs = arr.buffers()
    offsets = np.frombuffer(bufs[1], dtype=np.int64, count=n + 1, offset=arr.offset * 8)
    data = np.frombuffer(bufs[2], dtype=np.uint8) if bufs[2] is not None else np.zeros(1, np.uint8)
    lens = offsets[1:] - offsets[:-1]
    start = np.where(lens > max_len, offsets[1:] - max_len, offsets[:-1])
    lens_c = np.minimum(lens, max_len)
    out = np.zeros((n, max_len), dtype=np.uint8)
    for j in range(max_len):  # column-wise gather, fully vectorised
        m = lens_c > j
        out[m, j] = _LUT[data[start[m] + j]]
    return out, lens_c.astype(np.uint8)


DOT = VOCAB.index(".") + 2


def strip_dot(t):
    """Cut every row at its first '.' (in place on a copy). DRIFT leaks a shortcut: benign eSLDs keep
    dots/TLD fragments, DGA names never do. Deployment feeds only the registrable *label*."""
    t = np.array(t, copy=True)
    hit = t == DOT
    first = np.where(hit.any(1), hit.argmax(1), t.shape[1])
    t[np.arange(t.shape[1])[None, :] >= first[:, None]] = 0
    return t


def load_file(name):
    """Encode one parquet file (cached). Returns tokens, lengths, labels, domains-hash."""
    os.makedirs(CACHE, exist_ok=True)
    base = os.path.join(CACHE, name.replace(".parquet", ""))
    if os.path.exists(base + ".tok.npy"):
        return (np.load(base + ".tok.npy", mmap_mode="r"), np.load(base + ".len.npy"),
                np.load(base + ".lab.npy"), np.load(base + ".hash.npy"))
    import pyarrow as pa
    import pyarrow.compute as pc
    t = pq.read_table(os.path.join(RAW, name), columns=["domain", "label"])
    dom = pc.utf8_lower(t.column("domain").combine_chunks().cast(pa.large_string()))
    tok, ln = _encode_arrow(dom, MAX_LEN)
    lab = t.column("label").to_numpy().astype(np.uint8)
    # 64-bit hash of the full domain, used for train/test overlap analysis
    h = pc.hash_64(dom) if hasattr(pc, "hash_64") else None
    hv = np.asarray(h) if h is not None else _fnv_hash(tok)
    np.save(base + ".tok.npy", tok); np.save(base + ".len.npy", ln)
    np.save(base + ".lab.npy", lab); np.save(base + ".hash.npy", hv.astype(np.uint64))
    return load_file(name)


def _fnv_hash(tok):
    h = np.full(len(tok), 1469598103934665603, dtype=np.uint64)
    with np.errstate(over="ignore"):
        for j in range(tok.shape[1]):
            h ^= tok[:, j].astype(np.uint64)
            h *= np.uint64(1099511628211)
    return h


if __name__ == "__main__":
    import sys, time
    for f in sorted(os.listdir(RAW)):
        if f.endswith(".parquet"):
            t0 = time.time()
            tok, ln, lab, h = load_file(f)
            print(f"{f:28s} n={len(lab):>10,d} label={np.bincount(lab, minlength=2)} "
                  f"len p50={int(np.median(ln))} p99={int(np.percentile(ln, 99))} max={ln.max()} "
                  f"({time.time() - t0:.1f}s)", flush=True)
