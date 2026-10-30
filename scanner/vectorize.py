"""Vectorize EMBER2024 raw PE features (jsonl inside the HF zips) with the official EMBER v3
feature code (third_party/thrember, Apache-2.0).

Output per subset in data/ember2024/vec/:
  <subset>.X.f32   float32 [n, 2568] (raw, row-major)
  <subset>.meta.parquet  sha256, label, file_type, family, behavior, packer, file_property,
                         first_submission_date, week_id, caps, ttps, mbc
Subsets: train (Win32+Win64+.NET train), test (same, test), challenge.
"""
import io
import json
import multiprocessing as mp
import os
import sys
import time
import zipfile

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "third_party"))
ZIPS = os.path.join(ROOT, "data", "ember2024", "zips")
OUT = os.path.join(ROOT, "data", "ember2024", "vec")
META_KEYS = ["sha256", "label", "file_type", "family", "family_confidence", "behavior", "packer",
             "file_property", "exploit", "group", "first_submission_date", "week_id", "caps", "ttps", "mbc",
             "detection_ratio"]
SUBSETS = {
    "train": ["Win32_train.zip", "Win64_train.zip", "Dot_Net_train.zip"],
    "test": ["Win32_test.zip", "Win64_test.zip", "Dot_Net_test.zip"],
    "challenge": ["challenge.zip"],
}

_ext = None


def _init():
    global _ext
    from thrember.features import PEFeatureExtractor
    _ext = PEFeatureExtractor()


def _work(line):
    r = json.loads(line)
    if r.get("file_type") in ("APK", "ELF", "PDF"):
        return None
    try:
        v = _ext.process_raw_features(r)
    except Exception:  # noqa - malformed record
        return None
    meta = (r.get("label"), r.get("file_type"), r.get("family"), r.get("week_id"),
            r.get("first_submission_date"), "|".join(r.get("behavior") or []))
    return v.astype(np.float32).tobytes(), meta


def lines(zip_names, only_pe=True):
    for zn in zip_names:
        with zipfile.ZipFile(os.path.join(ZIPS, zn)) as z:
            for name in sorted(n for n in z.namelist() if n.endswith(".jsonl")):
                with z.open(name) as f:
                    for ln in io.TextIOWrapper(f, encoding="utf-8"):
                        yield ln


def run(subset, procs):
    import pyarrow as pa
    import pyarrow.parquet as pq
    os.makedirs(OUT, exist_ok=True)
    xp, mp_ = os.path.join(OUT, f"{subset}.X.f32"), os.path.join(OUT, f"{subset}.meta.parquet")
    if os.path.exists(mp_):
        print(subset, "exists, skipping"); return
    metas, n, t0 = [], 0, time.time()
    with open(xp + ".tmp", "wb") as fx, mp.Pool(procs, initializer=_init) as pool:
        for res in pool.imap(_work, lines(SUBSETS[subset]), chunksize=64):
            if res is None:
                continue
            fx.write(res[0]); metas.append(res[1]); n += 1
            if n % 50000 == 0:
                print(f"  {subset}: {n:,} rows  {n / (time.time() - t0):,.0f}/s", flush=True)
    os.replace(xp + ".tmp", xp)
    cols = list(zip(*metas))
    tab = pa.table({"label": pa.array(cols[0], pa.int8()), "file_type": cols[1], "family": cols[2],
                    "week_id": pa.array(cols[3], pa.int32()), "first_submission_date": pa.array(cols[4], pa.int64()),
                    "behavior": cols[5]})
    pq.write_table(tab, mp_)
    print(f"{subset}: {n:,} rows in {(time.time() - t0) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    procs = int(os.environ.get("PROCS", max(1, os.cpu_count() - 3)))
    for s in (sys.argv[1:] or ["challenge", "test", "train"]):
        run(s, procs)
