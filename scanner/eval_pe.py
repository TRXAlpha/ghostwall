"""Evaluate a LightGBM PE detector on EMBER2024 test and challenge sets (paper Tables 5/6 protocol).

  python scanner/eval_pe.py models/pe_baseline.lgb [more.lgb ...]
"""
import json
import os
import sys

import lightgbm as lgb
import numpy as np
import pyarrow.parquet as pq
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC = os.path.join(ROOT, "data", "ember2024", "vec")
DIM = 2568


def load(subset):
    m = pq.read_table(os.path.join(VEC, f"{subset}.meta.parquet"), columns=["label", "file_type", "family"]).to_pandas()
    X = np.memmap(os.path.join(VEC, f"{subset}.X.f32"), dtype=np.float32, mode="r", shape=(len(m), DIM))
    return m, X


def predict(booster, X, bs=100_000):
    return np.concatenate([booster.predict(np.asarray(X[i:i + bs])) for i in range(0, len(X), bs)])


def tpr_at_fpr(p, y, f):
    thr = np.quantile(p[y == 0], 1 - f)
    return float((p[y == 1] >= thr).mean())


def main(paths):
    mt, Xt = load("test")
    mc, Xc = load("challenge")
    yt = mt["label"].to_numpy()
    out = {}
    for path in paths:
        b = lgb.Booster(model_file=path)
        pt, pc = predict(b, Xt), predict(b, Xc)
        r = {"test_roc_auc": roc_auc_score(yt, pt), "test_pr_auc": average_precision_score(yt, pt)}
        for f in (0.01, 0.001, 0.0001):
            r[f"test_tpr@{f:g}fpr"] = tpr_at_fpr(pt, yt, f)
        # challenge: evasive malware + benign test files (paper Table 6)
        ben = yt == 0
        yy = np.concatenate([np.ones(len(pc)), np.zeros(int(ben.sum()))])
        pp = np.concatenate([pc, pt[ben]])
        r["challenge_roc_auc"] = roc_auc_score(yy, pp)
        r["challenge_pr_auc"] = average_precision_score(yy, pp)
        for f in (0.01, 0.001):
            thr = np.quantile(pt[ben], 1 - f)
            r[f"challenge_recall@{f:g}fpr"] = float((pc >= thr).mean())
        # novel families: test malware whose family never occurs in the training set
        mtr = pq.read_table(os.path.join(VEC, "train.meta.parquet"), columns=["family"]).to_pandas()
        seen = set(mtr["family"].dropna())
        nov = (yt == 1) & ~mt["family"].isin(seen).to_numpy() & mt["family"].notna().to_numpy()
        if nov.sum():
            m_ = nov | ben
            r["novel_family_n"] = int(nov.sum())
            r["novel_family_pr_auc"] = average_precision_score(nov[m_].astype(int), pt[m_])
        out[os.path.basename(path)] = {k: round(float(v), 4) for k, v in r.items()}
        print(path, json.dumps(out[os.path.basename(path)], indent=1), flush=True)
    json.dump(out, open(os.path.join(ROOT, "models", "pe_eval.json"), "w"), indent=1)


if __name__ == "__main__":
    main(sys.argv[1:])
