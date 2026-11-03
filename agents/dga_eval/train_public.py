#!/usr/bin/env python3
"""Train the opt-in "v3-public" n-gram model on public data and calibrate its thresholds.

    pip install numpy scikit-learn scipy onnxruntime
    python agents/dga_eval/train_public.py --data DIR [--download]

Writes ghostwall/models/lr_v3_public.npy (float16 weights) and lr_v3_public.json
(features, thresholds, provenance) and agents/dga_eval/results_v3_public.md.

Same data and splits as public_bench.py: the 200,000 normal test names it holds out
are held out here too. Steps:

1. Regularisation: train on 20 families, validate on the other 5 (and on held-out
   normal names); keep the strength that catches the most at 0.1% false positives.
2. Train on all 25 families and the normal training names.
3. Thresholds: ghost-dns's defaults (0.96 alert, 0.995 block, 0.80 corroborated and
   burst, 0.5 beacon) are on the shipped models' scale. For each one, pick the v3
   score that flags the SAME share of the held-out normal names as the shipped models
   do at that default, so switching models keeps the alert volume about the same.

The model is opt-in ("models": "v3-public" in ghost_dns.json): it was never measured
on DRIFT, and its normal names come from the same Tranco list as the test names.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import public_bench as B  # noqa: E402

SPEC = dict(B.LR_VARIANTS["lr-v3"])
ALPHAS = (1e-6, 3e-6, 1e-5, 3e-5, 1e-4)
DEFAULTS = {"recommend_threshold": 0.96, "block_threshold": 0.995, "corroborated_threshold": 0.80,
            "burst_min_score": 0.80, "beacon_min_dga": 0.5}
OUT = os.path.join(ROOT, "ghostwall", "models")


def sigmoid(z):
    return 1 / (1 + np.exp(-np.clip(z, -500, 500)))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", required=True)
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--report", default=os.path.join(HERE, "results_v3_public.md"))
    args = ap.parse_args(argv)
    B.fetch(args.data, args.download)

    # the same names and the same held-out normal test set as public_bench.py
    rng = np.random.default_rng(B.SEED)
    for labeller in (B.legacy_registrable_label, B.registrable_label):   # replay its rng use
        ben, _, _ = B.load(args.data, labeller)
        rng.permutation(len(ben))
    ben, dga, fams = B.load(args.data, B.registrable_label)
    fams = np.array(fams)
    ben = np.array(ben, dtype=object)
    perm = rng.permutation(len(ben))
    ben_test, ben_pool = ben[perm[:B.N_BENIGN_TEST]], ben[perm[B.N_BENIGN_TEST:]]
    t_test = B.tokens(ben_test)

    own = np.random.default_rng(B.SEED + 1)
    tr_ben = ben_pool[own.permutation(len(ben_pool))[:B.N_BENIGN_TRAIN]]

    # 1. regularisation on unseen families
    held = list(own.permutation(sorted(set(fams)))[:5])
    vmask = np.isin(fams, held)
    nval = len(tr_ben) // 10
    Xfit = B.tokens(list(tr_ben[nval:]) + list(dga[~vmask]))
    yfit = np.r_[np.zeros(len(tr_ben) - nval, np.int64), np.ones(int((~vmask).sum()), np.int64)]
    vb, vd = B.tokens(tr_ben[:nval]), B.tokens(dga[vmask])
    scores = {}
    for a in ALPHAS:
        coef, icpt = B.train_lr(Xfit, yfit, SPEC, alpha=a)
        t, _ = B.tpr_at(B.score_lr(coef, icpt, vb, SPEC), B.score_lr(coef, icpt, vd, SPEC), 0.001)
        scores[a] = t
        print(f"[alpha] {a:g}: caught {100 * t:.1f}% of {', '.join(sorted(held))} at 0.1% FP", flush=True)
    alpha = max(scores, key=scores.get)

    # 2. final model on everything but the held-out normal test names
    X = B.tokens(list(tr_ben) + list(dga))
    y = np.r_[np.zeros(len(tr_ben), np.int64), np.ones(len(dga), np.int64)]
    coef, icpt = B.train_lr(X, y, SPEC, alpha=alpha)
    coef16 = coef.astype(np.float16)
    p_v3 = sigmoid(B.score_lr(coef16.astype(np.float64), icpt, t_test, SPEC))

    # 3. thresholds with the shipped models' false-positive rates
    shipped = B.shipped_scorers()
    p_shipped = (shipped["shipped-trm"](t_test) + shipped["shipped-lr"](t_test)) / 2
    thresholds, rows = {}, []
    for key, thr in DEFAULTS.items():
        fp = float((p_shipped >= thr).mean())
        new = float(np.quantile(p_v3, 1 - fp, method="higher")) if fp > 0 else float(p_v3.max())
        new = min(new, 0.99999)
        thresholds[key] = round(new, 6)
        rows.append((key, thr, fp, thresholds[key], float((p_v3 >= thresholds[key]).mean())))
        print(f"[thr] {key}: shipped {thr} flags {100 * fp:.2f}% -> v3 {new:.6f}", flush=True)

    os.makedirs(OUT, exist_ok=True)
    np.save(os.path.join(OUT, "lr_v3_public.npy"), coef16)
    data_hashes = {name: sha for name, (_url, sha) in B.SOURCES.items()}
    meta = {"intercept": icpt, "buckets": SPEC["buckets"], "ngram_max": SPEC["ngram_max"],
            "boundary": SPEC["boundary"], "strip_dot": True, "alpha": alpha,
            "thresholds": thresholds,
            "trained_on": "agents/dga_eval/train_public.py: 25 Netlab 360 DGA families "
                          "(chrmor/DGA_domains_dataset) and Tranco V354N, minus 200,000 held-out normal names",
            "data_sha256": data_hashes,
            "weights_sha256": hashlib.sha256(coef16.tobytes()).hexdigest()}
    with open(os.path.join(OUT, "lr_v3_public.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=1)

    L = ["# Opt-in model v3-public", "",
         "Generated by `train_public.py`. A hashed 1-5-gram logistic regression trained on all 25 "
         "public DGA families and Tranco V354N (the 200,000 normal names `public_bench.py` tests "
         "on are held out). How well this recipe catches families it never saw is in "
         "[results_public.md](results_public.md) (row `lr-v3`, unseen families).", "",
         f"Regularisation {alpha:g}, chosen on 5 held-out families "
         f"({', '.join(sorted(held))}): " + ", ".join(f"{a:g} {100 * t:.1f}%" for a, t in scores.items())
         + " caught at 0.1% false positives.", "",
         "## Thresholds", "",
         "Each default threshold is moved to the v3 score that flags the same share of the "
         "held-out normal names as the shipped models do at that default.", "",
         "| Setting | Shipped default | Normal names flagged | v3-public value | Normal names flagged |",
         "|---|---|---|---|---|"]
    for key, thr, fp, new, fp_new in rows:
        L.append(f"| `{key}` | {thr} | {100 * fp:.2f}% | {new} | {100 * fp_new:.2f}% |")
    L += ["", "These are measured on Tranco names, which are popular sites: a home network also "
          "looks up less popular names, so expect more alerts than the table suggests in the "
          "first week, as with the shipped models.", ""]
    with open(args.report, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"[v3-public] wrote {OUT}/lr_v3_public.* and {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
