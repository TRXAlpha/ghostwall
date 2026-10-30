"""Run the forward-chaining evaluation for the trained baselines.

Writes results.json + results_baselines.md.
"""
import os
import sys
import json
import time

os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["OMP_NUM_THREADS"] = "3"
os.environ["MKL_NUM_THREADS"] = "3"

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import eval_lib as el
import train_baselines as tb


def fmt(m):
    return (f"| {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | "
            f"{m['f1']:.4f} | {m['fpr']:.4f} | {m['fnr']:.4f} | {m['roc_auc']:.4f} | "
            f"{m['tpr_at_fpr_1pct']:.4f} | {m['tpr_at_fpr_0.1pct']:.4f} |")


def run(name, predict_fn, results_dir):
    print(f"\n=== {name} ===", flush=True)
    t0 = time.time()
    res = el.evaluate_predictor(predict_fn, n_sample=500_000, predict_batch=100_000)
    dt = time.time() - t0
    res["name"] = name
    res["eval_seconds"] = round(dt, 1)
    with open(os.path.join(results_dir, f"results_{name}.json"), "w") as f:
        json.dump(res, f, indent=2, default=str)
    print(f"  micro: {res['micro']}")
    print(f"  leakage: {res['leakage']}")
    print(f"  done in {dt:.0f}s", flush=True)
    return res


def write_md(all_results, leakage, path):
    lines = [
        "# Baseline results (forward-chaining, DRIFT)",
        "",
        "Trained on 2017-2019 only (1M balanced rows, *_val hashes excluded).",
        "Test: 500k benign + 500k dga sampled per test year (seed 12345), 0.5 threshold.",
        "",
        "## Leakage check (share of test-year domains whose hash appears in training years)",
        "",
        "| year | overall | benign | dga |",
        "|---|---|---|---|",
    ]
    for y, v in leakage["overall"].items():
        lines.append(f"| 20{y} | {v:.4f} | {leakage['benign'][y]:.4f} | {leakage['dga'][y]:.4f} |")
    for name, res in all_results:
        m = res["micro"]
        lines += [
            "",
            f"## {name}",
            "",
            "| year | acc | prec | rec | F1 | FPR | FNR | ROC AUC | TPR@1%FPR | TPR@0.1%FPR |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for y, mm in res["years"].items():
            lines.append(f"| 20{y} " + fmt(mm) + "|")
        lines.append("| **micro** " + fmt(m) + " |")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def main():
    results_dir = HERE
    lr, lb, bbg, dbg = tb.load_predictors(os.path.join(HERE, "models"))
    pf_logreg = tb.make_logreg_predictor(lr)
    pf_lgbm = tb.make_lgbm_predictor(lb, bbg, dbg)

    all_results = []
    for name, pf in [("logreg_ngram", pf_logreg), ("lgbm_lexical", pf_lgbm)]:
        res = run(name, pf, results_dir)
        all_results.append((name, res))

    # leakage table per class
    leakage = {"overall": {}, "benign": {}, "dga": {}}
    hs = el._train_hash_array()
    for y in el.TEST_YEARS:
        ben = el.load_year(y, "benign", n_sample=200_000)
        dga = el.load_year(y, "dga", n_sample=200_000, seed_offset=1)
        hb, hd = ben["hashes"], dga["hashes"]
        for d, h in [("benign", hb), ("dga", hd)]:
            idx = np.minimum(np.searchsorted(hs, h), len(hs) - 1)
            leakage[d][y] = float((hs[idx] == h).mean())
        h = np.concatenate([hb, hd])
        idx = np.minimum(np.searchsorted(hs, h), len(hs) - 1)
        leakage["overall"][y] = float((hs[idx] == h).mean())

    write_md(all_results, leakage, os.path.join(results_dir, "results_baselines.md"))
    print("Wrote results_baselines.md", flush=True)


if __name__ == "__main__":
    main()
