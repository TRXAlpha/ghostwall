"""Train static PE malware detectors on EMBER2024 (Win32 + Win64 + .NET).

  python scanner/train_gbm.py baseline     # exact paper config (500 rounds, 64 leaves), full train
  python scanner/train_gbm.py tuned        # our config, early-stopped on the last 4 train weeks

Never looks at test/challenge while training or tuning.
"""
import json
import os
import sys
import time

import lightgbm as lgb
import numpy as np
import pyarrow.parquet as pq

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VEC = os.path.join(ROOT, "data", "ember2024", "vec")
MODELS = os.path.join(ROOT, "models")
DIM = 2568

BASELINE = {"objective": "binary", "boosting": "gbdt", "num_iterations": 500, "learning_rate": 0.1,
            "num_leaves": 64, "min_data_in_leaf": 100, "bagging_fraction": 0.9, "bagging_freq": 1,
            "feature_fraction": 0.9, "feature_fraction_bynode": 0.9, "lambda_l2": 1.0, "is_unbalance": True,
            "seed": 0, "num_threads": 0, "verbosity": -1, "metric": ["auc", "binary_logloss"]}

TUNED = {"objective": "binary", "boosting": "gbdt", "num_iterations": 4000, "learning_rate": 0.05,
         "num_leaves": 256, "min_data_in_leaf": 50, "max_bin": 255, "bagging_fraction": 0.8, "bagging_freq": 1,
         "feature_fraction": 0.5, "feature_fraction_bynode": 0.8, "lambda_l2": 1.0, "min_gain_to_split": 0.0,
         "seed": 0, "num_threads": 0, "verbosity": -1, "metric": ["auc", "binary_logloss"]}


class MemmapSeq(lgb.Sequence):
    """Stream rows of a raw float32 matrix to LightGBM without loading it all into RAM."""

    def __init__(self, path, n, rows=None, batch_size=8192):
        self.X = np.memmap(path, dtype=np.float32, mode="r", shape=(n, DIM))
        self.rows = rows if rows is not None else np.arange(n)
        self.batch_size = batch_size

    def __getitem__(self, idx):
        return np.asarray(self.X[self.rows[idx]], dtype=np.float64)   # LightGBM Sequence wants float64

    def __len__(self):
        return len(self.rows)


def load_meta(subset):
    return pq.read_table(os.path.join(VEC, f"{subset}.meta.parquet"),
                         columns=["label", "file_type", "family", "behavior", "week_id",
                                  "first_submission_date"]).to_pandas()


def dataset(subset, rows, label, weight=None, reference=None, cache=None):
    if cache and os.path.exists(cache):
        return lgb.Dataset(cache, reference=reference, free_raw_data=False)
    meta_n = int(os.path.getsize(os.path.join(VEC, f"{subset}.X.f32")) // (4 * DIM))
    seq = MemmapSeq(os.path.join(VEC, f"{subset}.X.f32"), meta_n, rows)
    ds = lgb.Dataset([seq], label=label, weight=weight, reference=reference, free_raw_data=False,
                     params={"max_bin": 255, "bin_construct_sample_cnt": 400000, "verbosity": -1})
    if cache:
        ds.save_binary(cache)
    return ds


def main(mode):
    os.makedirs(MODELS, exist_ok=True)
    m = load_meta("train")
    lab = m["label"].to_numpy()
    keep = np.flatnonzero(lab >= 0)                    # drop unlabeled (-1 / None)
    week = m["week_id"].to_numpy()
    print(f"train rows {len(m):,}  labeled {len(keep):,}  malicious {int((lab == 1).sum()):,}  weeks {week.min()}-{week.max()}",
          flush=True)
    t0 = time.time()
    if mode == "baseline":
        p = dict(BASELINE)
        ds = dataset("train", keep, lab[keep].astype(np.float32))
        booster = lgb.train(p, ds, callbacks=[lgb.log_evaluation(50)], valid_sets=[ds], valid_names=["train"])
    else:
        p = dict(TUNED)
        cut = week.max() - 3                           # last 4 training weeks = temporal validation
        tr = keep[week[keep] < cut]; va = keep[week[keep] >= cut]
        # mild recency weighting: newer weeks matter more under drift (x1 oldest -> x2 newest)
        w = 1.0 + (week[tr] - week.min()) / max(1, (cut - week.min()))
        print(f"tuned: fit {len(tr):,} rows (weeks <{cut}), validate {len(va):,} rows (weeks >={cut})", flush=True)
        dtr = dataset("train", tr, lab[tr].astype(np.float32), weight=w.astype(np.float32))
        dva = dataset("train", va, lab[va].astype(np.float32), reference=dtr)
        booster = lgb.train(p, dtr, valid_sets=[dva], valid_names=["val"],
                            callbacks=[lgb.log_evaluation(100), lgb.early_stopping(200, first_metric_only=True)])
        print(f"best iteration {booster.best_iteration}", flush=True)
    path = os.path.join(MODELS, f"pe_{mode}.lgb")
    booster.save_model(path, num_iteration=booster.best_iteration or None)
    json.dump({"mode": mode, "params": p, "best_iteration": booster.best_iteration,
               "minutes": (time.time() - t0) / 60}, open(path + ".json", "w"), indent=1)
    print(f"saved {path}  ({os.path.getsize(path) / 1e6:.1f} MB)  {(time.time() - t0) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tuned")
