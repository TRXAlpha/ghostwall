"""Forward-chaining evaluation harness for DGA detectors on the DRIFT dataset.

Protocol (comparable to DRIFT paper, arXiv 2605.10436):
  - Training years: 2017-2019 (never touch 2020-2025 for training).
  - Test years: 2020-2025, evaluated year by year (forward chaining / temporal split).
  - Every file's token cache lives in data/cache/T{YY}_{benign|dga}[_val].{tok,len,lab,hash}.npy
  - *_val.parquet caches are the held-out validation rows of each year; training
    subsampling excludes them by hash so they stay a clean holdout.

All loaders are memory-safe: token matrices are np.load(mmap_mode="r") and only the
sampled rows are materialised. CPU only.
"""
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, "data", "cache")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TRAIN_YEARS = [17, 18, 19]
TEST_YEARS = [20, 21, 22, 23, 24, 25]
SEED = 12345

_cache = {}


def _path(name):
    return os.path.join(CACHE, name + ".npy")


def _load(base, kind):
    return np.load(_path(f"{base}.{kind}"), mmap_mode="r")


def _sample_indices(n, k, seed_offset):
    """Deterministic random subsample of row indices (no replacement)."""
    rng = np.random.default_rng(SEED + seed_offset)
    if n <= k:
        return np.arange(n)
    return np.sort(rng.choice(n, size=k, replace=False))


def load_year(year, kind, n_sample=500_000, seed_offset=0):
    """Load one (year, kind) file, subsampled to n_sample rows.

    Returns dict with tokens [n,64] uint8 (materialised), lengths, labels, hashes.
    """
    base = f"T{year}_{kind}"
    tok = _load(base, "tok")
    lab = np.asarray(_load(base, "lab"))
    idx = _sample_indices(len(lab), n_sample, seed_offset=seed_offset + year * 10 + (0 if kind == "benign" else 1))
    return {
        "tokens": np.asarray(tok[idx]),
        "lengths": np.asarray(_load(base, "len"))[idx],
        "labels": lab[idx].astype(np.int8),
        "hashes": np.asarray(_load(base, "hash"))[idx],
    }


def load_year_full(year, kind):
    """Stream-safe handle to a full year's data (memmaps, not materialised)."""
    return {
        "tokens": _load(f"T{year}_{kind}", "tok"),
        "lengths": _load(f"T{year}_{kind}", "len"),
        "labels": np.asarray(_load(f"T{year}_{kind}", "lab")),
        "hashes": _load(f"T{year}_{kind}", "hash"),
    }


def load_train_pool(n_per_class=1_000_000, exclude_val=True):
    """Balanced subsample of 2017-2019 training rows, excluding *_val hashes.

    Returns dict with tokens, lengths, labels, hashes. n_per_class per class.
    """
    val_hashes = set()
    if exclude_val:
        for y in TRAIN_YEARS:
            for kind in ("benign", "dga"):
                vh = np.asarray(_load(f"T{y}_{kind}_val", "hash"))
                val_hashes.update(vh.tolist())

    parts = []
    for ci, kind in enumerate(("benign", "dga")):
        chunks_tok, chunks_len, chunks_lab = [], [], []
        got = 0
        for y in TRAIN_YEARS:
            need = n_per_class - got
            if need <= 0:
                break
            d = load_year(y, kind, n_sample=need, seed_offset=100 + ci)
            if exclude_val:
                mask = np.fromiter((int(h) not in val_hashes for h in d["hashes"]),
                                   dtype=bool, count=len(d["hashes"]))
                d = {k: v[mask] for k, v in d.items()}
            chunks_tok.append(d["tokens"]); chunks_len.append(d["lengths"]); chunks_lab.append(d["labels"])
            got += len(d["labels"])
        parts.append({
            "tokens": np.concatenate(chunks_tok),
            "lengths": np.concatenate(chunks_len),
            "labels": np.concatenate(chunks_lab),
        })
    out = {
        "tokens": np.concatenate([p["tokens"] for p in parts]),
        "lengths": np.concatenate([p["lengths"] for p in parts]),
        "labels": np.concatenate([p["labels"] for p in parts]),
    }
    return out


def decode(tokens, lengths):
    """Token matrix -> list of domain strings (for feature extraction)."""
    vocab = "abcdefghijklmnopqrstuvwxyz0123456789-._"
    lut = np.array(["<p>", "<u>"] + list(vocab), dtype=object)
    out = []
    for row, ln in zip(tokens, lengths):
        out.append("".join(lut[row[:ln]]))
    return out


def pr_metrics(y_true, y_score):
    """Accuracy, precision, recall, F1, FPR, FNR, ROC AUC, TPR@FPR<=1%/0.1%.

    Threshold 0.5 for the point metrics; ROC AUC and TPR@FPR from sklearn.
    """
    from sklearn.metrics import roc_auc_score, roc_curve

    y_true = np.asarray(y_true).astype(int)
    y_pred = (np.asarray(y_score) >= 0.5).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    acc = (tp + tn) / max(len(y_true), 1)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    auc = float(roc_auc_score(y_true, y_score))
    fprs, tprs, _ = roc_curve(y_true, y_score)
    tpr_1 = float(tprs[np.searchsorted(fprs, 0.01, side="right") - 1]) if np.any(fprs <= 0.01) else 0.0
    tpr_01 = float(tprs[np.searchsorted(fprs, 0.001, side="right") - 1]) if np.any(fprs <= 0.001) else 0.0
    return {
        "n": len(y_true), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
        "fpr": fpr, "fnr": fnr, "roc_auc": auc,
        "tpr_at_fpr_1pct": tpr_1, "tpr_at_fpr_0.1pct": tpr_01,
    }


def evaluate_predictor(predict_fn, test_years=None, n_sample=500_000,
                       predict_batch=200_000, verbose=True):
    """Generic forward-chaining evaluation.

    predict_fn(tokens: uint8 [N,64]) -> P(dga) float array [N].
    Every model scored under the identical protocol.

    Returns {"years": {year: metrics}, "micro": metrics,
             "leakage": {year: overlap_share}, "n_test": total}.
    """
    if test_years is None:
        test_years = TEST_YEARS
    results = {"years": {}, "leakage": {}}
    all_scores, all_labels = [], []

    train_hashes = _train_hash_array()
    for year in test_years:
        ben = load_year(year, "benign", n_sample=n_sample, seed_offset=0)
        dga = load_year(year, "dga", n_sample=n_sample, seed_offset=1)
        tokens = np.concatenate([ben["tokens"], dga["tokens"]])
        labels = np.concatenate([ben["labels"], dga["labels"]])

        scores = np.empty(len(tokens), dtype=np.float32)
        for i in range(0, len(tokens), predict_batch):
            scores[i:i + predict_batch] = predict_fn(tokens[i:i + predict_batch])
        m = pr_metrics(labels, scores)
        results["years"][year] = m
        # leakage: share of this test year's sampled domains whose hash appeared in training years
        h = np.concatenate([ben["hashes"], dga["hashes"]])
        idx = np.searchsorted(train_hashes, h)
        idx_clipped = np.minimum(idx, len(train_hashes) - 1)
        results["leakage"][year] = float(np.mean(train_hashes[idx_clipped] == h))
        if verbose:
            print(f"  {year}: acc={m['accuracy']:.4f} f1={m['f1']:.4f} "
                  f"auc={m['roc_auc']:.4f} fpr={m['fpr']:.4f} tpr@1%={m['tpr_at_fpr_1pct']:.3f}", flush=True)
        all_scores.append(scores); all_labels.append(labels)

    scores = np.concatenate(all_scores); labels = np.concatenate(all_labels)
    results["micro"] = pr_metrics(labels, scores)
    results["n_test"] = len(labels)
    return results


_train_hash_cache = None


def _train_hash_array():
    global _train_hash_cache
    if _train_hash_cache is None:
        parts = []
        for y in TRAIN_YEARS:
            for kind in ("benign", "dga"):
                parts.append(np.asarray(_load(f"T{y}_{kind}", "hash")))
        arr = np.concatenate(parts)
        arr = np.sort(arr)
        _train_hash_cache = arr
    return _train_hash_cache
