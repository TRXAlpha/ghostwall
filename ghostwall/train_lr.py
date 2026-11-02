"""Hashed char n-gram logistic regression DGA scorer (dot-stripped), exported as numpy for the Pi.

Needs the DRIFT parquet files in data/drift and scikit-learn + scipy (training only).
The features are agents/ghost_dns/ngram.py, the same code the scorer runs on the device.

    python ghostwall/train_lr.py            # v2, as shipped: 1-3-grams, 2^18 buckets
    python ghostwall/train_lr.py --v3       # 1-5-grams with start/end markers, 2^20 buckets

--v3 is the variant agents/dga_eval/public_bench.py compares; after training it, rerun
agents/dga_eval/eval_shipped.py before shipping it (the README's numbers are for v2).
"""
import argparse, os, sys, numpy as np, json
os.environ["OMP_NUM_THREADS"] = "3"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "trm"))
sys.path.insert(0, os.path.join(ROOT, "agents", "ghost_dns"))
import data as D
from ngram import hashed_ngrams
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import roc_auc_score

NGRAM_BUCKETS = 1 << 18
NGRAM_MAX = 3


def ngram_matrix(tokens, lengths=None, ngram_max=NGRAM_MAX, buckets=NGRAM_BUCKETS, boundary=False):
    """Hashed character 1..ngram_max-gram indicator features, sparse CSR (ngram.hashed_ngrams)."""
    from scipy.sparse import csr_matrix
    rows, cols = [], []
    for r, c in hashed_ngrams(tokens, buckets, ngram_max, boundary):
        rows.append(r); cols.append(c)
    rows = np.concatenate(rows); cols = np.concatenate(cols)
    return csr_matrix((np.ones(len(rows), dtype=np.float32), (rows, cols)), shape=(len(tokens), buckets))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--v3", action="store_true", help="1-5-grams + boundary markers, 2^20 buckets")
    ap.add_argument("--out", default=os.path.join(ROOT, "ghostwall", "models"))
    args = ap.parse_args()
    if args.v3:
        NGRAM_MAX, NGRAM_BUCKETS, BOUNDARY = 5, 1 << 20, True
    else:
        BOUNDARY = False
    feats = lambda T, L: ngram_matrix(T, L, NGRAM_MAX, NGRAM_BUCKETS, BOUNDARY)  # noqa: E731
    rng = np.random.default_rng(0)

    def sample(years, per, exclude=None):
        T, Y = [], []
        for y in years:
            for c in ("benign", "dga"):
                tok, ln, lab, h = D.load_file(f"T{y}_{c}.parquet")
                i = rng.choice(len(lab), per, replace=False)
                if exclude is not None:
                    i = i[~np.isin(h[i], exclude)]
                T.append(D.strip_dot(np.asarray(tok[np.sort(i)]))); Y.append(lab[np.sort(i)])
        T = np.concatenate(T); return T, (T != 0).sum(1), np.concatenate(Y)

    vh = np.concatenate([D.load_file(f"T{y}_{c}_val.parquet")[3] for y in (17, 18, 19) for c in ("benign", "dga")])
    T, L, Y = sample((17, 18, 19), 400_000, np.unique(vh))
    clf = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=20, tol=1e-4, random_state=0).fit(feats(T, L), Y)
    out = args.out
    np.save(os.path.join(out, "lr_coef.npy"), clf.coef_.ravel().astype(np.float32))
    res = {"intercept": float(clf.intercept_[0]), "buckets": NGRAM_BUCKETS, "ngram_max": NGRAM_MAX, "boundary": BOUNDARY, "strip_dot": True, "years": {}}
    for y in range(20, 26):
        Tt, Lt, Yt = sample((y,), 150_000)
        p = clf.predict_proba(feats(Tt, Lt))[:, 1]
        thr = np.quantile(p[Yt == 0], 0.99)
        res["years"][2000 + y] = {"auc": round(roc_auc_score(Yt, p), 4), "fpr@0.5": round(float((p[Yt == 0] >= .5).mean()), 4),
                                  "tpr@1%fpr": round(float((p[Yt == 1] >= thr).mean()), 4)}
        print(2000 + y, res["years"][2000 + y], flush=True)
    json.dump(res, open(os.path.join(out, "lr_meta.json"), "w"), indent=1)
