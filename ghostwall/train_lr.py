"""Char 1-3-gram hashed logistic regression DGA scorer (dot-stripped), exported as numpy for the Pi."""
import os, sys, numpy as np, json
os.environ["OMP_NUM_THREADS"] = "3"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "trm")); sys.path.insert(0, os.path.join(ROOT, "agents", "dga_eval"))
import data as D
from train_baselines import ngram_matrix, NGRAM_BUCKETS
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import roc_auc_score

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
clf = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=20, tol=1e-4, random_state=0).fit(ngram_matrix(T, L), Y)
out = os.path.join(ROOT, "ghostwall", "models")
np.save(os.path.join(out, "lr_coef.npy"), clf.coef_.ravel().astype(np.float32))
res = {"intercept": float(clf.intercept_[0]), "buckets": NGRAM_BUCKETS, "ngram_max": 3, "strip_dot": True, "years": {}}
for y in range(20, 26):
    Tt, Lt, Yt = sample((y,), 150_000)
    p = clf.predict_proba(ngram_matrix(Tt, Lt))[:, 1]
    thr = np.quantile(p[Yt == 0], 0.99)
    res["years"][2000 + y] = {"auc": round(roc_auc_score(Yt, p), 4), "fpr@0.5": round(float((p[Yt == 0] >= .5).mean()), 4),
                              "tpr@1%fpr": round(float((p[Yt == 1] >= thr).mean()), 4)}
    print(2000 + y, res["years"][2000 + y], flush=True)
json.dump(res, open(os.path.join(out, "lr_meta.json"), "w"), indent=1)
