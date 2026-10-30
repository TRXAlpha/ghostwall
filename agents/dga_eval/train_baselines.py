"""Train baselines on 2017-2019 only and run the forward-chaining evaluation.

Baselines:
  (a) Logistic regression on hashed character 1-3-gram features.
  (b) LightGBM on hand-crafted lexical features.

CPU only (CUDA_VISIBLE_DEVICES=""), <=3 threads.
"""
import os
import sys
import time

os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["OMP_NUM_THREADS"] = "3"
os.environ["MKL_NUM_THREADS"] = "3"

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import eval_lib as el

VOCAB = "abcdefghijklmnopqrstuvwxyz0123456789-._"
NGRAM_BUCKETS = 1 << 18
NGRAM_MAX = 3


# ---------------------------------------------------------------- features
def ngram_matrix(tokens, lengths, ngram_max=NGRAM_MAX, buckets=NGRAM_BUCKETS):
    """Hashed character 1..ngram_max-gram indicator features, sparse CSR.

    Vectorised: one pass over offsets, code = rolling base-131 hash of token ids.
    """
    from scipy.sparse import csr_matrix
    N = len(tokens)
    rows, cols = [], []
    for n in range(1, ngram_max + 1):
        for j in range(64 - n + 1):
            m = lengths >= (n + j)          # window fully inside the string
            if not m.any():
                continue
            code = np.zeros(int(m.sum()), dtype=np.int64)
            for k in range(n):
                code = code * 131 + tokens[m, j + k].astype(np.int64)
            code &= 0x7FFFFFFF
            rows.append(np.nonzero(m)[0])
            cols.append(code % buckets)
    rows = np.concatenate(rows); cols = np.concatenate(cols)
    return csr_matrix((np.ones(len(rows), dtype=np.float32), (rows, cols)),
                      shape=(N, buckets))


def char_bigram_counts(tokens, lengths, alpha=0.1):
    """Additive-smoothed bigram probability model over token ids (padded to 40)."""
    bg = np.full((40, 40), alpha, dtype=np.float64)
    for i in range(len(tokens)):
        seq = tokens[i, :lengths[i]]
        for a, b in zip(seq, seq[1:]):
            bg[int(a), int(b)] += 1.0
    bg /= bg.sum(axis=1, keepdims=True)
    return bg


def lexical_features(tokens, lengths, benign_bg, dga_bg):
    """Hand-crafted lexical features [N, 17] float32.

    Columns: length, entropy, digit ratio, vowel ratio, consonant ratio,
    longest consonant run, longest digit run, unique-char ratio, '-' count,
    '.' count, unique chars, char-freq std, digit count, doubled chars,
    label count, benign bigram LL, dga bigram LL.
    """
    N = len(tokens)
    F = 15
    feats = np.zeros((N, F), dtype=np.float32)
    vocab = VOCAB
    vowels = set("aeiou")
    consonants = set("bcdfghjklmnpqrstvwxyz")
    for i in range(N):
        seq = tokens[i, :lengths[i]]
        s = "".join(vocab[c - 2] if 2 <= c < 38 else "" for c in seq)
        L = len(s)
        if L == 0:
            continue
        cnt = np.bincount(seq, minlength=40)[:40].astype(np.float32)
        p = cnt[cnt > 0] / L
        H = float(-(p * np.log2(p)).sum())
        digits = sum(c.isdigit() for c in s)
        vowels_n = sum(c in vowels for c in s)
        consonants_n = sum(c in consonants for c in s)
        run_c = run_d = cur_c = cur_d = 0
        for c in s:
            if c in consonants:
                cur_c += 1; run_c = max(run_c, cur_c)
            else:
                cur_c = 0
            if c.isdigit():
                cur_d += 1; run_d = max(run_d, cur_d)
            else:
                cur_d = 0
        feats[i, 0] = L
        feats[i, 1] = H
        feats[i, 2] = digits / L
        feats[i, 3] = vowels_n / L
        feats[i, 4] = consonants_n / L
        feats[i, 5] = run_c
        feats[i, 6] = run_d
        feats[i, 7] = len(set(s)) / L
        feats[i, 8] = s.count("-")
        feats[i, 9] = s.count(".")
        feats[i, 10] = len(set(s))
        feats[i, 11] = float(np.std(p))
        feats[i, 12] = digits
        feats[i, 13] = sum(1 for a, b in zip(s, s[1:]) if a == b)
        feats[i, 14] = len(s.split("."))

    ll_ben = np.zeros(N, dtype=np.float32)
    ll_dga = np.zeros(N, dtype=np.float32)
    for i in range(N):
        seq = tokens[i, :lengths[i]]
        if len(seq) < 2:
            continue
        a, b = seq[:-1].astype(np.intp), seq[1:].astype(np.intp)
        ok = (a < 40) & (b < 40)
        if not np.any(a >= 40):  # all in-vocab: fast path
            ll_ben[i] = np.log(benign_bg[a, b] + 1e-10).mean()
            ll_dga[i] = np.log(dga_bg[a, b] + 1e-10).mean()
        else:
            ll_ben[i] = np.log(benign_bg[a[ok], b[ok]] + 1e-10).mean() if np.any(a[ok]) else 0.0
            ll_dga[i] = np.log(dga_bg[a[ok], b[ok]] + 1e-10).mean() if np.any(a[ok]) else 0.0
    return np.concatenate([feats, ll_ben[:, None], ll_dga[:, None]], axis=1)


# ---------------------------------------------------------------- baselines
def train_baselines(train_pool, model_dir):
    from sklearn.linear_model import SGDClassifier
    import lightgbm as lgb
    import joblib

    os.makedirs(model_dir, exist_ok=True)
    toks, lens, y = train_pool["tokens"], train_pool["lengths"], train_pool["labels"]

    # (a) logistic regression on hashed 1-3-grams
    print("Building n-gram features for train pool...", flush=True)
    t0 = time.time()
    X = ngram_matrix(toks, lens)
    print(f"  X shape {X.shape}, nnz {X.nnz} ({time.time()-t0:.0f}s)", flush=True)
    clf = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=8, tol=1e-4,
                        random_state=0)
    clf.fit(X, y)
    joblib.dump({"coef": clf.coef_, "intercept": clf.intercept_,
                 "buckets": NGRAM_BUCKETS, "ngram_max": NGRAM_MAX},
                os.path.join(model_dir, "logreg_ngram.joblib"))
    print("  logreg trained", flush=True)

    # (b) lightgbm on lexical features
    print("Building lexical features...", flush=True)
    benign_bg = char_bigram_counts(toks[y == 0], lens[y == 0])
    dga_bg = char_bigram_counts(toks[y == 1], lens[y == 1])
    t0 = time.time()
    Xl = lexical_features(toks, lens, benign_bg, dga_bg)
    print(f"  lexical shape {Xl.shape} ({time.time()-t0:.0f}s)", flush=True)
    lgbm = lgb.LGBMClassifier(n_estimators=300, num_leaves=63, learning_rate=0.08,
                              n_jobs=3, random_state=0, verbose=-1)
    lgbm.fit(Xl, y)
    joblib.dump({"model": lgbm}, os.path.join(model_dir, "lgbm_lexical.joblib"))
    np.save(os.path.join(model_dir, "benign_bigram.npy"), benign_bg)
    np.save(os.path.join(model_dir, "dga_bigram.npy"), dga_bg)
    print("  lgbm trained", flush=True)


# ---------------------------------------------------------------- predictors
def load_predictors(model_dir):
    import joblib
    lr = joblib.load(os.path.join(model_dir, "logreg_ngram.joblib"))
    lb = joblib.load(os.path.join(model_dir, "lgbm_lexical.joblib"))["model"]
    benign_bg = np.load(os.path.join(model_dir, "benign_bigram.npy"))
    dga_bg = np.load(os.path.join(model_dir, "dga_bigram.npy"))
    return lr, lb, benign_bg, dga_bg


def make_logreg_predictor(lr):
    """predict_fn(tokens [N,64] uint8) -> P(dga) float array."""
    def predict(tokens):
        lengths = (tokens != 0).sum(axis=1)
        X = ngram_matrix(tokens, lengths, lr["ngram_max"], lr["buckets"])
        z = X @ lr["coef"].ravel() + lr["intercept"][0]
        return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))

    return predict


def make_lgbm_predictor(lb, benign_bg, dga_bg):
    def predict(tokens):
        lengths = (tokens != 0).sum(axis=1)
        Xl = lexical_features(tokens, lengths, benign_bg, dga_bg)
        return lb.predict_proba(Xl)[:, 1]

    return predict


def main():
    t0 = time.time()
    model_dir = os.path.join(HERE, "models")
    os.makedirs(model_dir, exist_ok=True)

    print("Loading train pool (2017-2019, 1M/class, val excluded)...", flush=True)
    train_pool = el.load_train_pool(n_per_class=1_000_000, exclude_val=True)
    print(f"  train pool: {len(train_pool['labels'])} rows "
          f"(benign={int((train_pool['labels']==0).sum())}, dga={int((train_pool['labels']==1).sum())})", flush=True)

    train_baselines(train_pool, model_dir)
    print(f"Training done in {time.time()-t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
