#!/usr/bin/env python3
"""A public, reproducible DGA benchmark: n-gram models vs an Endgame-style LSTM.

The shipped models are measured on the DRIFT dataset (eval_shipped.py), which is not
public. This benchmark uses only data anyone can download, pinned by hash:

  * DGA names: 25 families x 13,500 from Netlab 360's open DGA feed, as collected in
    github.com/chrmor/DGA_domains_dataset (commit 9dcc29e, research use).
  * Normal names: the Tranco top-1M list V354N (2026-10-03 to 2026-11-01).

Every name is reduced to the label Ghostwall actually scores (tokenizer.registrable_label,
dots stripped), so the numbers describe the product, not a lab setup. Two protocols:

  mixed    80/20 split inside every family: the setting of most papers, including
           Woodbridge et al. 2016 (Endgame's LSTM, arXiv 1611.00791).
  unseen   5 folds; each fold trains on 20 families and tests on the 5 it never saw.
           Closer to real life, where the next malware family is a new one.

Normal names are split once: 200,000 test names, never used for training.

Models (all trained here on the same names, except the shipped ones):
  shipped-trm / shipped-lr / shipped-mean   the models in ghostwall/models, as is
                                            (trained on DRIFT; a zero-shot reference)
  lr-v2      the shipped recipe: hashed 1-3-grams, 2^18 buckets
  lr-v3      hashed 1-5-grams, 2^20 buckets (train_lr.py --v3)
  lr-v3b     the same with start/end-of-label markers
  lstm       Woodbridge et al.: embedding 128, LSTM 128, dropout 0.5, sigmoid

    pip install numpy scikit-learn scipy torch onnx onnxruntime
    python agents/dga_eval/public_bench.py --data DIR [--download] [--out results_public.md]

Takes about an hour on 4 CPU cores, most of it the LSTM. --quick runs a small version.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.request

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "agents", "ghost_dns"))

from ngram import hashed_ngrams  # noqa: E402
from tokenizer import N_TOKENS, PUBLIC_SUFFIXES, encode, registrable_label, strip_dot  # noqa: E402

SOURCES = {
    "dga_domains_full.csv": (
        "https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/"
        "9dcc29e5cc644fdfd99d82a3abec993c15bbc7bc/dga_domains_full.csv",
        "e8bbe54f180cd127a07abaa3dbddcd843e7b7943dff2f18628619b1bd22e8253"),
    "tranco_V354N.csv": (
        "https://tranco-list.eu/download/V354N/1000000",
        "d6ab280c73d5a954cfbb38b4c371f75d72a69d04e6627590f0ea343b663aebd8"),
}
SEED = 20261102
N_BENIGN_TEST = 200_000
N_BENIGN_TRAIN = 400_000
LR_VARIANTS = {
    # insertion order matters: it fixes the order the random generator is used in
    "lr-v2": {"ngram_max": 3, "boundary": False, "buckets": 1 << 18},
    "lr-v3": {"ngram_max": 5, "boundary": False, "buckets": 1 << 20},
    "lr-v3b": {"ngram_max": 5, "boundary": True, "buckets": 1 << 20},
}


# --------------------------------------------------------------------------- data
def fetch(data_dir: str, download: bool) -> None:
    os.makedirs(data_dir, exist_ok=True)
    for name, (url, sha) in SOURCES.items():
        path = os.path.join(data_dir, name)
        if not os.path.exists(path):
            if not download:
                raise SystemExit(f"{path} missing; run with --download")
            print(f"[data] downloading {url}", flush=True)
            req = urllib.request.Request(url, headers={"User-Agent": "ghostwall-bench/1.0"})
            with urllib.request.urlopen(req, timeout=300) as r, open(path + ".part", "wb") as f:
                f.write(r.read())
            os.replace(path + ".part", path)
        h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if h != sha:
            raise SystemExit(f"{path}: sha256 {h} is not the pinned {sha}")


def legacy_registrable_label(host: str) -> str:
    """registrable_label as shipped up to v0.2.0-beta.2 (no dynamic-DNS or ccSLD rules)."""
    parts = host.strip().rstrip(".").lower().split(".")
    if len(parts) <= 2:
        reg = ".".join(parts)
    elif ".".join(parts[-2:]) in PUBLIC_SUFFIXES:
        reg = ".".join(parts[-3:])
    else:
        reg = ".".join(parts[-2:])
    return reg.split(".")[0]


def load(data_dir: str, labeller) -> tuple[list[str], np.ndarray, list[str]]:
    """Unique scored labels: (benign, dga_labels, dga_families). A label that occurs as
    both normal and DGA, or in two families, is dropped: it can't be told apart."""
    fam_of: dict[str, set] = {}
    with open(os.path.join(data_dir, "dga_domains_full.csv"), newline="") as f:
        for cls, fam, dom in csv.reader(f):
            if cls == "dga":
                fam_of.setdefault(labeller(dom), set()).add(fam)
    benign = set()
    with open(os.path.join(data_dir, "tranco_V354N.csv"), newline="") as f:
        for _rank, dom in csv.reader(f):
            benign.add(labeller(dom))
    benign.discard("")
    clash = benign & set(fam_of)
    dga = sorted(lab for lab, fams in fam_of.items() if len(fams) == 1 and lab not in clash and lab)
    fams = [next(iter(fam_of[lab])) for lab in dga]
    return sorted(benign - clash), np.array(dga, dtype=object), fams


def tokens(labels) -> np.ndarray:
    return strip_dot(encode(list(labels)))


# --------------------------------------------------------------------------- metrics
def roc_auc(y: np.ndarray, p: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, p))


def tpr_at(p_benign: np.ndarray, p_dga: np.ndarray, fpr: float) -> tuple[float, float]:
    """Share of DGA names flagged at the lowest threshold that flags at most `fpr` of the
    normal names (score >= threshold). Ties count against the model: a model that gives
    many normal names the same top score cannot be run at a lower false-positive rate."""
    cand = np.unique(p_benign)[::-1]                    # high to low
    fp = np.searchsorted(np.sort(p_benign), cand, side="left")
    fp = (len(p_benign) - fp) / len(p_benign)          # share of normal names >= each candidate
    ok = cand[fp <= fpr]
    thr = float(ok[-1]) if len(ok) else float(np.nextafter(cand[0], np.inf))
    # the next candidate down would exceed fpr; anything above the highest normal score is free
    return float((p_dga >= thr).mean()), thr


def metrics(p_benign, p_dga, fams_test) -> dict:
    y = np.r_[np.zeros(len(p_benign)), np.ones(len(p_dga))]
    t1, thr1 = tpr_at(p_benign, p_dga, 0.01)
    t01, _ = tpr_at(p_benign, p_dga, 0.001)
    per = {}
    fams_test = np.asarray(fams_test)
    for fam in sorted(set(fams_test)):
        per[fam] = float((p_dga[fams_test == fam] >= thr1).mean())
    return {"auc": roc_auc(y, np.r_[p_benign, p_dga]), "tpr@1%": t1, "tpr@0.1%": t01, "family@1%": per}


# --------------------------------------------------------------------------- models
def csr(toks: np.ndarray, spec: dict):
    from scipy.sparse import csr_matrix
    rows, cols = [], []
    for r, c in hashed_ngrams(toks, spec["buckets"], spec["ngram_max"], spec["boundary"]):
        rows.append(r)
        cols.append(c)
    rows, cols = np.concatenate(rows), np.concatenate(cols)
    m = csr_matrix((np.ones(len(rows), dtype=np.float32), (rows, cols)),
                   shape=(len(toks), spec["buckets"]))
    m.sum_duplicates()
    return m


def train_lr(Xtok, y, spec, alpha=1e-6, epochs=50):
    from sklearn.linear_model import SGDClassifier
    clf = SGDClassifier(loss="log_loss", alpha=alpha, max_iter=epochs, tol=1e-4,
                        random_state=0, class_weight="balanced")
    clf.fit(csr(Xtok, spec), y)
    coef = clf.coef_.ravel().astype(np.float32)
    return coef, float(clf.intercept_[0])


def pick_alpha(Xtok, y, spec, rng, grid=(1e-8, 1e-7, 1e-6, 1e-5)):
    """Regularisation chosen on 10% of the training names (never the test names), by
    DGA caught at 0.1% false positives, the operating range Ghostwall alerts in."""
    val = rng.random(len(y)) < 0.1
    best, best_a = -1.0, grid[0]
    for a in grid:
        coef, icpt = train_lr(Xtok[~val], y[~val], spec, alpha=a)
        p = score_lr(coef, icpt, Xtok[val], spec)
        t, _ = tpr_at(p[y[val] == 0], p[y[val] == 1], 0.001)
        if t > best:
            best, best_a = t, a
    return best_a


def score_lr(coef, intercept, toks, spec, logit=True):
    """Logits by default: they rank like the probabilities but never saturate to 1.0."""
    z = np.full(len(toks), intercept, dtype=np.float64)
    for r, c in hashed_ngrams(toks, spec["buckets"], spec["ngram_max"], spec["boundary"]):
        z[r] += coef[c]
    return z if logit else 1 / (1 + np.exp(-np.clip(z, -500, 500)))


def lstm_model():
    import torch
    from torch import nn

    class EndgameLSTM(nn.Module):
        """Woodbridge et al. 2016: Embedding(128) -> LSTM(128) -> Dropout(0.5) -> Dense -> sigmoid."""

        def __init__(self):
            super().__init__()
            self.emb = nn.Embedding(N_TOKENS, 128, padding_idx=0)
            self.lstm = nn.LSTM(128, 128, batch_first=True)
            self.drop = nn.Dropout(0.5)
            self.out = nn.Linear(128, 1)

        def forward(self, toks):  # toks: [N, T] int64, left-aligned, 0-padded
            lengths = (toks != 0).sum(1).clamp(min=1)
            h, _ = self.lstm(self.emb(toks))
            last = h[torch.arange(toks.shape[0]), lengths - 1]   # state after the last character
            return self.out(self.drop(last)).squeeze(1)          # logit; sigmoid in the loss

    return EndgameLSTM()


def train_lstm(Xtok, y, epochs=4, batch=256, seed=0):
    import torch
    torch.manual_seed(seed)
    torch.set_num_threads(os.cpu_count() or 1)
    model = lstm_model()
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    lossf = torch.nn.BCEWithLogitsLoss(reduction="none")
    lengths = (Xtok != 0).sum(1)
    w_pos = (y == 0).sum() / max(1, (y == 1).sum())       # balanced, like the LR
    rng = np.random.default_rng(seed)
    for ep in range(epochs):
        model.train()
        # batches of similar length: much faster, same result
        order = np.argsort(lengths + rng.random(len(lengths)), kind="stable")
        chunks = [order[i:i + batch] for i in range(0, len(order), batch)]
        rng.shuffle(chunks)
        t0, tot = time.time(), 0.0
        for idx in chunks:
            L = int(lengths[idx].max()) or 1
            xb = torch.from_numpy(Xtok[idx, :L])
            yb = torch.from_numpy(y[idx].astype(np.float32))
            wb = torch.where(yb > 0, torch.tensor(float(w_pos)), torch.tensor(1.0))
            opt.zero_grad()
            loss = (lossf(model(xb), yb) * wb).mean()
            loss.backward()
            opt.step()
            tot += float(loss.detach()) * len(idx)
        print(f"    lstm epoch {ep + 1}/{epochs}: loss {tot / len(y):.4f} ({time.time() - t0:.0f}s)", flush=True)
    model.eval()
    return model


def score_lstm(model, toks, batch=4096):
    import torch
    out = []
    lengths = (toks != 0).sum(1)
    with torch.no_grad():
        for i in range(0, len(toks), batch):
            L = int(lengths[i:i + batch].max()) or 1
            out.append(model(torch.from_numpy(toks[i:i + batch, :L])).numpy())
    return np.concatenate(out).astype(np.float64)


def shipped_scorers():
    """The shipped models. The TRM costs milliseconds per name, so each distinct
    label is scored once (all cores) and remembered."""
    import onnxruntime as ort
    from scoring import DEFAULT_LR_COEF, DEFAULT_LR_META, DEFAULT_ONNX, LRModel
    so = ort.SessionOptions()
    so.intra_op_num_threads = os.cpu_count() or 1
    sess = ort.InferenceSession(DEFAULT_ONNX, so, providers=["CPUExecutionProvider"])
    inp = sess.get_inputs()[0].name
    lr = LRModel(DEFAULT_LR_COEF, DEFAULT_LR_META)
    memo: dict[bytes, float] = {}

    def s_trm(t):
        keys = [row.tobytes() for row in t]
        todo = sorted({k for k in keys if k not in memo})
        for i in range(0, len(todo), 4096):
            chunk = todo[i:i + 4096]
            arr = np.frombuffer(b"".join(chunk), dtype=np.int64).reshape(len(chunk), -1)
            for k, v in zip(chunk, sess.run(None, {inp: arr})[0]):
                memo[k] = float(v)
            print(f"    trm: {len(memo)} labels scored", flush=True)
        return np.array([memo[k] for k in keys])
    return {"shipped-trm": s_trm, "shipped-lr": lr.score_tokens}


# --------------------------------------------------------------------------- speed
SPEED_NAMES = ["google", "wikipedia", "xk2qv9zr7wpl3m", "brothernerveplace", "my-home-server",
               "cloudflare", "a1b2c3d4e5f6g7", "weatherscript", "netflix", "qwkdjfhzmx"]

def latency(fn, labels, reps=5000, rounds=5) -> float:
    """Microseconds to score ONE name (batch of 1), as the resolver does: the best of
    `rounds` runs, so other load on the machine doesn't count against a model."""
    for lab in labels:
        fn([lab])
    best = float("inf")
    for _ in range(rounds):
        t = time.perf_counter()
        for i in range(reps):
            fn([labels[i % len(labels)]])
        best = min(best, (time.perf_counter() - t) / reps * 1e6)
    return best


def speed_table(workdir: str, labels) -> list[tuple]:
    """Size and time per name of each model. Weights don't change either, so the
    models are built with random weights: this needs no training and no data."""
    import onnxruntime as ort
    import torch
    from scoring import DEFAULT_ONNX, LRModel, TRMModel
    rows = []
    trm = TRMModel(DEFAULT_ONNX)
    rows.append(("shipped-trm (ONNX)", os.path.getsize(DEFAULT_ONNX), latency(trm.score, labels, reps=300)))
    rng = np.random.default_rng(0)
    for name, spec in LR_VARIANTS.items():
        meta = os.path.join(workdir, f"{name}_meta.json")
        coef = os.path.join(workdir, f"{name}_coef.npy")
        np.save(coef, rng.normal(0, 0.1, spec["buckets"]).astype(np.float16))
        with open(meta, "w") as f:
            json.dump({"intercept": 0.0, **spec}, f)
        lr = LRModel(coef, meta)  # the device scorer itself
        rows.append((f"{name} (numpy)", os.path.getsize(coef) - 128, latency(lr.score, labels)))
    path = os.path.join(workdir, "lstm.onnx")
    torch.manual_seed(0)
    lstm = lstm_model().eval()
    torch.onnx.export(lstm, torch.ones((1, 16), dtype=torch.int64), path, input_names=["tokens"],
                      output_names=["p"], dynamic_axes={"tokens": {0: "n", 1: "t"}}, dynamo=False)
    so = ort.SessionOptions()
    so.intra_op_num_threads = so.inter_op_num_threads = 1
    sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])

    def s_lstm(b):
        t = tokens(b)
        L = int((t != 0).sum(1).max()) or 1
        return sess.run(None, {"tokens": t[:, :L]})[0]
    rows.append(("lstm (ONNX)", os.path.getsize(path), latency(s_lstm, labels)))
    return rows


# --------------------------------------------------------------------------- protocol
def run(args) -> dict:
    fetch(args.data, args.download)
    rng = np.random.default_rng(SEED)
    results = {"labelling": {}, "mixed": {}, "unseen": {}, "speed": []}
    shipped = shipped_scorers()

    # 1. What the shipped models see, before and after the suffix fix.
    for tag, labeller in (("before (v0.2.0-beta.2 labels)", legacy_registrable_label),
                          ("after (dynamic-DNS + ccSLD rules)", registrable_label)):
        ben, _, _ = load(args.data, labeller)
        b_idx = rng.permutation(len(ben))[:N_BENIGN_TEST if not args.quick else 20_000]
        tb = tokens([ben[i] for i in b_idx])
        # every DGA name as listed (not deduplicated), so a family whose names all
        # collapse to one label ("ddns") counts with its full weight
        raw_fam, raw_lab = [], []
        with open(os.path.join(args.data, "dga_domains_full.csv"), newline="") as f:
            for cls, fam, dom in csv.reader(f):
                if cls == "dga":
                    raw_fam.append(fam)
                    raw_lab.append(labeller(dom))
        if args.quick:
            pick = np.random.default_rng(SEED).permutation(len(raw_lab))[:20_000]
            raw_fam, raw_lab = [raw_fam[i] for i in pick], [raw_lab[i] for i in pick]
        td = tokens(raw_lab)
        pt, pl = shipped["shipped-trm"](tb), shipped["shipped-lr"](tb)
        qt, ql = shipped["shipped-trm"](td), shipped["shipped-lr"](td)
        results["labelling"][tag] = {
            "shipped-trm": metrics(pt, qt, raw_fam),
            "shipped-lr": metrics(pl, ql, raw_fam),
            "shipped-mean": metrics((pt + pl) / 2, (qt + ql) / 2, raw_fam),
        }
        print(f"[labels] {tag}: mean tpr@1% {results['labelling'][tag]['shipped-mean']['tpr@1%']:.3f}", flush=True)

    # 2. Training protocols on the fixed labels.
    ben, dga, fams = load(args.data, registrable_label)
    fams = np.array(fams)
    perm = rng.permutation(len(ben))
    n_test = N_BENIGN_TEST if not args.quick else 20_000
    n_train = N_BENIGN_TRAIN if not args.quick else 40_000
    ben = np.array(ben, dtype=object)
    ben_test, ben_pool = ben[perm[:n_test]], ben[perm[n_test:]]
    t_ben_test = tokens(ben_test)
    family_list = sorted(set(fams))
    if args.quick:
        keep = np.zeros(len(dga), bool)
        for f in family_list:
            keep[np.nonzero(fams == f)[0][:1500]] = True
        dga, fams = dga[keep], fams[keep]
    print(f"[data] {len(ben)} normal labels, {len(dga)} DGA labels in {len(family_list)} families", flush=True)

    alphas: dict[str, float] = {}

    def one_split(train_mask, test_mask, tag):
        tr_ben = ben_pool[rng.permutation(len(ben_pool))[:n_train]]
        Xtr = tokens(list(tr_ben) + list(dga[train_mask]))
        ytr = np.r_[np.zeros(len(tr_ben), np.int64), np.ones(int(train_mask.sum()), np.int64)]
        Xte = tokens(dga[test_mask])
        fte = fams[test_mask]
        out = {}
        for name, sc in shipped.items():
            out[name] = (sc(t_ben_test), sc(Xte))
        out["shipped-mean"] = tuple((a + b) / 2 for a, b in zip(out["shipped-trm"], out["shipped-lr"]))
        for name, spec in LR_VARIANTS.items():
            t0 = time.time()
            if name not in alphas:
                alphas[name] = pick_alpha(Xtr, ytr, spec, rng)
                print(f"  [{tag}] {name}: alpha {alphas[name]:g} (chosen on a validation slice)", flush=True)
            coef, icpt = train_lr(Xtr, ytr, spec, alpha=alphas[name])
            out[name] = (score_lr(coef, icpt, t_ben_test, spec), score_lr(coef, icpt, Xte, spec))
            print(f"  [{tag}] {name} trained in {time.time() - t0:.0f}s", flush=True)
        t0 = time.time()
        lstm = train_lstm(Xtr, ytr, epochs=args.lstm_epochs)
        out["lstm"] = (score_lstm(lstm, t_ben_test), score_lstm(lstm, Xte))
        print(f"  [{tag}] lstm trained in {time.time() - t0:.0f}s", flush=True)
        # the shipped architecture (mean with the TRM) with an n-gram model retrained here
        sig = lambda z: 1 / (1 + np.exp(-np.clip(z, -500, 500)))  # noqa: E731
        out["shipped-trm + lr-v3b"] = tuple((a + sig(b)) / 2 for a, b in zip(out["shipped-trm"], out["lr-v3b"]))
        res = {k: metrics(b, d, fte) for k, (b, d) in out.items()}
        for k, v in res.items():
            print(f"  [{tag}] {k:20s} auc {v['auc']:.4f}  tpr@1% {v['tpr@1%']:.3f}  tpr@0.1% {v['tpr@0.1%']:.3f}", flush=True)
        return res

    # mixed: 80/20 inside every family
    test_mask = np.zeros(len(dga), bool)
    for f in family_list:
        idx = np.nonzero(fams == f)[0]
        test_mask[rng.permutation(idx)[: len(idx) // 5]] = True
    results["mixed"] = one_split(~test_mask, test_mask, "mixed")

    # unseen: 5 folds of 5 families
    order = list(rng.permutation(family_list))
    folds = [order[i::5] for i in range(5)][: (1 if args.quick else 5)]
    for k, held in enumerate(folds):
        m = np.isin(fams, held)
        res = one_split(~m, m, f"unseen fold {k + 1}: {', '.join(sorted(held))}")
        results["unseen"][f"fold{k + 1}"] = {"families": sorted(held), "results": res}

    results["speed"] = speed_table(args.work, SPEED_NAMES)
    return results


# --------------------------------------------------------------------------- report
def pct(x):
    return f"{100 * x:.1f}%"


def report(res: dict, quick: bool) -> str:
    L = ["# Public DGA benchmark",
         "",
         "Generated by `public_bench.py`" + (" --quick (small sample: not for quoting)" if quick else "") +
         ". Data: Netlab 360 DGA feed via chrmor/DGA_domains_dataset (25 families) and the "
         "Tranco top-1M list V354N; 200,000 normal test names never used in training. "
         "Caught = share of DGA names scored above the threshold that flags 1% (or 0.1%) of "
         "the normal test names.",
         "",
         "Read with care: one seed, one dataset, and the LSTM is a reimplementation trained for "
         "6 epochs without tuning (the n-gram regularisation was chosen on a validation slice). "
         "These are not the DRIFT numbers in the README, and the shipped models were not "
         "retrained here. Dictionary-word families (matsnu, suppobox, gozi, nymaim) stay mostly "
         "uncaught by every model: their names are made of real words.",
         ""]
    L += ["## What the shipped models see", "",
          "The shipped models (trained on DRIFT, not retrained here) on every DGA name, scored "
          "on the label Ghostwall picks out of it.", "",
          "| Labels | Model | AUC | Caught at 1% FP | at 0.1% FP |", "|---|---|---|---|---|"]
    for tag, r in res["labelling"].items():
        for m in ("shipped-trm", "shipped-lr", "shipped-mean"):
            L.append(f"| {tag} | {m} | {r[m]['auc']:.3f} | {pct(r[m]['tpr@1%'])} | {pct(r[m]['tpr@0.1%'])} |")
    before, after = res["labelling"].values()
    worst = sorted(before["shipped-mean"]["family@1%"].items(), key=lambda kv: kv[1])[:6]
    L += ["", "Families caught worst before the fix (shipped mean, 1% FP): " +
          ", ".join(f"{f} {pct(v)} -> {pct(after['shipped-mean']['family@1%'][f])}" for f, v in worst), ""]

    order = ["shipped-trm", "shipped-lr", "shipped-mean", "lr-v2", "lr-v3", "lr-v3b", "lstm",
             "shipped-trm + lr-v3b"]
    L += ["## Mixed split (80/20 inside every family)", "",
          "| Model | AUC | Caught at 1% FP | at 0.1% FP |", "|---|---|---|---|"]
    for m in order:
        r = res["mixed"][m]
        L.append(f"| {m} | {r['auc']:.4f} | {pct(r['tpr@1%'])} | {pct(r['tpr@0.1%'])} |")
    L += ["", "## Unseen families (train on 20, test on the other 5; mean of the folds)", "",
          "| Model | AUC | Caught at 1% FP | at 0.1% FP |", "|---|---|---|---|"]
    folds = list(res["unseen"].values())
    for m in order:
        a = np.mean([f["results"][m]["auc"] for f in folds])
        t1 = np.mean([f["results"][m]["tpr@1%"] for f in folds])
        t01 = np.mean([f["results"][m]["tpr@0.1%"] for f in folds])
        L.append(f"| {m} | {a:.4f} | {pct(t1)} | {pct(t01)} |")
    L += ["", "Per family, unseen, caught at 1% FP:", "",
          "| Family | " + " | ".join(order) + " |", "|---|" + "---|" * len(order)]
    for f in folds:
        for fam in f["families"]:
            L.append(f"| {fam} | " + " | ".join(pct(f["results"][m]["family@1%"][fam]) for m in order) + " |")
    L += ["", "## Size and speed (one name at a time, one CPU thread, this machine)", "",
          "| Model | Size on disk | Microseconds per name (best of 5 runs) |", "|---|---|---|"]
    for name, size, us in res["speed"]:
        L.append(f"| {name} | {size / 1024:.0f} KB | {us:.0f} |")
    L += ["", "Speed is from the machine that ran the benchmark, not a Raspberry Pi, through the "
          "same code the device runs (the n-gram rows use scoring.LRModel with float16 weights). "
          "`--speed-only` remeasures this table alone.", ""]
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", required=True, help="folder for the two pinned data files")
    ap.add_argument("--download", action="store_true", help="fetch missing data files (checked by sha256)")
    ap.add_argument("--work", default=None, help="folder for the trained models (default: --data)")
    ap.add_argument("--out", default=os.path.join(HERE, "results_public.md"))
    ap.add_argument("--json", default=None, help="also write the raw results here")
    ap.add_argument("--lstm-epochs", type=int, default=6)
    ap.add_argument("--quick", action="store_true", help="small sample and one fold, to try it out")
    ap.add_argument("--from-json", help="re-render the report from a saved --json file")
    ap.add_argument("--speed-only", action="store_true",
                    help="with --from-json: remeasure the size and speed table (needs no data)")
    args = ap.parse_args(argv)
    args.work = args.work or args.data
    if args.from_json:
        with open(args.from_json, encoding="utf-8") as f:
            res = json.load(f)
        if args.speed_only:
            res["speed"] = speed_table(args.work, SPEED_NAMES)
            with open(args.from_json, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=1, default=float)
    else:
        res = run(args)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report(res, args.quick))
    if args.json and not args.from_json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=1, default=float)
    print(f"[bench] wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
