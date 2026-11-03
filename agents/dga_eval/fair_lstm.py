#!/usr/bin/env python3
"""A fairer rematch: the 1-5-gram model against an LSTM trained the way Woodbridge et al.
trained theirs (early stopping on held-out names), several seeds each.

results_public.md trained its LSTM once for a fixed 6 epochs with no tuning, which is a
weak opponent. Here every model gets the same data and splits as public_bench.py's
"unseen families" protocol, and:

  lstm     up to --max-epochs epochs, stopping when the loss on 10% held-out training
           names hasn't improved for 2 epochs; the best epoch is kept
  lr-v3    hashed 1-5-grams, regularisation from public_bench's validation pick (1e-5),
           with SGD's shuffling seeded the same way

    python agents/dga_eval/fair_lstm.py --data DIR [--seeds 3] [--max-epochs 15]

Writes results_lstm_fair.md: mean and range over the seeds, per fold and overall.
"""
from __future__ import annotations

import argparse
import copy
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import public_bench as B  # noqa: E402


def train_lstm_early(Xtok, y, seed, max_epochs=15, patience=2, batch=256):
    import torch
    torch.manual_seed(seed)
    torch.set_num_threads(os.cpu_count() or 1)
    rng = np.random.default_rng(seed)
    val = rng.random(len(y)) < 0.1
    Xt, yt, Xv, yv = Xtok[~val], y[~val], Xtok[val], y[val]
    model = B.lstm_model()
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    lossf = torch.nn.BCEWithLogitsLoss(reduction="none")
    w_pos = (yt == 0).sum() / max(1, (yt == 1).sum())
    lengths = (Xt != 0).sum(1)
    best, best_state, bad, epochs = float("inf"), None, 0, 0
    for ep in range(max_epochs):
        model.train()
        order = np.argsort(lengths + rng.random(len(lengths)), kind="stable")
        chunks = [order[i:i + batch] for i in range(0, len(order), batch)]
        rng.shuffle(chunks)
        for idx in chunks:
            L = int(lengths[idx].max()) or 1
            xb, yb = torch.from_numpy(Xt[idx, :L]), torch.from_numpy(yt[idx].astype(np.float32))
            wb = torch.where(yb > 0, torch.tensor(float(w_pos)), torch.tensor(1.0))
            opt.zero_grad()
            (lossf(model(xb), yb) * wb).mean().backward()
            opt.step()
        model.eval()
        pv = B.score_lstm(model, Xv)
        with torch.no_grad():
            vl = float(lossf(torch.from_numpy(pv), torch.from_numpy(yv.astype(np.float64))).mean())
        epochs = ep + 1
        if vl < best - 1e-4:
            best, best_state, bad = vl, copy.deepcopy(model.state_dict()), 0
        else:
            bad += 1
            if bad >= patience:
                break
    model.load_state_dict(best_state)
    model.eval()
    return model, epochs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", required=True)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--max-epochs", type=int, default=15)
    ap.add_argument("--out", default=os.path.join(HERE, "results_lstm_fair.md"))
    args = ap.parse_args(argv)
    B.fetch(args.data, False)

    # Same names, normal test set and folds as public_bench.py (its rng, replayed).
    rng = np.random.default_rng(B.SEED)
    for labeller in (B.legacy_registrable_label, B.registrable_label):
        ben, _, _ = B.load(args.data, labeller)
        rng.permutation(len(ben))
    ben, dga, fams = B.load(args.data, B.registrable_label)
    fams = np.array(fams)
    ben = np.array(ben, dtype=object)
    perm = rng.permutation(len(ben))
    ben_test, ben_pool = ben[perm[:B.N_BENIGN_TEST]], ben[perm[B.N_BENIGN_TEST:]]
    t_test = B.tokens(ben_test)
    family_list = sorted(set(fams))
    test_mask = np.zeros(len(dga), bool)
    for f in family_list:
        idx = np.nonzero(fams == f)[0]
        test_mask[rng.permutation(idx)[: len(idx) // 5]] = True
    rng.permutation(len(ben_pool))                       # the mixed split's normal sample...
    n_mixed = B.N_BENIGN_TRAIN + int((~test_mask).sum())
    for _ in B.LR_VARIANTS:                              # ...and pick_alpha's validation draws
        rng.random(n_mixed)
    order = list(rng.permutation(family_list))
    folds = [order[i::5] for i in range(5)]
    for k, held in enumerate(folds):
        print(f"fold {k + 1}: {', '.join(sorted(held))}", flush=True)

    spec = B.LR_VARIANTS["lr-v3"]
    res = {"lr-v3": [], "lstm": []}   # per fold: list over seeds of (auc, tpr1, tpr01)
    epochs_used = []
    for k, held in enumerate(folds):
        m = np.isin(fams, held)
        fold = {"lr-v3": [], "lstm": []}
        for seed in range(args.seeds):
            srng = np.random.default_rng(1000 * k + seed)
            tr_ben = ben_pool[srng.permutation(len(ben_pool))[:B.N_BENIGN_TRAIN]]
            Xtr = B.tokens(list(tr_ben) + list(dga[~m]))
            ytr = np.r_[np.zeros(len(tr_ben), np.int64), np.ones(int((~m).sum()), np.int64)]
            Xte = B.tokens(dga[m])
            from sklearn.linear_model import SGDClassifier
            t0 = time.time()
            clf = SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=50, tol=1e-4,
                                random_state=seed, class_weight="balanced").fit(B.csr(Xtr, spec), ytr)
            coef, icpt = clf.coef_.ravel(), float(clf.intercept_[0])
            pb, pd_ = B.score_lr(coef, icpt, t_test, spec), B.score_lr(coef, icpt, Xte, spec)
            met = B.metrics(pb, pd_, fams[m])
            fold["lr-v3"].append((met["auc"], met["tpr@1%"], met["tpr@0.1%"]))
            t1 = time.time()
            model, ep = train_lstm_early(Xtr, ytr, seed, args.max_epochs)
            epochs_used.append(ep)
            met = B.metrics(B.score_lstm(model, t_test), B.score_lstm(model, Xte), fams[m])
            fold["lstm"].append((met["auc"], met["tpr@1%"], met["tpr@0.1%"]))
            print(f"[fold {k + 1} seed {seed}] lr-v3 {fold['lr-v3'][-1][1]:.3f} ({t1 - t0:.0f}s)  "
                  f"lstm {fold['lstm'][-1][1]:.3f} after {ep} epochs ({time.time() - t1:.0f}s)", flush=True)
        for name in res:
            res[name].append(fold[name])

    def pct(x):
        return f"{100 * x:.1f}%"

    L = ["# A fairer rematch: 1-5-gram model vs an early-stopped LSTM", "",
         f"Generated by `fair_lstm.py`. Same data, normal test names and unseen-family folds as "
         f"[results_public.md](results_public.md). The LSTM (Woodbridge et al. 2016 layout) trains "
         f"for up to {args.max_epochs} epochs and keeps its best epoch on 10% held-out training names "
         f"(it stopped after {min(epochs_used)}-{max(epochs_used)} epochs); {args.seeds} seeds per fold for "
         "both models. Caught = DGA names scored above the threshold that flags 1% (or 0.1%) of the "
         "200,000 normal test names. Mean over seeds, range in brackets.", "",
         "| Fold (held-out families) | Model | AUC | Caught at 1% FP | at 0.1% FP |", "|---|---|---|---|---|"]
    for k, held in enumerate(folds):
        for name in ("lr-v3", "lstm"):
            arr = np.array(res[name][k])
            cells = []
            for j in range(3):
                col = arr[:, j]
                cells.append(f"{col.mean():.4f}" if j == 0 else f"{pct(col.mean())} [{pct(col.min())}-{pct(col.max())}]")
            L.append(f"| {k + 1}: {', '.join(sorted(held))} | {name} | " + " | ".join(cells) + " |")
    L += ["", "Mean of the five folds (each fold's seed mean):", "",
          "| Model | AUC | Caught at 1% FP | at 0.1% FP |", "|---|---|---|---|"]
    for name in ("lr-v3", "lstm"):
        arr = np.array([np.mean(f, axis=0) for f in res[name]])
        L.append(f"| {name} | {arr[:, 0].mean():.4f} | {pct(arr[:, 1].mean())} | {pct(arr[:, 2].mean())} |")
    L += ["", "One dataset still: a family-held-out split of 25 families from one feed.", ""]
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"[fair] wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
