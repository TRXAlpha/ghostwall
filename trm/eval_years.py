"""Forward-chaining eval of a TRM checkpoint on DRIFT test years (frozen model, no retraining)."""
import sys, os, json, numpy as np, torch
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import data as D
from model import TRM
from train import evaluate, metrics, batches
from sklearn.metrics import roc_auc_score

def tpr_at_fpr(p, y, f):
    thr = np.quantile(p[y == 0], 1 - f); return float((p[y == 1] >= thr).mean())

def main(run, n_per=300_000, years=range(20, 26)):
    ck = torch.load(f"runs/{run}/best.pt", map_location="cuda")
    m = TRM(**ck["cfg"]).cuda(); m.load_state_dict(ck["state"]); m.eval()
    rng = np.random.default_rng(1); rows = []; allp = []; ally = []
    for y in years:
        T, L, Y = [], [], []
        for c in ("benign", "dga"):
            tok, ln, lab, h = D.load_file(f"T{y}_{c}.parquet")
            i = np.sort(rng.choice(len(lab), min(n_per, len(lab)), replace=False))
            T.append(np.asarray(tok[i])); L.append(ln[i]); Y.append(lab[i])
        T, L, Y = map(np.concatenate, (T, L, Y))
        p = evaluate(m, T, L, Y)
        r = metrics(p, Y); r.update(year=2000 + y, auc=float(roc_auc_score(Y, p)),
                                    tpr_1=tpr_at_fpr(p, Y, 0.01), tpr_01=tpr_at_fpr(p, Y, 0.001))
        rows.append(r); allp.append(p); ally.append(Y)
        print(f"{2000+y}: acc {r['acc']:.4f} f1 {r['f1']:.4f} fpr {r['fpr']:.4f} fnr {r['fnr']:.4f} auc {r['auc']:.4f} "
              f"TPR@1%FPR {r['tpr_1']:.3f} TPR@0.1%FPR {r['tpr_01']:.3f}", flush=True)
    p, Y = np.concatenate(allp), np.concatenate(ally); r = metrics(p, Y)
    print(f"micro: acc {r['acc']:.4f} f1 {r['f1']:.4f} fpr {r['fpr']:.4f} fnr {r['fnr']:.4f}")
    json.dump(rows + [dict(year="micro", **r)], open(f"runs/{run}/forward_chaining.json", "w"), indent=1)

if __name__ == "__main__":
    main(sys.argv[1])
