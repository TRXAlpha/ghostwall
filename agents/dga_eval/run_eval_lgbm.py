"""Resume evaluation: only lgbm_lexical (logreg already done), then write results_baselines.md."""
import os, sys, json, time
os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["OMP_NUM_THREADS"] = "3"
os.environ["MKL_NUM_THREADS"] = "3"
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import eval_lib as el
import train_baselines as tb
from run_eval import fmt, write_md, run


def main():
    lr, lb, bbg, dbg = tb.load_predictors(os.path.join(HERE, "models"))
    pf_logreg = tb.make_logreg_predictor(lr)
    pf_lgbm = tb.make_lgbm_predictor(lb, bbg, dbg)

    res_logreg = json.load(open(os.path.join(HERE, "results_logreg_ngram.json")))
    all_results = [("logreg_ngram", res_logreg)]
    res = run("lgbm_lexical", pf_lgbm, HERE)
    all_results.append(("lgbm_lexical", res))

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

    write_md(all_results, leakage, os.path.join(HERE, "results_baselines.md"))
    print("Wrote results_baselines.md", flush=True)


if __name__ == "__main__":
    main()
