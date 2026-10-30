"""Train a TRM DGA detector on DRIFT 2017-2019 (forward-chaining protocol of the DRIFT paper).

    python trm/train.py --name trm_d96 --samples 24e6
    python trm/train.py --name flat_d96 --n 1 --T 1 --n-sup 1     # no-recursion ablation
"""
import argparse
import copy
import json
import math
import os
import sys
import time

import numpy as np
import torch
import torch.nn.functional as F

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import data as D  # noqa: E402
from model import TRM, count_params  # noqa: E402

RUNS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runs")
TRAIN_YEARS = [17, 18, 19]
AMP = False  # T1200 (TU117) has no tensor cores: fp16 is slower than fp32


def load_pool(years, exclude_hashes):
    toks, lens, labs = [], [], []
    for y in years:
        for c in ("benign", "dga"):
            tok, ln, lab, h = D.load_file(f"T{y}_{c}.parquet")
            keep = ~np.isin(h, exclude_hashes)
            toks.append(np.asarray(tok)[keep]); lens.append(ln[keep]); labs.append(lab[keep])
            print(f"  T{y}_{c}: {keep.sum():,} train rows ({(~keep).sum():,} held out)", flush=True)
    return np.concatenate(toks), np.concatenate(lens), np.concatenate(labs)


def load_val(years):
    toks, lens, labs, hs = [], [], [], []
    for y in years:
        for c in ("benign", "dga"):
            tok, ln, lab, h = D.load_file(f"T{y}_{c}_val.parquet")
            toks.append(np.asarray(tok)); lens.append(ln); labs.append(lab); hs.append(h)
    return np.concatenate(toks), np.concatenate(lens), np.concatenate(labs), np.concatenate(hs)


def batches(tok, ln, idx, bs, rng, bucket=64, shuffle=True):
    """Yield (tok_batch, idx) with length bucketing to minimise padding."""
    for i in range(0, len(idx), bs * bucket):
        chunk = idx[i:i + bs * bucket]
        chunk = chunk[np.argsort(ln[chunk], kind="stable")]
        bl = [chunk[j:j + bs] for j in range(0, len(chunk), bs)]
        if shuffle:
            rng.shuffle(bl)
        for b in bl:
            L = max(8, int(math.ceil(max(1, ln[b].max()) / 8) * 8))
            t = D.strip_dot(tok[b, :L])
            t[~(t != 0).any(1), 0] = D.UNK  # never feed an all-pad row
            yield t, b


@torch.no_grad()
def evaluate(model, tok, ln, lab, bs=4096, n_sup=None, dev="cuda"):
    model.eval()
    probs = np.zeros(len(lab), np.float32)
    idx = np.arange(len(lab))
    for t, b in batches(tok, ln, idx, bs, None, shuffle=False):
        with torch.autocast("cuda", dtype=torch.float16, enabled=AMP):
            p = model.predict_proba(torch.from_numpy(t).long().to(dev), n_sup)[:, 1]
        probs[b] = p.cpu().numpy()
    return probs


def metrics(prob, lab, thr=0.5):
    pred = prob >= thr
    tp = int((pred & (lab == 1)).sum()); fp = int((pred & (lab == 0)).sum())
    fn = int((~pred & (lab == 1)).sum()); tn = int((~pred & (lab == 0)).sum())
    prec = tp / max(1, tp + fp); rec = tp / max(1, tp + fn)
    return dict(acc=(tp + tn) / max(1, len(lab)), prec=prec, rec=rec,
                f1=2 * prec * rec / max(1e-9, prec + rec), fpr=fp / max(1, fp + tn), fnr=fn / max(1, fn + tp),
                tp=tp, fp=fp, fn=fn, tn=tn)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--d", type=int, default=96)
    ap.add_argument("--heads", type=int, default=4)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--n", type=int, default=3)
    ap.add_argument("--T", type=int, default=2)
    ap.add_argument("--n-sup", type=int, default=3)
    ap.add_argument("--samples", type=float, default=24e6, help="training samples seen")
    ap.add_argument("--bs", type=int, default=1024)
    ap.add_argument("--lr", type=float, default=2e-3)
    ap.add_argument("--wd", type=float, default=0.05)
    ap.add_argument("--ema", type=float, default=0.999)
    ap.add_argument("--eval-every", type=int, default=2000)
    ap.add_argument("--val-max", type=int, default=300_000)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    out = os.path.join(RUNS, a.name)
    os.makedirs(out, exist_ok=True)
    torch.manual_seed(a.seed)
    rng = np.random.default_rng(a.seed)
    dev = "cuda"

    print("loading validation (2017-2019 holdout)...", flush=True)
    vtok, vln, vlab, vh = load_val(TRAIN_YEARS)
    vsel = rng.choice(len(vlab), min(a.val_max, len(vlab)), replace=False)
    print("loading training pool (2017-2019 minus holdout)...", flush=True)
    tok, ln, lab = load_pool(TRAIN_YEARS, np.unique(vh))
    pos, neg = np.flatnonzero(lab == 1), np.flatnonzero(lab == 0)
    print(f"pool: {len(lab):,} rows  benign={len(neg):,} dga={len(pos):,}", flush=True)

    model = TRM(D.N_TOKENS, D.MAX_LEN, a.d, a.heads, a.layers, a.n, a.T, a.n_sup).to(dev)
    ema = copy.deepcopy(model).eval()
    for p in ema.parameters():
        p.requires_grad_(False)
    nparam = count_params(model)
    print(f"model: {nparam:,} params  effective depth/step={a.T * (a.n + 1) * a.layers} layers, n_sup={a.n_sup}",
          flush=True)

    decay = [p for n_, p in model.named_parameters() if p.ndim >= 2 and "emb" not in n_]
    other = [p for n_, p in model.named_parameters() if not (p.ndim >= 2 and "emb" not in n_)]
    opt = torch.optim.AdamW([{"params": decay, "weight_decay": a.wd}, {"params": other, "weight_decay": 0}],
                            lr=a.lr, betas=(0.9, 0.95), fused=True)
    scaler = torch.amp.GradScaler(enabled=AMP)
    total_steps = int(a.samples // a.bs)
    warm = min(1000, total_steps // 20)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1, (s + 1) / warm) * 0.5 * (1 + math.cos(math.pi * min(1.0, s / total_steps))))

    json.dump(dict(vars(a), params=nparam, cfg=model.cfg), open(os.path.join(out, "config.json"), "w"), indent=1)
    log = open(os.path.join(out, "log.jsonl"), "a")
    step, best, t0, seen = 0, -1, time.time(), 0
    while step < total_steps:
        # balanced epoch-chunk: equal benign / dga, freshly sampled
        k = min(4_000_000, (total_steps - step) * a.bs // 2 + a.bs)
        idx = np.concatenate([rng.choice(neg, k, replace=len(neg) < k), rng.choice(pos, k, replace=len(pos) < k)])
        rng.shuffle(idx)
        model.train()
        for t, b in batches(tok, ln, idx, a.bs, rng):
            x = torch.from_numpy(t).to(dev, non_blocking=True).long()
            yb = torch.from_numpy(lab[b]).to(dev).long()
            opt.zero_grad(set_to_none=True)
            # deep supervision: backprop each supervision step on its own so only one step's
            # activations are alive at a time (fits the 4 GB GPU)
            yz = None
            loss_sum = 0.0
            for s in range(model.n_sup):
                with torch.autocast("cuda", dtype=torch.float16, enabled=AMP):
                    xe, mask, keep = model.embed(x)   # cheap; gives every step its own graph
                    if yz is None:
                        y0 = model.y0.expand_as(xe).contiguous(); z0 = model.z0.expand_as(xe).contiguous()
                    else:
                        y0, z0 = yz
                    y_, z_ = model.recurse(xe, y0, z0, mask, grad_last=True)
                    loss_s = F.cross_entropy(model.head(model._pool(y_, keep)).float(), yb) / model.n_sup
                scaler.scale(loss_s).backward()
                loss_sum += loss_s.item()
                yz = (y_.detach(), z_.detach())
            loss = torch.tensor(loss_sum)
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(opt); scaler.update(); sched.step()
            with torch.no_grad():
                for pe, pm in zip(ema.parameters(), model.parameters()):
                    pe.lerp_(pm, 1 - a.ema)
            step += 1; seen += len(b)
            if step % 50 == 0:
                el = time.time() - t0
                print(f"step {step}/{total_steps} loss {loss.item():.4f} lr {sched.get_last_lr()[0]:.2e} "
                      f"{seen / el:,.0f} samples/s  eta {(total_steps - step) * el / step / 60:.0f} min", flush=True)
            if step % a.eval_every == 0 or step >= total_steps:
                pv = evaluate(ema, vtok[vsel], vln[vsel], vlab[vsel])
                m = metrics(pv, vlab[vsel])
                rec = dict(step=step, seen=seen, loss=loss.item(), **{f"val_{k_}": v for k_, v in m.items()})
                log.write(json.dumps(rec) + "\n"); log.flush()
                print(f"  VAL step {step}: acc {m['acc']:.4f} f1 {m['f1']:.4f} fpr {m['fpr']:.4f} fnr {m['fnr']:.4f}",
                      flush=True)
                torch.save({"cfg": model.cfg, "state": ema.state_dict(), "step": step}, os.path.join(out, "last.pt"))
                if m["f1"] > best:
                    best = m["f1"]
                    torch.save({"cfg": model.cfg, "state": ema.state_dict(), "step": step}, os.path.join(out, "best.pt"))
                model.train()
            if step >= total_steps:
                break
    print(f"done. best val f1 {best:.4f}  time {(time.time() - t0) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
