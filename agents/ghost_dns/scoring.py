"""Domain DGA scoring: TRM ONNX model + numpy logistic-regression, ensembled.

Both models score the *registrable label* (dot-stripped) of a domain and return
P(dga) in 0..1. Either model may be absent; the scorer degrades gracefully:

  - both present  -> ensemble = mean(trm, lr)
  - one present   -> that one
  - none present  -> a cheap lexical entropy heuristic (so the resolver still runs)

Honest note (docs/ARCHITECTURE.md#models): at a 0.5 cut-off these models wrongly flag
4-11% of normal domains. They are alert-grade, not block-grade. The resolver therefore
only blocks on score when a domain is *also* novel and not on the popular
allowlist, and only when learning mode is off.
"""
from __future__ import annotations

import json
import math
import os

import numpy as np

from tokenizer import encode, registrable_label, strip_dot

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_ONNX = os.path.join(ROOT, "ghostwall", "models", "trm_dga_v2.onnx")
DEFAULT_LR_COEF = os.path.join(ROOT, "ghostwall", "models", "lr_coef.npy")
DEFAULT_LR_META = os.path.join(ROOT, "ghostwall", "models", "lr_meta.json")


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))


def _entropy(label: str) -> float:
    if not label:
        return 0.0
    counts: dict[str, int] = {}
    for c in label:
        counts[c] = counts.get(c, 0) + 1
    n = len(label)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class TRMModel:
    """ONNX TRM scorer. tokens[int64 N,64] -> p_dga[float N]."""

    def __init__(self, path: str):
        import onnxruntime as ort

        so = ort.SessionOptions()
        so.intra_op_num_threads = 1
        so.inter_op_num_threads = 1
        self.sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
        self.input_name = self.sess.get_inputs()[0].name

    def score(self, labels: list[str]) -> np.ndarray:
        toks = strip_dot(encode(labels))
        return self.sess.run(None, {self.input_name: toks})[0].astype(float)


class LRModel:
    """Pure-numpy hashed char 1-3-gram logistic regression (no sklearn/scipy).

    Reproduces agents/dga_eval/train_baselines.ngram_matrix @ coef + intercept
    exactly, so it matches lr_coef.npy / lr_meta.json trained for the Pi.
    """

    def __init__(self, coef_path: str, meta_path: str):
        self.coef = np.load(coef_path).astype(np.float64).ravel()
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.intercept = float(meta["intercept"])
        self.buckets = int(meta["buckets"])
        self.ngram_max = int(meta.get("ngram_max", 3))

    def score(self, labels: list[str]) -> np.ndarray:
        toks = strip_dot(encode(labels))
        lengths = (toks != 0).sum(axis=1)
        n = len(labels)
        z = np.full(n, self.intercept, dtype=np.float64)
        width = toks.shape[1]
        for ng in range(1, self.ngram_max + 1):
            for j in range(width - ng + 1):
                m = lengths >= (ng + j)
                if not m.any():
                    continue
                code = np.zeros(int(m.sum()), dtype=np.int64)
                for k in range(ng):
                    code = code * 131 + toks[m, j + k].astype(np.int64)
                code &= 0x7FFFFFFF
                z[m] += self.coef[code % self.buckets]
        return _sigmoid(z)


class Scorer:
    """Ensemble DGA scorer with graceful fallback."""

    def __init__(
        self,
        onnx_path: str | None = DEFAULT_ONNX,
        lr_coef_path: str | None = DEFAULT_LR_COEF,
        lr_meta_path: str | None = DEFAULT_LR_META,
    ):
        self.trm: TRMModel | None = None
        self.lr: LRModel | None = None
        if onnx_path and os.path.exists(onnx_path):
            try:
                self.trm = TRMModel(onnx_path)
            except Exception:  # noqa: BLE001 - onnxruntime optional at runtime
                self.trm = None
        if lr_coef_path and lr_meta_path and os.path.exists(lr_coef_path) and os.path.exists(lr_meta_path):
            try:
                self.lr = LRModel(lr_coef_path, lr_meta_path)
            except Exception:  # noqa: BLE001
                self.lr = None

    @property
    def backend(self) -> str:
        parts = []
        if self.trm:
            parts.append("trm")
        if self.lr:
            parts.append("lr")
        return "+".join(parts) if parts else "heuristic"

    def score_one(self, domain: str) -> dict:
        """Return {'dga': float, 'dga_trm': float|None, 'dga_lr': float|None}."""
        label = registrable_label(domain)
        out: dict = {"dga_trm": None, "dga_lr": None}
        vals = []
        if self.trm is not None:
            v = float(self.trm.score([label])[0])
            out["dga_trm"] = round(v, 4)
            vals.append(v)
        if self.lr is not None:
            v = float(self.lr.score([label])[0])
            out["dga_lr"] = round(v, 4)
            vals.append(v)
        if vals:
            out["dga"] = round(sum(vals) / len(vals), 4)
        else:
            # No model available: map lexical entropy into a soft 0..1 score so
            # the pipeline still produces a ranked signal (very weak).
            h = _entropy(label)
            out["dga"] = round(min(1.0, max(0.0, (h - 3.0) / 2.0)), 4)
        return out
