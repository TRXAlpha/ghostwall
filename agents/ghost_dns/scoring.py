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

# onnxruntime 1.29 and later send usage telemetry to Microsoft by default (see
# docs/Privacy.md in its repository). Nothing about this box should leave it, so
# telemetry is switched off before onnxruntime is first imported; that is the only
# point where the switch works.
os.environ.setdefault("ORT_DISABLE_TELEMETRY", "1")

import numpy as np  # noqa: E402

from ngram import hashed_ngrams, hashed_ngrams_one  # noqa: E402
from tokenizer import encode, registrable_label, strip_dot  # noqa: E402

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

        if os.environ.get("ORT_DISABLE_TELEMETRY") == "1" and hasattr(ort, "disable_telemetry_events"):
            ort.disable_telemetry_events()
        so = ort.SessionOptions()
        so.intra_op_num_threads = 1
        so.inter_op_num_threads = 1
        self.sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
        self.input_name = self.sess.get_inputs()[0].name

    def score(self, labels: list[str]) -> np.ndarray:
        return self.score_tokens(strip_dot(encode(labels)))

    def score_tokens(self, toks: np.ndarray) -> np.ndarray:
        """Dot-stripped int64 token rows -> p_dga (used by agents/dga_eval)."""
        return self.sess.run(None, {self.input_name: toks})[0].astype(float)


class LRModel:
    """Pure-numpy hashed char n-gram logistic regression (no sklearn/scipy).

    Features come from ngram.hashed_ngrams, the same function the trainers use;
    lr_meta.json says which ones (ngram_max, boundary, buckets). A meta file without
    "boundary" is the shipped v2 model (1-3-grams, no boundary markers).
    """

    def __init__(self, coef_path: str, meta_path: str):
        self.coef = np.load(coef_path, allow_pickle=False).astype(np.float64).ravel()
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.intercept = float(meta["intercept"])
        self.buckets = int(meta["buckets"])
        if self.buckets < 1:  # rejected here: a zero modulus would fail on every lookup, not at load
            raise ValueError(f"{meta_path}: buckets must be at least 1, not {self.buckets}")
        self.ngram_max = int(meta.get("ngram_max", 3))
        self.boundary = bool(meta.get("boundary", False))
        if self.coef.shape[0] != self.buckets:
            raise ValueError(f"{coef_path}: {self.coef.shape[0]} weights for {self.buckets} buckets")

    def score(self, labels: list[str]) -> np.ndarray:
        return self.score_tokens(strip_dot(encode(labels)))

    def score_tokens(self, toks: np.ndarray) -> np.ndarray:
        """Dot-stripped int64 token rows -> p_dga (used by agents/dga_eval)."""
        if len(toks) == 1:  # the resolver's case: one name, no numpy loop overhead
            cols = hashed_ngrams_one(toks[0], self.buckets, self.ngram_max, self.boundary)
            z = self.intercept + float(self.coef[cols].sum()) if cols else self.intercept
            return _sigmoid(np.array([z], dtype=np.float64))
        z = np.full(len(toks), self.intercept, dtype=np.float64)
        for rows, cols in hashed_ngrams(toks, self.buckets, self.ngram_max, self.boundary):
            z[rows] += self.coef[cols]
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
        # The TRM costs milliseconds per name on a Pi and most lookups repeat a few
        # thousand names, so scores are kept per label (bounded; cleared when full).
        self._cache: dict[str, dict] = {}
        self.cache_max = 50_000
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
        hit = self._cache.get(label)
        if hit is not None:
            return dict(hit)
        out = self._score_label(label)
        if len(self._cache) >= self.cache_max:
            self._cache.clear()
        self._cache[label] = out
        return dict(out)

    def _score_label(self, label: str) -> dict:
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
