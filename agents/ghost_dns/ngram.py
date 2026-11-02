"""Hashed character n-gram features for the logistic-regression DGA scorer. numpy only.

One definition shared by the scorer on the device (scoring.LRModel) and the
trainers (ghostwall/train_lr.py, agents/dga_eval/public_bench.py), so a model is
always scored with exactly the features it was trained on.

A row of token ids (tokenizer.encode + strip_dot, 0 = padding) becomes the hashed
ids of its 1..ngram_max-grams: code = rolling base-131 hash of the token ids,
& 0x7FFFFFFF, % buckets. With boundary=True the label is first wrapped in a start
and an end marker, so "^ab" and "yz$" (how names begin and end) are features too.
boundary=False is the shipped v2 feature set, bit for bit.
"""
from __future__ import annotations

import numpy as np

from tokenizer import N_TOKENS

BOS = N_TOKENS        # start-of-label marker (never produced by the tokenizer)
EOS = N_TOKENS + 1    # end-of-label marker


def with_boundaries(toks: np.ndarray, lengths: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """[BOS] + label + [EOS], left-aligned, zero padded; returns (tokens, lengths)."""
    n, w = toks.shape
    out = np.zeros((n, w + 2), dtype=np.int64)
    out[:, 0] = BOS
    out[:, 1:w + 1] = toks
    out[np.arange(n), lengths + 1] = EOS
    return out, lengths + 2


def hashed_ngrams(toks: np.ndarray, buckets: int, ngram_max: int = 3, boundary: bool = False,
                  ngram_min: int = 1):
    """Yield (row_indices, bucket_ids) per n-gram position for token rows `toks`."""
    toks = np.asarray(toks, dtype=np.int64)
    lengths = (toks != 0).sum(axis=1)
    if boundary:
        toks, lengths = with_boundaries(toks, lengths)
    width = toks.shape[1]
    for ng in range(ngram_min, ngram_max + 1):
        for j in range(width - ng + 1):
            m = lengths >= (ng + j)          # window fully inside the (wrapped) label
            if not m.any():
                continue
            code = np.zeros(int(m.sum()), dtype=np.int64)
            for k in range(ng):
                code = code * 131 + toks[m, j + k]
            code &= 0x7FFFFFFF
            yield np.nonzero(m)[0], code % buckets
