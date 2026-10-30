#!/usr/bin/env python3
"""Sanity-check the exported ONNX model from the scorer's point of view.

Encodes a few well-known benign and DGA-looking domains with the scorer's own
tokenizer and prints P(dga). Run after export_onnx.py:
    python check_cache.py [model.onnx]
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from scorer import Scorer  # noqa: E402


def main(out_path=None):
    out_path = out_path or os.path.join(HERE, "trm_dga.onnx")
    s = Scorer(out_path)
    doms = ["www.google.com", "api.github.com", "www.wikipedia.org",   # benign, with TLD
            "tjzlzpwf", "xkfjqzwnmstvbdh", "lekwnlokmpmspmxz"]          # DGA-style, bare
    out = s.score(doms)
    print("sample scores:", {d: round(float(p), 3) for d, p in zip(doms, out)})


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
