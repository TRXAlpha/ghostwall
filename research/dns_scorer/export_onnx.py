"""Export the TRM DGA model to ONNX for the Raspberry Pi 4 scorer.

Loads runs/trm_dga_d64/best.pt if it exists, else random init (same config).
Input:  tokens int64 [B, L] with dynamic batch and L <= 64 (0 = pad).
Output: P(dga) float32 [B].

Usage: python export_onnx.py [--checkpoint PATH] [--out PATH]
"""
import argparse
import os
import sys

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")
import numpy as np
import torch  # noqa: E402
import onnx  # noqa: E402
import onnxruntime as ort  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from trm.model import TRM  # noqa: E402
from infer_model import TRMInfer  # noqa: E402

DEFAULT_CKPT = os.path.join(ROOT, "runs", "trm_dga_d64", "best.pt")
DEFAULT_OUT = os.path.join(HERE, "trm_dga.onnx")


def load_model(ckpt_path: str, seed: int = 0):
    torch.set_num_threads(3)
    if os.path.exists(ckpt_path):
        blob = torch.load(ckpt_path, map_location="cpu")
        cfg = blob.get("cfg", {})
        cfg.setdefault("n_tokens", 41)  # trm/data.py N_TOKENS
        m = TRM(**{k: cfg[k] for k in
                   ("n_tokens", "max_len", "d", "heads", "layers", "n", "T", "n_sup", "n_classes")
                   if k in cfg})
        missing, unexpected = m.load_state_dict(blob["state"], strict=False)
        print(f"loaded checkpoint step={blob.get('step')} "
              f"missing={missing} unexpected={unexpected}")
    else:
        print(f"checkpoint not found at {ckpt_path}; using RANDOM init (same config)")
        torch.manual_seed(seed)
        m = TRM(41)
    m.eval()
    return TRMInfer(m)


def export(model, out_path: str, dummy_len: int = 32):
    tok = torch.randint(0, 41, (2, dummy_len), dtype=torch.int64)
    tok[1, 20:] = 0  # include padding
    torch.onnx.export(
        model, (tok,), out_path, input_names=["tokens"], output_names=["p_dga"],
        dynamic_axes={"tokens": {0: "batch", 1: "length"}, "p_dga": {0: "batch"}},
        opset_version=17, do_constant_folding=True, dynamo=False,
    )
    onnx.checker.check_model(onnx.load(out_path))
    print(f"exported {out_path}")


def verify(model, out_path: str, n_cases: int = 8, seed: int = 1):
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    so = ort.SessionOptions()
    so.intra_op_num_threads = 3
    sess = ort.InferenceSession(out_path, so, providers=["CPUExecutionProvider"])
    max_err = 0.0

    def cmp(t, tag):
        nonlocal max_err
        with torch.no_grad():
            ref = model(t).numpy()
        out = sess.run(None, {"tokens": t.numpy()})[0]
        err = float(np.abs(ref - out).max())
        max_err = max(max_err, err)

    for i in range(n_cases):
        L = int(rng.integers(8, 65))
        B = int(rng.integers(1, 8))
        t = torch.randint(0, 41, (B, L), dtype=torch.int64)
        t[rng.random((B, L)) < 0.3] = 0  # random padding
        cmp(t, None)
    # real rows from the training caches (dense + heavy padding, all widths)
    import glob
    for f in sorted(glob.glob(os.path.join(ROOT, "data", "cache", "T*_val.tok.npy")))[:4]:
        tok = np.asarray(np.load(f, mmap_mode="r")[:256]).astype(np.int64)
        cmp(torch.tensor(tok), None)
    print(f"onnxruntime parity vs torch: max abs err = {max_err:.2e} "
          f"(random + real data rows)")
    assert max_err < 1e-4, "ONNX output deviates from torch by more than 1e-4"
    return max_err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", default=DEFAULT_CKPT)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--skip-parity", action="store_true")
    args = ap.parse_args()
    model = load_model(args.checkpoint)
    export(model, args.out)
    if not args.skip_parity:
        verify(model, args.out)


if __name__ == "__main__":
    main()
