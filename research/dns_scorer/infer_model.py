"""Inference wrapper around trm.model.TRM: returns P(dga) of the final
supervision step. Used for ONNX export: the legacy TorchScript exporter
(dynamo=False) decomposes F.scaled_dot_product_attention into ONNX ops
(MatMul + Softmax with an additive mask), so the original model exports
as-is — no numerical rewrite needed and parity is exact.

Do not train with this; it is for export/parity checking only.
"""
import os
import sys

import torch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from trm.model import TRM  # noqa: E402,F401  (re-exported for importers)


class TRMInfer(torch.nn.Module):
    """tok int64 [B, L] -> P(dga) float32 [B]. Shares weights with the given
    TRM (no copies)."""

    def __init__(self, trm: TRM):
        super().__init__()
        self.trm = trm
        self.cfg = trm.cfg

    def forward(self, tok: torch.Tensor) -> torch.Tensor:
        """tok int64 [B, L] -> P(dga) float32 [B] (final supervision step)."""
        logits = self.trm(tok)[-1]
        return torch.softmax(logits.float(), dim=-1)[:, 1]
