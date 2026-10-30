"""Tiny Recursive Model (TRM, Jolicoeur-Martineau 2025) adapted to domain-name classification.

One tiny shared network `net` (2 post-norm transformer blocks) is applied recursively:

    for each supervision step s = 1..n_sup:
        repeat T times (all but the last without gradient):
            repeat n times:  z <- net(x + y + z)     # latent reasoning
            y <- net(y + z)                           # answer refinement
        logits_s = head(pool(y));  y, z <- detach(y, z)

Training puts a loss on every supervision step (deep supervision); inference returns the last
step (optionally exiting early once confident). Effective depth = n_sup * T * (n+1) * 2 layers
with the parameters of 2.
"""
import math

import torch
import torch.nn as nn
import torch.nn.functional as F


class RMSNorm(nn.Module):
    def __init__(self, d, eps=1e-6):
        super().__init__()
        self.w = nn.Parameter(torch.ones(d))
        self.eps = eps

    def forward(self, x):
        return x * torch.rsqrt(x.float().pow(2).mean(-1, keepdim=True) + self.eps).to(x.dtype) * self.w


class Block(nn.Module):
    def __init__(self, d, heads, ffn_mult=8 / 3):
        super().__init__()
        self.h = heads
        self.qkv = nn.Linear(d, 3 * d, bias=False)
        self.o = nn.Linear(d, d, bias=False)
        f = int(round(d * ffn_mult / 16) * 16)
        self.gate_up = nn.Linear(d, 2 * f, bias=False)
        self.down = nn.Linear(f, d, bias=False)
        self.n1, self.n2 = RMSNorm(d), RMSNorm(d)

    def forward(self, x, mask):
        B, L, D = x.shape
        q, k, v = self.qkv(x).view(B, L, 3, self.h, D // self.h).permute(2, 0, 3, 1, 4)
        a = F.scaled_dot_product_attention(q, k, v, attn_mask=mask)
        x = self.n1(x + self.o(a.transpose(1, 2).reshape(B, L, D)))
        g, u = self.gate_up(x).chunk(2, -1)
        return self.n2(x + self.down(F.silu(g) * u))


class TRM(nn.Module):
    def __init__(self, n_tokens, max_len=64, d=96, heads=4, layers=2, n=3, T=2, n_sup=3, n_classes=2):
        super().__init__()
        self.cfg = dict(n_tokens=n_tokens, max_len=max_len, d=d, heads=heads, layers=layers,
                        n=n, T=T, n_sup=n_sup, n_classes=n_classes)
        self.n, self.T, self.n_sup = n, T, n_sup
        self.emb = nn.Embedding(n_tokens, d, padding_idx=0)
        self.pos = nn.Parameter(torch.randn(max_len, d) * 0.02)
        self.blocks = nn.ModuleList([Block(d, heads) for _ in range(layers)])
        self.y0 = nn.Parameter(torch.randn(d) * 0.02)
        self.z0 = nn.Parameter(torch.randn(d) * 0.02)
        self.head = nn.Linear(d, n_classes)
        self.scale = math.sqrt(d)
        self.apply(self._init)

    @staticmethod
    def _init(m):
        if isinstance(m, nn.Linear):
            nn.init.trunc_normal_(m.weight, std=0.02)
            if m.bias is not None:
                nn.init.zeros_(m.bias)
        elif isinstance(m, nn.Embedding):
            nn.init.trunc_normal_(m.weight, std=0.02)

    def net(self, h, mask):
        for b in self.blocks:
            h = b(h, mask)
        return h

    def _pool(self, y, keep):
        return (y * keep).sum(1) / keep.sum(1).clamp(min=1)

    def embed(self, tok):
        L = tok.shape[1]
        x = self.emb(tok) * self.scale + self.pos[:L]
        valid = tok != 0
        mask = valid[:, None, None, :]            # attend only to real characters
        keep = valid[..., None].to(x.dtype)
        return x, mask, keep

    def recurse(self, x, y, z, mask, grad_last=True):
        for t in range(self.T):
            ctx = torch.enable_grad() if (grad_last and t == self.T - 1) else torch.no_grad()
            with ctx:
                for _ in range(self.n):
                    z = self.net(x + y + z, mask)
                y = self.net(y + z, mask)
        return y, z

    def forward(self, tok, n_sup=None):
        """Returns list of logits, one per supervision step."""
        x, mask, keep = self.embed(tok)
        y = self.y0.expand_as(x).contiguous()
        z = self.z0.expand_as(x).contiguous()
        outs = []
        for s in range(n_sup or self.n_sup):
            y, z = self.recurse(x, y, z, mask, grad_last=self.training)
            outs.append(self.head(self._pool(y, keep)))
            y, z = y.detach(), z.detach()
        return outs

    @torch.no_grad()
    def predict_proba(self, tok, n_sup=None):
        return torch.softmax(self.forward(tok, n_sup)[-1].float(), -1)


def count_params(m):
    return sum(p.numel() for p in m.parameters())


if __name__ == "__main__":
    m = TRM(41)
    print(count_params(m), "params")
    t = torch.randint(2, 41, (4, 20)); t[:, 15:] = 0
    print([o.shape for o in m(t)])
