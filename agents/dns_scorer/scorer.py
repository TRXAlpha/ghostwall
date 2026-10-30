#!/usr/bin/env python3
"""DNS scorer: watches an AdGuard Home querylog.json, scores new domains with the
TRM DGA ONNX model, appends alerts to alerts.jsonl. Designed for Raspberry Pi 4:
pure numpy tokenizer + onnxruntime CPU, incremental byte-offset resume, dedupe
per (client, day), allowlist support.

Usage:
  python scorer.py --log PATH [--state PATH] [--alerts PATH]
                   [--model PATH] [--allowlist PATH] [--threshold 0.5] [--tail N]

Incremental mode is stateful: a byte offset (and per-client/day dedupe set) are
saved to the state file, so repeated runs only score new lines. --tail N processes
only the last N lines instead (ignores state, useful for testing).
"""
import argparse
import json
import os
from datetime import datetime, timezone

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- tokenizer --
# Must match trm/data.py exactly.
MAX_LEN = 64
VOCAB = "abcdefghijklmnopqrstuvwxyz0123456789-._"
PAD, UNK = 0, 1
N_TOKENS = len(VOCAB) + 2

_LUT = bytearray([UNK]) * 256
for _i, _ch in enumerate(VOCAB):
    _LUT[ord(_ch)] = _i + 2
    if _ch.isalpha():
        _LUT[ord(_ch.upper())] = _i + 2

# Small built-in public-suffix list: common TLDs and 2-level suffixes
# (second-level public suffixes where registration happens at the 3rd level).
PUBLIC_SUFFIXES = frozenset("""
com net org edu gov mil int info biz xyz online site store tech app dev io
co uk co.uk org.uk ac.uk gov.uk me.uk net.uk sch.uk
com.au net.au org.au edu.au gov.au id.au
co.nz net.nz org.nz
co.jp ne.jp or.jp ac.jp go.jp
com.br com.mx com.ar com.co com.cn com.tw com.hk com.sg com.my com.tr com.ru
co.in co.za co.il co.kr co.id co.th com.my
eu de fr it es nl se no fi dk pt pl cz at ch be gr hu ro ie bg hr sk si lt lv ee
ca us mx br ar cl pe za ng ke gh eg in pk bd lk np ir il sa ae qa kw om jo tr
ru ua by kz ge am az md cn jp kr hk tw mo sg my id th vn ph mm kh la mn np
cat asia aero name pro museum travel jobs mobi tel xxx post shop club top wang win
me tv cc ws nu to io ai sh ac st
""".split())


def registrable_part(host: str) -> str:
    """Drop the public suffix; return '<something>.<suffix>' or host if ambiguous."""
    host = host.strip().rstrip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def encode_domains(domains: list[str]) -> np.ndarray:
    """list[str] -> int64 tokens [N, MAX_LEN], same mapping/last-64-chars as trm/data.py."""
    n = len(domains)
    out = np.zeros((n, MAX_LEN), dtype=np.int64)
    for i, d in enumerate(domains):
        # byte-level like trm/data.py: pyarrow strings are UTF-8; _LUT maps each
        # byte, so multibyte chars become one UNK per byte. Keeps the LAST 64 BYTES.
        b = d.encode("utf-8")[-MAX_LEN:]
        row = [_LUT[c] for c in b]
        out[i, :len(row)] = row  # left-aligned, trailing pad — same layout as trm/data.py
    return out


# ---------------------------------------------------------------- scoring ----
class Scorer:
    def __init__(self, model_path: str, threshold: float = 0.5):
        import onnxruntime as ort
        so = ort.SessionOptions()
        so.intra_op_num_threads = 1
        so.inter_op_num_threads = 1
        self.sess = ort.InferenceSession(model_path, so, providers=["CPUExecutionProvider"])
        self.threshold = threshold

    def score(self, domains: list[str]) -> np.ndarray:
        if not domains:
            return np.zeros(0)
        toks = encode_domains(domains)
        return self.sess.run(None, {"tokens": toks})[0].astype(float)


# ---------------------------------------------------------------- log tail ---
def parse_line(line: str):
    """AdGuard Home querylog NDJSON -> (ts_str, client, domain) or None."""
    try:
        j = json.loads(line)
    except ValueError:
        return None
    host = j.get("QH") or j.get("domain") or j.get("hostname")
    if not host:
        return None
    client = j.get("IP") or j.get("client") or "?"
    t = j.get("T") or j.get("time")
    if isinstance(t, (int, float)):
        ts = datetime.fromtimestamp(t / 1000 if t > 1e11 else t, tz=timezone.utc)
        ts = ts.isoformat()
    else:
        ts = str(t)
    return ts, str(client), str(host)


def load_state(path: str):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"offset": 0, "seen_day": "", "seen": []}


def save_state(path: str, st: dict):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, path)


def run(args):
    allow = set()
    if args.allowlist and os.path.exists(args.allowlist):
        with open(args.allowlist) as f:
            allow = {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}

    scorer = Scorer(args.model, args.threshold)

    if args.tail is not None:
        with open(args.log, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 65536))
            lines = f.read().decode("utf-8", "replace").splitlines()
        records = [r for r in (parse_line(l) for l in lines[-args.tail:]) if r]
    else:
        st = load_state(args.state)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        seen = set(st["seen"]) if st.get("seen_day") == today else set()
        with open(args.log, "rb") as f:
            f.seek(st["offset"])
            records = []
            for raw in f:
                st["offset"] += len(raw)
                r = parse_line(raw.decode("utf-8", "replace").strip())
                if r:
                    records.append(r)
        # dedupe per client per day on the registrable part
        deduped, seen_keys = [], []
        for ts, client, host in records:
            dom = registrable_part(host)
            key = f"{client}|{today}|{dom}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append((ts, client, dom))
        if deduped:
            scores = scorer.score([d for _, _, d in deduped])
            with open(args.alerts, "a") as af:
                for (ts, client, dom), s in zip(deduped, scores):
                    if dom in allow:
                        continue
                    if s >= args.threshold:
                        af.write(json.dumps({"time": ts, "client": client,
                                             "domain": dom, "score": round(float(s), 4)}) + "\n")
        st["seen_day"] = today
        st["seen"] = list(seen)[-20000:]  # cap state size
        save_state(args.state, st)
        print(f"processed {len(records)} lines, {len(deduped)} new domains, "
              f"alerts appended to {args.alerts}")
        return

    # --tail path
    deduped, seen = [], set()
    for ts, client, host in records:
        dom = registrable_part(host)
        key = f"{client}|{dom}"
        if key in seen or dom in allow:
            continue
        seen.add(key)
        deduped.append((ts, client, dom))
    scores = scorer.score([d for _, _, d in deduped]) if deduped else []
    for (ts, client, dom), s in zip(deduped, scores):
        mark = "ALERT" if s >= args.threshold else "ok   "
        print(f"{mark} {s:.4f} {client:>15} {dom}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--log", required=True, help="path to AdGuard Home querylog.json")
    ap.add_argument("--state", default=os.path.join(HERE, "state.json"))
    ap.add_argument("--alerts", default=os.path.join(HERE, "alerts.jsonl"))
    ap.add_argument("--model", default=os.path.join(HERE, "trm_dga.onnx"))
    ap.add_argument("--allowlist", default=os.path.join(HERE, "allowlist.txt"))
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--tail", type=int, default=None,
                    help="only process the last N lines (no state)")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
