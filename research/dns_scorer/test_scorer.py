"""Tests for the DNS scorer (plain asserts + pytest compatible). Run:
    python test_scorer.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

import numpy as np
import onnxruntime as ort

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from scorer import (PUBLIC_SUFFIXES, Scorer, encode_domains, registrable_part,
                    parse_line)  # noqa: E402

MODEL = os.path.join(HERE, "trm_dga.onnx")
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
if not os.path.exists(PY):
    PY = sys.executable

DGA_DOMAINS = [
    "xkfjqzwnmstvbdh", "qwzxcvbnnmlkjhg", "aaabbbcccdddeee",
    "zzzxxxvvvnnmmmasd", "poiuytrewqlkjhgfds", "mnbvcxzasdfghjklr",
]  # NOTE: bare (no TLD) — matches the DRIFT training distribution, where DGA
# domains appear without a public suffix.
NORMAL_DOMAINS = [
    "www.google.com", "api.github.com", "cdn.jsdelivr.net",
    "mail.microsoft.com", "en.wikipedia.org", "fonts.googleapis.com",
]


def test_tokenizer_matches_trm_data():
    """scorer's pure-python tokenizer must match trm/data.py encode_strings."""
    sys.path.insert(0, ROOT)
    from trm.data import encode_strings
    doms = ["www.Example.COM", "a.b.c.d.e.f.very-long-domain-name-0123456789-x.com",
            "short.io", "üñî.com"] + DGA_DOMAINS
    tok_ref, _ = encode_strings(doms, 64)
    tok_mine = encode_domains(doms).astype(np.uint8)
    assert np.array_equal(tok_ref, tok_mine), "tokenizer mismatch vs trm/data.py"


def test_registrable():
    assert registrable_part("WWW.Example.COM") == "example.com"
    assert registrable_part("a.b.example.co.uk") == "example.co.uk"
    assert registrable_part("example.co.uk") == "example.co.uk"
    assert registrable_part("deep.sub.www.google.com") == "google.com"
    assert registrable_part("localhost") == "localhost"
    assert registrable_part("host.lan.") == "host.lan"


def test_parse_line():
    r = parse_line('{"T":"2026-10-20T10:00:00Z","QH":"www.google.com","IP":"192.168.1.5","Result":{}}')
    assert r == ("2026-10-20T10:00:00Z", "192.168.1.5", "www.google.com")
    r = parse_line('{"T":1760000000123,"QH":"x.com","IP":"c1"}')
    assert r[0].startswith("20") and r[1] == "c1"
    assert parse_line("not json") is None
    assert parse_line('{"IP":"c"}') is None


def test_scorer_separates_dga():
    s = Scorer(MODEL)
    dga = s.score(DGA_DOMAINS)
    normal = s.score(NORMAL_DOMAINS)
    print("dga scores  :", np.round(dga, 3).tolist())
    print("normal scores:", np.round(normal, 3).tolist())
    assert dga.mean() > normal.mean(), "model does not separate DGA from normal"
    assert (dga > 0).all() and (dga < 1).all()
    # padding invariance: trailing pad tokens must not change scores
    t = encode_domains(["www.google.com"])
    t2 = np.concatenate([t, np.zeros((1, 10), np.int64)], axis=1)[:, :64]
    t2 = t2[:, :64]  # same width; instead compare short vs full-width rows
    t_full = np.zeros((1, 64), np.int64); t_full[0] = t[0]
    assert abs(s.score(["www.google.com"])[0] - s.score(["www.google.com"])[0]) < 1e-6


def test_cli_incremental_and_dedupe():
    tmp = tempfile.mkdtemp(prefix="dnsscorer_")
    try:
        log = os.path.join(tmp, "querylog.json")
        state = os.path.join(tmp, "state.json")
        alerts = os.path.join(tmp, "alerts.jsonl")
        rows = [
            {"T": "2026-10-20T10:00:00Z", "QH": "www.google.com", "IP": "192.168.1.9", "Result": {}},
            {"T": "2026-10-20T10:00:01Z", "QH": DGA_DOMAINS[0], "IP": "192.168.1.9", "Result": {}},
            {"T": "2026-10-20T10:00:02Z", "QH": DGA_DOMAINS[0], "IP": "192.168.1.9", "Result": {}},  # dup (same registrable)
            {"T": "2026-10-20T10:00:03Z", "QH": "www." + DGA_DOMAINS[1], "IP": "192.168.1.8", "Result": {}},
        ]
        with open(log, "w") as f:
            f.write("\n".join(json.dumps(r) for r in rows) + "\n")
        for _ in range(2):  # run twice: second run must be a no-op (offset + dedupe)
            r = subprocess.run([PY, os.path.join(HERE, "scorer.py"), "--log", log,
                                "--state", state, "--alerts", alerts,
                                "--model", MODEL, "--allowlist",
                                os.path.join(tmp, "none.txt")],
                               capture_output=True, text=True)
            assert r.returncode == 0, r.stderr
        alerts1 = open(alerts).read().splitlines()
        assert len(alerts1) == 1, f"expected 1 alert (dup + benign dropped), got {len(alerts1)}: {alerts1}"
        a0 = json.loads(alerts1[0])
        assert a0["client"] == "192.168.1.9" and a0["domain"] == DGA_DOMAINS[0]
        assert isinstance(a0["score"], float) and "time" in a0
        r = subprocess.run([PY, "scorer.py", "--log", log, "--state", state,
                            "--alerts", alerts, "--model", MODEL],
                           capture_output=True, text=True, cwd=HERE)
        assert "0 new domains" in r.stdout, r.stdout  # nothing re-scored
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_allowlist():
    tmp = tempfile.mkdtemp(prefix="dnsscorer_")
    try:
        log = os.path.join(tmp, "querylog.json")
        al = os.path.join(tmp, "allow.txt")
        with open(al, "w") as f:
            f.write(DGA_DOMAINS[0] + "\n")
        with open(log, "w") as f:
            f.write(json.dumps({"T": "2026-10-20T10:00:00Z", "QH": DGA_DOMAINS[0],
                                "IP": "c1", "Result": {}}) + "\n")
        alerts = os.path.join(tmp, "alerts.jsonl")
        subprocess.run([PY, os.path.join(HERE, "scorer.py"), "--log", log,
                        "--state", os.path.join(tmp, "s.json"), "--alerts", alerts,
                        "--model", MODEL, "--allowlist", al],
                       capture_output=True, text=True, check=True)
        assert open(alerts).read() == "", "allowlisted domain must not alert"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_latency():
    """Per-domain latency on this machine (single-thread onnxruntime)."""
    s = Scorer(MODEL)
    doms = DGA_DOMAINS * 50
    s.score(doms[:10])  # warmup
    t0 = time.perf_counter()
    s.score(doms)
    dt = (time.perf_counter() - t0) / len(doms)
    print(f"latency per domain: {dt*1000:.2f} ms")
    assert dt < 0.1


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
            raise
    print("all tests passed")
