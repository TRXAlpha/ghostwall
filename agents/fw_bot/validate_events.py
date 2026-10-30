"""events.jsonl validator (schema: docs/REFERENCE.md). Stdlib only.

Usage: python validate_events.py <events.jsonl | - >  (exit 0 = all valid)
Also importable: validate_event(obj) -> list[str] of errors (empty = valid).
"""
from __future__ import annotations

import json
import re
import sys

EVENT_ID_RE = __import__("re").compile(r"^[A-Za-z0-9_-]{1,64}$")
MAC_RE = __import__("re").compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
TIME_RE = __import__("re").compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$")
DOMAIN_RE = __import__("re").compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$")
SEVERITIES = {"info", "warn", "high", "critical"}
ACTIONS = {"block", "recommend", "allow"}
REQUIRED = ("time", "device", "domain", "rule", "action", "event_id")


def validate_event(evt: object) -> list[str]:
    """Return a list of schema violations ([] means valid)."""
    errs: list[str] = []
    if not isinstance(evt, dict):
        return ["line is not a JSON object"]
    for f in REQUIRED:
        if f not in evt or evt[f] in (None, ""):
            errs.append(f"missing required field '{f}'")
    if evt.get("time") and not (isinstance(evt["time"], str) and TIME_RE.match(evt["time"])):
        errs.append("time must be ISO 8601 UTC like 2026-10-20T21:04:05Z")
    if not isinstance(evt.get("device"), str) or not evt.get("device"):
        if "device" in evt or not errs:
            errs.append("device must be a non-empty string")
    dom = evt.get("domain")
    if not isinstance(dom, str) or not DOMAIN_OK(dom):
        errs.append("domain must be a lowercase hostname without trailing dot")
    if "mac" in evt and evt["mac"] not in (None, "") and not (
            isinstance(evt["mac"], str) and MAC_RE.match(evt["mac"])):
        errs.append("mac must be lowercase colon-separated or null")
    if evt.get("scores") is not None:
        sc = evt["scores"]
        if not isinstance(sc, dict) or not all(
            isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1
            for v in sc.values()
        ):
            errs.append("scores must be an object of numbers 0..1")
    if evt.get("action") not in ("block", "recommend", "allow"):
        errs.append("action must be one of block/recommend/allow")
    sev = evt.get("severity", "warn")
    if sev not in SEVERITIES:
        errs.append("severity must be one of info/warn/high/critical")
    if not isinstance(evt.get("rule"), str) or not evt.get("rule"):
        if "rule" in evt or not errs:
            errs.append("rule must be a non-empty string")
    eid = evt.get("event_id")
    if not isinstance(eid, str) or not EVENT_ID_RE.match(eid):
        errs.append("event_id must match ^[A-Za-z0-9_-]{1,64}$")
    return errs


def DOMAIN_OK(domain: str) -> bool:
    if not isinstance(domain, str) or domain != domain.lower() or domain.endswith("."):
        return False
    return bool(re.match(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", domain))


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "-"
    fh = sys.stdin if path == "-" else open(path, encoding="utf-8")
    bad = 0
    try:
        for n, line in enumerate(fh := fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                errs = validate_event(json.loads(line))
            except json.JSONDecodeError as exc:
                errs = [f"invalid JSON: {exc}"]
            if errs:
                bad += 1
                print(f"line {n}: " + "; ".join(errs))
    finally:
        if fh is not sys.stdin:
            fh.close()
    if bad:
        print(f"{bad} invalid line(s)")
        return 1
    print("all lines valid")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
