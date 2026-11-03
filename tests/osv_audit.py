#!/usr/bin/env python3
"""Known vulnerabilities in the pinned Python dependencies, from the OSV database
(osv.dev, which collects the PyPI and GitHub advisories). Stdlib only.

    python3 tests/osv_audit.py requirements.lock requirements-gateway.lock

Exit 0: no advisory for any pinned version. Exit 1: some (listed, with the fix to look
for). Exit 2: the lock files or OSV could not be read. The lock files pin exact versions
with hashes, so nothing updates them by itself; .github/workflows/deps.yml runs this
weekly so a new advisory against a pinned version shows up as a failed run.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request

OSV = "https://api.osv.dev/v1/querybatch"
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def pins(paths: list[str]) -> list[tuple[str, str]]:
    """(name, version) for every `name==version` line, each pair once."""
    out: list[tuple[str, str]] = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = PIN.match(line.strip())
                if m and (m.group(1).lower(), m.group(2)) not in out:
                    out.append((m.group(1).lower(), m.group(2)))
    return out


def query(packages: list[tuple[str, str]], url: str = OSV) -> list[list[str]]:
    """Advisory ids per package, in order."""
    body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
                                   for n, v in packages]}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        results = json.load(r)["results"]
    return [[v["id"] for v in (res.get("vulns") or [])] for res in results]


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[3].strip(), file=sys.stderr)
        return 2
    try:
        packages = pins(argv)
        found = query(packages)
    except (OSError, ValueError, KeyError) as exc:
        print(f"could not check: {exc}", file=sys.stderr)
        return 2
    bad = [(p, ids) for p, ids in zip(packages, found) if ids]
    for (name, version), ids in bad:
        print(f"{name}=={version}: {', '.join(ids)}  (https://osv.dev/vulnerability/{ids[0]})")
    print(f"{len(packages)} pinned versions checked, {len(bad)} with known vulnerabilities.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
