"""Small, careful edits to AdGuard Home's YAML, without a YAML library.

    python adguard_conf.py /opt/AdGuardHome/AdGuardHome.yaml --flush 10 [--port-back]

--flush N     lower `querylog.size_memory` to N. AdGuard keeps that many queries in
              memory before writing querylog.json (default 1000), which on a home
              network can delay Ghostwall's alerts by hours.
--port-back   move `dns.port` from 5300 back to 53 (undoes inline mode).

Prints what changed ("port", "flush:<old value>"), or nothing. The file is rewritten
atomically and only if something changed. AdGuard reads its YAML at startup, so restart
AdGuard afterwards.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile


def edit(text: str, flush: int = 0, port_back: bool = False) -> tuple[str, list[str]]:
    lines = text.split("\n")
    block = None
    changes = []
    for i, line in enumerate(lines):
        if re.match(r"^\S", line):
            block = line.rstrip().rstrip(":")
        if port_back and block == "dns" and line.rstrip() == "  port: 5300":
            lines[i] = "  port: 53"
            changes.append("port")
        m = re.match(r"^(\s+)size_memory:\s*(\d+)\s*$", line)
        if m and block == "querylog" and flush > 0 and int(m.group(2)) > flush:
            lines[i] = f"{m.group(1)}size_memory: {flush}"
            changes.append(f"flush:{m.group(2)}")
    return "\n".join(lines), changes


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("yaml")
    ap.add_argument("--flush", type=int, default=0)
    ap.add_argument("--port-back", action="store_true")
    a = ap.parse_args(argv)
    with open(a.yaml, encoding="utf-8") as f:
        text = f.read()
    new, changes = edit(text, a.flush, a.port_back)
    if changes:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(a.yaml)), prefix=".AdGuardHome-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new)
        shutil.copymode(a.yaml, tmp)
        os.replace(tmp, a.yaml)
    print(" ".join(changes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
