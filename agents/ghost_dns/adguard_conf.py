"""Small, careful edits to AdGuard Home's YAML, without a YAML library.

    python adguard_conf.py /opt/AdGuardHome/AdGuardHome.yaml --flush 10 [--port-back]

--flush N     lower `querylog.size_memory` to N. AdGuard keeps that many queries in
              memory before writing querylog.json (default 1000), which on a home
              network can delay Ghostwall's alerts by hours.
--port-back   move `dns.port` from 5300 back to 53 (undoes inline mode).
--check       print (one per line) any setting that leaves Ghostwall blind or makes every
              device look the same; changes nothing.

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


def problems(text: str) -> list[str]:
    """AdGuard settings Ghostwall can't work with, in plain words."""
    block, found = None, []
    for line in text.split("\n"):
        if re.match(r"^\S", line):
            block = line.rstrip().rstrip(":")
        m = re.match(r"^  (\w+):\s*(\S+)\s*$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).lower()
        if block == "querylog" and key == "enabled" and val == "false":
            found.append("AdGuard's query log is off (querylog.enabled: false): Ghostwall sees nothing. "
                         "Turn it on: Settings > General settings > Logs configuration.")
        elif block == "querylog" and key == "file_enabled" and val == "false":
            found.append("AdGuard keeps its query log in memory only (querylog.file_enabled: false): "
                         "no file is written, so Ghostwall sees nothing. Set it to true.")
        elif block == "dns" and key == "anonymize_client_ip" and val == "true":
            found.append("AdGuard anonymizes client IPs (dns.anonymize_client_ip: true): every device "
                         "then looks like the same one to Ghostwall. Turn it off: Settings > General "
                         "settings > Logs > Anonymize client IP.")
    return found


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("yaml")
    ap.add_argument("--flush", type=int, default=0)
    ap.add_argument("--port-back", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    with open(a.yaml, encoding="utf-8") as f:
        text = f.read()
    if a.check:
        print("\n".join(problems(text)))
        return 0
    new, changes = edit(text, a.flush, a.port_back)
    if changes:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(a.yaml)), prefix=".AdGuardHome-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new)
        shutil.copymode(a.yaml, tmp)
        st = os.stat(a.yaml)
        if (os.stat(tmp).st_uid, os.stat(tmp).st_gid) != (st.st_uid, st.st_gid):
            # The new file must keep the owner: AdGuard may run as that user, and its
            # config is 0600. Without the right to chown, leave the file alone.
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except PermissionError:
                os.unlink(tmp)
                print(f"can't keep {a.yaml}'s owner (uid {st.st_uid}); not changed", file=sys.stderr)
                return 1
        os.replace(tmp, a.yaml)
    print(" ".join(changes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
