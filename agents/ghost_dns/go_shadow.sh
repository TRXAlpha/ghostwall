#!/usr/bin/env bash
# Put Ghostwall in SHADOW mode: AdGuard Home owns port 53, and ghost-dns only scores
# AdGuard's query log. Ghostwall cannot affect DNS in this mode.
#
#   sudo bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh
#
# AdGuard paths come from /etc/ghostwall/ghostwall.env (see ghostwall.env.example).
# Safe to re-run. If AdGuard was moved to port 5300 for inline mode, it is moved back
# to 53 and the script aborts if AdGuard then does not answer.
set -euo pipefail

[ -f /etc/ghostwall/ghostwall.env ] && . /etc/ghostwall/ghostwall.env
YAML=${ADGUARD_YAML:-/opt/AdGuardHome/AdGuardHome.yaml}
QUERYLOG=${ADGUARD_QUERYLOG:-/opt/AdGuardHome/data/querylog.json}
RESTART=${ADGUARD_RESTART:-systemctl restart AdGuardHome}
FEED=${GHOSTWALL_FEED:-/var/lib/ghostwall/threat_feed.txt}
CFG=/opt/ghostwall/agents/ghost_dns/ghost_dns.json
PY=/opt/ghostwall/.venv/bin/python

ask() {  # ask <port> -> prints number of answers for google.com, or ERR
  "$PY" - "$1" <<'PYEOF'
import socket, struct, sys
h = struct.pack(">HHHHHH", 1, 0x100, 1, 0, 0, 0) + b"\x06google\x03com\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
try:
    s.sendto(h, ("127.0.0.1", int(sys.argv[1]))); r = s.recvfrom(512)[0]
    print(struct.unpack(">H", r[6:8])[0])
except Exception:
    print("ERR")
PYEOF
}

echo "1) stop ghost-dns"
systemctl stop ghostwall-dns 2>/dev/null || true

echo "2) AdGuard on port 53"
if [ -f "$YAML" ] && grep -q '^  port: 5300$' "$YAML"; then
  cp "$YAML" "$YAML.bak-shadow-$(date +%s)"
  sed -i 's/^  port: 5300$/  port: 53/' "$YAML"
  $RESTART >/dev/null
fi
n=ERR
for _ in 1 2 3 4 5 6 7 8; do
  n=$(ask 53)
  [ "$n" != "ERR" ] && [ "$n" -ge 1 ] && break
  sleep 2
done
if [ "$n" = "ERR" ] || [ "$n" -lt 1 ]; then
  echo "FAIL: nothing answers DNS on 127.0.0.1:53. Is AdGuard Home running?" >&2
  exit 1
fi
echo "   AdGuard answers on :53 ($n records for google.com)"
[ -f "$QUERYLOG" ] || echo "   WARNING: $QUERYLOG not found yet. Check ADGUARD_QUERYLOG and that the query log is on in AdGuard." >&2

echo "3) write shadow config"
[ -f "$CFG" ] || cp /opt/ghostwall/agents/ghost_dns/ghost_dns.example.json "$CFG"
"$PY" - "$CFG" "$QUERYLOG" "$FEED" <<'PYEOF'
import json, sys
p, querylog, feed = sys.argv[1:4]
c = json.load(open(p))
c.update({"shadow": True, "learning": True, "enforce": "null",
          "querylog": querylog, "threat_feed_path": feed})
c.pop("dns_host", None); c.pop("dns_port", None)   # shadow serves no DNS
# Drop thresholds pinned by older configs so the measured defaults in config.py apply.
for k in ("recommend_threshold", "block_threshold"):
    c.pop(k, None)
json.dump(c, open(p, "w"), indent=2)
print("   shadow=true, learning=true, enforce=null")
PYEOF

echo "4) start ghost-dns in shadow mode"
systemctl enable ghostwall-dns >/dev/null 2>&1 || true
systemctl restart ghostwall-dns
sleep 4
state=$("$PY" - <<'PYEOF'
import json, urllib.request
try:
    s = json.load(urllib.request.urlopen("http://127.0.0.1:5380/status", timeout=4))
    print("shadow" if s.get("shadow") else "NOT-SHADOW")
except Exception as e:
    print("ERR", e)
PYEOF
)
echo "   control API reports: $state"
[ "$state" = "shadow" ] || { echo "FAIL: ghost-dns is not in shadow mode (journalctl -u ghostwall-dns)" >&2; exit 1; }
echo "DONE: AdGuard serves DNS; Ghostwall is watching from the side."
