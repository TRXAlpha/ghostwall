#!/usr/bin/env bash
# Put Ghostwall in SHADOW mode: AdGuard Home or Pi-hole owns port 53, and ghost-dns only
# scores its query log. Ghostwall cannot affect DNS in this mode.
#
#   sudo bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh
#
# Settings come from /etc/ghostwall/ghostwall.env (install.sh writes it). Safe to re-run.
# AdGuard only: if AdGuard was moved to port 5300 for inline mode, it is moved back to 53
# and the script aborts if AdGuard then does not answer. AdGuard's query-log buffer
# (querylog.size_memory, 1000 by default) is lowered to ADGUARD_FLUSH_EVERY (10) so
# alerts arrive within seconds instead of hours; a backup of the YAML is kept.
set -euo pipefail

[ -f /etc/ghostwall/ghostwall.env ] && . /etc/ghostwall/ghostwall.env
SOURCE=${DNS_SOURCE:-adguard}
YAML=${ADGUARD_YAML:-/opt/AdGuardHome/AdGuardHome.yaml}
RESTART=${ADGUARD_RESTART:-systemctl restart AdGuardHome}
FLUSH=${ADGUARD_FLUSH_EVERY:-10}
FEED=${GHOSTWALL_FEED:-/var/lib/ghostwall/threat_feed.txt}
CFG=/opt/ghostwall/agents/ghost_dns/ghost_dns.json
PY=/opt/ghostwall/.venv/bin/python
case "$SOURCE" in
  adguard) QUERYLOG=${ADGUARD_QUERYLOG:-/opt/AdGuardHome/data/querylog.json}; NAME="AdGuard Home" ;;
  pihole)  QUERYLOG=${PIHOLE_LOG:-/var/log/pihole/pihole.log}; NAME="Pi-hole" ;;
  *) echo "FAIL: DNS_SOURCE must be adguard or pihole, not '$SOURCE'" >&2; exit 1 ;;
esac

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

echo "2) $NAME on port 53"
moved=0
if [ "$SOURCE" = adguard ] && [ -f "$YAML" ]; then
  backup="$YAML.bak-ghostwall-$(date +%s)"
  cp -p "$YAML" "$backup"
  # The DNS port back to 53 if inline mode moved it, and a small query-log buffer.
  changes=$("$PY" /opt/ghostwall/agents/ghost_dns/adguard_conf.py "$YAML" --flush "$FLUSH" --port-back)
  if [ -z "$changes" ]; then
    rm -f "$backup"
  else
    echo "   backup of the original: $backup"
    case " $changes " in *" port "*) moved=1 ;; esac
    case "$changes" in *flush:*) echo "   AdGuard now writes its query log every $FLUSH queries (was ${changes##*flush:}), so alerts arrive in seconds" ;; esac
    $RESTART >/dev/null
  fi
fi
n=ERR
for _ in 1 2 3 4 5 6 7 8; do
  n=$(ask 53)
  [ "$n" != "ERR" ] && [ "$n" -ge 1 ] && break
  sleep 2
done
if [ "$n" = "ERR" ] || [ "$n" -lt 1 ]; then
  if [ "$moved" = 1 ]; then
    echo "FAIL: AdGuard was moved back to port 53 but nothing answers on 127.0.0.1:53." >&2
    echo "      Check it now: $RESTART; dig @127.0.0.1 google.com" >&2
    exit 1
  fi
  echo "   note: nothing answers DNS on 127.0.0.1:53 (fine if $NAME listens on another address)"
else
  echo "   DNS answers on :53 ($n records for google.com)"
fi
if [ ! -f "$QUERYLOG" ]; then
  if [ "$SOURCE" = pihole ]; then
    echo "   WARNING: $QUERYLOG not found yet. Check PIHOLE_LOG in /etc/ghostwall/ghostwall.env." >&2
  else
    echo "   WARNING: $QUERYLOG not found yet. AdGuard creates it after its first buffer of queries;" >&2
    echo "            if it never appears, check ADGUARD_QUERYLOG and that the query log is on in AdGuard." >&2
  fi
fi

echo "3) write shadow config"
[ -f "$CFG" ] || cp /opt/ghostwall/agents/ghost_dns/ghost_dns.example.json "$CFG"
"$PY" - "$CFG" "$QUERYLOG" "$SOURCE" "$FEED" <<'PYEOF'
import json, sys
p, querylog, fmt, feed = sys.argv[1:5]
c = json.load(open(p))
c.update({"shadow": True, "learning": True, "enforce": "null",
          "querylog": querylog, "querylog_format": fmt, "threat_feed_path": feed})
c.pop("dns_host", None); c.pop("dns_port", None)   # shadow serves no DNS
# Drop thresholds pinned by older configs so the measured defaults in config.py apply.
for k in ("recommend_threshold", "block_threshold"):
    c.pop(k, None)
json.dump(c, open(p, "w"), indent=2)
print(f"   shadow=true, learning=true, enforce=null, source={fmt}")
PYEOF

echo "4) start ghost-dns in shadow mode"
systemctl enable ghostwall-dns >/dev/null 2>&1 || true
systemctl restart ghostwall-dns
state=ERR
for _ in 1 2 3 4 5 6 7 8 9 10; do
  sleep 2
  state=$("$PY" - <<'PYEOF'
import json, urllib.request
try:
    s = json.load(urllib.request.urlopen("http://127.0.0.1:5380/status", timeout=4))
    print("shadow" if s.get("shadow") else "NOT-SHADOW")
except Exception as e:
    print("ERR")
PYEOF
)
  [ "$state" != ERR ] && break
done
echo "   control API reports: $state"
[ "$state" = "shadow" ] || { echo "FAIL: ghost-dns is not in shadow mode (journalctl -u ghostwall-dns)" >&2; exit 1; }
echo "DONE: $NAME serves DNS; Ghostwall is watching from the side."
