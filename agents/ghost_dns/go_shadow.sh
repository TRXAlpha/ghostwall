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
#
# ghost-dns keeps its config in /etc/ghostwall and its state and alerts in
# /var/lib/ghostwall, so uninstalling the code keeps them. Installs from before v0.2.0b2
# kept them in /opt/ghostwall/agents/ghost_dns; they are moved on the first run.
set -euo pipefail

set -a   # exported, so dns_block.py (below) sees DNS_BLOCK_* and the DNS server's login
[ -f /etc/ghostwall/ghostwall.env ] && . /etc/ghostwall/ghostwall.env
set +a
SOURCE=${DNS_SOURCE:-adguard}
YAML=${ADGUARD_YAML:-/opt/AdGuardHome/AdGuardHome.yaml}
RESTART=${ADGUARD_RESTART:-systemctl restart AdGuardHome}
FLUSH=${ADGUARD_FLUSH_EVERY:-10}
FEED=${GHOSTWALL_FEED:-/var/lib/ghostwall/threat_feed.txt}
CFG=/etc/ghostwall/ghost_dns.json
DATA=/var/lib/ghostwall
OLD=/opt/ghostwall/agents/ghost_dns
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

adguard_warnings() {  # adguard_warnings <check command...>: print what it reports as warnings
  # Advisory only, so it must never stop the script: under `set -e -o pipefail` a loop
  # whose last command was a false test (`[ -n "" ] && ...` on an empty line) used to
  # abort here on every clean AdGuard config, leaving ghost-dns stopped.
  local out p
  out=$("$@" 2>&1) || { echo "   WARNING: could not check AdGuard's settings ($*)" >&2; return 0; }
  while IFS= read -r p; do
    if [ -n "$p" ]; then echo "   WARNING: $p" >&2; fi
  done <<<"$out"
  return 0
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
    echo "   restarting $NAME to apply it: a few seconds without DNS (ADGUARD_FLUSH_EVERY=0 skips this)"
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
if [ "$SOURCE" = adguard ] && [ -f "$YAML" ]; then
  adguard_warnings "$PY" /opt/ghostwall/agents/ghost_dns/adguard_conf.py "$YAML" --check
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
install -d -m 750 -o ghostwall -g ghostwall "$DATA"
# Move what older versions kept next to the code (the uninstaller deletes /opt/ghostwall).
for f in state.json events.jsonl; do
  if [ -f "$OLD/$f" ] && [ ! -e "$DATA/$f" ]; then
    mv "$OLD/$f" "$DATA/$f" && chown ghostwall:ghostwall "$DATA/$f" && echo "   moved $f to $DATA"
  fi
done
if [ ! -f "$CFG" ] && [ -f "$OLD/ghost_dns.json" ]; then
  mv "$OLD/ghost_dns.json" "$CFG" && echo "   moved ghost_dns.json to $CFG"
fi
if [ ! -f /etc/ghostwall/devices.json ] && [ -f /opt/ghostwall/agents/netconf/devices.json ]; then
  cp /opt/ghostwall/agents/netconf/devices.json /etc/ghostwall/devices.json && echo "   copied devices.json to /etc/ghostwall"
fi
[ -f "$CFG" ] || cp "$OLD/ghost_dns.example.json" "$CFG"
"$PY" - "$CFG" "$QUERYLOG" "$SOURCE" "$FEED" "$DATA" <<'PYEOF'
import json, sys
p, querylog, fmt, feed, data = sys.argv[1:6]
c = json.load(open(p))
c.update({"shadow": True, "learning": True, "enforce": "null",
          "querylog": querylog, "querylog_format": fmt, "threat_feed_path": feed})
c.pop("dns_host", None); c.pop("dns_port", None)   # shadow serves no DNS
# Drop the thresholds the first versions pinned (0.60 / 0.90: far too noisy) so the
# measured defaults in config.py apply. Anything else is a choice (yours, or
# `ghostwall calibrate --apply`, which also sets "thresholds_from") and is kept.
if "thresholds_from" not in c:
    for k, legacy in (("recommend_threshold", (0.6, 0.85)), ("block_threshold", (0.9, 0.95))):
        if c.get(k) in legacy:
            c.pop(k)
# Paths outside /opt/ghostwall, unless you chose your own.
old = "/opt/ghostwall/agents/"
for key, new in (("state_path", f"{data}/state.json"), ("events_path", f"{data}/events.jsonl"),
                 ("resolved_ips_path", f"{data}/resolved_ips.jsonl"),
                 ("devices_json", "/etc/ghostwall/devices.json")):
    if not c.get(key) or str(c[key]).startswith(old):
        c[key] = new
if str(c.get("query_log") or "").startswith(old):
    c["query_log"] = None   # old inline-mode copy of every query; the DNS server keeps its own
# DNS-server blocking (dns_block.py): copied from ghostwall.env when set there, otherwise
# whatever the config already says (default off). Nothing here changes a DNS upstream.
import os
for key, env in (("dns_block_feed", "DNS_BLOCK_FEED"), ("dns_block_ads", "DNS_BLOCK_ADS"),
                 ("dns_block_bypass", "DNS_BLOCK_BYPASS"), ("dns_block_canaries", "DNS_BLOCK_CANARIES")):
    if os.environ.get(env):
        c[key] = os.environ[env].strip().lower()
up = os.environ.get("DNS_PROTECTIVE_UPSTREAM", "").strip().lower()
if up in ("quad9", "cloudflare"):
    c["protective_upstream"] = up
json.dump(c, open(p, "w"), indent=2)
print(f"   shadow=true, learning=true, enforce=null, source={fmt}")
PYEOF
chown root:ghostwall "$CFG" && chmod 640 "$CFG"
[ -f /etc/ghostwall/devices.json ] && chown root:ghostwall /etc/ghostwall/devices.json && chmod 640 /etc/ghostwall/devices.json

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
echo "5) DNS-server blocklists and protective upstream (only if you asked for them in ghostwall.env)"
# Idle unless DNS_BLOCK_FEED / DNS_BLOCK_ADS / DNS_BLOCK_BYPASS is set. Never fatal: Ghostwall keeps
# watching whatever the DNS server's API says. The upstream changes only when DNS_PROTECTIVE_UPSTREAM
# says so (and "off" puts back what Ghostwall changed).
if [ -f /etc/systemd/system/ghostwall-dnsblock.service ]; then
  systemctl enable ghostwall-dnsblock >/dev/null 2>&1 || true
  systemctl restart ghostwall-dnsblock || echo "   WARNING: ghostwall-dnsblock did not start (journalctl -u ghostwall-dnsblock)" >&2
  case "${DNS_BLOCK_FEED:-off}/${DNS_BLOCK_ADS:-off}/${DNS_BLOCK_BYPASS:-off}" in
    off/off/off) echo "   blocking with your DNS server is off (DNS_BLOCK_FEED=dry-run shows what it would do first)" ;;
    *) echo "   feed=${DNS_BLOCK_FEED:-off} ads=${DNS_BLOCK_ADS:-off} bypass=${DNS_BLOCK_BYPASS:-off}: sudo ghostwall blocking" ;;
  esac
  if [ -n "${DNS_PROTECTIVE_UPSTREAM:-}" ]; then
    (cd /opt/ghostwall/agents/ghost_dns && "$PY" dns_block.py upstream --config "$CFG") \
      || echo "   WARNING: could not set the upstream (see above); nothing was changed" >&2
  fi
fi
echo "DONE: $NAME serves DNS; Ghostwall is watching from the side."
