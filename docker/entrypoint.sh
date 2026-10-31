#!/usr/bin/env bash
# Ghostwall in a container: ghost-dns in shadow mode plus the dashboard, state in /data.
#
# Environment (all optional):
#   GHOSTWALL_QUERYLOG         the DNS server's log as mounted here
#                              (default /adguard/work/data/querylog.json; Pi-hole: /pihole/log/pihole.log)
#   GHOSTWALL_QUERYLOG_FORMAT  adguard, pihole or auto (default auto)
#   GHOSTWALL_WEB_PASSWORD     dashboard password (default: generated once, kept in /data/web_password)
#   GHOSTWALL_ADGUARD_YAML     AdGuard's config, mounted writable, so its log buffer can be lowered
#                              (default /adguard/conf/AdGuardHome.yaml; skipped if absent)
#   ADGUARD_FLUSH_EVERY        the buffer size to set (default 10; 0 = leave AdGuard alone)
set -euo pipefail
cd /opt/ghostwall
D=/data
QUERYLOG=${GHOSTWALL_QUERYLOG:-/adguard/work/data/querylog.json}
FORMAT=${GHOSTWALL_QUERYLOG_FORMAT:-auto}
YAML=${GHOSTWALL_ADGUARD_YAML:-/adguard/conf/AdGuardHome.yaml}
FLUSH=${ADGUARD_FLUSH_EVERY:-10}
mkdir -p "$D"

if [ -z "${GHOSTWALL_WEB_PASSWORD:-}" ]; then
  [ -s "$D/web_password" ] || python -c 'import secrets; print(secrets.token_urlsafe(12))' > "$D/web_password"
  GHOSTWALL_WEB_PASSWORD=$(cat "$D/web_password")
  export GHOSTWALL_WEB_PASSWORD
fi
echo "[ghostwall] dashboard on port 8088, user ghostwall, password: $GHOSTWALL_WEB_PASSWORD"

# Config lives in /data so edits (thresholds, learning) survive image updates; the
# container-specific keys are rewritten on every start.
python - "$D" "$QUERYLOG" "$FORMAT" <<'PY'
import json, os, sys
d, querylog, fmt = sys.argv[1:4]
p = os.path.join(d, "ghost_dns.json")
c = json.load(open(p)) if os.path.exists(p) else {"learning": True}
c.update({"shadow": True, "querylog": querylog, "querylog_format": fmt, "enforce": "null",
          "control_host": "127.0.0.1", "query_log": None, "resolved_ips_path": None,
          "state_path": f"{d}/state.json", "events_path": f"{d}/events.jsonl",
          "devices_json": f"{d}/devices.json", "threat_feed_path": f"{d}/threat_feed.txt"})
json.dump(c, open(p, "w"), indent=2)
PY

tune_adguard() {  # lower AdGuard's query-log buffer; AdGuard applies it on its next restart
  [ "$FLUSH" -gt 0 ] && [ -f "$YAML" ] && [ -w "$YAML" ] || return 0
  local changed
  changed=$(python agents/ghost_dns/adguard_conf.py "$YAML" --flush "$FLUSH" 2>/dev/null) || return 0
  case "$changed" in
    *flush:*) echo "[ghostwall] AdGuard was buffering ${changed##*flush:} queries before writing its log; set to $FLUSH." \
                   "Restart AdGuard once so alerts arrive in seconds: docker compose restart adguardhome" ;;
  esac
}

# Threat feed now and daily; AdGuard's buffer every few minutes (its setup wizard writes
# the YAML after this container starts). ghost-dns reloads the feed when it changes.
( while :; do python agents/ghost_dns/update_feed.py --out "$D/threat_feed.txt" || true; sleep 86400; done ) &
( while :; do tune_adguard; sleep 300; done ) &

python agents/ghost_dns/app.py --config "$D/ghost_dns.json" &
python agents/web_ui/app.py --bind 0.0.0.0 --port 8088 --events "$D/events.jsonl" &
# If either service exits, stop the container so Docker's restart policy brings it back.
wait -n
exit 1
