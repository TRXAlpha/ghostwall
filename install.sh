#!/usr/bin/env bash
# Install Ghostwall in shadow mode next to an existing AdGuard Home or Pi-hole.
#
#   sudo ./install.sh
#
# Works on a Raspberry Pi or any 64-bit Linux box or VM with systemd (Debian 12+,
# Ubuntu 22.04+, Raspberry Pi OS; x86_64 or arm64) and Python 3.10+. It finds your
# DNS server by itself: AdGuard Home (native, snap or Docker) or Pi-hole (native or
# Docker). To choose yourself:  sudo DNS_SOURCE=pihole PIHOLE_LOG=/path/pihole.log ./install.sh
#
# Shadow mode never touches DNS or the firewall: Ghostwall only reads the DNS server's
# query log and alerts. Safe to re-run (that is also how you update): your settings in
# /etc/ghostwall are kept.
set -euo pipefail

SRC=$(cd "$(dirname "$0")" && pwd)
DEST=/opt/ghostwall
ENVF=/etc/ghostwall/ghostwall.env
say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root: sudo ./install.sh"
command -v systemctl >/dev/null || die "no systemd here. Use Docker instead: see 'Docker' in README.md"
command -v python3 >/dev/null || die "python3 is required (apt install python3)"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "Python 3.10+ is required (found $(python3 -V))"

# --- find the DNS server -------------------------------------------------------------
# Each finder prints KEY=VALUE lines for ghostwall.env, or nothing.

adguard_paths() {  # adguard_paths <AdGuardHome.yaml> <work dir> <restart command>
  python3 - "$@" <<'PY'
import os, re, sys
yaml, work, restart = sys.argv[1:4]
qdir = ""
inq = False
for line in open(yaml, encoding="utf-8", errors="replace"):
    if re.match(r"^\S", line):
        inq = line.rstrip() == "querylog:"
    elif inq:
        m = re.match(r"^\s+dir_path:\s*['\"]?([^'\"\n]*)", line)
        if m:
            qdir = m.group(1).strip()
qlog = os.path.join(qdir or os.path.join(work, "data"), "querylog.json")
print(f"DNS_SOURCE=adguard\nADGUARD_YAML={yaml}\nADGUARD_QUERYLOG={qlog}\nADGUARD_RESTART={restart}")
PY
}

docker_mount() {  # docker_mount <container> <path inside> -> host path
  docker inspect -f "{{range .Mounts}}{{if eq .Destination \"$2\"}}{{.Source}}{{end}}{{end}}" "$1" 2>/dev/null
}

find_dns_server() {
  local y name image conf work logs
  y=/opt/AdGuardHome/AdGuardHome.yaml
  [ -f "$y" ] && { adguard_paths "$y" /opt/AdGuardHome "systemctl restart AdGuardHome"; return; }
  y=/var/snap/adguard-home/current/AdGuardHome.yaml
  [ -f "$y" ] && { adguard_paths "$y" /var/snap/adguard-home/common "snap restart adguard-home"; return; }
  for y in /var/log/pihole/pihole.log /var/log/pihole.log; do
    [ -f "$y" ] && { printf 'DNS_SOURCE=pihole\nPIHOLE_LOG=%s\n' "$y"; return; }
  done
  if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    while read -r name image; do
      case "$image" in
        *adguardhome*)
          conf=$(docker_mount "$name" /opt/adguardhome/conf); work=$(docker_mount "$name" /opt/adguardhome/work)
          if [ -n "$conf" ] && [ -f "$conf/AdGuardHome.yaml" ] && [ -n "$work" ]; then
            adguard_paths "$conf/AdGuardHome.yaml" "$work" "docker restart $name"; return
          fi
          say "   found AdGuard container '$name' but its conf/work folders are not mounted from the host" >&2 ;;
        *pihole*)
          logs=$(docker_mount "$name" /var/log/pihole)
          if [ -n "$logs" ]; then printf 'DNS_SOURCE=pihole\nPIHOLE_LOG=%s/pihole.log\n' "$logs"; return; fi
          say "   found Pi-hole container '$name', but /var/log/pihole is not mounted." >&2
          say "   Add a volume such as ./pihole/log:/var/log/pihole to it, recreate it, then re-run." >&2 ;;
      esac
    done < <(docker ps --format '{{.Names}} {{.Image}}')
  fi
}

setenv() {  # setenv KEY VALUE: replace or append KEY in ghostwall.env
  python3 - "$ENVF" "$1" "$2" <<'PY'
import re, shlex, sys
path, key, val = sys.argv[1:4]
lines = open(path, encoding="utf-8").read().splitlines()
new = f"{key}={shlex.quote(val) if re.search(r'''[\s"'$`\\]''', val) else val}"
for i, line in enumerate(lines):
    if line.startswith(key + "="):
        lines[i] = new
        break
else:
    lines.append(new)
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
}

say "1) find your DNS server"
install -d -m 755 /etc/ghostwall
FRESH=0
if [ ! -f "$ENVF" ]; then
  FRESH=1
  install -m 640 "$SRC/agents/ghost_dns/ghostwall.env.example" "$ENVF"
fi
# Explicit choice > existing config > detection.
if [ -n "${DNS_SOURCE:-}" ]; then
  setenv DNS_SOURCE "$DNS_SOURCE"
  for k in ADGUARD_YAML ADGUARD_QUERYLOG ADGUARD_RESTART PIHOLE_LOG; do
    [ -n "${!k:-}" ] && setenv "$k" "${!k}"
  done
elif [ "$FRESH" = 1 ] || ! grep -q '^DNS_SOURCE=' "$ENVF"; then
  found=$(find_dns_server || true)
  if [ -z "$found" ] && [ "$FRESH" = 1 ]; then
    rm -f "$ENVF"
    die "no AdGuard Home or Pi-hole found on this machine.
  Install one first (AdGuard: https://github.com/AdguardTeam/AdGuardHome#getting-started,
  Pi-hole: https://docs.pi-hole.net), or run both with Docker: see 'Docker' in README.md.
  If it is installed somewhere unusual: sudo DNS_SOURCE=adguard ADGUARD_YAML=... ADGUARD_QUERYLOG=... ./install.sh"
  fi
  [ -z "$found" ] && found="DNS_SOURCE=adguard"   # configs from before detection existed
  while IFS='=' read -r k v; do setenv "$k" "$v"; done <<<"$found"
fi
. "$ENVF"
case "${DNS_SOURCE:-adguard}" in
  pihole) say "   Pi-hole, log ${PIHOLE_LOG:-/var/log/pihole/pihole.log}" ;;
  *)      say "   AdGuard Home, log ${ADGUARD_QUERYLOG:-/opt/AdGuardHome/data/querylog.json}" ;;
esac

say "2) copy to $DEST"
if [ "$SRC" != "$DEST" ]; then
  mkdir -p "$DEST"
  tar -C "$SRC" --exclude=./.git --exclude=./.venv --exclude=./data --exclude=./runs --exclude=./research \
      -cf - . | tar -C "$DEST" -xf -
fi

say "3) python environment"
if ! python3 -c 'import ensurepip' 2>/dev/null; then
  command -v apt-get >/dev/null || die "python3 venv support is missing; install your distro's python3-venv package"
  say "   installing python3-venv"
  apt-get install -y -qq python3-venv >/dev/null || { apt-get update -qq && apt-get install -y -qq python3-venv >/dev/null; }
fi
[ -x "$DEST/.venv/bin/python" ] || python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install -q --disable-pip-version-check --upgrade pip
if ! "$DEST/.venv/bin/pip" install -q --disable-pip-version-check -r "$DEST/requirements.txt"; then
  # onnxruntime has no wheel for some platforms (32-bit ARM, brand-new Python): run on numpy alone.
  "$DEST/.venv/bin/pip" install -q --disable-pip-version-check numpy
  say "   onnxruntime is not available here: scoring uses the numpy model only (slightly less accurate)"
fi

say "4) user, config and dashboard password"
id ghostwall >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ghostwall
install -d -m 755 -o ghostwall -g ghostwall /var/lib/ghostwall
if ! grep -q '^GHOSTWALL_WEB_PASSWORD=.' "$ENVF"; then
  setenv GHOSTWALL_WEB_PASSWORD "$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
  [ "$FRESH" = 1 ] && setenv GHOSTWALL_WEB_BIND 0.0.0.0
fi
chown root:ghostwall "$ENVF"
chmod 640 "$ENVF"
. "$ENVF"

say "5) systemd units"
for u in agents/ghost_dns/ghostwall-dns.service agents/ghost_dns/ghostwall-feed.service \
         agents/ghost_dns/ghostwall-feed.timer agents/web_ui/ghostwall-web.service \
         agents/fw_bot/ghostwall-fw-bot.service; do
  install -m 644 "$DEST/$u" /etc/systemd/system/
done
systemctl daemon-reload

say "6) threat feed (daily)"
systemctl enable --now ghostwall-feed.timer >/dev/null
systemctl start ghostwall-feed.service || say "   feed download failed; the timer retries daily"

say "7) ghost-dns in shadow mode"
bash "$DEST/agents/ghost_dns/go_shadow.sh"

say "8) web dashboard"
systemctl enable ghostwall-web >/dev/null 2>&1
systemctl restart ghostwall-web
BIND=${GHOSTWALL_WEB_BIND:-127.0.0.1}
HOST=$BIND
case "$BIND" in 0.0.0.0|::) HOST=$(hostname -I 2>/dev/null | awk '{print $1}'); HOST=${HOST:-$(hostname)} ;; esac
sleep 1
systemctl is-active --quiet ghostwall-web || say "   WARNING: the dashboard did not start: journalctl -u ghostwall-web"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && [ "$HOST" != "$BIND" ]; then
  say "   ufw is on; to reach the dashboard from your network: sudo ufw allow 8088/tcp"
fi

cat <<EOF

Installed. Ghostwall is watching your DNS server's query log; it cannot block anything.

  Dashboard:  http://$HOST:8088   user: ghostwall   password: ${GHOSTWALL_WEB_PASSWORD:-(none, loopback only)}
              (the password is GHOSTWALL_WEB_PASSWORD in $ENVF)
  Alerts:     tail -f $DEST/agents/ghost_dns/events.jsonl
  Health:     curl -s http://127.0.0.1:5380/status   ("stats.queries" should keep going up)

Next steps (README.md): name your devices, add Telegram alerts, replay your history.
Remove it again: sudo $DEST/uninstall.sh
EOF
