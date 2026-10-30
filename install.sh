#!/usr/bin/env bash
# Install Ghostwall in shadow mode next to an existing AdGuard Home.
#
#   sudo ./install.sh
#
# Tested target: Raspberry Pi OS / Debian 12+, Python 3.11+, AdGuard Home already
# answering DNS on port 53 with its query log on. Shadow mode never touches DNS or the
# firewall: Ghostwall only reads AdGuard's query log and alerts.
# Safe to re-run: existing config in /etc/ghostwall is kept.
set -euo pipefail

SRC=$(cd "$(dirname "$0")" && pwd)
DEST=/opt/ghostwall
[ "$(id -u)" = 0 ] || { echo "run as root: sudo ./install.sh" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

echo "1) copy to $DEST"
if [ "$SRC" != "$DEST" ]; then
  mkdir -p "$DEST"
  tar -C "$SRC" --exclude=./.git --exclude=./.venv --exclude=./data --exclude=./runs -cf - . | tar -C "$DEST" -xf -
fi

echo "2) python environment"
python3 -m venv "$DEST/.venv" || { echo "install python3-venv first: apt install python3-venv" >&2; exit 1; }
"$DEST/.venv/bin/pip" install -q --upgrade pip
"$DEST/.venv/bin/pip" install -q -r "$DEST/requirements.txt"

echo "3) user and config"
id ghostwall >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ghostwall
install -d -m 755 /etc/ghostwall
install -d -m 755 -o ghostwall -g ghostwall /var/lib/ghostwall
[ -f /etc/ghostwall/ghostwall.env ] || install -m 644 "$DEST/agents/ghost_dns/ghostwall.env.example" /etc/ghostwall/ghostwall.env

echo "4) systemd units"
for u in agents/ghost_dns/ghostwall-dns.service agents/ghost_dns/ghostwall-feed.service \
         agents/ghost_dns/ghostwall-feed.timer agents/web_ui/ghostwall-web.service \
         agents/fw_bot/ghostwall-fw-bot.service; do
  install -m 644 "$DEST/$u" /etc/systemd/system/
done
systemctl daemon-reload

echo "5) threat feed (daily)"
systemctl enable --now ghostwall-feed.timer >/dev/null
systemctl start ghostwall-feed.service || echo "   feed download failed; the timer retries daily"

echo "6) ghost-dns in shadow mode"
bash "$DEST/agents/ghost_dns/go_shadow.sh"

echo "7) web dashboard"
systemctl enable --now ghostwall-web >/dev/null
. /etc/ghostwall/ghostwall.env
echo "   http://${GHOSTWALL_WEB_BIND:-127.0.0.1}:8088"

cat <<EOF

Installed. Ghostwall is scoring AdGuard's query log; it cannot block anything yet.
  Decisions:   tail -f $DEST/agents/ghost_dns/events.jsonl
  Status:      curl -s http://127.0.0.1:5380/status

Optional Telegram alerts and /fw commands:
  cp $DEST/agents/fw_bot/fw_bot.env.example /etc/ghostwall/fw_bot.env   # add token + secret
  echo '{"chat_id": YOUR_CHAT_ID}' > /etc/ghostwall/owner.json
  chown root:ghostwall /etc/ghostwall/fw_bot.env /etc/ghostwall/owner.json
  chmod 640 /etc/ghostwall/fw_bot.env /etc/ghostwall/owner.json
  systemctl enable --now ghostwall-fw-bot
EOF
