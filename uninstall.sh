#!/usr/bin/env bash
# Remove Ghostwall.
#
#   sudo ./uninstall.sh            # keeps your settings in /etc/ghostwall and /var/lib/ghostwall
#   sudo ./uninstall.sh --purge    # removes those and the ghostwall user too
#
# Your DNS server keeps running. If you had switched to inline mode, AdGuard is moved
# back to port 53 first, so DNS never goes down. The installer lowered AdGuard's
# query-log buffer (querylog.size_memory); that is harmless to keep, and the original
# AdGuardHome.yaml is saved next to it as AdGuardHome.yaml.bak-ghostwall-*.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ -f /etc/ghostwall/ghostwall.env ] && . /etc/ghostwall/ghostwall.env
YAML=${ADGUARD_YAML:-/opt/AdGuardHome/AdGuardHome.yaml}
if [ -f "$YAML" ] && grep -q '^  port: 5300$' "$YAML" && [ -f /opt/ghostwall/agents/ghost_dns/go_shadow.sh ]; then
  echo "1) inline mode is on: handing port 53 back to AdGuard"
  bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh
else
  echo "1) shadow mode: DNS is not affected"
fi

echo "2) stop and remove services"
for s in ghostwall-fw-bot ghostwall-web ghostwall-dns ghostwall-flow ghostwall-feed.timer ghostwall-feed ghost-capture; do
  systemctl disable --now "$s" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/ghostwall-*.service /etc/systemd/system/ghostwall-*.timer \
      /etc/systemd/system/ghost-capture.service
systemctl daemon-reload
command -v nft >/dev/null && nft delete table inet ghostwall 2>/dev/null || true

echo "3) remove /opt/ghostwall"
rm -rf /opt/ghostwall

if [ "$PURGE" = 1 ]; then
  echo "4) remove settings, threat feed and the ghostwall user"
  rm -rf /etc/ghostwall /var/lib/ghostwall
  id ghostwall >/dev/null 2>&1 && userdel ghostwall
else
  echo "4) kept /etc/ghostwall and /var/lib/ghostwall (use --purge to remove them)"
fi
echo "Ghostwall is gone. Your DNS server keeps running as before."
