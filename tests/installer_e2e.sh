#!/usr/bin/env bash
# Run install.sh for real: a Debian/Ubuntu container with systemd as PID 1, a fake native
# AdGuard Home (root-only config and query log, a dummy service), the repo cloned by a
# normal user. Then check what a user would: services up under their sandbox, code not
# writable by that user, queries scored, CLI, HTTPS, token, update keeps settings,
# uninstall cleans up.
#
#   tests/installer_e2e.sh [IMAGE]          IMAGE: debian:bookworm (default), ubuntu:22.04, ...
#
# Needs Docker that can run a privileged container. EXTRA_CA=/path/ca.pem trusts an extra
# CA inside the container (for networks behind a TLS-intercepting proxy).
set -euo pipefail
IMAGE=${1:-debian:bookworm}
NAME=gw-installer-e2e
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
fail() { echo "FAIL: $*" >&2; docker exec "$NAME" journalctl -u 'ghostwall*' -n 40 --no-pager >&2 || true; exit 1; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

cat > "$WORK/Dockerfile" <<EOF
FROM $IMAGE
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \\
      systemd systemd-sysv python3 python3-venv ca-certificates curl procps openssl sudo >/dev/null && apt-get clean
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
docker build -q -t gw-installer-e2e "$WORK" >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock gw-installer-e2e >/dev/null
for _ in $(seq 30); do
  s=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
  case "$s" in running|degraded) break ;; esac
  sleep 1
done
ENVS=()
if [ -n "${EXTRA_CA:-}" ]; then
  docker cp "$EXTRA_CA" "$NAME:/usr/local/share/extra-ca.pem"
  ENVS=(-e PIP_CERT=/usr/local/share/extra-ca.pem -e SSL_CERT_FILE=/usr/local/share/extra-ca.pem)
fi
tar -C "$REPO" --exclude=./.git -cf - . | docker exec -i "$NAME" bash -c 'useradd -m pi; mkdir /home/pi/ghostwall && tar -C /home/pi/ghostwall -xf - && chown -R pi:pi /home/pi/ghostwall'

ex() { docker exec "${ENVS[@]}" "$NAME" bash -c "$1"; }

echo "== fake AdGuard Home"
ex 'mkdir -p /opt/AdGuardHome/data
printf "dns:\n  port: 53\nquerylog:\n  dir_path: \"\"\n  size_memory: 1000\n  enabled: true\n" > /opt/AdGuardHome/AdGuardHome.yaml
chmod 600 /opt/AdGuardHome/AdGuardHome.yaml; : > /opt/AdGuardHome/data/querylog.json
chmod 700 /opt/AdGuardHome/data; chmod 600 /opt/AdGuardHome/data/querylog.json
printf "[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/AdGuardHome.service
systemctl daemon-reload; systemctl enable --now AdGuardHome >/dev/null 2>&1'

echo "== install.sh"
ex 'cd /home/pi/ghostwall && ./install.sh' > "$WORK/install.log" 2>&1 || { cat "$WORK/install.log"; fail "install.sh exited non-zero"; }
grep -q "Installed." "$WORK/install.log" || { cat "$WORK/install.log"; fail "no success message"; }
grep -q "size_memory: 10$" <(ex 'cat /opt/AdGuardHome/AdGuardHome.yaml') || fail "AdGuard buffer not lowered"

echo "== services and sandbox"
for s in ghostwall-dns ghostwall-web; do
  [ "$(ex "systemctl is-active $s")" = active ] || fail "$s not active"
done
ex 'grep -q "^Seccomp:\s*2" /proc/$(systemctl show -p MainPID --value ghostwall-web)/status' || fail "web not under seccomp"
[ "$(ex 'grep ^CapEff /proc/$(systemctl show -p MainPID --value ghostwall-web)/status | cut -f2')" = 0000000000000000 ] \
  || fail "web has capabilities"
[ "$(ex 'stat -c %U /opt/ghostwall/agents/ghost_dns/app.py')" = root ] || fail "code not root-owned"
if ex 'su pi -s /bin/sh -c "touch /opt/ghostwall/agents/ghost_dns/app.py"' 2>/dev/null; then fail "user can edit the code"; fi
[ "$(ex 'stat -c %a /var/lib/ghostwall/control_token')" = 600 ] || fail "token not 0600"
ex 'ghostwall version' | grep -q "^ghostwall 0\." || fail "no version recorded"

echo "== scoring, CLI, dashboard"
ex 'echo "{\"T\":\"2026-11-02T18:00:00Z\",\"QH\":\"xk2qv9zr7wpl3mfa.top\",\"QT\":\"A\",\"IP\":\"192.168.1.20\"}" >> /opt/AdGuardHome/data/querylog.json'
for _ in $(seq 30); do ex 'ghostwall alerts -n 1' 2>/dev/null | grep -q xk2qv9zr7wpl3mfa.top && break; sleep 1; done
ex 'ghostwall alerts -n 1' | grep -q xk2qv9zr7wpl3mfa.top || fail "query not scored / no alert"
ex 'su pi -s /bin/sh -c "ghostwall status"' | grep -q "1 queries" || fail "status (no sudo) wrong"
if ex 'su pi -s /bin/sh -c "ghostwall allow example.org"' 2>/dev/null; then fail "non-root could take an action"; fi
ex 'ghostwall allow example.org' >/dev/null || fail "root could not take an action"
ex 'ghostwall trusted' | grep -qx example.org || fail "trusted list wrong"
ex 'ghostwall allow undo.example && ghostwall untrust undo.example' >/dev/null || fail "untrust failed"
PASS=$(ex 'ghostwall password' | awk '{print $4}')
[ "$(ex "curl -sk -o /dev/null -w %{http_code} https://127.0.0.1:8088/")" = 401 ] || fail "https without password"
[ "$(ex "curl -sk -o /dev/null -w %{http_code} -u ghostwall:$PASS https://127.0.0.1:8088/api/events")" = 200 ] || fail "https with password"
[ "$(ex "curl -s -o /dev/null -w %{http_code} http://127.0.0.1:8088/")" = 301 ] || fail "http not redirected"

echo "== update keeps settings"
ex 'python3 - <<PY
import json; p = "/etc/ghostwall/ghost_dns.json"; c = json.load(open(p))
c["recommend_threshold"] = 0.97; c["thresholds_from"] = "me"; json.dump(c, open(p, "w"))
PY'
FPR=$(ex 'openssl x509 -noout -fingerprint -sha256 -in /etc/ghostwall/tls/cert.pem')
ex 'cd /home/pi/ghostwall && ./install.sh' > "$WORK/update.log" 2>&1 || { cat "$WORK/update.log"; fail "update failed"; }
[ "$FPR" = "$(ex 'openssl x509 -noout -fingerprint -sha256 -in /etc/ghostwall/tls/cert.pem')" ] || fail "cert replaced"
[ "$PASS" = "$(ex 'ghostwall password' | awk '{print $4}')" ] || fail "password changed"
ex 'grep -q example.org /var/lib/ghostwall/state.json' || fail "allowlist lost"
ex 'grep -q "\"recommend_threshold\": 0.97" /etc/ghostwall/ghost_dns.json' || fail "update dropped a chosen threshold"

echo "== uninstall"
ex '/opt/ghostwall/uninstall.sh' >/dev/null 2>&1 || fail "uninstall failed"
if ex 'test -e /opt/ghostwall || test -e /usr/local/bin/ghostwall'; then fail "code left behind"; fi
ex 'test -f /etc/ghostwall/ghostwall.env' || fail "settings not kept"
echo "PASS: installer end to end on $IMAGE"
