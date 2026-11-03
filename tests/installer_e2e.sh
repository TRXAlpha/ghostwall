#!/usr/bin/env bash
# Run install.sh for real: a Debian/Ubuntu container with systemd as PID 1, a fake native
# AdGuard Home (root-only config and query log, a dummy service), the repo cloned by a
# normal user. Then check what a user would: services up under their sandbox, code not
# writable by that user, queries scored, CLI, HTTPS, token, update keeps settings,
# uninstall cleans up.
#
#   tests/installer_e2e.sh [IMAGE]          IMAGE: debian:bookworm (default), ubuntu:22.04, ...
#   FROM_REF=v0.2.0-beta.2 tests/installer_e2e.sh ubuntu:24.04
#                                           an upgrade: that release first, with some history
#                                           (an alert, a trusted domain, a named device, a
#                                           threshold), then this tree over it, as `git pull`
#                                           would; checks the history survived, then the rest.
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
# A tiny DNS server standing in for AdGuard: answers A 192.0.2.10 for any name, on the
# port its AdGuardHome.yaml names (so inline mode's port move is real).
docker exec -i "$NAME" bash -c 'cat > /usr/local/bin/fake-adguard' <<'PY'
import re, socket, struct
port = int(re.search(r"^  port: (\d+)", open("/opt/AdGuardHome/AdGuardHome.yaml").read(), re.M).group(1))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
while True:
    q, addr = s.recvfrom(512)
    end = 12
    while q[end]:
        end += q[end] + 1
    end += 5
    hdr = q[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
    ans = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton("192.0.2.10")
    s.sendto(hdr + q[12:end] + ans, addr)
PY
ex 'mkdir -p /opt/AdGuardHome/data
printf "dns:\n  port: 53\nquerylog:\n  dir_path: \"\"\n  size_memory: 1000\n  enabled: true\n" > /opt/AdGuardHome/AdGuardHome.yaml
chmod 600 /opt/AdGuardHome/AdGuardHome.yaml; : > /opt/AdGuardHome/data/querylog.json
chmod 700 /opt/AdGuardHome/data; chmod 600 /opt/AdGuardHome/data/querylog.json
printf "[Service]\nExecStart=/usr/bin/python3 /usr/local/bin/fake-adguard\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/AdGuardHome.service
systemctl daemon-reload; systemctl enable --now AdGuardHome >/dev/null 2>&1'

if [ -n "${FROM_REF:-}" ]; then
  echo "== $FROM_REF first, with some history"
  git -C "$REPO" rev-parse -q --verify "$FROM_REF^{commit}" >/dev/null || git -C "$REPO" fetch -q --depth 1 origin tag "$FROM_REF"
  docker exec "$NAME" bash -c 'mv /home/pi/ghostwall /home/pi/ghostwall.new && mkdir /home/pi/ghostwall'
  git -C "$REPO" archive "$FROM_REF" | docker exec -i "$NAME" bash -c 'tar -C /home/pi/ghostwall -xf - && chown -R pi:pi /home/pi/ghostwall'
  ex 'cd /home/pi/ghostwall && ./install.sh' > "$WORK/old.log" 2>&1 || { cat "$WORK/old.log"; fail "$FROM_REF did not install"; }
  ex 'echo "{\"T\":\"2026-11-01T10:00:00Z\",\"QH\":\"oldalertxkq9zv7.top\",\"QT\":\"A\",\"IP\":\"192.168.1.30\"}" >> /opt/AdGuardHome/data/querylog.json'
  for _ in $(seq 30); do ex 'grep -q oldalertxkq9zv7.top /var/lib/ghostwall/events.jsonl' 2>/dev/null && break; sleep 1; done
  ex 'grep -q oldalertxkq9zv7.top /var/lib/ghostwall/events.jsonl' || fail "$FROM_REF: no alert to keep"
  ex 'curl -sf -X POST -H "Content-Type: application/json" -d "{\"domain\": \"kept.example\"}" http://127.0.0.1:5380/allow >/dev/null' \
    || fail "$FROM_REF: could not trust a domain"
  ex 'echo "{\"devices\": [], \"_pending\": [{\"name\": \"oldlaptop\", \"ip\": \"192.168.1.30\", \"mac\": null}]}" > /etc/ghostwall/devices.json
python3 -c "import json; p = \"/etc/ghostwall/ghost_dns.json\"; c = json.load(open(p)); c[\"recommend_threshold\"] = 0.975; json.dump(c, open(p, \"w\"), indent=2)"
systemctl restart ghostwall-dns; sleep 2'
  echo "== this tree over it (as git pull would)"
  docker exec "$NAME" bash -c 'rm -rf /home/pi/ghostwall && mv /home/pi/ghostwall.new /home/pi/ghostwall'
fi

echo "== install.sh"
ex 'cd /home/pi/ghostwall && ./install.sh' > "$WORK/install.log" 2>&1 || { cat "$WORK/install.log"; fail "install.sh exited non-zero"; }
grep -q "Installed." "$WORK/install.log" || { cat "$WORK/install.log"; fail "no success message"; }
grep -q "size_memory: 10$" <(ex 'cat /opt/AdGuardHome/AdGuardHome.yaml') || fail "AdGuard buffer not lowered"
if [ -n "${FROM_REF:-}" ]; then
  echo "== what $FROM_REF left behind survived the upgrade"
  for _ in $(seq 20); do ex 'ghostwall trusted' >/dev/null 2>&1 && break; sleep 1; done
  ex 'ghostwall alerts -n 50' | grep -q oldalertxkq9zv7.top || fail "upgrade: old alert gone"
  ex 'ghostwall trusted' | grep -qx kept.example || fail "upgrade: trusted domain gone"
  ex 'python3 -c "import json; c = json.load(open(\"/etc/ghostwall/ghost_dns.json\")); assert c.get(\"recommend_threshold\") == 0.975, c"' \
    || fail "upgrade: the threshold you set was reset"
  ex 'ghostwall devices' | grep -q "^  oldlaptop " || fail "upgrade: device name gone"
  ex 'python3 -c "import json; s = json.load(open(\"/var/lib/ghostwall/state.json\")); assert not any(\".\" in k for k in s[\"first_seen\"]), list(s[\"first_seen\"])[:3]"' \
    || fail "upgrade: state.json still lists every domain in the clear"
fi

echo "== threat feed (sandboxed service, real download)"
if [ -n "${EXTRA_CA:-}" ]; then   # behind a TLS-intercepting proxy: let the service trust it too
  ex 'mkdir -p /etc/systemd/system/ghostwall-feed.service.d && printf "[Service]\nEnvironment=SSL_CERT_FILE=/usr/local/share/extra-ca.pem\n" > /etc/systemd/system/ghostwall-feed.service.d/ca.conf && systemctl daemon-reload'
fi
ex 'systemctl start ghostwall-feed' || fail "feed service failed under its sandbox"
[ "$(ex 'wc -l < /var/lib/ghostwall/threat_feed.txt')" -gt 1000 ] || fail "feed too small"

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
ex 'ghostwall devices' | grep -q "192.168.1.20" || fail "unnamed client not listed"
if ex 'su pi -s /bin/sh -c "curl -s http://127.0.0.1:5380/status"' | grep -q "192.168.1.20"; then
  fail "any local user can read the device list"; fi
ex 'ghostwall name 192.168.1.20 laptop' >/dev/null || fail "naming failed"
for _ in $(seq 20); do ex 'ghostwall devices' 2>/dev/null | grep -q "^  laptop " && break; sleep 1; done
ex 'echo "{\"T\":\"2026-11-02T18:00:05Z\",\"QH\":\"q7zk2xv9wplmfa.top\",\"QT\":\"A\",\"IP\":\"192.168.1.20\"}" >> /opt/AdGuardHome/data/querylog.json'
for _ in $(seq 30); do ex 'ghostwall alerts -n 1' 2>/dev/null | grep -q "laptop .*q7zk2xv9wplmfa.top" && break; sleep 1; done
ex 'ghostwall alerts -n 1' | grep -q "laptop .*q7zk2xv9wplmfa.top" || fail "alert does not use the new name"
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

echo "== inline mode (docs/OPERATIONS.md, 'Going inline')"
docker exec -i "$NAME" bash -c 'cat > /usr/local/bin/dnsq' <<'PY'
import socket, struct, sys
name, port = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 53
q = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + b"".join(
    bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(6)
s.sendto(q, ("127.0.0.1", port))
r = s.recvfrom(512)[0]
rcode, an = r[3] & 15, struct.unpack(">H", r[6:8])[0]
print("rcode=%d" % rcode, socket.inet_ntoa(r[-4:]) if an and rcode == 0 else "-")
PY
ex 'sed -i "s/^  port: 53$/  port: 5300/" /opt/AdGuardHome/AdGuardHome.yaml && systemctl restart AdGuardHome && sleep 1'
[ "$(ex 'python3 /usr/local/bin/dnsq example.com 5300')" = "rcode=0 192.0.2.10" ] || fail "fake AdGuard not on 5300"
ex 'python3 - <<PY
import json; p = "/etc/ghostwall/ghost_dns.json"; c = json.load(open(p))
c.update({"shadow": False, "dns_host": "127.0.0.1", "dns_port": 53, "dns_host6": None,
          "upstream": "127.0.0.1", "upstream_port": 5300, "upstream_fallbacks": [], "learning": True})
json.dump(c, open(p, "w"), indent=2)
PY
systemctl restart ghostwall-dns'
for _ in $(seq 20); do ex 'python3 /usr/local/bin/dnsq example.com' >/dev/null 2>&1 && break; sleep 1; done
[ "$(ex 'python3 /usr/local/bin/dnsq example.com')" = "rcode=0 192.0.2.10" ] \
  || fail "inline: ghost-dns (unprivileged, CAP_NET_BIND_SERVICE) does not answer on :53"
[ "$(ex 'python3 /usr/local/bin/dnsq kjqwehdzxklqwpe.biz')" = "rcode=0 192.0.2.10" ] || fail "learning mode must not block"
# learning mode answers first and scores right after: the alert follows within moments
for _ in $(seq 10); do ex 'ghostwall alerts -n 3' | grep -q kjqwehdzxklqwpe.biz && break; sleep 1; done
ex 'ghostwall alerts -n 3' | grep -q kjqwehdzxklqwpe.biz || fail "inline: no alert"
ex 'ghostwall learning off' >/dev/null
[ "$(ex 'python3 /usr/local/bin/dnsq bexmnvoqeiduwq.xyz')" = "rcode=0 0.0.0.0" ] || fail "inline: new DGA name not sinkholed"
[ "$(ex 'python3 /usr/local/bin/dnsq example.com')" = "rcode=0 192.0.2.10" ] || fail "inline: normal name broken while blocking"
ex 'ghostwall learning on' >/dev/null
ex 'systemctl stop AdGuardHome'
[ "$(ex 'python3 /usr/local/bin/dnsq example.org')" = "rcode=2 -" ] || fail "inline: dead upstream must give SERVFAIL, not hang"
ex 'systemctl start AdGuardHome'
echo "== back to shadow (go_shadow.sh moves AdGuard back to :53)"
ex 'bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh' > "$WORK/shadow.log" 2>&1 || { cat "$WORK/shadow.log"; fail "go_shadow.sh failed"; }
[ "$(ex 'python3 /usr/local/bin/dnsq example.com')" = "rcode=0 192.0.2.10" ] || fail "AdGuard not back on :53"
ex 'su pi -s /bin/sh -c "ghostwall status"' | grep -q "mode:     shadow" || fail "not back in shadow mode"

echo "== uninstall"
ex '/opt/ghostwall/uninstall.sh' >/dev/null 2>&1 || fail "uninstall failed"
if ex 'test -e /opt/ghostwall || test -e /usr/local/bin/ghostwall'; then fail "code left behind"; fi
ex 'test -f /etc/ghostwall/ghostwall.env' || fail "settings not kept"
echo "PASS: installer end to end on $IMAGE"
