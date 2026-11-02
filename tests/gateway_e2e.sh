#!/usr/bin/env bash
# Gateway mode for real: ghost-flow on a kernel queue and capture with real tcpdump, in
# one privileged container. A "lan" network namespace holds a device (camera, 10.9.0.2),
# a "wan" namespace answers on 1.1.1.1 (a DoH resolver's address) and 93.184.215.14 (any
# public IP); the container routes between them like the Pi would. No internet needed.
#
#   tests/gateway_e2e.sh                     EXTRA_CA=/path/ca.pem behind a TLS-intercepting proxy
#
# Checks: the documented queue rule loads; ghost-flow raises doh_ip and raw_ip for the
# device and lets the traffic through; with ghost-flow stopped traffic still flows
# (queue bypass); capture keeps rotating past one ring, prunes to its window, and a
# freeze holds the packets from right before the alert.
set -euo pipefail
NAME=gw-gateway-e2e
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
fail() { echo "FAIL: $*" >&2; docker exec "$NAME" sh -c 'cat /tmp/flow.log /tmp/cap.log 2>/dev/null' >&2 || true; exit 1; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

cat > "$WORK/Dockerfile" <<'EOF'
FROM debian:bookworm
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      nftables iptables iproute2 python3 python3-venv python3-dev build-essential libnetfilter-queue-dev \
      tcpdump curl ca-certificates procps >/dev/null && apt-get clean
EOF
[ -n "${BASE_MIRROR:-}" ] && sed -i "s|^FROM debian:bookworm|FROM $BASE_MIRROR|" "$WORK/Dockerfile"
docker build -q -t gw-gateway-e2e "$WORK" >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged gw-gateway-e2e sleep infinity >/dev/null
PIPENV=""
if [ -n "${EXTRA_CA:-}" ]; then docker cp "$EXTRA_CA" "$NAME:/root/ca.pem"; PIPENV="PIP_CERT=/root/ca.pem"; fi
tar -C "$REPO" --exclude=./.git -cf - . | docker exec -i "$NAME" sh -c 'mkdir -p /opt/ghostwall && tar -C /opt/ghostwall -xf -'
ex() { docker exec "$NAME" bash -c "$1"; }

echo "== ghost-flow's dependency (hash-checked)"
ex "python3 -m venv /opt/ghostwall/.venv && $PIPENV /opt/ghostwall/.venv/bin/pip install -q --require-hashes -r /opt/ghostwall/requirements-gateway.lock" \
  || fail "requirements-gateway.lock does not install"

echo "== lab network"
ex 'set -e
ip netns add lan; ip netns add wan
ip link add gw0 type veth peer name lan0; ip link set lan0 netns lan
ip link add gw1 type veth peer name wan0; ip link set wan0 netns wan
ip addr add 10.9.0.1/24 dev gw0; ip link set gw0 up
ip addr add 198.51.100.1/24 dev gw1; ip link set gw1 up
ip -n lan addr add 10.9.0.2/24 dev lan0; ip -n lan link set lan0 up; ip -n lan link set lo up
ip -n lan route add default via 10.9.0.1
ip -n wan addr add 198.51.100.2/24 dev wan0; ip -n wan link set wan0 up; ip -n wan link set lo up
ip -n wan addr add 1.1.1.1/32 dev lo; ip -n wan addr add 93.184.215.14/32 dev lo
ip -n wan route add default via 198.51.100.1
ip route add 1.1.1.1/32 via 198.51.100.2; ip route add 93.184.215.14/32 via 198.51.100.2
sysctl -qw net.ipv4.ip_forward=1
ip netns exec wan sh -c "python3 -m http.server 80 >/dev/null 2>&1 &"
ip netns exec wan sh -c "python3 -m http.server 443 >/dev/null 2>&1 &"
sleep 1'
get() { ex "ip netns exec lan curl -s -o /dev/null -w %{http_code} --connect-timeout 4 $1"; }
[ "$(get http://93.184.215.14/)" = 200 ] || fail "lab routing broken"

echo "== the generated gateway firewall (netconf/gen.py) loads, reloads and breaks glass"
ex 'set -e; cd /opt/ghostwall/agents/netconf
python3 gen.py --devices devices.example.json --out /tmp/netconf >/dev/null
f=/tmp/netconf/ghostwall.nft
if ! nft -f $f 2>/tmp/nft.err; then
  # a kernel without flowtables (CONFIG_NF_FLOW_TABLE): load the rest of the ruleset
  grep -q "flowtable\|flow add" /tmp/nft.err || { cat /tmp/nft.err; exit 1; }
  echo "   kernel lacks flowtables: loading without the fast path"
  python3 -c "import re,sys; s=open(sys.argv[1]).read(); s=re.sub(r\"    flowtable f \\{.*?\\n    \\}\\n\", \"\", s, flags=re.S); open(sys.argv[1],\"w\").write(s.replace(\"        ct state established,related flow add @f\\n\", \"\"))" $f
  nft -f $f
fi
nft -f $f                                   # reload: idempotent
nft add element inet ghostwall isolated_dev { 192.168.1.50 }
nft list chain inet ghostwall prerouting_nat | grep -q "redirect to :53"
cd /opt/ghostwall/agents/ghost_dns && python3 - <<PY
# ghost-dns enforcement (what the control API calls for isolate / release / lockdown), real table
import subprocess
from enforce import Enforcer, NftBackend
e = Enforcer(NftBackend())
nft = lambda *a: subprocess.run(["nft", *a], capture_output=True, text=True, check=True).stdout
e.isolate("192.168.1.77")
assert "192.168.1.77" in nft("list", "set", "inet", "ghostwall", "isolated_dev"), "isolate"
e.release("192.168.1.77")
assert "192.168.1.77" not in nft("list", "set", "inet", "ghostwall", "isolated_dev"), "release"
e.block_ip("203.0.113.66")
assert "203.0.113.66" in nft("list", "set", "inet", "ghostwall", "blocked_ip"), "block_ip"
e.set_lockdown(True, "192.168.1.20")
assert "ghostwall_lockdown" in nft("-a", "list", "chain", "inet", "ghostwall", "forward"), "lockdown on"
e.set_lockdown(False, "192.168.1.20")
assert "ghostwall_lockdown" not in nft("-a", "list", "chain", "inet", "ghostwall", "forward"), "lockdown off"
print("   enforcement: isolate, release, block_ip, lockdown on/off all work on nft")
PY
bash /tmp/netconf/breakglass.sh >/dev/null 2>&1
! nft list tables | grep -q "inet ghostwall"' || fail "generated ruleset or ghost-dns enforcement failed on real nftables"

echo "== the documented queue rule (docs/OPERATIONS.md, gateway mode step 5)"
ex 'nft add table inet ghostwall && nft "add chain inet ghostwall forward { type filter hook forward priority 0; policy accept; }"'
if ex "nft add rule inet ghostwall forward iifname \"gw0\" ct state new meta l4proto '{ tcp, udp }' th dport != 53 queue num 100 bypass" 2>"$WORK/nft.err"; then
  echo "   nft queue rule loaded"
else
  grep -q "No such file" "$WORK/nft.err" || { cat "$WORK/nft.err"; fail "documented nft rule rejected"; }
  # This kernel has no nft 'queue' expression (CONFIG_NFT_QUEUE); the syntax parsed. Feed
  # the same netlink queue through the iptables target instead.
  echo "   kernel lacks nft queue: using iptables NFQUEUE for the same queue 100"
  ex 'iptables -A FORWARD -i gw0 -m conntrack --ctstate NEW -p tcp ! --dport 53 -j NFQUEUE --queue-num 100 --queue-bypass'
fi

echo "== ghost-flow on queue 100"
ex 'mkdir -p /var/lib/ghostwall /etc/ghostwall; : > /var/lib/ghostwall/resolved_ips.jsonl
echo "[{\"name\": \"camera\", \"ip\": \"10.9.0.2\"}]" > /etc/ghostwall/devices.json
python3 -c "import json; c = json.load(open(\"/opt/ghostwall/agents/ghost_flow/ghost_flow.example.json\")); c[\"capture_enabled\"] = False; json.dump(c, open(\"/etc/ghostwall/ghost_flow.json\", \"w\"))"
# as ghostwall-flow.service runs it: the ghostwall user with CAP_NET_ADMIN only
useradd --system --no-create-home ghostwall 2>/dev/null || true
chown -R ghostwall:ghostwall /var/lib/ghostwall
cd /opt/ghostwall/agents/ghost_flow && (setpriv --reuid=ghostwall --regid=ghostwall --init-groups \
   --inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin --bounding-set=-all,+net_admin \
   /opt/ghostwall/.venv/bin/python app.py --config /etc/ghostwall/ghost_flow.json > /tmp/flow.log 2>&1 &)
sleep 2'
[ "$(get http://93.184.215.14/)" = 200 ] || fail "raw-IP traffic blocked through the queue"
[ "$(get http://1.1.1.1:443/)" = 200 ] || fail "DoH-IP traffic blocked through the queue"
sleep 1
ev=$(ex 'cat /var/lib/ghostwall/events.jsonl')
echo "$ev" | grep -q '"rule":"raw_ip".*"device":"camera"\|"device":"camera".*"rule":"raw_ip"' || fail "no raw_ip event"
echo "$ev" | grep -q '"rule":"doh_ip"' || fail "no doh_ip event"
[ "$(ex 'stat -c %U /var/lib/ghostwall/events.jsonl')" = ghostwall ] || fail "events.jsonl not owned by ghostwall"
ex 'for p in $(pgrep -f "[a]pp.py --config /etc/ghostwall/ghost_flow.json"); do kill $p; done; sleep 1'
[ "$(get http://93.184.215.14/)" = 200 ] || fail "with ghost-flow stopped, traffic must still flow (bypass)"

echo "== capture: real tcpdump ring and a freeze"
ex 'mkdir -p /run/ghostwall/cap && mount -t tmpfs -o size=64M tmpfs /run/ghostwall/cap
cd /opt/ghostwall/agents/capture
printf "{\"interface\": \"gw0\", \"ring_seconds\": 3, \"ring_keep_minutes\": 0.15, \"freeze_extra_minutes\": 0.05}\n" > capture_conf.json
echo "[{\"name\": \"camera\", \"ip\": \"10.9.0.2\"}]" > devices.json
(python3 capture_mgr.py serve --devices devices.json --ring-dir /run/ghostwall/cap > /tmp/cap.log 2>&1 &)
for i in $(seq 25); do ip netns exec lan curl -s -o /dev/null http://93.184.215.14/; sleep 1; done'
st=$(ex 'curl -s http://127.0.0.1:5381/status')
echo "$st" | grep -q '"capturing": true' || fail "tcpdump stopped after one ring: $st"
files=$(echo "$st" | python3 -c 'import sys,json; print(json.load(sys.stdin)["devices"][0]["ring_files"])')
[ "$files" -le 6 ] || fail "ring not pruned to its window ($files files)"
ex 'ip netns exec lan curl -s -o /dev/null http://1.1.1.1:443/
curl -s -X POST http://127.0.0.1:5381/freeze -H "Content-Type: application/json" -d "{\"device\":\"camera\",\"event_id\":\"evt_e2e\"}" >/dev/null
sleep 7'
n=$(ex 'tcpdump -nr /var/lib/ghostwall/incidents/evt_e2e/evt_e2e.pcap 2>/dev/null | grep -c "> 1.1.1.1"' || true)
[ "${n:-0}" -ge 1 ] || fail "the freeze lacks the packets from right before the alert"
echo "PASS: gateway mode (ghost-flow + capture) end to end"
