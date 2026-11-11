r"""Unit tests for gen.py — stdlib unittest, runs on Windows:
    .venv\Scripts\python.exe -m unittest agents.netconf.test_gen -v
(also pytest-compatible).

Each test class guards a bug that actually broke on the Pi.
"""
import ipaddress
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Rendered into a temp dir from devices.example.json (deterministic, leak-free,
# and never clobbers a real ./out). Reassigned in setUpModule.
OUT = HERE / "out"

# RFC 1123 hostname label
RFC1123 = re.compile(r"^(?=.{1,63}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


_TMP_OUT = None


def setUpModule():
    global OUT, _TMP_OUT
    _TMP_OUT = tempfile.mkdtemp(prefix="netconf_out_")
    OUT = Path(_TMP_OUT)
    r = subprocess.run(
        [sys.executable, str(HERE / "gen.py"),
         "--devices", str(HERE / "devices.example.json"), "--out", _TMP_OUT],
        capture_output=True, text=True, cwd=str(HERE),
    )
    assert r.returncode == 0, f"gen.py failed: {r.stderr}"
    for f in ["dnsmasq.conf", "99-ghostwall.conf", "ghostwall.nft", "breakglass.sh", "health.sh"]:
        assert (OUT / f).exists(), f"missing rendered file {f}"


def tearDownModule():
    if _TMP_OUT:
        shutil.rmtree(_TMP_OUT, ignore_errors=True)


def _strip_comments(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def _set_body(t, setname):
    m = re.search(rf"set {setname} \{{(.*?)\n    \}}", _strip_comments(t), re.S)
    assert m is not None, f"set {setname} not found"
    return m.group(1)


class TestNoEmptyElements(unittest.TestCase):
    """Bug 1: nftables rejects an empty `elements = { }` block."""

    def test_no_empty_elements_block(self):
        t = (OUT / "ghostwall.nft").read_text()
        self.assertNotRegex(
            _strip_comments(t),
            r"elements\s*=\s*\{\s*\}",
            "empty elements = { } block found — nft -c rejects it; omit the elements line",
        )

    def test_empty_sets_have_no_elements_line(self):
        # blocked_ip / isolated_dev start empty: their set blocks must not
        # contain an elements line at all.
        t = _strip_comments((OUT / "ghostwall.nft").read_text())
        for setname in ("blocked_ip", "isolated_dev"):
            body = _set_body(t, setname)
            self.assertNotIn("elements", body,
                             f"{setname} must have no elements line while empty")


class TestNftSetTypes(unittest.TestCase):
    """Bug 2: IPv6 addresses inside an ipv4_addr set -> `nft -c` type error."""

    def _elements(self, setname):
        t = (OUT / "ghostwall.nft").read_text()
        body = _set_body(_strip_comments(t), setname)
        tm = re.search(r"type\s+(\S+)", body)
        em = re.search(r"elements\s*=\s*\{(.*?)\}", body, re.S)
        # strip trailing # comments from each element line
        elems = "\n".join(l.split("#")[0] for l in (em.group(1) if em else "").splitlines())
        return (tm.group(1) if tm else None, elems)

    def test_sets_split_by_family(self):
        t = (OUT / "ghostwall.nft").read_text()
        self.assertIn("table inet ghostwall", t)
        self.assertIn("set doh_ip4", t)
        self.assertIn("set doh_ip6", t)
        self.assertNotIn("set doh_ip\n", t)  # old merged set gone

    def test_ipv4_set_elements_parse_as_ipv4(self):
        _, elems = self._elements("doh_ip4")
        self.assertTrue(elems.strip())
        for tok in re.findall(r"[A-Za-z0-9:.]+(?:/\d+)?", elems):
            ipaddress.IPv4Network(tok, strict=False)  # raises on IPv6/garbage

    def test_ipv6_set_elements_parse_as_ipv6(self):
        _, elems = self._elements("doh_ip6")
        self.assertTrue(elems.strip(), "doh_ip6 set is empty")
        for tok in re.findall(r"[A-Za-z0-9:.]+(?:/\d+)?", elems):
            ipaddress.IPv6Network(tok, strict=False)  # raises on IPv4/garbage

    def test_doh_sets_come_from_the_shared_list(self):
        import gen
        v4, v6 = gen.doh_ips()
        _, e4 = self._elements("doh_ip4")
        _, e6 = self._elements("doh_ip6")
        for ip in ("1.1.1.2", "45.90.28.0", "194.242.2.2"):     # security, NextDNS, Mullvad
            self.assertIn(ip, v4)
            self.assertIn(ip, e4)
        self.assertIn("2a07:a8c0::", e6)
        self.assertEqual(len(v4), len(set(v4)))

    def test_doh_list_refuses_private_or_garbage(self):
        import tempfile
        import gen
        d = Path(tempfile.mkdtemp())
        for bad in ("192.168.1.1\n2606:4700:4700::1111\n", "1.1.1.1; drop\n2606:4700:4700::1111\n",
                    "1.1.1.1\n"):
            (d / "l.txt").write_text(bad)
            with self.assertRaises(gen.GenError):
                gen.doh_ips(d / "l.txt")

    def _render(self, cfg_over=None, iot=False):
        import json
        d = Path(tempfile.mkdtemp())
        dev = json.loads((HERE / "devices.example.json").read_text())
        if iot:
            dev["devices"][0]["profile"] = "iot"
        (d / "dev.json").write_text(json.dumps(dev))
        cfg = json.loads((HERE / "config.json").read_text())
        cfg.update(cfg_over or {})
        (d / "cfg.json").write_text(json.dumps(cfg))
        r = subprocess.run([sys.executable, str(HERE / "gen.py"), "--devices", str(d / "dev.json"),
                            "--config", str(d / "cfg.json"), "--out", str(d / "out")],
                           capture_output=True, text=True, cwd=str(HERE))
        return r, (d / "out" / "ghostwall.nft").read_text() if r.returncode == 0 else ""

    def test_blocked_and_criminal_networks_dropped_both_ways(self):
        t = _strip_comments((OUT / "ghostwall.nft").read_text())
        for rule in ("ip daddr @blocked_ip counter drop", "ip saddr @blocked_ip counter drop",
                     "ip saddr @drop_net4 counter drop", "ip6 saddr @drop_net6 counter drop"):
            self.assertIn(rule, t)
        inp = t.split("chain input {")[1].split("chain forward {")[0]
        self.assertIn("ip saddr @blocked_ip counter drop", inp)          # this box is covered too
        self.assertLess(inp.index("@blocked_ip"), inp.index("dport 22"))  # before any accept
        out = t.split("chain output {")[1].split("}")[0]
        self.assertIn("ip daddr @blocked_ip counter drop", out)
        self.assertIn("ip daddr @drop_net4 counter drop", out)

    def test_input_policy_and_this_boxes_services(self):
        t = _strip_comments((OUT / "ghostwall.nft").read_text())
        self.assertIn("hook input priority filter; policy accept;", t)       # default: unchanged
        self.assertIn("tcp dport { 3000, 8088 } accept", t)
        self.assertNotIn("8080", t)                                           # no stray service ports
        r, t = self._render({"input_policy": "drop", "lan_services_tcp": [8088]})
        self.assertEqual(r.returncode, 0, r.stderr)
        t = _strip_comments(t)
        self.assertIn("hook input priority filter; policy drop;", t)
        inp = t.split("chain input {")[1].split("chain forward {")[0]
        for needed in ("tcp dport 22", "udp dport 53", "udp dport 67", "ct state established,related accept",
                       "tcp dport { 8088 } accept"):
            self.assertIn(needed, inp)                                        # nobody is locked out
        self.assertNotIn("3000", inp)
        for bad in ({"input_policy": "reject"}, {"lan_services_tcp": ["ssh"]}, {"lan_services_tcp": [0]}):
            self.assertNotEqual(self._render(bad)[0].returncode, 0, bad)

    def test_antispoof_binds_named_addresses_to_their_macs(self):
        t = _strip_comments((OUT / "ghostwall.nft").read_text())
        self.assertIn("set named_mac", t)
        self.assertNotIn("!= @named_mac", t)                                  # off by default
        r, t = self._render({"antispoof": "on"})
        self.assertEqual(r.returncode, 0, r.stderr)
        t = _strip_comments(t)
        rule = "ip saddr @named_dev ip saddr . ether saddr != @named_mac counter drop"
        self.assertIn(rule, t)
        self.assertLess(t.rindex(rule), t.index("flow add @f"))
        inp = t.split("chain input {")[1].split("chain forward {")[0]
        self.assertIn(rule, inp)                                              # lookups sent to this box too
        self.assertLess(inp.index(rule), inp.index("udp dport 53 accept"))
        r, t = self._render({"antispoof": "log"})
        self.assertIn('log prefix "ghostwall antispoof: "', t)
        self.assertNotIn("!= @named_mac counter drop", t)
        self.assertNotEqual(self._render({"antispoof": "yes"})[0].returncode, 0)

    def test_isolated_devices_get_a_trickle_of_dns_and_no_way_into_the_tailnet(self):
        t = _strip_comments((OUT / "ghostwall.nft").read_text())
        inp = t.split("chain input {")[1].split("chain forward {")[0]
        limit = "ip saddr @isolated_dev meta l4proto { tcp, udp } th dport 53 limit rate over 20/minute"
        self.assertIn(limit, inp)
        self.assertLess(inp.index(limit), inp.index("udp dport 53 accept"))
        self.assertIn("ip saddr @isolated_dev ip daddr 100.64.0.0/10 ct state new counter drop", t)

    def test_egress_ports_dropped_toward_the_internet_only(self):
        t = (OUT / "ghostwall.nft").read_text()
        self.assertIn('ip daddr != 192.168.1.0/24 tcp dport { 23, 25, 135, 139, 445, 2323 } counter drop', t)
        self.assertIn('udp dport { 137, 138, 1900 } counter drop', t)
        self.assertNotIn("@iot_dev ip daddr", t)          # IoT lock off by default
        r, t = self._render({"egress_block": False})
        self.assertNotIn("dport { 23,", t)
        r, t = self._render({"egress_block_tcp": [25]})
        self.assertIn("tcp dport { 25 } counter drop", t)

    def test_iot_egress_lock_modes(self):
        r, t = self._render({"iot_egress_lock": "on"}, iot=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("elements = { 192.168.1.50 }", t)
        self.assertIn("ip saddr @iot_dev ip daddr != 192.168.1.20 ip daddr != 100.64.0.0/10 meta l4proto tcp "
                      "tcp dport != { 80, 443, 8883 } counter drop", t)
        r, t = self._render({"iot_egress_lock": "log"}, iot=True)
        self.assertIn('log prefix "ghostwall iot-egress: "', t)
        self.assertNotIn("8883 } counter drop", t)
        r, t = self._render({"iot_egress_lock": "on"})        # no IoT device: no rule, empty set
        self.assertNotIn("@iot_dev ip daddr", t)
        self.assertNotIn("elements = { }", t)

    def test_egress_config_is_checked(self):
        for bad in ({"iot_egress_lock": "yes"}, {"egress_block_tcp": [25, "445; drop"]},
                    {"iot_allowed_tcp": [70000]}):
            r, _ = self._render(bad, iot=True)
            self.assertNotEqual(r.returncode, 0, bad)

    def test_matching_rules_cover_both_families(self):
        t = (OUT / "ghostwall.nft").read_text()
        for line in [
            "ip daddr @doh_ip4 udp dport 443 drop",
            "ip daddr @doh_ip4 tcp dport 443 drop",
            "ip6 daddr @doh_ip6 udp dport 443 drop",
            "ip6 daddr @doh_ip6 tcp dport 443 drop",
        ]:
            self.assertIn(line, t, f"missing rule: {line}")


class TestDhcpLeases(unittest.TestCase):
    """Bug 3: fake MACs / non-ASCII hostnames broke dnsmasq --test."""

    def setUp(self):
        self.t = (OUT / "dnsmasq.conf").read_text()
        self.lines = [l for l in self.t.splitlines() if l.startswith("dhcp-host=")]
        self.assertTrue(self.lines, "no dhcp-host lines rendered")

    def test_hostnames_rfc1123(self):
        for l in self.lines:
            name = l.split(",")[2]
            self.assertRegex(name, RFC1123, f"bad hostname in {l!r}")

    def test_macs_valid(self):
        for l in self.lines:
            mac = l.split(",")[0].replace("dhcp-host=", "")
            self.assertRegex(mac, MAC, f"bad MAC in {l!r}")

    def test_no_duplicate_ips_or_macs(self):
        ips = [l.split(",")[1] for l in self.lines]
        macs = [l.split(",")[0] for l in self.lines]
        self.assertEqual(len(ips), len(set(ips)), f"duplicate IPs: {ips}")
        self.assertEqual(len(macs), len(set(macs)), f"duplicate MACs: {macs}")

    def test_no_lease_for_pi(self):
        for l in self.lines:
            self.assertNotEqual("192.168.1.20", l.split(",")[1],
                                "the Pi must never be a DHCP lease")

    def test_real_devices_present(self):
        # Values come from devices.example.json (made-up MACs/IPs).
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.50,workpc,", self.t)
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:02,192.168.1.51,bambu-a1mini,", self.t)

    def test_pending_devices_are_commented_out(self):
        t = self.t
        self.assertIn("# TODO: fill in MAC", t)
        # ps4 and phone must appear ONLY on comment lines
        for name in ("ps4", "phone"):
            for l in t.splitlines():
                if f",{name} " in l or name + "," in l:
                    self.assertTrue(l.lstrip().startswith("#"),
                                    f"pending device {name} is an active lease line: {l}")

    def test_no_non_ascii(self):
        # Lease lines (what dnsmasq parses) must be pure ASCII; template
        # comments may keep UTF-8 decoration.
        for l in (OUT / "dnsmasq.conf").read_text(encoding="utf-8").splitlines():
            if l.startswith("dhcp-host="):
                l.encode("ascii")  # raises on non-ASCII


class TestNtpRemoved(unittest.TestCase):
    """Bug 4: the Pi runs no NTP server."""

    def test_no_ntp_server_option(self):
        t = _strip_comments((OUT / "dnsmasq.conf").read_text())
        self.assertNotIn("ntp-server", t)


class TestDnsmasqOptionAllowlist(unittest.TestCase):
    """Bug 7 (Pi round 2): 'log-leases' is not a dnsmasq option ->
    'bad option at line 29'. Every non-comment line's option name must be
    in this allowlist; each entry verified against the dnsmasq 2.91 man page:
      port, dhcp-range, dhcp-option, dhcp-lease-max, dhcp-host,
      dhcp-leasefile, log-dhcp, log-facility, log-async,
      bind-interfaces, interface, dhcp-authoritative, no-resolv.
    """

    ALLOWED = {
        "port", "dhcp-range", "dhcp-option", "dhcp-lease-max", "dhcp-host",
        "dhcp-leasefile", "log-dhcp", "log-facility", "log-async",
        "bind-interfaces", "interface", "dhcp-authoritative", "no-resolv",
    }

    def test_every_option_in_allowlist(self):
        bad = []
        for raw in (OUT / "dnsmasq.conf").read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            opt = line.split("=")[0].strip()
            if opt not in self.ALLOWED:
                bad.append(f"{opt!r} (line: {line!r})")
        self.assertEqual(bad, [], f"unknown dnsmasq option(s) not in allowlist: {bad}")

    def test_log_dhcp_present_and_log_leases_gone(self):
        t = _strip_comments((OUT / "dnsmasq.conf").read_text())
        self.assertIn("log-dhcp", t)
        self.assertNotIn("log-leases", t)


class TestSysctlIpv6Forwarding(unittest.TestCase):
    """Bug 5: ipv6.conf.all.forwarding=0 breaks the Tailscale exit node."""

    def test_no_ipv6_forwarding_line(self):
        t = _strip_comments((OUT / "99-ghostwall.conf").read_text())
        self.assertNotRegex(t, r"net\.ipv6\.conf\.[\w.]*forwarding")

    def test_ipv4_settings_still_present(self):
        t = (OUT / "99-ghostwall.conf").read_text()
        self.assertIn("net.ipv4.ip_forward = 1", t)
        self.assertIn("net.ipv4.conf.all.send_redirects = 0", t)
        self.assertIn("net.ipv4.conf.all.rp_filter = 2", t)
        self.assertIn("net.ipv6.conf.all.accept_ra = 2", t)


class TestBreakglassRestore(unittest.TestCase):
    """Bug 6: breakglass hardcoded rp_filter=1; must restore recorded values."""

    def test_no_hardcoded_rp_filter_1(self):
        bg = _strip_comments((OUT / "breakglass.sh").read_text())
        self.assertNotRegex(bg, r"rp_filter=1\b")
        self.assertIn("sysctl-before.conf", bg)
        self.assertRegex(bg, r'restore "\$k" 2')  # rp_filter fallback = 2

    def test_no_ipv6_forwarding_touch(self):
        bg = _strip_comments((OUT / "breakglass.sh").read_text())
        self.assertNotIn("ipv6.conf", bg)

    def test_table_family_consistent(self):
        bg = (OUT / "breakglass.sh").read_text()
        self.assertIn("nft delete table inet ghostwall", bg)
        h = (OUT / "health.sh").read_text()
        self.assertIn("nft list table inet ghostwall", h)
        nft = (OUT / "ghostwall.nft").read_text()
        # idempotent on nftables 1.0.6 too (Debian 12): no "destroy", declare-then-delete
        self.assertNotIn("destroy table", nft)
        self.assertIn("table inet ghostwall {}\ndelete table inet ghostwall", nft)


class TestLanInterface(unittest.TestCase):
    """The LAN interface was eth0 written into every file; it comes from config.json."""

    def render(self, iface):
        import json
        d = tempfile.mkdtemp(prefix="netconf_iface_")
        cfg = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
        cfg["lan_iface"] = iface
        cfg_path = Path(d) / "config.json"
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        out = Path(d) / "out"
        r = subprocess.run([sys.executable, str(HERE / "gen.py"), "--devices", str(HERE / "devices.example.json"),
                            "--config", str(cfg_path), "--out", str(out)], capture_output=True, text=True, cwd=str(HERE))
        return r, out

    def test_interface_is_configurable(self):
        r, out = self.render("enp1s0")
        self.assertEqual(r.returncode, 0, r.stderr)
        for p in out.iterdir():
            self.assertNotIn("eth0", p.read_text(), p.name)
        self.assertIn('iifname "enp1s0"', (out / "ghostwall.nft").read_text())
        self.assertIn("interface=enp1s0", (out / "dnsmasq.conf").read_text())

    def test_interface_name_cannot_inject_rules(self):
        r, _ = self.render('eth0" accept; #')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is not an interface name", r.stderr)


if __name__ == "__main__":
    unittest.main()
