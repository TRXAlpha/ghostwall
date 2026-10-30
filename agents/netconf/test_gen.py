"""Unit tests for gen.py — stdlib unittest, runs on Windows:
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
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.50,dell,", self.t)
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
        self.assertIn("destroy table inet ghostwall", nft)


if __name__ == "__main__":
    unittest.main()
