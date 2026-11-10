"""dns_block: the feed as a blocklist in AdGuard Home / Pi-hole, with mocked DNS-server APIs.
Example names only (example.com style); the passwords are made-up sentinels."""
import base64
import json
import os
import struct
import sys
import tempfile
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dns_block as B

AG_PASS = "ag-sentinel-Pw-12345"
PH_PASS = "ph-sentinel-Pw-67890"
FEED = ("# Ghostwall threat feed\n#@source\thttps://x.example/a\t2026-11-07\tURLhaus\tmalware\n"
        "evil.example.com\nsub.evil.example.com\nbad.example.net\n"
        "#@source\thttps://x.example/b\t2026-11-07\tCERT Polska\tphishing\nphish.example.org\nbad.example.net\n")


class FakeAdGuard:
    """Just enough of AdGuard Home's /control/filtering API."""

    def __init__(self, fail=None):
        self.filters, self.rules, self.calls, self.fail = [], ["||mine.example.com^"], [], fail
        self.refreshes = 0

    def request(self, method, url, headers=None, body=None, timeout=30):
        path = url.split("127.0.0.1:3000", 1)[1]
        self.calls.append((method, path, headers, body))
        if self.fail:
            raise B.ApiError(f"{method} 127.0.0.1:3000: ConnectionRefusedError: refused (sent {headers.get('Authorization')})")
        j = json.loads(body) if body else {}
        ok = lambda o=None: (200, json.dumps(o or {}).encode())
        if headers.get("Authorization") != "Basic " + base64.b64encode(f"admin:{AG_PASS}".encode()).decode():
            return 401, b"Unauthorized"
        if path == "/control/filtering/status":
            return ok({"enabled": True, "filters": self.filters or None, "user_rules": self.rules})
        if path == "/control/filtering/add_url":
            self.filters.append({"id": len(self.filters) + 1, "url": j["url"], "name": j["name"], "enabled": True})
            return 200, b"OK 5 rules added"
        if path == "/control/filtering/remove_url":
            self.filters = [f for f in self.filters if f["url"] != j["url"]]
            return ok()
        if path == "/control/filtering/refresh":
            self.refreshes += 1
            return ok({"updated": 1})
        if path == "/control/filtering/set_rules":
            self.rules = j["rules"]
            return ok()
        return 404, b"nope"

    def posts(self, suffix):
        return [c for c in self.calls if c[0] == "POST" and c[1].endswith(suffix)]


class FakePiHole:
    def __init__(self):
        self.lists, self.regex, self.calls, self.gravity = {}, {}, [], 0
        self.deny = {}
        self.special = {"mozillaCanary": False, "iCloudPrivateRelay": False}

    def request(self, method, url, headers=None, body=None, timeout=30):
        path = url.split("127.0.0.1", 1)[1]
        self.calls.append((method, path, dict(headers or {}), body))
        j = json.loads(body) if body else {}
        ok = lambda o=None: (200, json.dumps(o or {}).encode())
        if path == "/api/auth" and method == "POST":
            if j.get("password") != PH_PASS:
                return 401, json.dumps({"error": {"message": "password incorrect"}}).encode()
            return ok({"session": {"valid": True, "sid": "sid-sentinel-abc"}})
        if (headers or {}).get("X-FTL-SID") != "sid-sentinel-abc":
            return 401, b"{}"
        if path == "/api/auth":
            return ok()
        if path.startswith("/api/lists") and method == "GET":
            return ok({"lists": list(self.lists.values())})
        if path.startswith("/api/lists") and method == "POST":
            self.lists[j["address"]] = {"address": j["address"], "comment": j["comment"], "enabled": True}
            return 201, b"{}"
        if path.startswith("/api/lists/") and method == "DELETE":
            self.lists.pop(urllib.request.unquote(path.split("/api/lists/")[1].split("?")[0]), None)
            return 204, b""
        if path == "/api/domains/allow/regex" and method == "GET":
            return ok({"domains": list(self.regex.values())})
        if path == "/api/domains/allow/regex" and method == "POST":
            self.regex[j["domain"]] = {"domain": j["domain"], "comment": j["comment"]}
            return 201, b"{}"
        if path.startswith("/api/domains/allow/regex/") and method == "DELETE":
            self.regex.pop(urllib.request.unquote(path.rsplit("/", 1)[1]), None)
            return 204, b""
        if path == "/api/domains/deny/regex" and method == "GET":
            return ok({"domains": list(self.deny.values())})
        if path == "/api/domains/deny/regex" and method == "POST":
            self.deny[j["domain"]] = {"domain": j["domain"], "comment": j["comment"]}
            return 201, b"{}"
        if path.startswith("/api/domains/deny/regex/") and method == "DELETE":
            self.deny.pop(urllib.request.unquote(path.rsplit("/", 1)[1]), None)
            return 204, b""
        if path == "/api/action/gravity":
            self.gravity += 1
            return ok()
        if path == "/api/config/dns/specialDomains":
            return ok({"config": {"dns": {"specialDomains": self.special}}})
        if path == "/api/config" and method == "PATCH":
            sd = j["config"]["dns"].get("specialDomains")
            if sd:
                self.special.update(sd)
            return ok()
        return 404, b"{}"


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.feed = os.path.join(self.d, "threat_feed.txt")
        self.state = os.path.join(self.d, "state.json")
        self.logs = []
        self.write_feed(FEED)

    def write_feed(self, text):
        with open(self.feed, "w") as f:
            f.write(text)
        os.utime(self.feed, (os.stat(self.feed).st_atime, os.stat(self.feed).st_mtime + 1))

    def settings(self, **kw):
        env = {"DNS_SOURCE": "adguard", "DNS_BLOCK_FEED": "on", "ADGUARD_USER": "admin", "ADGUARD_PASSWORD": AG_PASS,
               "PIHOLE_PASSWORD": PH_PASS, "ADGUARD_URL": "http://127.0.0.1:3000", "PIHOLE_URL": "http://127.0.0.1"}
        env.update(kw)
        s = B.load_settings(env)
        s.update(feed_path=self.feed, state_path=self.state, data=self.d, events_path=os.path.join(self.d, "events.jsonl"),
                 allowlist_path=None)
        return s

    def syncer(self, http, **kw):
        return B.Syncer(self.settings(**kw), http, log=self.logs.append, serve=False)

    def trust(self, trusted=(), exceptions=(), blocked=()):
        with open(os.path.join(self.d, "dns_view.json"), "w") as f:
            json.dump({"trusted": list(trusted), "exceptions": list(exceptions), "blocked": list(blocked), "starter": []}, f)


class Rendering(Base):
    def test_adguard_format_prunes_children_and_adds_canaries(self):
        names, _ = B.read_feed(self.feed)
        text = B.render_adguard(names, "on")
        rules = [l for l in text.splitlines() if not l.startswith("!")]
        self.assertIn("||evil.example.com^", rules)
        self.assertNotIn("||sub.evil.example.com^", rules)        # covered by its parent
        self.assertEqual(rules.count("||bad.example.net^"), 1)    # in two sources, once in the list
        self.assertIn("||use-application-dns.net^$dnsrewrite=NXDOMAIN", rules)
        self.assertIn("||mask.icloud.com^$dnsrewrite=NXDOMAIN", rules)
        self.assertIn("||mask-h2.icloud.com^$dnsrewrite=NXDOMAIN", rules)
        norelay = B.render_adguard(names, "no-relay")
        self.assertIn("use-application-dns.net", norelay)
        self.assertNotIn("icloud", norelay)
        self.assertNotIn("use-application-dns.net", B.render_adguard(names, "off"))

    def test_pihole_format_is_plain_names_without_exceptions(self):
        names, _ = B.read_feed(self.feed)
        text = B.render_pihole(names, {"evil.example.com"})
        rows = [l for l in text.splitlines() if not l.startswith("#")]
        self.assertEqual(rows, ["bad.example.net", "phish.example.org"])   # evil + its subdomain dropped

    def test_exceptions_are_trust_unblock_and_starter_names_that_are_listed(self):
        self.trust(trusted=["trusted.example.com"], exceptions=["unblocked.example.com"])
        s = self.settings()
        with open(self.state, "w") as f:
            json.dump({}, f)
        b = B.build(s)
        self.assertEqual(b["exceptions"], {"trusted.example.com", "unblocked.example.com"})
        self.assertEqual(B.exceptions_adguard_rules(b["exceptions"]),
                         ["@@||trusted.example.com^", "@@||unblocked.example.com^"])

    def test_ghostwalls_own_blocklist_is_included(self):
        self.trust(blocked=["confirmed.example.com"])
        self.assertIn("confirmed.example.com", B.build(self.settings())["names"])

    def test_view_falls_back_to_state_json(self):
        with open(self.state, "w") as f:
            json.dump({"allowlist": ["a.example.com", "starter.example.com"], "dns_exceptions": ["b.example.com"]}, f)
        al = os.path.join(self.d, "allowlist.txt")
        with open(al, "w") as f:
            f.write("# starter\nstarter.example.com\n")
        s = self.settings()
        s["allowlist_path"] = al
        v = B.load_view(s)
        self.assertEqual((v["trusted"], v["exceptions"]), (["a.example.com"], ["b.example.com"]))

    def test_regex_for_pihole_matches_name_and_subdomains_only(self):
        import re
        rx = re.compile(B.pihole_regex("example.com"))
        self.assertTrue(rx.search("example.com") and rx.search("a.example.com"))
        self.assertFalse(rx.search("notexample.com") or rx.search("example.com.evil.net"))


class AdGuardSync(Base):
    def test_registration_is_idempotent(self):
        ag = FakeAdGuard()
        sy = self.syncer(ag)
        self.assertTrue(sy.sync_once())
        self.assertEqual([f["name"] for f in ag.filters], ["Ghostwall threat feed"])
        self.assertEqual(len(ag.posts("add_url")), 1)
        n = len(ag.calls)
        self.assertTrue(sy.sync_once())                         # nothing changed
        self.assertEqual(len(ag.posts("add_url")), 1)
        self.assertEqual(ag.refreshes, 0)
        self.assertEqual([c[1] for c in ag.calls[n:]], ["/control/filtering/status"])   # a look, no writes
        self.write_feed(FEED + "new.example.org\n")             # a feed update: refresh, no second list
        self.assertTrue(sy.sync_once())
        self.assertEqual((len(ag.filters), ag.refreshes), (1, 1))

    def test_exceptions_live_in_a_marked_block_and_user_rules_survive(self):
        ag = FakeAdGuard()
        self.trust(trusted=["trusted.example.com"])
        sy = self.syncer(ag)
        sy.sync_once()
        self.assertEqual(ag.rules, ["||mine.example.com^", B.RULES_BEGIN, "@@||trusted.example.com^", B.RULES_END])
        self.trust(trusted=[])                                   # Untrust: the block goes, the user's rule stays
        sy.sync_once()
        self.assertEqual(ag.rules, ["||mine.example.com^"])

    def test_ads_and_bypass_are_registered_and_removed_without_touching_other_lists(self):
        ag = FakeAdGuard()
        ag.filters.append({"id": 9, "url": "https://lists.example.com/mine.txt", "name": "My list", "enabled": True})
        sy = self.syncer(ag, DNS_BLOCK_ADS="pro", DNS_BLOCK_BYPASS="on")
        sy.sync_once()
        names = {f["name"] for f in ag.filters}
        self.assertEqual(names, {"My list", "Ghostwall threat feed", "Ghostwall ads: HaGeZi Multi PRO",
                                 "Ghostwall bypass: HaGeZi DoH/VPN/TOR/Proxy Bypass"})
        sy2 = self.syncer(ag, DNS_BLOCK_ADS="off", DNS_BLOCK_BYPASS="off", DNS_BLOCK_FEED="on")
        sy2.sync_once()
        self.assertEqual({f["name"] for f in ag.filters}, {"My list", "Ghostwall threat feed"})

    def test_switching_everything_off_unregisters_once_then_makes_no_calls(self):
        ag = FakeAdGuard()
        self.syncer(ag).sync_once()
        off = self.syncer(ag, DNS_BLOCK_FEED="off")
        self.assertTrue(off.sync_once())
        self.assertEqual([f["name"] for f in ag.filters], [])
        n = len(ag.calls)
        self.assertTrue(self.syncer(ag, DNS_BLOCK_FEED="off").sync_once())
        self.assertEqual(len(ag.calls), n)

    def test_off_from_the_start_makes_no_api_call(self):
        ag = FakeAdGuard()
        self.assertTrue(self.syncer(ag, DNS_BLOCK_FEED="off").sync_once())
        self.assertEqual(ag.calls, [])


class PiHoleSync(Base):
    def test_registers_once_updates_gravity_only_on_change(self):
        ph = FakePiHole()
        self.trust(trusted=["trusted.example.com"])
        sy = self.syncer(ph, DNS_SOURCE="pihole")
        self.assertTrue(sy.sync_once())
        self.assertEqual(list(ph.lists), ["http://127.0.0.1:5382/ghostwall-blocklist.txt"])
        self.assertEqual(ph.gravity, 1)
        self.assertIn(B.pihole_regex("trusted.example.com"), ph.regex)
        self.assertTrue(ph.special["mozillaCanary"] and ph.special["iCloudPrivateRelay"])
        self.assertTrue(sy.sync_once())
        self.assertEqual((len(ph.lists), ph.gravity), (1, 1))
        self.trust(trusted=[])
        sy.sync_once()
        self.assertEqual(ph.regex, {})
        self.assertEqual(ph.gravity, 1)             # an exception needs no gravity run
        self.assertTrue(all(c[3] is None or PH_PASS not in c[3].decode() or c[1] == "/api/auth" for c in ph.calls))
        self.assertEqual(ph.calls[-1][:2], ("DELETE", "/api/auth"))   # the session is closed

    def test_wrong_password_is_a_warning_not_a_crash(self):
        ph = FakePiHole()
        sy = self.syncer(ph, DNS_SOURCE="pihole", PIHOLE_PASSWORD="wrong-sentinel-pw")
        self.assertFalse(sy.sync_once())
        self.assertTrue(any("API failed" in m for m in self.logs))
        self.assertFalse(any("wrong-sentinel-pw" in m for m in self.logs))


class Failures(Base):
    def test_api_failure_keeps_running_warns_once_and_never_logs_credentials(self):
        ag = FakeAdGuard(fail=True)
        sy = self.syncer(ag)
        for _ in range(3):
            self.assertFalse(sy.sync_once())
        warnings = [m for m in self.logs if "WARNING" in m]
        self.assertEqual(len(warnings), 1, self.logs)
        out = "\n".join(self.logs)
        self.assertNotIn(AG_PASS, out)
        self.assertNotIn(base64.b64encode(f"admin:{AG_PASS}".encode()).decode(), out)
        self.assertGreater(sy.next_try, 0)                      # backs off
        sy.http = FakeAdGuard()                                  # the DNS server is back
        self.assertTrue(sy.sync_once())
        self.assertTrue(any("answers again" in m for m in self.logs))

    def test_wrong_adguard_password_message_has_status_only(self):
        sy = self.syncer(FakeAdGuard(), ADGUARD_PASSWORD="not-the-password-sentinel")
        self.assertFalse(sy.sync_once())
        out = "\n".join(self.logs)
        self.assertIn("HTTP 401", out)
        self.assertNotIn("not-the-password-sentinel", out)

    def test_credentials_are_not_written_to_disk(self):
        sy = self.syncer(FakeAdGuard())
        sy.sync_once()
        for name in os.listdir(self.d):
            with open(os.path.join(self.d, name), errors="replace") as f:
                self.assertNotIn(AG_PASS, f.read(), name)

    def test_bad_setting_is_treated_as_off_with_one_warning(self):
        ag = FakeAdGuard()
        sy = self.syncer(ag, DNS_BLOCK_FEED="yes please")
        self.assertTrue(sy.sync_once())
        self.assertTrue(sy.sync_once())
        self.assertEqual(ag.calls, [])
        self.assertEqual(len([m for m in self.logs if "DNS_BLOCK_FEED" in m]), 1)

    def test_empty_feed_registers_nothing(self):
        ag = FakeAdGuard()
        os.remove(self.feed)
        self.assertTrue(self.syncer(ag).sync_once())
        self.assertEqual(ag.calls, [])


class DryRun(Base):
    def test_dry_run_makes_no_api_call_and_reports(self):
        ag = FakeAdGuard()
        self.trust(trusted=["trusted.example.com"])
        with open(os.path.join(self.d, "events.jsonl"), "w") as f:
            f.write(json.dumps({"time": "2099-01-01T00:00:00Z", "rule": "threat_feed", "domain": "evil.example.com"}) + "\n")
        sy = self.syncer(ag, DNS_BLOCK_FEED="dry-run", DNS_BLOCK_ADS="pro")
        self.assertTrue(sy.sync_once())
        self.assertEqual(ag.calls, [])
        self.assertIsNone(sy.server)                             # nothing is even served
        with open(os.path.join(self.d, "dns_block_report.json")) as f:
            rep = json.load(f)
        self.assertEqual((rep["mode_feed"], rep["names"], rep["exceptions"], rep["registered"]), ("dry-run", 4, 1, False))
        self.assertEqual(rep["hits_week"], 1)
        self.assertEqual(rep["sources"], {"URLhaus (malware)": 3, "CERT Polska (phishing)": 2})
        self.assertTrue(os.path.exists(os.path.join(self.d, B.SERVED)))


class Serving(Base):
    def test_list_is_served_over_http_and_only_that_path(self):
        srv = B.Server("127.0.0.1", 0)
        try:
            port = srv.httpd.server_address[1]
            srv.set("||evil.example.com^\n")
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/{B.SERVED}", timeout=5) as r:
                self.assertEqual(r.read(), b"||evil.example.com^\n")
                self.assertTrue(r.headers["Content-Type"].startswith("text/plain"))
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/state.json", timeout=5)
            self.assertEqual(cm.exception.code, 404)
        finally:
            srv.close()


class Upstream(Base):
    class Ups(FakeAdGuard):
        def __init__(self):
            super().__init__()
            self.ups = ["tls://dns.example.net"]

        def request(self, method, url, headers=None, body=None, timeout=30):
            path = url.split("127.0.0.1:3000", 1)[1]
            if path == "/control/dns_info":
                return 200, json.dumps({"upstream_dns": self.ups}).encode()
            if path == "/control/dns_config":
                self.ups = json.loads(body)["upstream_dns"]
                return 200, b"{}"
            return super().request(method, url, headers, body, timeout)

    def test_never_changed_unless_asked_then_restored_on_off(self):
        ag = self.Ups()
        sy = self.syncer(ag)                                      # DNS_PROTECTIVE_UPSTREAM unset: off
        self.assertTrue(sy.apply_upstream())
        self.assertEqual(ag.calls, [])
        sy = self.syncer(ag, DNS_PROTECTIVE_UPSTREAM="quad9")
        self.assertTrue(sy.apply_upstream())
        self.assertEqual(ag.ups, ["https://dns.quad9.net/dns-query"])
        n = len(ag.calls)
        self.assertTrue(self.syncer(ag, DNS_PROTECTIVE_UPSTREAM="quad9").apply_upstream())
        self.assertEqual(len(ag.calls), n)                        # already applied: no call
        self.assertTrue(self.syncer(ag, DNS_PROTECTIVE_UPSTREAM="off").apply_upstream())
        self.assertEqual(ag.ups, ["tls://dns.example.net"])

    def test_off_leaves_a_hand_edited_upstream_alone(self):
        ag = self.Ups()
        self.syncer(ag, DNS_PROTECTIVE_UPSTREAM="cloudflare").apply_upstream()
        ag.ups = ["https://my.example.net/dns-query"]
        self.syncer(ag, DNS_PROTECTIVE_UPSTREAM="off").apply_upstream()
        self.assertEqual(ag.ups, ["https://my.example.net/dns-query"])


class UpstreamFilterSignals(unittest.TestCase):
    """Replies as measured over DoH on 2026-11-07 (see dnsmsg.filtered_by_upstream)."""

    @staticmethod
    def reply(name, rcode=0, answers=(), soa=False, ede=None):
        q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
        extra = b""
        n_ans = len(answers)
        body = q
        for a in answers:
            body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + bytes(a)
        ns = 0
        if soa:
            body += b"\x03com\x00" + struct.pack(">HHIH", 6, 1, 30, 22) + b"\x00\x00" + b"\x00" * 20
            ns = 1
        ar = 0
        if ede is not None:
            opt = struct.pack(">HH", 15, 2) + struct.pack(">H", ede)
            body += b"\x00" + struct.pack(">HHIH", 41, 1232, 0, len(opt)) + opt
            ar = 1
        return struct.pack(">HHHHHH", 1, 0x8180 | rcode, 1, n_ans, ns, ar) + body + extra

    def test_quad9_style_and_cloudflare_style_and_real_answers(self):
        import dnsmsg
        f = dnsmsg.filtered_by_upstream
        quad9 = self.reply("bad.example.com", 3, ede=17)
        self.assertTrue(f(quad9))                                     # EDE alone is enough
        self.assertTrue(f(self.reply("bad.example.com", 3), no_soa_filters=True))   # no SOA, EDE stripped
        self.assertFalse(f(self.reply("bad.example.com", 3)))         # unknown upstream: not assumed
        self.assertFalse(f(self.reply("gone.example.com", 3, soa=True), no_soa_filters=True))   # a real NXDOMAIN
        self.assertTrue(f(self.reply("bad.example.com", 0, answers=[(0, 0, 0, 0)], ede=16)))
        self.assertTrue(f(self.reply("bad.example.com", 0, answers=[(0, 0, 0, 0)])))   # 0.0.0.0 alone
        self.assertFalse(f(self.reply("ok.example.com", 0, answers=[(192, 0, 2, 7)])))
        self.assertFalse(f(b"\x00\x01"))

    def adguard_line(self, host, msg):
        return json.dumps({"IP": "192.168.1.20", "QH": host, "QT": "A", "T": "2026-11-07T10:00:00Z",
                           "Answer": base64.b64encode(msg).decode(), "Result": {}})

    def test_adguard_log_entry_reads_filtered(self):
        import shadow
        line = self.adguard_line("bad.example.com", self.reply("bad.example.com", 3))
        self.assertEqual(shadow.parse_adguard_entry(line)[4], "NXDOMAIN")
        self.assertEqual(shadow.parse_adguard_entry(line, no_soa_filters=True)[4], "FILTERED")
        line = self.adguard_line("bad.example.com", self.reply("bad.example.com", 3, ede=17))
        self.assertEqual(shadow.parse_adguard_entry(line)[4], "FILTERED")

    def test_pihole_reply_of_all_zeros_is_filtered(self):
        import shadow
        self.assertEqual(shadow.pihole_reply("Nov  7 10:00:00 dnsmasq[1]: reply bad.example.com is 0.0.0.0"),
                         ("bad.example.com", "FILTERED"))
        self.assertEqual(shadow.pihole_reply("Nov  7 10:00:00 dnsmasq[1]: reply ok.example.com is 192.0.2.7")[1], "NOERROR")


if __name__ == "__main__":
    unittest.main()
