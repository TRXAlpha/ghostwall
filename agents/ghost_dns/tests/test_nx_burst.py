"""nx_burst: a device failing to resolve many different unregistered domains (a DGA
looking for its server), and every guard that keeps normal NXDOMAINs out of it.

All names are synthetic (example.com-style, or made-up DGA-like words); all addresses are
192.168.1.x LAN or documentation ranges."""
import base64
import json
import os
import socket
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
import detectors as D
import dnsmsg
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from shadow import QueryLogFollower, adguard_rcode, parse_adguard_entry, pihole_reply
from state import GhostState

INFECTED, LAPTOP = "192.168.1.66", "192.168.1.20"
WORDS = ("brother nerve place stone river candle market winter garden silver orange window "
         "father mother pocket travel sudden middle number letter").split()


def dga_names(n, tld="net", seed=0):
    """Dictionary-DGA-like names (suppobox/matsnu style): three words glued together."""
    out = []
    for i in range(n):
        j = i + seed * 1000
        out.append(WORDS[j % 20] + WORDS[(j // 20 + 7) % 20] + WORDS[(j // 400 + 3 + j) % 20] + f".{tld}")
    return list(dict.fromkeys(out))


def qname(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"


def query(name, qtype=1):
    return struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack(">HH", qtype, 1)


def reply(name, rcode=0, soa=None, ip=None, qtype=1):
    """A DNS reply: rcode, an optional A answer and an optional SOA in the authority
    section (what a resolver sends with an NXDOMAIN: the closest zone that exists)."""
    flags = 0x8180 | rcode
    out = struct.pack(">HHHHHH", 0x4242, flags, 1, 1 if ip else 0, 1 if soa is not None else 0, 0)
    out += qname(name) + struct.pack(">HH", qtype, 1)
    if ip:
        out += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
    if soa is not None:
        rdata = qname("ns1." + soa) + qname("hostmaster." + soa) + struct.pack(">IIIII", 1, 2, 3, 4, 5)
        out += qname(soa) + struct.pack(">HHIH", 6, 1, 900, len(rdata)) + rdata
    return out


def nx(name):
    """NXDOMAIN for an unregistered domain: the SOA is the TLD's."""
    return reply(name, 3, soa=name.rsplit(".", 1)[-1])


def adguard_row(ip, name, msg=None, result=None, qtype="A"):
    row = {"T": "2026-11-05T10:00:00.000000000Z", "QH": name, "QT": qtype, "QC": "IN", "CP": "",
           "Result": result or {}, "Elapsed": 21000, "IP": ip, "Upstream": "198.51.100.53:53"}
    if msg is not None:
        row["Answer"] = base64.b64encode(msg).decode()
    return json.dumps(row)


class FakeScorer:
    """Low scores: nothing here may alert for looking random, only for failing."""

    def score_one(self, domain):
        return {"dga": 0.05, "dga_trm": 0.05, "dga_lr": 0.05}


class Base(unittest.TestCase):
    def setUp(self):
        self.build()

    def build(self, **over):
        self.dir = tempfile.mkdtemp()
        cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "s.json"), "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "allowlist_path": None,
            "threat_feed_path": None, "upstream_fallbacks": [], **over})
        self.cfg = cfg
        self.state = GhostState(cfg["state_path"], learning_default=True)
        dm = DeviceMap.from_json([{"name": "laptop", "ip": LAPTOP}, {"name": "tv-box", "ip": INFECTED}])
        self.now = 1000.0
        self.r = Resolver(cfg, self.state, FakeScorer(), Enforcer(NullBackend()), dm, EventLog(cfg["events_path"]))
        self.r.clock = lambda: self.now
        return self.r

    def events(self, rule="nx_burst"):
        p = self.cfg["events_path"]
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [e for e in (json.loads(l) for l in f if l.strip()) if rule is None or e["rule"] == rule]

    def nx_storm(self, ip, names, step=5.0, zone="tld"):
        out = []
        for n in names:
            z = n.rsplit(".", 1)[-1] if zone == "tld" else zone
            out.append(self.r.decide(ip, n, "A", rcode="NXDOMAIN", nx_zone=z))
            self.now += step
        return out


# ---------------------------------------------------------------- rcode parsing
class RcodeParsingTests(unittest.TestCase):
    def test_reply_rcode(self):
        self.assertEqual(dnsmsg.reply_rcode(reply("example.com", 0, ip="192.0.2.1")), "NOERROR")
        self.assertEqual(dnsmsg.reply_rcode(nx("brothernerveplace.net")), "NXDOMAIN")
        self.assertEqual(dnsmsg.reply_rcode(reply("example.com", 2)), "SERVFAIL")
        self.assertIsNone(dnsmsg.reply_rcode(query("example.com")))      # a query, not a reply
        self.assertIsNone(dnsmsg.reply_rcode(b"\x00\x01"))
        self.assertIsNone(dnsmsg.reply_rcode(None))

    def test_negative_zone(self):
        self.assertEqual(dnsmsg.negative_zone(nx("brothernerveplace.net")), "net")
        self.assertEqual(dnsmsg.negative_zone(reply("typo.example.com", 3, soa="example.com")), "example.com")
        self.assertEqual(dnsmsg.negative_zone(reply("x.invalid", 3, soa="")), "")    # root zone
        self.assertIsNone(dnsmsg.negative_zone(reply("x.example.com", 3)))           # no SOA sent
        self.assertIsNone(dnsmsg.negative_zone(nx("brothernerveplace.net")[:-12]))   # cut short
        for junk in (b"", b"\xff" * 11, b"\xff" * 40, os.urandom(64)):
            dnsmsg.negative_zone(junk)   # never raises

    def test_adguard_answer(self):
        e = parse_adguard_entry(adguard_row(INFECTED, "brothernerveplace.net", nx("brothernerveplace.net")))
        self.assertEqual(e, (INFECTED, "brothernerveplace.net", "A", False, "NXDOMAIN", "net"))
        ok = parse_adguard_entry(adguard_row(LAPTOP, "www.example.com", reply("www.example.com", 0, ip="192.0.2.7")))
        self.assertEqual(ok[4:], ("NOERROR", None))

    def test_adguard_missing_or_garbled_answer_is_unknown(self):
        for row in (adguard_row(LAPTOP, "a.example.com"),                                   # no Answer
                    adguard_row(LAPTOP, "a.example.com").replace('"Upstream"', '"Answer":"%%%","Upstream"'),
                    adguard_row(LAPTOP, "a.example.com").replace('"Upstream"', '"Answer":"AAEC","Upstream"'),
                    adguard_row(LAPTOP, "a.example.com", nx("other-name.com"))):            # reply to another name
            self.assertEqual(parse_adguard_entry(row)[3:], (False, None, None), row)

    def test_adguard_blocked_or_rewritten_nxdomain_never_counts(self):
        """AdGuard in "NXDOMAIN" blocking mode answers its own blocks with NXDOMAIN, and a
        `$dnsrewrite=NXDOMAIN` rule does too without IsFiltered."""
        name = "ads.tracker-example.com"
        blocked = adguard_row(LAPTOP, name, nx(name),
                              {"IsFiltered": True, "Reason": 3, "Rules": [{"Text": "||tracker-example.com^"}]})
        self.assertEqual(parse_adguard_entry(blocked)[3:], (True, None, None))
        for reason in (4, 5, 7, 8, 9, 10, 11):
            row = adguard_row(LAPTOP, name, nx(name), {"Reason": reason})
            self.assertEqual(parse_adguard_entry(row)[4:], (None, None), reason)
        allowed_by_rule = adguard_row(LAPTOP, name, nx(name), {"Reason": 1, "Rules": [{"Text": "@@||x^"}]})
        self.assertEqual(parse_adguard_entry(allowed_by_rule)[4], "NXDOMAIN")
        self.assertEqual(adguard_rcode({"Answer": base64.b64encode(nx(name)).decode()}, name, True), (None, None))

    def test_pihole_reply_lines(self):
        cases = {
            "Nov  5 10:00:01 dnsmasq[812]: reply brothernerveplace.net is NXDOMAIN": ("brothernerveplace.net", "NXDOMAIN"),
            "Nov  5 10:00:01 dnsmasq[812]: cached brothernerveplace.net is NXDOMAIN": ("brothernerveplace.net", "NXDOMAIN"),
            "Nov  5 10:00:01 dnsmasq[812]: 77 192.168.1.66/40312 reply Brothernerveplace.NET is NXDOMAIN":
                ("brothernerveplace.net", "NXDOMAIN"),
            "Nov  5 10:00:01 dnsmasq[812]: reply www.example.com is 192.0.2.7": ("www.example.com", "NOERROR"),
            "Nov  5 10:00:01 dnsmasq[812]: reply www.example.com is 2001:db8::7": ("www.example.com", "NOERROR"),
            "Nov  5 10:00:01 dnsmasq[812]: reply www.example.com is <CNAME>": ("www.example.com", "NOERROR"),
            "Nov  5 10:00:01 dnsmasq[812]: reply www.example.com is NODATA-IPv6": ("www.example.com", "NOERROR"),
        }
        for line, want in cases.items():
            self.assertEqual(pihole_reply(line), want, line)
        for line in ("Nov  5 10:00:01 dnsmasq[812]: config nas.lan is NXDOMAIN",
                     "Nov  5 10:00:01 dnsmasq[812]: gravity blocked ads.example.com is NXDOMAIN",
                     "Nov  5 10:00:01 dnsmasq[812]: regex blacklisted x.example.com is NXDOMAIN",
                     "Nov  5 10:00:01 dnsmasq[812]: /etc/hosts nas.example.com is 192.168.1.5",
                     "Nov  5 10:00:01 dnsmasq[812]: query[A] example.com from 192.168.1.20",
                     "Nov  5 10:00:01 dnsmasq[812]: forwarded example.com to 198.51.100.53"):
            self.assertIsNone(pihole_reply(line), line)


# ---------------------------------------------------------------- the detector
class NxBurstUnitTests(unittest.TestCase):
    def test_threshold(self):
        nb = D.NxBurst(min_distinct=10)
        names = dga_names(10)
        self.assertEqual([nb.observe("pc", n, 100.0 + i) for i, n in enumerate(names[:9])], [None] * 9)
        hit = nb.observe("pc", names[9], 110.0)
        self.assertEqual((hit.rule, hit.severity), ("nx_burst", "high"))
        self.assertIn("10 different unregistered domains", hit.reasons[0])
        self.assertTrue(hit.reasons[1].startswith("e.g. ") and names[9] in hit.reasons[1])

    def test_counts_registrable_domains_not_names(self):
        nb = D.NxBurst(min_distinct=3)
        self.assertIsNone(nb.observe("pc", "stoneriver.com", 1))
        self.assertIsNone(nb.observe("pc", "www.stoneriver.com", 2))
        self.assertIsNone(nb.observe("pc", "stoneriver.com", 3))
        self.assertIsNone(nb.observe("pc", "candlemarket.com", 4))
        self.assertIsNotNone(nb.observe("pc", "wintergarden.com", 5))

    def test_window(self):
        nb = D.NxBurst(min_distinct=10, window=600)
        self.assertTrue(all(nb.observe("pc", n, i * 70.0) is None for i, n in enumerate(dga_names(20))))

    def test_per_device(self):
        nb = D.NxBurst(min_distinct=10)
        names = dga_names(10)
        for i, n in enumerate(names[:5]):
            nb.observe("a", n, i)
        self.assertTrue(all(nb.observe("b", n, 10 + i) is None for i, n in enumerate(names[5:])))

    def test_cooldown_then_alerts_again_on_new_names(self):
        nb = D.NxBurst(min_distinct=10, cooldown=1800)
        first, second, third = dga_names(10, seed=1), dga_names(10, seed=2), dga_names(10, seed=3)
        self.assertIsNotNone([nb.observe("pc", n, i) for i, n in enumerate(first)][-1])
        self.assertEqual([nb.observe("pc", n, 100 + i) for i, n in enumerate(second)], [None] * 10)
        self.assertIsNotNone([nb.observe("pc", n, 2000 + i) for i, n in enumerate(third)][-1])

    def test_same_dead_domains_alert_once(self):
        """An old device stuck on the same few dead update servers is not a new finding
        every half hour: names already in an alert are not counted again."""
        nb = D.NxBurst(min_distinct=10, cooldown=1800)
        names = dga_names(10)
        self.assertIsNotNone([nb.observe("pc", n, i) for i, n in enumerate(names)][-1])
        for day in range(1, 5):
            self.assertEqual([nb.observe("pc", n, day * 86400 + i) for i, n in enumerate(names)], [None] * 10)

    def test_memory_is_bounded(self):
        nb = D.NxBurst(min_distinct=10 ** 6, max_per_device=64)
        for i in range(500):
            nb.observe("pc", f"n{i}x.com", float(i) / 10)
            nb.observe(f"dev{i}", "stoneriver.com", float(i))
        self.assertLessEqual(len(nb._q["pc"]), 64)
        nb2 = D.NxBurst()
        for i in range(6000):
            nb2.observe(f"dev{i}", "stoneriver.com", float(i * 1000))
        self.assertLessEqual(len(nb2._q), 5001)


# ---------------------------------------------------------------- name guards
class CountableNameTests(unittest.TestCase):
    def test_registrable_names_count(self):
        for h in ("brothernerveplace.net", "www.brothernerveplace.net", "qx7kz2vbn.com", "kj3h2.co.uk",
                  "a8f7d6.ru", "z9x8.top", "mortiscontrastatim.com", "kf83hd.ddns.net", "x7y8.pw", "q1w2.website"):
            self.assertTrue(D.nx_countable(h), h)

    def test_subdomains_never_count(self):
        """Typos and probes under a real domain, dead tracker hosts, search suffixes
        appended to a random label (Chrome): none says the parent is unregistered."""
        for h in ("mial.example.com", "tracker.deadsite-example.com", "qwhxkzpsdm.corp-example.com",
                  "a.b.brothernerveplace.net", "api.www.brothernerveplace.net"):
            self.assertFalse(D.nx_countable(h), h)

    def test_local_and_special_names_never_count(self):
        for h in ("printer", "qwhxkzpsdm", "tv", "pc", "_sip.com", "speedport.ip", "nas.lan", "nas.local", "nas.home.arpa", "tv.home", "x.fritz.box",
                  "qwhxkzpsdm.fritz.box", "pc.corp", "foo.localdomain", "printer.internal", "nas.router",
                  "x.speedport.ip", "4.3.2.1.in-addr.arpa", "1.0.0.0.ip6.arpa", "_ldap._tcp.example.com",
                  "_dns.resolver.arpa", "wpad.co.uk", "wpad.com", "isatap.net", "x.onion", "a.test"):
            self.assertFalse(D.nx_countable(h), h)

    def test_unknown_suffix_never_counts(self):
        for h in ("server.mycompany", "nas.homenet", "box.workgroup", "x.notatld"):
            self.assertFalse(D.nx_countable(h), h)


# ---------------------------------------------------------------- wiring + FP guards
class DecideTests(Base):
    def test_storm_alerts_once_with_examples(self):
        decisions = self.nx_storm(INFECTED, dga_names(30))
        self.assertEqual(sum(d.reason == "nx_burst" for d in decisions), 1)
        evs = self.events()
        self.assertEqual(len(evs), 1)
        e = evs[0]
        self.assertEqual((e["device"], e["action"], e["severity"]), ("tv-box", "recommend", "high"))
        text = " ".join(e["reasons"])
        self.assertIn("10 different unregistered domains", text)
        self.assertIn("within 1 min", text)
        self.assertIn("e.g. ", text)
        self.assertIn("isolate", text)
        self.assertNotIn("—", text)
        self.assertNotIn("trust", e)

    def test_unknown_rcode_counts_nothing(self):
        for n in dga_names(30):
            self.r.decide(INFECTED, n, "A")
        self.assertEqual(self.events(), [])

    def test_can_be_turned_off(self):
        self.build(nx_burst_enabled=False)
        self.nx_storm(INFECTED, dga_names(30))
        self.assertEqual(self.events(), [])

    def test_thresholds_from_config(self):
        self.build(nx_burst_min_distinct=4, nx_burst_window=60)
        self.nx_storm(INFECTED, dga_names(3), step=1)
        self.assertEqual(self.events(), [])
        self.now += 1000
        self.nx_storm(INFECTED, dga_names(4, seed=5), step=30)   # 4 within 90 s > 60 s window
        self.assertEqual(self.events(), [])
        self.now += 1000
        self.nx_storm(INFECTED, dga_names(4, seed=6), step=1)
        self.assertEqual(len(self.events()), 1)

    def test_shipped_defaults(self):
        cfg = config_mod.load_config(None)
        self.assertEqual((cfg["nx_burst_enabled"], cfg["nx_burst_min_distinct"], cfg["nx_burst_window"]),
                         (True, 10, 600))

    def test_guard_domain_that_resolved_before(self):
        """www.<shop> and <shop> NXDOMAIN after something in <shop> resolved: a site
        without that name, or a domain that lapsed. Not a DGA."""
        shops = [f"{w}shop.com" for w in WORDS[:12]]
        for s in shops:
            self.r.decide(INFECTED, "api." + s, "A", rcode="NOERROR")
        self.nx_storm(INFECTED, ["www." + s for s in shops], zone=None)   # Pi-hole: no SOA to tell
        self.assertEqual(self.events(), [])
        self.nx_storm(INFECTED, dga_names(12))                            # control: same device still alerts
        self.assertEqual(len(self.events()), 1)

    def test_guard_resolved_before_survives_a_restart(self):
        shops = [f"{w}shop.com" for w in WORDS[:12]]
        for s in shops:
            self.r.decide(INFECTED, "api." + s, "A", rcode="NOERROR")
        self.state.save()
        self.state = GhostState(self.cfg["state_path"])
        self.r.state = self.state
        self.nx_storm(INFECTED, ["www." + s for s in shops], zone=None)
        self.assertEqual(self.events(), [])
        with open(self.cfg["state_path"], encoding="utf-8") as f:
            self.assertNotIn("shop.com", f.read())   # hashed, like first_seen

    def test_guard_soa_inside_the_domain(self):
        """An NXDOMAIN whose SOA is the domain itself: the domain exists, only the name is
        missing. Counts nothing, and teaches that the domain is registered."""
        shops = [f"{w}shop.com" for w in WORDS[:12]]
        for s in shops:
            self.r.decide(INFECTED, "www." + s, "A", rcode="NXDOMAIN", nx_zone=s)
            self.now += 5
        self.assertEqual(self.events(), [])
        self.assertTrue(self.state.has_resolved(shops[0]))

    def test_guard_subdomains_of_unregistered_domains(self):
        """Dead tracker hosts (tracker.<gone>.com) from a torrent client: the domain is
        gone, but the name was never generated by a DGA."""
        self.nx_storm(INFECTED, [f"tracker.{w}gone.com" for w in WORDS[:15]])
        self.assertEqual(self.events(), [])

    def test_guard_search_domain_and_chrome_probes(self):
        names = ([f"{w}.home" for w in WORDS[:6]] + [f"{w}.fritz.box" for w in WORDS[:6]]
                 + [f"{w}.corp" for w in WORDS[6:12]] + [f"{w}lkjq" for w in WORDS[:6]]
                 + [f"{w}lkjq.corp-example.com" for w in WORDS[:6]])
        self.nx_storm(INFECTED, names, zone="")
        self.assertEqual(self.events(), [])

    def test_guard_internal_reverse_service_wpad(self):
        names = ([f"{i}.1.168.192.in-addr.arpa" for i in range(12)] + [f"_svc{i}._tcp.example.com" for i in range(12)]
                 + [f"nas{i}.lan" for i in range(12)] + [f"cam{i}.home.arpa" for i in range(12)]
                 + ["wpad.co.uk", "wpad.com", "wpad.net", "wpad.org", "wpad.de", "wpad.fr", "wpad.nl", "wpad.it",
                    "wpad.es", "wpad.eu", "wpad.info"])
        self.nx_storm(INFECTED, names, zone="")
        self.assertEqual(self.events(), [])

    def test_guard_not_a_real_tld(self):
        self.nx_storm(INFECTED, [f"{w}.localdomain" for w in WORDS[:6]] + [f"{w}.internal" for w in WORDS[:6]]
                      + [f"{w}.mycompany" for w in WORDS[:6]], zone="")
        self.assertEqual(self.events(), [])

    def test_guard_allowlisted_and_trusted(self):
        names = dga_names(12)
        for n in names[:6]:
            self.state.allow(n)                      # Trust on the name
        for n in names[6:]:
            self.state.allow(n)
        self.nx_storm(INFECTED, ["www." + n for n in names[6:]] + names[:6])   # parent trust covers www.
        self.assertEqual(self.events(), [])

    def test_guard_blocked_upstream(self):
        for n in dga_names(30):
            self.r.decide(INFECTED, n, "A", upstream_blocked=True, rcode="NXDOMAIN", nx_zone="net")
        self.assertEqual(self.events(), [])

    def test_servfail_and_refused_count_nothing(self):
        for i, n in enumerate(dga_names(30)):
            self.r.decide(INFECTED, n, "A", rcode="SERVFAIL" if i % 2 else "REFUSED")
        self.assertEqual(self.events(), [])

    def test_normal_device_with_a_handful_of_nxdomains_is_quiet(self):
        r = self.r
        for s in ("example.com", "example.net", "example.org", "brightlamp.com", "stonebridge.org"):
            r.decide(LAPTOP, "www." + s, "A", rcode="NOERROR")
        noise = [("examplle.com", "com"), ("exmaple.org", "org"),                  # typos of real sites
                 ("wwww.example.com", "example.com"), ("mial.example.net", "example.net"),
                 ("telemetry-probe.example.org", "example.org"),                   # NX probe under a real domain
                 ("www.brightlamp.com", None), ("stonebridge.org", None),          # resolved before, no SOA
                 ("qwhxkzpsdm", ""), ("hzjqwkeolp", ""), ("qwhxkzpsdm.fritz.box", "box"),   # Chrome probes
                 ("wpad.lan", ""), ("nas.home", ""), ("printer.localdomain", ""), ("_ipp._tcp.lan", ""),
                 ("7.1.168.192.in-addr.arpa", "in-addr.arpa"), ("tracker.gonesite.com", "com")]
        for name, zone in noise * 3:
            r.decide(LAPTOP, name, "A", rcode="NXDOMAIN", nx_zone=zone)
            self.now += 2
        self.assertEqual(self.events(), [])


class InlineTests(Base):
    """handle_packet reads the upstream's rcode (no sockets: _forward is stubbed)."""

    def serve(self, ip, names, rcode_for):
        self.r._forward = lambda packet, tcp=False: rcode_for(dnsmsg.parse_question(packet).name)
        for n in names:
            self.r.handle_packet(ip, query(n))
            self.now += 3
        self.r.drain()

    def test_learning_scores_after_the_answer_with_its_rcode(self):
        self.serve(INFECTED, dga_names(15), nx)
        self.assertEqual(len(self.events()), 1)

    def test_blocking_mode_feeds_the_answer_after_deciding(self):
        self.state.set_learning(False)
        self.serve(INFECTED, dga_names(15), nx)
        self.assertEqual(len(self.events()), 1)

    def test_noerror_answers_teach_registered_domains(self):
        self.serve(LAPTOP, ["api.stoneriver.com"], lambda n: reply(n, 0, ip="192.0.2.9"))
        self.assertTrue(self.state.has_resolved("www.stoneriver.com"))

    def test_blocking_mode_skips_allowlisted_and_internal(self):
        self.state.set_learning(False)
        names = dga_names(12)
        for n in names:
            self.state.allow(n)
        self.serve(INFECTED, names + [f"nas{i}.lan" for i in range(12)], nx)
        self.assertEqual(self.events(), [])

    def test_upstream_down_still_scores(self):
        self.serve(INFECTED, dga_names(15), lambda n: None)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.r.stats["errors"], 15)


class ShadowEndToEndTests(Base):
    def follow(self, fmt, text):
        self.build(shadow=True)
        log = os.path.join(self.dir, "querylog.json" if fmt == "adguard" else "pihole.log")
        open(log, "w").close()
        f = QueryLogFollower(self.r, log, fmt=fmt)
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(text)
        f.poll_once()

    def test_adguard_dga_storm_alerts_once_normal_device_stays_quiet(self):
        rows = []
        # the laptop: normal browsing, then a handful of everyday NXDOMAINs
        for s in ("example.com", "example.net", "example.org", "brightlamp.com"):
            rows.append(adguard_row(LAPTOP, "www." + s, reply("www." + s, 0, ip="192.0.2.10")))
        everyday = [("examplle.com", nx("examplle.com")),
                    ("mial.example.net", reply("mial.example.net", 3, soa="example.net")),
                    ("telemetry-probe.example.org", reply("telemetry-probe.example.org", 3, soa="example.org")),
                    ("cdn.brightlamp.com", reply("cdn.brightlamp.com", 3)),          # no SOA, resolved before
                    ("qwhxkzpsdm", reply("qwhxkzpsdm", 3, soa="")),                   # Chrome probe
                    ("hzjqwkeolp.fritz.box", reply("hzjqwkeolp.fritz.box", 3)),       # Chrome probe + suffix
                    ("wpad.lan", reply("wpad.lan", 3)), ("nas.home", reply("nas.home", 3)),
                    ("7.1.168.192.in-addr.arpa", reply("7.1.168.192.in-addr.arpa", 3, soa="168.192.in-addr.arpa")),
                    ("tracker.gonesite.com", nx("tracker.gonesite.com"))]
        for name, msg in everyday * 2:
            rows.append(adguard_row(LAPTOP, name, msg))
        # AdGuard blocking in NXDOMAIN mode: 20 different ad domains, all IsFiltered
        for w in WORDS:
            n = f"{w}-ads.com"
            rows.append(adguard_row(LAPTOP, n, nx(n), {"IsFiltered": True, "Reason": 3,
                                                       "Rules": [{"Text": f"||{n}^"}]}))
        # the infected box: 40 dictionary-DGA names, all NXDOMAIN
        for n in dga_names(40):
            rows.append(adguard_row(INFECTED, n, nx(n)))
            rows.append(adguard_row(INFECTED, n, nx(n), qtype="AAAA"))
        self.follow("adguard", "\n".join(rows) + "\n")
        evs = self.events()
        self.assertEqual(len(evs), 1, evs)
        self.assertEqual(evs[0]["device"], "tv-box")
        self.assertEqual(self.events(None), evs)   # nothing else alerted either

    def test_pihole_dga_storm_alerts_once_normal_device_stays_quiet(self):
        lines = []
        t = "Nov  5 10:00:{:02d} dnsmasq[812]: "
        for s in ("example.com", "brightlamp.com"):
            lines += [t.format(0) + f"query[A] www.{s} from {LAPTOP}",
                      t.format(0) + f"forwarded www.{s} to 198.51.100.53",
                      t.format(0) + f"reply www.{s} is 192.0.2.10"]
        for name, kind in (("examplle.com", "reply"), ("cdn.brightlamp.com", "reply"), ("nas.lan", "config"),
                           ("qwhxkzpsdm", "config"), ("tracker.gonesite.com", "reply"), ("www.brightlamp.com", "cached")):
            lines += [t.format(1) + f"query[A] {name} from {LAPTOP}", t.format(1) + f"{kind} {name} is NXDOMAIN"]
        for w in WORDS:   # Pi-hole blocks: never NXDOMAIN evidence
            lines += [t.format(2) + f"query[A] {w}-ads.com from {LAPTOP}",
                      t.format(2) + f"gravity blocked {w}-ads.com is NXDOMAIN"]
        for i, n in enumerate(dga_names(40)):
            lines += [t.format(3 + i) + f"query[A] {n} from {INFECTED}",
                      t.format(3 + i) + f"forwarded {n} to 198.51.100.53",
                      t.format(3 + i) + f"query[AAAA] example.com from {LAPTOP}",   # interleaved traffic
                      t.format(3 + i) + f"reply {n} is NXDOMAIN"]
        self.follow("pihole", "\n".join(lines) + "\n")
        evs = self.events()
        self.assertEqual(len(evs), 1, evs)
        self.assertEqual(evs[0]["device"], "tv-box")

    def test_pihole_blocked_query_with_nxdomain_reply_does_not_count(self):
        lines = []
        for w in WORDS:
            n = f"{w}stone.com"
            lines += [f"Nov  5 10:00:00 dnsmasq[812]: query[A] {n} from {INFECTED}",
                      f"Nov  5 10:00:00 dnsmasq[812]: regex blacklisted {n} is NXDOMAIN",
                      f"Nov  5 10:00:00 dnsmasq[812]: reply {n} is NXDOMAIN"]
        self.follow("pihole", "\n".join(lines) + "\n")
        self.assertEqual(self.events(), [])

    def test_follower_passes_no_rcode_for_a_blocked_query(self):
        class Rec:
            stats = {"queries": 0}
            calls = []

            def decide(self, ip, host, qtype, upstream_blocked=False, **kw):
                self.calls.append((host, upstream_blocked, kw))

        d = tempfile.mkdtemp()
        log = os.path.join(d, "pihole.log")
        open(log, "w").close()
        rec = Rec()
        f = QueryLogFollower(rec, log, fmt="pihole")
        with open(log, "a") as fh:
            fh.write(f"Nov  5 10:00:00 dnsmasq[812]: query[A] stoneriver.com from {INFECTED}\n"
                     "Nov  5 10:00:00 dnsmasq[812]: gravity blocked stoneriver.com is NXDOMAIN\n"
                     "Nov  5 10:00:00 dnsmasq[812]: reply stoneriver.com is NXDOMAIN\n"
                     f"Nov  5 10:00:01 dnsmasq[812]: query[A] candleriver.com from {INFECTED}\n"
                     "Nov  5 10:00:01 dnsmasq[812]: reply candleriver.com is NXDOMAIN\n"
                     f"Nov  5 10:00:02 dnsmasq[812]: query[A] example.com from {INFECTED}\n")
        f.poll_once()
        self.assertEqual(rec.calls, [("stoneriver.com", True, {}),
                                     ("candleriver.com", False, {"rcode": "NXDOMAIN", "nx_zone": None}),
                                     ("example.com", False, {})])


if __name__ == "__main__":
    unittest.main()
