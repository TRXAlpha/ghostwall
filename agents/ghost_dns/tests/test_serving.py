"""Real-socket tests: UDP+TCP+IPv6 serving, upstream failover, fail-open, dedupe, shadow mode."""
import contextlib
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
import dnsmsg
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from shadow import QueryLogFollower, parse_line
from state import GhostState

ANSWER_IP = "1.2.3.4"


def build_query(name, qtype=1):
    h = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return h + q + struct.pack(">HH", qtype, 1)


def make_reply(pkt):
    q = dnsmsg.parse_question(pkt)
    h = pkt[:2] + struct.pack(">H", 0x8180) + struct.pack(">HHHH", 1, 1, 0, 0)
    return h + pkt[12:q.end] + struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ANSWER_IP)


def free_port():
    """A port free for both UDP and TCP on loopback. Tries many random high ports
    (the OS dynamic pick can collide with excluded/reserved ranges on Windows)."""
    import random
    for _ in range(400):
        port = random.randint(20000, 59999)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("127.0.0.1", port))
            u.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            s.close()
            u.close()
    raise RuntimeError("no free port")


class FakeUpstream:
    """UDP + TCP DNS server answering every A query with ANSWER_IP."""

    def __init__(self, port):
        self.port = port
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", port))
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", port))
        self.tcp.listen(8)
        self.tcp_hits = 0
        threading.Thread(target=self._udp, daemon=True).start()
        threading.Thread(target=self._tcp, daemon=True).start()

    def _udp(self):
        while True:
            try:
                pkt, addr = self.udp.recvfrom(4096)
            except OSError:
                return
            self.udp.sendto(make_reply(pkt), addr)

    def _tcp(self):
        while True:
            try:
                c, _ = self.tcp.accept()
            except OSError:
                return
            self.tcp_hits += 1
            try:
                n = struct.unpack(">H", c.recv(2))[0]
                pkt = c.recv(n)
                r = make_reply(pkt)
                c.sendall(struct.pack(">H", len(r)) + r)
            finally:
                c.close()

    def close(self):
        self.udp.close()
        self.tcp.close()


def udp_ask(port, name, host="127.0.0.1", family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(build_query(name), (host, port))
    r = s.recvfrom(4096)[0]
    s.close()
    return struct.unpack(">H", r[2:4])[0] & 0xF, struct.unpack(">H", r[6:8])[0]


def tcp_ask(port, name, host="127.0.0.1", family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    q = build_query(name)
    s.sendall(struct.pack(">H", len(q)) + q)
    n = struct.unpack(">H", s.recv(2))[0]
    r = b""
    while len(r) < n:
        r += s.recv(n - len(r))
    s.close()
    return struct.unpack(">H", r[2:4])[0] & 0xF, struct.unpack(">H", r[6:8])[0]


class FakeScorer:
    def __init__(self, dga=0.0):
        self.dga = dga

    def score_one(self, domain):
        return {"dga": self.dga, "dga_trm": self.dga, "dga_lr": self.dga}


def have_ipv6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


class Base(unittest.TestCase):
    def build(self, upstream_port, dns_port, **over):
        self.dir = tempfile.mkdtemp()
        cfg = config_mod.load_config(None, {
            "dns_host": "127.0.0.1", "dns_port": dns_port,
            "dns_host6": "::1" if have_ipv6() else None,
            "upstream": "127.0.0.1", "upstream_port": upstream_port,
            "upstream_fallbacks": [], "dns_timeout": 1.0,
            "state_path": os.path.join(self.dir, "s.json"),
            "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": os.path.join(self.dir, "q.log"),
            "resolved_ips_path": os.path.join(self.dir, "r.jsonl"),
            "allowlist_path": os.path.join(self.dir, "none.txt"),
            "recommend_threshold": 0.60, "block_threshold": 0.90, "threat_feed_path": None,
            **over,
        })
        self.cfg = cfg
        self.state = GhostState(cfg["state_path"], learning_default=True)
        self.events = EventLog(cfg["events_path"])
        dm = DeviceMap.from_json([{"name": "dell", "ip": "127.0.0.1"}])
        self.r = Resolver(cfg, self.state, FakeScorer(), Enforcer(NullBackend()), dm, self.events)
        return self.r

    def read_events(self):
        p = self.cfg["events_path"]
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]


class ServingTests(Base):
    def setUp(self):
        self.up_port, self.dns_port = free_port(), free_port()
        self.up = FakeUpstream(self.up_port)
        self.build(self.up_port, self.dns_port)
        self.r.start()

    def tearDown(self):
        self.r.stop()
        self.up.close()

    def test_udp_v4(self):
        self.assertEqual(udp_ask(self.dns_port, "example.com"), (0, 1))

    def test_tcp_v4(self):
        self.assertEqual(tcp_ask(self.dns_port, "example.com"), (0, 1))
        self.assertGreaterEqual(self.up.tcp_hits, 1, "TCP query must be forwarded over TCP")

    @unittest.skipUnless(have_ipv6(), "no IPv6 on this host")
    def test_udp_v6(self):
        self.assertIn("udp6", self.r.listening)
        self.assertEqual(udp_ask(self.dns_port, "example.com", "::1", socket.AF_INET6), (0, 1))

    @unittest.skipUnless(have_ipv6(), "no IPv6 on this host")
    def test_tcp_v6(self):
        self.assertIn("tcp6", self.r.listening)
        self.assertEqual(tcp_ask(self.dns_port, "example.com", "::1", socket.AF_INET6), (0, 1))

    def test_listeners_report(self):
        self.assertIn("udp4", self.r.listening)
        self.assertIn("tcp4", self.r.listening)


class FailoverTests(Base):
    def test_fallback_when_primary_dead(self):
        dead = free_port()                      # nothing listens here
        fb_port = free_port()
        fb = FakeUpstream(fb_port)
        self.addCleanup(fb.close)
        self.build(dead, free_port(), upstream_fallbacks=[f"127.0.0.1:{fb_port}"])
        pkt = build_query("example.com")
        t0 = time.time()
        reply = self.r.handle_packet("127.0.0.1", pkt)
        self.assertEqual(struct.unpack(">H", reply[6:8])[0], 1)
        self.assertEqual(self.r.stats["fallbacks"], 1)
        # second query skips the dead primary instead of waiting out another timeout
        t1 = time.time()
        self.r.handle_packet("127.0.0.1", build_query("example.org"))
        self.assertLess(time.time() - t1, 0.5)
        self.assertGreater(time.time() - t0, 0)

    def test_servfail_when_everything_dead(self):
        self.build(free_port(), free_port())
        reply = self.r.handle_packet("127.0.0.1", build_query("example.com"))
        self.assertEqual(struct.unpack(">H", reply[2:4])[0] & 0xF, 2)  # SERVFAIL

    def test_fail_open_when_scoring_explodes(self):
        up = FakeUpstream(free_port())
        self.addCleanup(up.close)
        self.build(up.port, free_port())

        def boom(*a, **k):
            raise RuntimeError("model crashed")

        self.r.scorer.score_one = boom
        reply = self.r.handle_packet("127.0.0.1", build_query("example.com"))
        self.assertEqual(struct.unpack(">H", reply[6:8])[0], 1, "must still resolve")
        self.assertEqual(self.r.stats["failopen"], 1)


class DedupeTests(Base):
    def test_same_domain_family_alerts_once(self):
        self.build(free_port(), free_port())
        self.r.scorer = FakeScorer(0.7)             # suspicious, below block threshold
        for host in ("a.cdn.example", "b.cdn.example", "cdn.example"):
            self.r.decide("127.0.0.1", host, "A")
        self.assertEqual(len(self.read_events()), 1)
        self.assertEqual(self.r.stats["suppressed"], 2)

    def test_different_device_alerts_separately(self):
        self.build(free_port(), free_port())
        self.r.devices = DeviceMap.from_json([{"name": "dell", "ip": "10.0.0.1"},
                                              {"name": "phone", "ip": "10.0.0.2"}])
        self.r.scorer = FakeScorer(0.7)
        self.r.decide("10.0.0.1", "cdn.example", "A")
        self.r.decide("10.0.0.2", "cdn.example", "A")
        self.assertEqual(len(self.read_events()), 2)

    def test_blocks_never_suppressed(self):
        self.build(free_port(), free_port())
        self.state.add_block("bad.example")
        self.r.decide("127.0.0.1", "bad.example", "A")
        self.r.decide("127.0.0.1", "bad.example", "A")
        self.assertEqual(len(self.read_events()), 2)


class ShadowTests(Base):
    def setUp(self):
        self.build(free_port(), free_port(), shadow=True)
        self.log = os.path.join(self.dir, "querylog.json")
        open(self.log, "w").close()

    def _write(self, *rows, raw=""):
        with open(self.log, "a", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
            f.write(raw)

    def test_parse_line(self):
        self.assertEqual(parse_line(json.dumps({"IP": "1.2.3.4", "QH": "Example.COM.", "QT": "AAAA"})),
                         ("1.2.3.4", "example.com", "AAAA"))
        self.assertIsNone(parse_line("garbage"))
        self.assertIsNone(parse_line(json.dumps({"IP": "1.2.3.4"})))

    def test_scores_new_lines_only(self):
        self._write({"IP": "127.0.0.1", "QH": "old.example", "QT": "A"})   # before start: ignored
        self.r.scorer = FakeScorer(0.7)
        f = QueryLogFollower(self.r, self.log)
        self._write({"IP": "127.0.0.1", "QH": "new.example", "QT": "A"})
        self.assertEqual(f.poll_once(), 1)
        self.assertEqual([e["domain"] for e in self.read_events()], ["new.example"])

    def test_shadow_never_blocks_even_with_learning_off(self):
        self.state.set_learning(False)
        self.r.scorer = FakeScorer(0.99)
        f = QueryLogFollower(self.r, self.log)
        self._write({"IP": "127.0.0.1", "QH": "kjwqehdzxklqw.biz", "QT": "A"})
        f.poll_once()
        evs = self.read_events()
        self.assertEqual(evs[0]["action"], "recommend")
        self.assertFalse(self.state.is_blocked("kjwqehdzxklqw.biz"))
        self.assertIn("shadow mode", " ".join(evs[0]["reasons"]))

    def test_partial_line_and_rotation(self):
        self.r.scorer = FakeScorer(0.7)
        f = QueryLogFollower(self.r, self.log)
        full = json.dumps({"IP": "127.0.0.1", "QH": "p.example", "QT": "A"})
        self._write(raw=full[:15])
        self.assertEqual(f.poll_once(), 0)
        self._write(raw=full[15:] + "\n")
        self.assertEqual(f.poll_once(), 1)
        open(self.log, "w").close()                       # rotated
        self._write({"IP": "127.0.0.1", "QH": "q.example", "QT": "A"})
        self.assertEqual(f.poll_once(), 1)

    def test_missing_log_warns_once(self):
        f = QueryLogFollower(self.r, os.path.join(self.dir, "absent.json"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(f.poll_once(), 0)
            self.assertEqual(f.poll_once(), 0)
        self.assertTrue(f.missing)
        self.assertEqual(err.getvalue().count("querylog not found"), 1)


if __name__ == "__main__":
    unittest.main()
