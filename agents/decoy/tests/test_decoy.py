"""Tests for ghost-decoy: config refusal, touch rules, guards, and real sockets.

The service tests bind 127.0.0.1 on ephemeral ports (port 0). Loopback is not a
LAN peer in production, so those tests inject an is_lan check that accepts it.
"""
import asyncio
import io
import json
import os
import random
import socket
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # agents/decoy
sys.path.insert(0, HERE)
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(HERE)), "agents", "fw_bot"))

import decoy as D                      # noqa: E402
from devices import DeviceMap          # noqa: E402
from events import EventLog            # noqa: E402
import validate_events as V            # noqa: E402

EXAMPLE = os.path.join(HERE, "decoy.example.json")
LOCAL_NAME = "office-pc-example"


def on_settings(**kw):
    """Settings for a test: decoy on, loopback bind, short timers, no stats ticks."""
    raw = {"decoy": "on", "bind": "127.0.0.1", "ports": [23], "stats_seconds": 0,
           "listen_seconds": 1, "dedupe_seconds": 3600, "max_events_per_device_hour": 6,
           "events_path": "/unused/events.jsonl", "devices_json": "/unused/devices.json"}
    settings = D.parse_config(raw)
    return replace(settings, **kw)


def wait_until(fn, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.02)
    return bool(fn())


class Running:
    """A Decoy on its own event loop thread, so the test thread can use blocking sockets."""

    def __init__(self, settings, devices, log, ports=(0,), **kw):
        self.decoy = D.Decoy(settings, devices, log, ports=ports, **kw)
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.ports = ()

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)

    def __enter__(self):
        self.thread.start()
        self._run(self.decoy.start())
        self.ports = tuple(self.decoy.actual_ports)
        return self

    def __exit__(self, *exc):
        self._run(self.decoy.stop())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


def touch(port, data=b"", hold=0.0):
    """Connect to a decoy, optionally send bytes, optionally hold open, then close."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        if data:
            s.sendall(data)
        if hold:
            time.sleep(hold)
    finally:
        s.close()


def read_events(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "events.jsonl")
        self.log = EventLog(self.path)
        self.devices = DeviceMap.from_json([{"name": LOCAL_NAME, "ip": "127.0.0.1"}])
        self.settings = on_settings()

    def running(self, settings=None, ports=(0,), **kw):
        # loopback is not a LAN peer in production, so tests treat it as one
        kw.setdefault("is_lan", lambda ip: ip == "127.0.0.1")
        return Running(settings or self.settings, self.devices, self.log, ports=ports, **kw)

    def test_data_gives_one_event(self):
        with self.running() as r:
            touch(r.ports[0], b"hello\r\n")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("events", 0) == 1))
        events = read_events(self.path)
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e["rule"], "decoy_touch")
        self.assertEqual(e["severity"], "high")
        self.assertEqual(e["action"], "recommend")
        self.assertEqual(e["device"], LOCAL_NAME)
        self.assertEqual(e["ip"], "127.0.0.1")
        self.assertTrue(e["domain"].startswith("decoy-port-"))
        self.assertEqual(V.validate_event(e), [])

    def test_connect_and_close_gives_no_event(self):
        with self.running() as r:
            touch(r.ports[0])
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("silent", 0) == 1))
            self.assertEqual(r.decoy.stats.get("events", 0), 0)
        self.assertEqual(read_events(self.path), [])

    def test_silent_connection_times_out_without_event(self):
        with self.running() as r:
            s = socket.create_connection(("127.0.0.1", r.ports[0]), timeout=5)
            try:
                # Held open and silent: the server gives up after listen_seconds.
                self.assertTrue(wait_until(lambda: r.decoy.stats.get("silent", 0) == 1, timeout=5))
            finally:
                s.close()
            self.assertEqual(r.decoy.stats.get("events", 0), 0)
        self.assertEqual(read_events(self.path), [])

    def test_non_lan_peer_gives_no_event(self):
        with self.running(is_lan=lambda ip: False) as r:
            touch(r.ports[0], b"x")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("not_lan", 0) == 1))
        self.assertEqual(read_events(self.path), [])

    def test_exempt_device_by_name_gives_no_event(self):
        settings = on_settings(exempt=(LOCAL_NAME,))
        with self.running(settings) as r:
            touch(r.ports[0], b"scan")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("exempt", 0) == 1))
            self.assertEqual(r.decoy.stats.get("events", 0), 0)
        self.assertEqual(read_events(self.path), [])

    def test_exempt_device_by_address_gives_no_event(self):
        settings = on_settings(exempt=("127.0.0.1",))
        with self.running(settings) as r:
            touch(r.ports[0], b"scan")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("exempt", 0) == 1))
        self.assertEqual(read_events(self.path), [])

    def test_dedupe_one_event_per_device_per_port(self):
        with self.running() as r:
            touch(r.ports[0], b"one")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("events", 0) == 1))
            touch(r.ports[0], b"two")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("deduped", 0) == 1))
            self.assertEqual(r.decoy.stats.get("events", 0), 1)
        self.assertEqual(len(read_events(self.path)), 1)

    def test_dedupe_window_expires(self):
        now = [1000.0]
        with self.running(clock=lambda: now[0]) as r:
            touch(r.ports[0], b"one")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("events", 0) == 1))
            now[0] += 3601
            touch(r.ports[0], b"two")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("events", 0) == 2))
        self.assertEqual(len(read_events(self.path)), 2)

    def test_each_port_is_its_own_event(self):
        with self.running(ports=(0, 0)) as r:
            for p in r.ports:
                touch(p, b"x")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("events", 0) == 2))
        events = read_events(self.path)
        self.assertEqual(len({e["domain"] for e in events}), 2)

    def test_per_device_hourly_cap(self):
        settings = on_settings(max_events_per_device_hour=2)
        with self.running(settings, ports=(0, 0, 0)) as r:
            for p in r.ports:
                touch(p, b"x")
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("rate_limited", 0) == 1))
            self.assertEqual(r.decoy.stats.get("events", 0), 2)
        self.assertEqual(len(read_events(self.path)), 2)

    def test_oversized_input_is_capped_and_service_survives(self):
        big = b"A" * (4 * 2 ** 20)
        with self.running() as r:
            try:
                touch(r.ports[0], big)
            except OSError:
                pass  # the server closes after its capped read; the client may see a reset
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("events", 0) == 1))
            # the read never took more than max_bytes from the one connection
            self.assertLessEqual(r.decoy.stats.get("bytes_seen", 0), self.settings.max_bytes)
            self.assertEqual(r.decoy.stats.get("errors", 0), 0)
            # still accepting after the oversized connection
            touch(r.ports[0])
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("silent", 0) == 1))
        self.assertEqual(len(read_events(self.path)), 1)

    def test_random_bytes_do_not_crash(self):
        rng = random.Random(7)
        with self.running() as r:
            blob = bytes(rng.randrange(256) for _ in range(300)) + b"\x00\xff\xfe\n"
            touch(r.ports[0], blob)
            self.assertTrue(wait_until(lambda: r.decoy.stats.get("events", 0) == 1))
            self.assertEqual(r.decoy.stats.get("errors", 0), 0)

    def test_connection_limit_refuses_extra(self):
        settings = on_settings(max_connections=1, listen_seconds=2)
        with self.running(settings) as r:
            holder = socket.create_connection(("127.0.0.1", r.ports[0]), timeout=5)
            try:
                self.assertTrue(wait_until(lambda: r.decoy.active == 1))
                touch(r.ports[0], b"second")
                self.assertTrue(wait_until(lambda: r.decoy.stats.get("over_capacity", 0) == 1))
            finally:
                holder.close()
            self.assertEqual(r.decoy.stats.get("events", 0), 0)

    def test_bind_failure_is_reported(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        try:
            d = D.Decoy(on_settings(), self.devices, self.log, ports=(port,))
            loop = asyncio.new_event_loop()
            try:
                with self.assertRaises(D.DecoyBindError) as cm:
                    loop.run_until_complete(d.start())
                self.assertIn(str(port), str(cm.exception))
            finally:
                loop.close()
        finally:
            blocker.close()


class ConfigTests(unittest.TestCase):
    def test_default_is_off(self):
        s = D.parse_config({})
        self.assertFalse(s.on)
        self.assertEqual(s.ports, (23, 2323, 3389, 5900))
        self.assertNotIn(445, s.ports)                     # Windows browsing knocks on SMB

    def test_on_needs_one_spare_address_not_every_address(self):
        for bind in ("0.0.0.0", "::"):
            with self.assertRaises(D.ConfigError):
                D.parse_config({"decoy": "on", "bind": bind})
        self.assertTrue(D.parse_config({"decoy": "on", "bind": "192.168.1.250"}).on)

    def test_missing_file_is_off(self):
        self.assertFalse(D.load_config(os.path.join(tempfile.mkdtemp(), "nope.json")).on)

    def test_example_file_is_valid_and_off(self):
        s = D.load_config(EXAMPLE)
        self.assertFalse(s.on)
        self.assertEqual(s.bind, "192.168.1.250")

    def test_on_with_defaults(self):
        self.assertTrue(D.parse_config({"decoy": "on", "bind": "192.168.1.250"}).on)

    def test_comment_keys_are_allowed(self):
        self.assertFalse(D.parse_config({"_comment": "hi", "decoy": "off"}).on)

    def test_typo_key_is_refused_with_hint(self):
        with self.assertRaisesRegex(D.ConfigError, 'unknown key "ports_".*"ports"'):
            D.parse_config({"decoy": "on", "ports_": [23]})

    def test_bad_values_are_refused(self):
        cases = [
            ("decoy must be", {"decoy": "On"}),
            ("decoy must be", {"decoy": True}),
            ("bind must be an IP", {"bind": "not-an-ip"}),
            ("bind must be an IP", {"bind": 5}),
            ("port number from 1 to 65535", {"ports": [0]}),
            ("port number from 1 to 65535", {"ports": [70000]}),
            ("port number from 1 to 65535", {"ports": [True]}),
            ("port number from 1 to 65535", {"ports": ["23"]}),
            ("listed twice", {"ports": [23, 23]}),
            ("ports must be a list", {"ports": []}),
            ("ports must be a list", {"ports": 23}),
            ("listen_seconds must be a number", {"listen_seconds": 0}),
            ("listen_seconds must be a number", {"listen_seconds": True}),
            ("max_bytes must be a whole number", {"max_bytes": 0}),
            ("max_bytes must be a whole number", {"max_bytes": 100000}),
            ("max_bytes must be a whole number", {"max_bytes": 2.5}),
            ("max_connections must be a whole number", {"max_connections": 0}),
            ("dedupe_seconds must be a whole number", {"dedupe_seconds": 0}),
            ("max_events_per_device_hour must be a whole number", {"max_events_per_device_hour": 0}),
            ("exempt must be a list", {"exempt": "owner-scanner"}),
            ("exempt: each entry", {"exempt": [""]}),
            ("exempt: each entry", {"exempt": [7]}),
            ("control characters", {"exempt": ["bad\nname"]}),
            ("events_path must be a file path", {"events_path": ""}),
        ]
        for needle, extra in cases:
            with self.subTest(extra=extra):
                raw = {"decoy": "on", "bind": "192.168.1.250", **extra}
                with self.assertRaisesRegex(D.ConfigError, needle):
                    D.parse_config(raw)

    def test_non_object_and_bad_json_are_refused(self):
        with self.assertRaisesRegex(D.ConfigError, "JSON object"):
            D.parse_config([1, 2])
        d = tempfile.mkdtemp()
        p = os.path.join(d, "decoy.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaisesRegex(D.ConfigError, "cannot read"):
            D.load_config(p)

    def test_main_refuses_bad_config_with_exit_2(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "decoy.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"decoy": "on", "bind": "192.168.1.250", "ports": [0]}, f)
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            rc = D.main(["--config", p])
        self.assertEqual(rc, 2)
        self.assertIn("ports", err.getvalue())

    def test_main_off_exits_clean_without_binding(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = D.main(["--config", EXAMPLE])
        self.assertEqual(rc, 0)
        self.assertIn("off", out.getvalue())

    def test_main_check_on_valid_config(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "decoy.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"decoy": "on", "bind": "127.0.0.1", "ports": [2323]}, f)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(D.main(["--config", p, "--check"]), 0)


class LanPeerTests(unittest.TestCase):
    def test_private_is_lan_loopback_and_public_are_not(self):
        self.assertTrue(D.lan_peer("192.168.1.20"))
        self.assertTrue(D.lan_peer("10.0.0.5"))
        self.assertTrue(D.lan_peer("::ffff:192.168.1.20"))
        self.assertTrue(D.lan_peer("fe80::1%eth0"))
        self.assertFalse(D.lan_peer("127.0.0.1"))
        self.assertFalse(D.lan_peer("0.0.0.0"))
        self.assertFalse(D.lan_peer("93.184.216.34"))
        self.assertFalse(D.lan_peer("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
