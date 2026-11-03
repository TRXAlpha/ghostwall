"""Tests for ring.py using the fake tcpdump: rotation, wrap, stop, status."""
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ring import RingManager, safe_name

PY = sys.executable
FAKE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_tcpdump.py")


class TestRing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="capring_")
        self.ring_dir = os.path.join(self.tmp, "cap")
        os.makedirs(self.ring_dir)
        self.cfg = {"ring_dir": self.ring_dir, "ring_seconds": 1,
                    "ring_keep_minutes": 1, "snaplen": 128,
                    "interface": "eth0", "tcpdump": PY}
        self.devs = [{"name": "laptop", "ip": "192.168.1.51"},
                     {"name": "phone", "ip": "192.168.1.50"}]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mgr(self, count=3):
        # fake tcpdump is invoked as: python fake_tcpdump.py <real args>
        mgr = RingManager(self.cfg, self.devs)
        orig = mgr.tcpdump_args

        def args(dev, out_dir):
            return [PY, FAKE] + orig(dev, out_dir)[1:]
        mgr.tcpdump_args = args
        mgr.count = count
        return mgr

    def test_safe_name(self):
        self.assertEqual(safe_name("bad name/x"), "bad_name_x")

    def test_start_stop_and_files(self):
        mgr = self._mgr(count=3)
        try:
            mgr.start_all()
            self.assertTrue(mgr.alive("laptop"))
            time.sleep(3.5)  # > 3 rotations at 1 s
            u = mgr.status()
            by = {r["name"]: r for r in u}
            self.assertTrue(by["laptop"]["capturing"])
            self.assertGreaterEqual(by["laptop"]["ring_files"], 3)   # still rotating
            # argv recorded by the fake proves the real flags were passed
            argv = open(os.path.join(self.ring_dir, "laptop", "argv.txt")).read()
            for flag in ("-s", "128", "-U", "-G", "1", "src", "host", "192.168.1.51"):
                self.assertIn(flag, argv)
            self.assertNotIn("-W", argv.split())   # with -G it would make tcpdump exit
        finally:
            mgr.stop_all()
        self.assertFalse(mgr.alive("laptop"))
        self.assertEqual(mgr.procs, {})

    def test_capture_outlives_one_ring_and_prune_keeps_the_window(self):
        self.cfg["ring_keep_minutes"] = 2 / 60.0          # 2 s of history (+1 s rotation)
        mgr = self._mgr()
        try:
            mgr.start_all()
            time.sleep(5.5)
            self.assertTrue(mgr.alive("laptop"))            # the real-tcpdump -W trap would have ended it
            before = mgr.status()[0]["ring_files"]
            self.assertGreaterEqual(before, 5)
            self.assertGreater(mgr.prune(), 0)
            after = mgr.status()[0]["ring_files"]
            self.assertLessEqual(after, 4)
            self.assertGreaterEqual(after, 1)               # the file being written stays
        finally:
            mgr.stop_all()

    def test_prune_enforces_size_share(self):
        mgr = self._mgr()
        d = os.path.join(self.ring_dir, "laptop")
        os.makedirs(d)
        for i in range(5):
            p = os.path.join(d, "cap-%d.pcap" % i)
            with open(p, "wb") as f:
                f.write(b"x" * 400_000)
            os.utime(p, (time.time() + i, time.time() + i))
        self.cfg["total_ring_mb"] = 2 * 1.0                 # 1 MB each for 2 devices
        mgr.prune()
        left = sorted(os.listdir(d))
        self.assertEqual(left, ["cap-3.pcap", "cap-4.pcap"])   # newest kept, under 1 MB

    def test_filter_is_src_only(self):
        mgr = self._mgr()
        a = mgr.tcpdump_args(self.devs[0], "x")
        self.assertIn("src", a)
        self.assertNotIn("dst", a)

    def test_status_reports_dead_process(self):
        mgr = self._mgr()
        rows = mgr.status()
        self.assertFalse(any(r["capturing"] for r in rows))


if __name__ == "__main__":
    unittest.main()
