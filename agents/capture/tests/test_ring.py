"""Tests for ring.py using the fake tcpdump: rotation, wrap, stop, status."""
import os
import shutil
import subprocess
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
            self.assertGreaterEqual(by["laptop"]["ring_files"], 2)
            self.assertLessEqual(by["laptop"]["ring_files"], 4)
            # argv recorded by the fake proves the real flags were passed
            argv = open(os.path.join(self.ring_dir, "laptop", "argv.txt")).read()
            for flag in ("-s", "128", "-G", "1", "-W", "3",
                         "src", "host", "192.168.1.51"):
                self.assertIn(flag, argv)
        finally:
            mgr.stop_all()
        self.assertFalse(mgr.alive("laptop"))
        self.assertEqual(mgr.procs, {})

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
