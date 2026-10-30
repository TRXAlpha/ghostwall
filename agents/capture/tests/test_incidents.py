"""Tests for incidents.py: freeze flow, dns history JSON, retention cap."""
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from incidents import freeze_incident, enforce_retention, write_dns_history
import incidents

PCAP_HDR = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 1)
PKT = struct.Struct("<IIII")


def make_ring(ring_dir, device, nfiles=3, npackets=2):
    d = os.path.join(ring_dir, device)
    os.makedirs(d, exist_ok=True)
    for i in range(nfiles):
        # stagger mtimes so ordering is deterministic
        p = os.path.join(d, "cap_%d.pcap" % i)
        with open(p, "wb") as f:
            f.write(PCAP_HDR)
            for k in range(npackets):
                f.write(PKT.pack(1000 + i * 10 + k, k, 60, 60))
                f.write(b"\x22" * 60)
        os.utime(p, (time.time() - 100 + i, time.time() - 100 + i))
    return d


class FakeMgr:
    def __init__(self, devices):
        self.devices = devices

    def device_ip(self, name):
        for d in self.devices:
            if d["name"] == name:
                return d["ip"]
        return None


class TestIncidents(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="capinc_")
        self.ring_dir = os.path.join(self.tmp, "cap")
        self.inc = os.path.join(self.tmp, "incidents")
        os.makedirs(self.ring_dir)
        self.cfg = {"ring_dir": self.ring_dir, "incidents_dir": self.inc,
                    "ring_keep_minutes": 5, "freeze_extra_minutes": 0.0,
                    "retention_mb": 2048, "mergecap": ""}

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_freeze_writes_pcap_and_metadata(self):
        make_ring(self.ring_dir, "laptop", nfiles=3)
        mgr = FakeMgr([{"name": "laptop", "ip": "192.168.1.51"}])
        meta = freeze_incident(self.cfg, "laptop", "evt_1",
                               [{"domain": "a.com", "score": 0.9}], mgr,
                               logger=lambda *a: None)
        self.assertEqual(meta["merge_method"], "pure-python")
        self.assertEqual(meta["part1_files"], 3)
        self.assertEqual(meta["part2_files"], 0)
        pcap = meta["pcap"]
        self.assertTrue(os.path.isfile(pcap))
        self.assertEqual(open(pcap, "rb").read()[:4], b"\xd4\xc3\xb2\xa1")
        dj = json.load(open(os.path.join(os.path.dirname(pcap),
                                         "dns_history.json"), encoding="utf-8"))
        self.assertEqual(dj["queries"][0]["domain"], "a.com")
        mj = json.load(open(os.path.join(os.path.dirname(pcap),
                                         "incident.json"), encoding="utf-8"))
        self.assertEqual(mj["ip"], "192.168.1.51")

    def test_freeze_rejects_bad_event_id(self):
        make_ring(self.ring_dir, "laptop")
        mgr = FakeMgr([{"name": "laptop", "ip": "1"}])
        with self.assertRaises(ValueError):
            freeze_incident(self.cfg, "laptop", "../evil", [], mgr,
                            logger=lambda *a: None)

    def test_retention_deletes_oldest(self):
        inc = self.cfg["incidents_dir"]
        for i, age in enumerate([100, 50, 10]):
            d = os.path.join(inc, "evt%d" % i)
            os.makedirs(d)
            with open(os.path.join(d, "x.pcap"), "wb") as f:
                f.write(b"a" * (900 * 1024))  # ~0.9 MB each
            os.utime(d, (time.time() - age,) * 2)
        deleted = enforce_retention(inc, 2.0)  # cap 2 MB -> keep 2 newest
        self.assertEqual([os.path.basename(x) for x in deleted], ["evt0"])
        remaining = sorted(os.listdir(inc))
        self.assertEqual(remaining, ["evt1", "evt2"])

    def test_retention_noop_under_cap(self):
        inc = self.cfg["incidents_dir"]
        os.makedirs(os.path.join(inc, "evtA"))
        self.assertEqual(enforce_retention(inc, 2048), [])

    def test_write_dns_history(self):
        p = os.path.join(self.tmp, "h.json")
        write_dns_history(p, [{"domain": "x"}])
        data = json.load(open(p, encoding="utf-8"))
        self.assertEqual(data["queries"][0]["domain"], "x")


if __name__ == "__main__":
    unittest.main()
