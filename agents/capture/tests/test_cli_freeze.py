"""End-to-end CLI test: capture_mgr freeze command with fake ring files."""
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
PKT = struct.Struct("<IIII")


class TestCliFreeze(unittest.TestCase):
    def test_cli_freeze_creates_incident(self):
        tmp = tempfile.mkdtemp(prefix="capcli_")
        try:
            ring_dir = os.path.join(tmp, "cap")
            inc = os.path.join(tmp, "incidents")
            dev_dir = os.path.join(ring_dir, "laptop")
            os.makedirs(ring_dir)
            hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 1)
            for i in range(2):
                p = os.path.join(ring_dir, "laptop", "cap_%d.pcap" % i)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "wb") as f:
                    f.write(hdr)
                    f.write(struct.pack("<IIII", 1, 0, 60, 60) + b"\x00" * 60)
                old = time.time() - 120
                os.utime(p, (old, old))
            dns = os.path.join(tmp, "dns.json")
            with open(dns, "w") as f:
                json.dump([{"domain": "bad.example"}], f)
            r = subprocess.run(
                [PY, os.path.join(HERE, "capture_mgr.py"), "freeze", "laptop",
                 "--event-id", "evtCLI", "--dns-history", dns,
                 "--devices", os.path.join(HERE, "devices.example.json"),
                 "--ring-dir", ring_dir, "--incidents-dir",
                 os.path.join(tmp, "incidents"),
                 "--freeze-extra-minutes", "0"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            out = os.path.join(tmp, "incidents", "evtCLI", "evtCLI.pcap")
            self.assertTrue(os.path.isfile(out), r.stdout + r.stderr)
            data = open(out, "rb").read()
            self.assertEqual(data[:4], b"\xd4\xc3\xb2\xa1")
            self.assertTrue(os.path.isfile(
                os.path.join(os.path.dirname(out), "dns_history.json")))
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
