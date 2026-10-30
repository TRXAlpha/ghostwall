"""Smoke test: fw_bot.py CLI entry works (owner file, help text)."""
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CliTests(unittest.TestCase):
    def test_help_runs(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "fw_bot.py"), "--help"],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0)
        self.assertIn("fw_bot", r.stdout.lower() + r.stderr.lower())


if __name__ == "__main__":
    unittest.main()
