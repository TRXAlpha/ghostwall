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

    def test_config_error_is_a_message_not_a_traceback(self):
        import tempfile
        owner = os.path.join(tempfile.mkdtemp(), "owner.json")
        with open(owner, "w") as f:
            f.write('{"chat_id": 1}')
        env = {k: v for k, v in os.environ.items() if k != "FW_BOT_CALLBACK_SECRET"}
        r = subprocess.run([sys.executable, os.path.join(ROOT, "fw_bot.py"), "--owner-file", owner],
                           capture_output=True, text=True, cwd=ROOT, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("config error", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
