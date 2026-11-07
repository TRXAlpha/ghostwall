"""go_shadow.sh's AdGuard check is advisory: it must never stop the script.

v0.3.0b2's loop ended on `[ -n "$p" ] && echo ...`, which is false for an empty line;
under `set -euo pipefail` that aborted go_shadow.sh (and install.sh) on every AdGuard
config with nothing to warn about, leaving ghost-dns stopped.
"""
import os
import re
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "go_shadow.sh")


def function_source() -> str:
    with open(SCRIPT, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^adguard_warnings\(\) \{.*?^\}\n", text, re.S | re.M)
    assert m, "adguard_warnings() not found in go_shadow.sh"
    return m.group(0)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class AdguardWarnings(unittest.TestCase):
    def run_check(self, stub: str):
        script = "set -euo pipefail\n" + function_source() + f"adguard_warnings {stub}\necho REACHED\n"
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)

    def test_clean_config_with_blank_line_continues(self):
        r = self.run_check("printf '\\n'")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("REACHED", r.stdout)
        self.assertEqual(r.stderr, "")

    def test_no_output_continues(self):
        r = self.run_check("true")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("REACHED", r.stdout)

    def test_problems_are_warnings(self):
        r = self.run_check("printf 'query log is off\\nanonymize is on\\n'")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("REACHED", r.stdout)
        self.assertEqual(r.stderr.count("WARNING:"), 2)
        self.assertIn("WARNING: query log is off", r.stderr)

    def test_failing_check_is_a_warning_not_an_abort(self):
        r = self.run_check("false")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("REACHED", r.stdout)
        self.assertIn("could not check", r.stderr)

    def test_go_shadow_calls_it(self):
        with open(SCRIPT, encoding="utf-8") as f:
            text = f.read()
        self.assertIn('adguard_warnings "$PY"', text)
        self.assertNotIn('[ -n "$p" ] && echo', text)


class InstallVersion(unittest.TestCase):
    def test_version_names_lightweight_release_tags(self):
        """Release tags are lightweight; `git describe` without --tags skips them and
        `ghostwall version` showed the commit as "v0.2.0-beta.1-86-g..." on v0.3.0-beta.2."""
        with open(os.path.join(HERE, "..", "..", "..", "install.sh"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("describe --tags --always --dirty", text)


if __name__ == "__main__":
    unittest.main()
