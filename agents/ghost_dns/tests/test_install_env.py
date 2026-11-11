"""install.sh writes ghostwall.env, and root later sources that file. Every value written by
setenv() must come back from `. file` as the same text, and must never run a command.

Synthetic values only. The function is taken from install.sh itself, so the test follows
the real code."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

INSTALL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "install.sh")


def setenv_source() -> str:
    with open(INSTALL, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^setenv\(\) \{.*?^\}\n", text, re.S | re.M)
    assert m, "setenv() not found in install.sh"
    return m.group(0)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class SetenvQuoting(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.envf = os.path.join(self.dir, "ghostwall.env")
        self.sentinel = os.path.join(self.dir, "ran")
        with open(self.envf, "w", encoding="utf-8") as f:
            f.write("DNS_SOURCE=adguard\n")

    def write(self, key, value):
        script = f'ENVF={self.envf!r}\n' + setenv_source() + "setenv \"$1\" \"$2\"\n"
        subprocess.run(["bash", "-c", script, "setenv", key, value], check=True, timeout=20)

    def sourced(self, key):
        r = subprocess.run(["bash", "-c", f'set -a; . "{self.envf}"; printf %s "${key}"'],
                           capture_output=True, text=True, timeout=20)
        return r.stdout

    def test_shell_syntax_without_spaces_is_not_run(self):
        # no whitespace in any payload: `:>file` creates the sentinel if the shell runs it
        for value in (f"/srv/adguard;:>{self.sentinel}", f"/srv/x$(:>{self.sentinel})",
                      f"/srv/x`:>{self.sentinel}`", f"/srv/x&:>{self.sentinel}"):
            with self.subTest(value=value):
                if os.path.exists(self.sentinel):
                    os.remove(self.sentinel)
                self.write("ADGUARD_QUERYLOG", value)
                self.assertEqual(self.sourced("ADGUARD_QUERYLOG"), value)
                self.assertFalse(os.path.exists(self.sentinel))

    def test_odd_but_harmless_values_round_trip(self):
        for value in ("/srv/my logs/querylog.json", "it's here", "a\"b", "/mnt/x=y"):
            with self.subTest(value=value):
                self.write("PIHOLE_LOG", value)
                self.assertEqual(self.sourced("PIHOLE_LOG"), value)

    def test_plain_paths_are_written_unchanged(self):
        self.write("ADGUARD_YAML", "/opt/AdGuardHome/AdGuardHome.yaml")
        with open(self.envf, encoding="utf-8") as f:
            self.assertIn("ADGUARD_YAML=/opt/AdGuardHome/AdGuardHome.yaml\n", f.read())

    def test_existing_key_is_replaced_not_duplicated(self):
        self.write("DNS_SOURCE", "pihole")
        with open(self.envf, encoding="utf-8") as f:
            self.assertEqual(f.read().count("DNS_SOURCE="), 1)
        self.assertEqual(self.sourced("DNS_SOURCE"), "pihole")


if __name__ == "__main__":
    unittest.main()
