"""adguard_conf.py: edits only the intended keys of AdGuard's YAML."""
import contextlib, io, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import adguard_conf

YAML = """http:
  address: 0.0.0.0:3000
dns:
  bind_hosts:
    - 0.0.0.0
  port: 5300
  upstream_dns:
    - https://dns10.quad9.net/dns-query
querylog:
  dir_path: ""
  interval: 2160h
  size_memory: 1000
  enabled: true
  file_enabled: true
statistics:
  interval: 24h
  size_memory: 1000
schema_version: 29
"""


class EditTests(unittest.TestCase):
    def test_flush_only_in_querylog_block(self):
        new, changes = adguard_conf.edit(YAML, flush=10)
        self.assertEqual(changes, ["flush:1000"])
        self.assertIn("querylog:\n  dir_path: \"\"\n  interval: 2160h\n  size_memory: 10\n", new)
        self.assertIn("statistics:\n  interval: 24h\n  size_memory: 1000\n", new)  # untouched
        self.assertIn("  port: 5300", new)                                         # not asked

    def test_port_back(self):
        new, changes = adguard_conf.edit(YAML, port_back=True)
        self.assertEqual(changes, ["port"])
        self.assertIn("dns:\n  bind_hosts:\n    - 0.0.0.0\n  port: 53\n", new)

    def test_no_change_when_already_low(self):
        new, changes = adguard_conf.edit(YAML.replace("size_memory: 1000\n  enabled", "size_memory: 5\n  enabled"), flush=10)
        self.assertEqual(changes, [])

    def test_cli_rewrites_only_on_change(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "AdGuardHome.yaml")
        with open(p, "w") as f:
            f.write(YAML)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            adguard_conf.main([p, "--flush", "10", "--port-back"])
        self.assertEqual(out.getvalue().strip(), "port flush:1000")
        with contextlib.redirect_stdout(io.StringIO()) as again:
            adguard_conf.main([p, "--flush", "10", "--port-back"])
        self.assertEqual(again.getvalue().strip(), "")
        self.assertEqual(os.listdir(d), ["AdGuardHome.yaml"])  # no temp files left

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root to own files as others")
    def test_rewrite_keeps_the_files_owner(self):
        # AdGuard may run as a normal user with a 0600 config: a root-owned rewrite
        # would lock it out of its own file.
        d = tempfile.mkdtemp()
        p = os.path.join(d, "AdGuardHome.yaml")
        with open(p, "w") as f:
            f.write(YAML)
        os.chmod(p, 0o600)
        os.chown(p, 1001, 1001)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(adguard_conf.main([p, "--flush", "10"]), 0)
        st = os.stat(p)
        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (1001, 1001, 0o600))
        with open(p) as f:
            self.assertIn("size_memory: 10\n", f.read())

    def test_refuses_when_owner_cannot_be_kept(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "AdGuardHome.yaml")
        with open(p, "w") as f:
            f.write(YAML)
        real_chown, real_stat = os.chown, os.stat

        def fake_stat(path, *a, **k):  # pretend the config belongs to someone else
            st = real_stat(path, *a, **k)
            if path == p:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 4242, 4242) + tuple(st)[6:])
            return st

        def deny(*a, **k):
            raise PermissionError("no CAP_CHOWN")
        adguard_conf.os.chown, adguard_conf.os.stat = deny, fake_stat
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(adguard_conf.main([p, "--flush", "10"]), 1)
        finally:
            adguard_conf.os.chown, adguard_conf.os.stat = real_chown, real_stat
        with open(p) as f:
            self.assertIn("size_memory: 1000", f.read())       # untouched
        self.assertEqual(os.listdir(d), ["AdGuardHome.yaml"])  # temp file removed


class CheckTests(unittest.TestCase):
    """Settings that leave Ghostwall blind, or make every device look the same."""

    def test_a_good_config_has_no_problems(self):
        self.assertEqual(adguard_conf.problems(YAML), [])

    def test_each_problem_is_named(self):
        bad = (YAML.replace("  enabled: true\n  file_enabled: true", "  enabled: false\n  file_enabled: false")
                   .replace("  port: 5300\n", "  port: 5300\n  anonymize_client_ip: true\n"))
        found = " ".join(adguard_conf.problems(bad))
        for words in ("query log is off", "in memory only", "anonymizes client IPs"):
            self.assertIn(words, found)

    def test_same_keys_elsewhere_are_not_mistaken(self):
        other = YAML.replace("statistics:\n  interval: 24h", "statistics:\n  enabled: false\n  interval: 24h")
        self.assertEqual(adguard_conf.problems(other), [])

    def test_check_flag_changes_nothing(self):
        p = os.path.join(tempfile.mkdtemp(), "AdGuardHome.yaml")
        with open(p, "w") as f:
            f.write(YAML.replace("  enabled: true\n", "  enabled: false\n", 1))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(adguard_conf.main([p, "--check"]), 0)
        self.assertIn("query log is off", out.getvalue())
        with open(p) as f:
            self.assertIn("  enabled: false", f.read())

    def test_check_prints_nothing_for_a_clean_config(self):
        p = os.path.join(tempfile.mkdtemp(), "AdGuardHome.yaml")
        with open(p, "w") as f:
            f.write(YAML)
        self.assertEqual(adguard_conf.problems(YAML), [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(adguard_conf.main([p, "--check"]), 0)
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
