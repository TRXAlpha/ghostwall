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


if __name__ == "__main__":
    unittest.main()
