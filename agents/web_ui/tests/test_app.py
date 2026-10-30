"""Tests for web_ui/app.py action validation (no network)."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app

class ValidateTests(unittest.TestCase):
    def test_allow_normalises_domain(self):
        path, body = app.validate_action({"action": "allow", "params": {"domain": " FBSBX.com. "}})
        self.assertEqual((path, body), ("/allow", {"domain": "fbsbx.com"}))

    def test_rejects_bad_domain(self):
        with self.assertRaises(ValueError):
            app.validate_action({"action": "allow", "params": {"domain": "a b;rm -rf"}})

    def test_rejects_unknown_action(self):
        with self.assertRaises(ValueError):
            app.validate_action({"action": "shutdown", "params": {}})

    def test_device_name_validated(self):
        path, body = app.validate_action({"action": "isolate", "params": {"name": "bambu-a1mini"}})
        self.assertEqual(path, "/isolate")
        with self.assertRaises(ValueError):
            app.validate_action({"action": "isolate", "params": {"name": "x; drop"}})

    def test_drops_unexpected_keys(self):
        _, body = app.validate_action({"action": "learning", "params": {"enabled": 1, "evil": "x"}})
        self.assertEqual(body, {"enabled": True})

if __name__ == "__main__":
    unittest.main()
