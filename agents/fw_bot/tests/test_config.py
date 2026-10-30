"""Tests for config.py"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config as cfgmod
from config import Config, ConfigError


def _write_owner(path, owner=111):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"owner_chat_id": owner}, f)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.env = {"FW_BOT_CALLBACK_SECRET": "s3cret"}
        self.tmp = tempfile.mkdtemp(prefix="fwbot_cfg_")
        self.owner = os.path.join(self.tmp, "owner.json")
        _write_owner(self.owner, 4242)

    def test_owner_load_and_check(self):
        c = Config.load(self.owner, env=self.env)
        self.assertTrue(c.is_owner(4242))
        self.assertFalse(c.is_owner(4243))
        self.assertFalse(c.is_owner(None))
        self.assertFalse(c.is_owner("4242"))

    def test_missing_secret_raises(self):
        with self.assertRaises(ConfigError):
            Config.load(self.owner, env={})

    def test_bad_owner_file_raises(self):
        p = os.path.join(self.tmp, "bad.json")
        with open(p, "w") as f:
            json.dump({"owner_chat_id": "123"}, f)
        with self.assertRaises(ConfigError):
            Config.load(p, env=self.env)
        with open(p, "w") as f:
            f.write("not json")
        with self.assertRaises(Exception):
            Config.load(p, env=self.env)

    def test_window_from_env_and_validation(self):
        c = Config.load(self.owner, env={**self.env, "FW_BOT_GROUP_WINDOW_MINUTES": "15"})
        self.assertEqual(c.group_window_minutes, 15)
        with self.assertRaises(ConfigError):
            Config.load(self.owner, env={**self.env, "FW_BOT_GROUP_WINDOW_MINUTES": "abc"})
        with self.assertRaises(ConfigError):
            Config.load(self.owner, env={**self.env, "FW_BOT_GROUP_WINDOW_MINUTES": "0"})

    def test_telegram_api_from_env(self):
        c = Config.load(self.owner, env={**self.env, "FW_BOT_TELEGRAM_API": "http://127.0.0.1:5999"})
        self.assertEqual(c.telegram_api, "http://127.0.0.1:5999")
        c2 = Config.load(self.owner, env=self.env)
        self.assertEqual(c2.telegram_api, cfgmod.TELEGRAM_API_DEFAULT)

    def test_chat_id_format_primary(self):
        p = os.path.join(self.tmp, "hub_owner.json")
        with open(p, "w") as f:
            json.dump({"chat_id": 4242, "user": "owner"}, f)
        c = Config.load(p, env=self.env)
        self.assertEqual(c.owner_chat_id, 4242)
        self.assertTrue(c.is_owner(4242))
        self.assertEqual(c.extra.get("user"), "owner")

    def test_owner_chat_id_fallback(self):
        # _write_owner uses owner_chat_id; still supported
        c = Config.load(self.owner, env=self.env)
        self.assertEqual(c.owner_chat_id, 4242)

    def test_both_keys_missing_raises(self):
        p = os.path.join(self.tmp, "nokey.json")
        with open(p, "w") as f:
            json.dump({"user": "owner"}, f)
        with self.assertRaises(ConfigError):
            Config.load(p, env=self.env)
        with open(p, "w") as f:
            json.dump({}, f)
        with self.assertRaises(ConfigError):
            Config.load(p, env=self.env)

    def test_chat_id_bool_rejected(self):
        p = os.path.join(self.tmp, "bool.json")
        with open(p, "w") as f:
            json.dump({"chat_id": True}, f)
        with self.assertRaises(ConfigError):
            Config.load(p, env=self.env)
        with open(p, "w") as f:
            json.dump({"chat_id": "4242"}, f)
        with self.assertRaises(ConfigError):
            Config.load(p, env=self.env)

    def test_severities(self):
        self.assertEqual(cfgmod.SEVERITIES, ("info", "warn", "high", "critical"))
        self.assertEqual(cfgmod.SEVERITY_ORDER["critical"], 3)


if __name__ == "__main__":
    unittest.main()
