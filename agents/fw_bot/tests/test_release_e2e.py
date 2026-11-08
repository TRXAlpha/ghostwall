"""The Release device button end to end: an auto-isolated event in events.jsonl, its
signed button, the dispatcher, the real control client with the token, ghost-dns's
control API, and the isolated nft set (a fake that behaves like nft)."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

FW_BOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, FW_BOT)
sys.path.append(os.path.join(os.path.dirname(FW_BOT), "ghost_dns"))
from alerts import format_alert, inline_keyboard   # noqa: E402
from config import Config                         # noqa: E402
from dispatch import Dispatcher                   # noqa: E402

from control_api import ControlServer, ensure_token   # noqa: E402  (ghost_dns)
from devices import DeviceMap                         # noqa: E402
from enforce import Enforcer, NullBackend             # noqa: E402
from state import GhostState                          # noqa: E402

SECRET = b"s3cret"
OWNER = 4242
TV = "192.168.1.20"
EVENT = {
    "time": "2026-11-07T20:00:00Z", "device": "tv-box", "ip": TV, "mac": None,
    "domain": "evil.example", "rule": "threat_feed", "action": "block", "severity": "high",
    "event_id": "evt_iso01", "auto_isolated": True,
    "reasons": ["evil.example is on the threat feed",
                f"isolated tv-box ({TV}) automatically: threat_feed; undo: the Release button, "
                "the dashboard or sudo ghostwall release tv-box"],
}


class NftSet(NullBackend):
    def __init__(self):
        super().__init__()
        self.members = set()

    @property
    def name(self):
        return "nft"

    def _run(self, *args):
        self.calls.append(args)
        if "isolated_dev" in args:
            ip = args[args.index("{") + 1]
            if args[0] == "add":
                self.members.add(ip)
            elif ip in self.members:
                self.members.discard(ip)
            else:
                raise subprocess.CalledProcessError(1, ["nft"], stderr="Error: Could not process rule: "
                                                                        "No such file or directory")


class StubAPI:
    def __init__(self):
        self.edits = []

    def edit_alert(self, chat_id, message_id, text, event=None, secret=None):
        self.edits.append(text)


class ReleaseButtonE2E(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.state = GhostState(os.path.join(tmp, "state.json"), learning_default=False)
        self.nft = NftSet()
        enforcer = Enforcer(self.nft)
        devices = DeviceMap.from_json([{"name": "tv-box", "ip": TV}])
        # what ghost-dns's auto_isolate did
        enforcer.isolate(TV)
        self.state.isolate("tv-box", TV)
        token_file = os.path.join(tmp, "control_token")
        server = ControlServer({"control_host": "127.0.0.1", "control_port": 0}, self.state, enforcer,
                               devices, token=ensure_token(token_file))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        events = os.path.join(tmp, "events.jsonl")
        with open(events, "w", encoding="utf-8") as f:
            f.write(json.dumps(EVENT) + "\n")
        owner = os.path.join(tmp, "owner.json")
        with open(owner, "w") as f:
            json.dump({"owner_chat_id": OWNER}, f)
        cfg = Config.load(owner, env={"FW_BOT_CALLBACK_SECRET": SECRET.decode()},
                          labels_path=os.path.join(tmp, "labels.jsonl"))
        self.api = StubAPI()
        with mock.patch.dict(os.environ, {"FW_BOT_CONTROL_TOKEN_FILE": token_file}):
            self.d = Dispatcher(cfg, events, f"http://127.0.0.1:{server.httpd.server_address[1]}", self.api)

    def press(self, text="Release device", user=OWNER, data=None):
        btn = [b for b in inline_keyboard(EVENT, SECRET)[0] if b["text"] == text][0]
        return self.d.callback({"message": {"chat": {"id": OWNER}, "message_id": 7},
                                "from": {"id": user}, "data": data or btn["callback_data"]})

    def test_alert_says_isolated_and_offers_release(self):
        text = format_alert(EVENT)
        self.assertTrue(text.startswith("ISOLATED · tv-box"))
        self.assertIn("sudo ghostwall release tv-box", text)

    def test_release_button_unisolates_through_the_control_api(self):
        self.assertEqual(self.press(), "tv-box released.")
        self.assertEqual(self.nft.members, set())
        self.assertFalse(self.state.is_isolated("tv-box"))
        self.assertEqual(self.api.edits, ["tv-box released."])
        # pressed again (a double tap, or released on the dashboard first): still fine
        self.assertEqual(self.press(), "tv-box released.")
        self.assertFalse(self.state.is_isolated("tv-box"))

    def test_only_the_owner_and_only_a_signed_button(self):
        self.assertTrue(self.press(user=999).startswith("ignored"))
        btn = inline_keyboard(EVENT, SECRET)[0][0]["callback_data"]
        forged = btn[:-1] + ("0" if btn[-1] != "0" else "1")
        self.assertTrue(self.press(data=forged).startswith("ignored"))
        self.assertEqual(self.nft.members, {TV})
        self.assertTrue(self.state.is_isolated("tv-box"))
        self.assertEqual(self.api.edits, [])


if __name__ == "__main__":
    unittest.main()
