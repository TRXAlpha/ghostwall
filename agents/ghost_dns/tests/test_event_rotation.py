"""events.jsonl rotation: bounded size, nothing lost, safe with two writer processes."""
import json
import multiprocessing as mp
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from events import EventLog, read_tail  # noqa: E402


def _writer(path, tag, n, max_bytes):
    log = EventLog(path, max_bytes=max_bytes)
    for i in range(n):
        log.write({"event_id": f"{tag}{i}", "pad": "x" * 100})


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "events.jsonl")

    def _ids(self, p):
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(l)["event_id"] for l in f]

    def test_rotates_and_keeps_one_old_file(self):
        log = EventLog(self.path, max_bytes=2000)
        for i in range(60):
            log.write({"event_id": f"e{i}", "pad": "x" * 100})
        self.assertLessEqual(os.path.getsize(self.path), 2000)
        self.assertLessEqual(os.path.getsize(self.path + ".1"), 2000)
        self.assertFalse(os.path.exists(self.path + ".2"))
        both = self._ids(self.path + ".1") + self._ids(self.path)
        self.assertEqual(both, [f"e{i}" for i in range(60 - len(both), 60)])  # newest kept, in order

    def test_read_tail_continues_into_rotated_file(self):
        log = EventLog(self.path, max_bytes=2000)
        for i in range(20):
            log.write({"event_id": f"e{i}", "pad": "x" * 100})
        got = [e["event_id"] for e in read_tail(self.path, 12, 256 * 1024)]
        self.assertEqual(got, [f"e{i}" for i in range(19, 7, -1)])

    @unittest.skipUnless(hasattr(os, "fork"), "needs fork")
    def test_two_processes_lose_nothing(self):
        # big enough that no line is dropped by a second rotation within the test
        ps = [mp.get_context("fork").Process(target=_writer, args=(self.path, t, 300, 40_000))
              for t in ("a", "b")]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        ids = self._ids(self.path + ".1") + self._ids(self.path)
        self.assertEqual(len(ids), len(set(ids)))
        for t in ("a", "b"):  # each writer's newest events survive, in its own order
            mine = [int(i[1:]) for i in ids if i[0] == t]
            self.assertEqual(mine, sorted(mine))
            self.assertEqual(mine[-1], 299)


if __name__ == "__main__":
    unittest.main()
