"""Model files that are missing, corrupt or hostile must not crash the resolver.

Each case writes a small model pair into a temp folder (example data only). A pickled
array must be refused, not run; a zero bucket count must be rejected when the model loads
(before, it loaded and then failed with ZeroDivisionError on every name).
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import numpy as np  # noqa: E402

import scoring  # noqa: E402


class ModelLoadTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.coef = os.path.join(self.dir, "coef.npy")
        self.meta = os.path.join(self.dir, "meta.json")

    def write_meta(self, **fields):
        meta = {"intercept": 0.0, "buckets": 8}
        meta.update(fields)
        with open(self.meta, "w", encoding="utf-8") as f:
            json.dump(meta, f)

    def test_zero_buckets_is_rejected_at_load(self):
        np.save(self.coef, np.zeros(0))
        self.write_meta(buckets=0)
        with self.assertRaises(ValueError):
            scoring.LRModel(self.coef, self.meta)

    def test_scorer_falls_back_when_lr_meta_is_bad(self):
        np.save(self.coef, np.zeros(0))
        self.write_meta(buckets=0)
        s = scoring.Scorer(onnx_path=None, lr_coef_path=self.coef, lr_meta_path=self.meta)
        self.assertIsNone(s.lr)
        self.assertEqual(s.backend, "heuristic")
        self.assertGreaterEqual(s.score_one("kjwqehdzxklqw.biz")["dga"], 0.0)

    def test_pickled_coefficients_are_refused_not_run(self):
        # A pickle that would write a file if it were loaded. np.load must refuse it.
        marker = os.path.join(self.dir, "ran")

        class Evil:
            def __reduce__(self):
                return (open, (marker, "w"))

        with open(self.coef, "wb") as f:
            # an object array, the only way a .npy holds a pickle
            np.save(f, np.array([Evil()], dtype=object), allow_pickle=True)
        self.write_meta(buckets=8)
        with self.assertRaises(ValueError):
            scoring.LRModel(self.coef, self.meta)
        self.assertFalse(os.path.exists(marker))

    def test_corrupt_coefficient_file_is_a_load_error(self):
        with open(self.coef, "wb") as f:
            f.write(b"not a numpy file")
        self.write_meta(buckets=8)
        s = scoring.Scorer(onnx_path=None, lr_coef_path=self.coef, lr_meta_path=self.meta)
        self.assertIsNone(s.lr)


if __name__ == "__main__":
    unittest.main()
