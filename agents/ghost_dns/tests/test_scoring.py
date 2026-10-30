"""Tests for scoring.py (uses the real models if present; falls back otherwise)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import scoring


BENIGN = ["google.com", "cloudflare.com", "microsoft.com", "facebook.com"]
DGAISH = ["kjwqehdzxklqw.biz", "x7g2qophablz.top", "bexmnvoqeidu.xyz"]


class ScoringTests(unittest.TestCase):
    def test_backends_available(self):
        s = scoring.Scorer()
        # On this repo both models ship; at minimum one backend must load.
        self.assertIn("trm", s.backend)

    def test_benign_vs_dga_separation(self):
        s = scoring.Scorer()
        benign = max(s.score_one(d)["dga"] for d in BENIGN)
        dga = min(s.score_one(d)["dga"] for d in DGAISH)
        self.assertLess(benign, 0.6, "a benign domain scored suspiciously high")
        self.assertGreater(dga, 0.85, "a DGA-like domain scored too low")

    def test_scores_in_range(self):
        s = scoring.Scorer()
        for d in BENIGN + DGAISH:
            sc = s.score_one(d)
            self.assertGreaterEqual(sc["dga"], 0.0)
            self.assertLessEqual(sc["dga"], 1.0)

    def test_heuristic_fallback_when_no_models(self):
        s = scoring.Scorer(onnx_path=None, lr_coef_path=None, lr_meta_path=None)
        self.assertEqual(s.backend, "heuristic")
        sc = s.score_one("kjwqehdzxklqw.biz")
        self.assertGreaterEqual(sc["dga"], 0.0)
        self.assertLessEqual(sc["dga"], 1.0)
        self.assertIsNone(sc["dga_trm"])
        self.assertIsNone(sc["dga_lr"])

    def test_lr_matches_meta_shape(self):
        if not os.path.exists(scoring.DEFAULT_LR_COEF):
            self.skipTest("lr model absent")
        lr = scoring.LRModel(scoring.DEFAULT_LR_COEF, scoring.DEFAULT_LR_META)
        self.assertEqual(lr.coef.shape[0], lr.buckets)


if __name__ == "__main__":
    unittest.main()
