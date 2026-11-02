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
    def test_onnxruntime_telemetry_is_off(self):
        # onnxruntime >= 1.29 sends telemetry to Microsoft unless this is set before
        # it is imported, which scoring.py does on import.
        self.assertEqual(os.environ.get("ORT_DISABLE_TELEMETRY"), "1")

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


class NgramCompatTests(unittest.TestCase):
    """ngram.hashed_ngrams with boundary=False must score the shipped model bit for bit."""

    @staticmethod
    def _v2_reference(lr, toks):
        # the LRModel.score_tokens loop as shipped in v0.2.0-beta.2
        import numpy as np
        lengths = (toks != 0).sum(axis=1)
        z = np.full(len(toks), lr.intercept, dtype=np.float64)
        width = toks.shape[1]
        for ng in range(1, lr.ngram_max + 1):
            for j in range(width - ng + 1):
                m = lengths >= (ng + j)
                if not m.any():
                    continue
                code = np.zeros(int(m.sum()), dtype=np.int64)
                for k in range(ng):
                    code = code * 131 + toks[m, j + k].astype(np.int64)
                code &= 0x7FFFFFFF
                z[m] += lr.coef[code % lr.buckets]
        return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))

    def test_shipped_lr_scores_unchanged(self):
        if not os.path.exists(scoring.DEFAULT_LR_COEF):
            self.skipTest("lr model absent")
        import numpy as np
        from tokenizer import encode, strip_dot
        lr = scoring.LRModel(scoring.DEFAULT_LR_COEF, scoring.DEFAULT_LR_META)
        self.assertFalse(lr.boundary)
        names = BENIGN + DGAISH + ["a", "", "x" * 80, "my-site", "foo.bar", "q1w2e3r4t5y6u7i8o9p0"]
        toks = strip_dot(encode(names))
        np.testing.assert_array_equal(lr.score_tokens(toks), self._v2_reference(lr, toks))

    def test_boundary_markers_add_start_and_end_grams(self):
        import numpy as np
        from ngram import BOS, EOS, with_boundaries
        from tokenizer import encode, strip_dot
        toks = strip_dot(encode(["ab", "abc.de"]))
        ext, n = with_boundaries(toks, (toks != 0).sum(1))
        self.assertEqual(list(n), [4, 5])
        self.assertEqual(ext[0, 0], BOS)
        self.assertEqual(ext[0, 3], EOS)
        self.assertEqual(ext[1, 4], EOS)
        self.assertTrue((ext[0, 4:] == 0).all())


class CacheTests(unittest.TestCase):
    def test_cached_scores_match_and_are_bounded(self):
        s = scoring.Scorer()
        first = s.score_one("www.kjwqehdzxklqw.biz")
        again = s.score_one("mail.kjwqehdzxklqw.biz")   # same scored label
        self.assertEqual(first, again)
        again["dga"] = -1  # callers get a copy
        self.assertNotEqual(s.score_one("kjwqehdzxklqw.biz")["dga"], -1)
        s.cache_max = 3
        for d in ["a1.com", "b2.com", "c3.com", "d4.com", "e5.com"]:
            s.score_one(d)
        self.assertLessEqual(len(s._cache), 3)


class SingleNamePathTests(unittest.TestCase):
    def test_one_name_path_matches_batch_path(self):
        import numpy as np
        from ngram import hashed_ngrams, hashed_ngrams_one
        from tokenizer import encode, strip_dot
        names = BENIGN + DGAISH + ["a", "", "x" * 80, "my-site", "q1w2e3r4t5y6u7i8o9p0", "brothernerveplace"]
        toks = strip_dot(encode(names))
        for nmax, b in ((3, False), (5, False), (5, True)):
            want = [[] for _ in names]
            for rows, cols in hashed_ngrams(toks, 1 << 20, nmax, b):
                for r, c in zip(rows, cols):
                    want[r].append(int(c))
            for i in range(len(names)):
                self.assertEqual(sorted(hashed_ngrams_one(toks[i], 1 << 20, nmax, b)), sorted(want[i]),
                                 (names[i], nmax, b))

    def test_scores_equal_one_at_a_time(self):
        if not os.path.exists(scoring.DEFAULT_LR_COEF):
            self.skipTest("lr model absent")
        import numpy as np
        lr = scoring.LRModel(scoring.DEFAULT_LR_COEF, scoring.DEFAULT_LR_META)
        names = BENIGN + DGAISH + ["", "x" * 80]
        batch = lr.score(names)
        single = np.array([lr.score([n])[0] for n in names])
        np.testing.assert_allclose(single, batch, rtol=0, atol=1e-12)
