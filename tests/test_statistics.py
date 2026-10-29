"""Unit tests for Statistical Functions (Wilson CI, Exact McNemar, Newcombe CI, Repeat Aggregation)."""
import unittest

from core.evaluator.stats import (
    wilson_interval,
    rate_with_ci,
    exact_mcnemar_test,
    newcombe_paired_ci,
    aggregate_case_repeats,
    estimate_requests,
)


class StatisticsMathTests(unittest.TestCase):
    def test_hand_calculated_wilson_intervals(self):
        # 1. Zero successes: k=0, n=10 -> high = z^2 / (n + z^2) = 3.84146 / 13.84146 = 0.27753
        low0, high0 = wilson_interval(0, 10)
        self.assertAlmostEqual(low0, 0.0, places=4)
        self.assertAlmostEqual(high0, 0.27753, places=3)

        # 2. Perfect successes: k=10, n=10 -> low = 1 - 0.27753 = 0.72247
        low10, high10 = wilson_interval(10, 10)
        self.assertAlmostEqual(low10, 0.72247, places=3)
        self.assertAlmostEqual(high10, 1.0, places=4)

        # 3. 50% successes: k=5, n=10
        low5, high5 = wilson_interval(5, 10)
        self.assertAlmostEqual(low5, 0.2366, places=2)
        self.assertAlmostEqual(high5, 0.7634, places=2)

    def test_exact_mcnemar_hand_calculated(self):
        # Case 1: 10 discordant pairs, b=1, c=9
        # Exact two-sided binomial p-value:
        # P(X <= 1) + P(X >= 9) = (1 + 10 + 10 + 1) / 1024 = 22 / 1024 = 0.021484375
        y1 = [1] + [0] * 9 + [1] * 5 + [0] * 5
        y2 = [0] + [1] * 9 + [1] * 5 + [0] * 5
        res = exact_mcnemar_test(y1, y2)
        self.assertEqual(res["b"], 1)
        self.assertEqual(res["c"], 9)
        self.assertEqual(res["discordant_total"], 10)
        self.assertAlmostEqual(res["p_value"], 0.021484375, places=5)

        # Case 2: Equal discordant pairs b=5, c=5 -> p=1.0
        y1_eq = [1] * 5 + [0] * 5
        y2_eq = [0] * 5 + [1] * 5
        res_eq = exact_mcnemar_test(y1_eq, y2_eq)
        self.assertEqual(res_eq["p_value"], 1.0)

        # Case 3: Zero discordant pairs b=0, c=0 -> p=1.0
        y_same = [1, 0, 1, 0]
        res_zero = exact_mcnemar_test(y_same, y_same)
        self.assertEqual(res_zero["discordant_total"], 0)
        self.assertEqual(res_zero["p_value"], 1.0)

    def test_newcombe_paired_ci(self):
        y1 = [1, 1, 1, 1, 0, 0, 0, 0]
        y2 = [1, 1, 0, 0, 0, 0, 0, 0]
        res = newcombe_paired_ci(y1, y2)
        # y1 rate = 4/8 = 50%, y2 rate = 2/8 = 25%, diff = 25.0%
        self.assertEqual(res["diff"], 25.0)
        self.assertLess(res["ci95_low"], res["diff"])
        self.assertGreater(res["ci95_high"], res["diff"])
        self.assertGreaterEqual(res["ci95_low"], -100.0)
        self.assertLessEqual(res["ci95_high"], 100.0)

    def test_aggregate_case_repeats_majority_vote(self):
        # Rule: succeeds if >= 2 out of 3 repeats succeed
        self.assertEqual(aggregate_case_repeats([1, 1, 0], threshold=2), 1)
        self.assertEqual(aggregate_case_repeats([1, 0, 1], threshold=2), 1)
        self.assertEqual(aggregate_case_repeats([0, 1, 1], threshold=2), 1)
        self.assertEqual(aggregate_case_repeats([1, 1, 1], threshold=2), 1)
        self.assertEqual(aggregate_case_repeats([1, 0, 0], threshold=2), 0)
        self.assertEqual(aggregate_case_repeats([0, 0, 0], threshold=2), 0)

    def test_estimate_requests(self):
        est = estimate_requests(n_cases=10, n_defenses=2, repeats=3, buffer_multiplier=1.5)
        self.assertEqual(est["chats"], 60)
        self.assertEqual(est["min_requests"], 60)
        self.assertEqual(est["typical_low"], 120)
        self.assertEqual(est["typical_high"], int(60 * 3 * 1.5))
        self.assertEqual(est["buffer_multiplier"], 1.5)

    def test_exact_mcnemar_without_scipy(self):
        import sys
        from unittest.mock import patch
        # Ensure exact_mcnemar_test executes cleanly even if scipy is explicitly blocked/absent
        with patch.dict(sys.modules, {"scipy": None, "scipy.stats": None}):
            res = exact_mcnemar_test([1, 0, 1, 0], [0, 1, 1, 0])
            self.assertEqual(res["discordant_total"], 2)
            self.assertEqual(res["p_value"], 1.0)



if __name__ == "__main__":
    unittest.main()
