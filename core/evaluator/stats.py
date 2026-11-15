"""Statistical evaluation helpers and inferential hypothesis testing.

Includes:
- Wilson 95% score interval for single proportions.
- Exact McNemar test (exact binomial test on discordant pairs) for paired comparisons.
- Newcombe paired difference confidence interval (Method 10).
- Aggregation helper (majority vote >= 2 of 3 repeats).
- Paired triplet bootstrap testing with confidence intervals.
- Benjamini-Hochberg False Discovery Rate (FDR) adjustment.
"""
from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Optional, Sequence, Tuple

Z_95 = 1.959963984540054  # two-sided 95% normal quantile


def wilson_interval(successes: int, n: int, z: float = Z_95) -> Tuple[Optional[float], Optional[float]]:
    """Wilson score interval for a binomial proportion.

    Returns (low, high) as proportions in [0, 1], or (None, None) when n == 0.
    Raises ValueError for impossible inputs (successes < 0 or > n, n < 0).
    """
    if n < 0 or successes < 0 or successes > n:
        raise ValueError(f"invalid counts: successes={successes}, n={n}")
    if n == 0:
        return (None, None)
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z * math.sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n))) / denom
    low = max(0.0, center - half)
    high = min(1.0, center + half)
    return (low, high)


def rate_with_ci(successes: int, n: int) -> dict:
    """Return rate (%), counts and Wilson 95% CI (%) as a plain dict."""
    low, high = wilson_interval(successes, n)
    return {
        "k": successes,
        "n": n,
        "rate": None if n == 0 else round(successes / n * 100.0, 2),
        "ci95_low": None if low is None else round(low * 100.0, 2),
        "ci95_high": None if high is None else round(high * 100.0, 2),
    }


def format_rate(stat: dict) -> str:
    """Human-readable 'k/n = x% [lo-hi%]'; always shows n."""
    if not stat or stat.get("n", 0) == 0:
        return "n=0 (no data)"
    return (
        f"{stat['k']}/{stat['n']} = {stat['rate']:.1f}% "
        f"[95% CI {stat['ci95_low']:.1f}-{stat['ci95_high']:.1f}%]"
    )


def exact_mcnemar_test(
    y1: Sequence[int],
    y2: Sequence[int],
) -> Dict[str, Any]:
    """Perform exact McNemar test for paired binary data using exact binomial distribution.

    Discordant pairs:
      b = number of pairs where y1=1 and y2=0
      c = number of pairs where y1=0 and y2=1
    Under H0: b ~ Binomial(n=b+c, p=0.5).
    """
    if len(y1) != len(y2):
        raise ValueError(f"Lengths must match for paired test: len(y1)={len(y1)}, len(y2)={len(y2)}")
    n = len(y1)
    if n == 0:
        return {"n": 0, "a": 0, "b": 0, "c": 0, "d": 0, "p_value": 1.0, "discordant_total": 0}

    a = sum(1 for a_i, b_i in zip(y1, y2) if a_i == 1 and b_i == 1)
    b = sum(1 for a_i, b_i in zip(y1, y2) if a_i == 1 and b_i == 0)
    c = sum(1 for a_i, b_i in zip(y1, y2) if a_i == 0 and b_i == 1)
    d = sum(1 for a_i, b_i in zip(y1, y2) if a_i == 0 and b_i == 0)

    discordant = b + c
    if discordant == 0 or b == c:
        p_val = 1.0
    else:
        k = min(b, c)
        p_val = min(1.0, 2.0 * sum(math.comb(discordant, i) * (0.5 ** discordant) for i in range(k + 1)))

    return {
        "n": n,
        "a": a,
        "b": b,
        "c": c,
        "d": d,
        "discordant_total": discordant,
        "p_value": p_val,
    }


def newcombe_paired_ci(
    y1: Sequence[int],
    y2: Sequence[int],
    z: float = Z_95,
) -> Dict[str, Any]:
    """Calculate Newcombe paired confidence interval for difference in proportions (Method 10).

    Returns difference (p1 - p2) and 95% confidence interval bounds.
    """
    if len(y1) != len(y2):
        raise ValueError(f"Lengths must match: len(y1)={len(y1)}, len(y2)={len(y2)}")
    n = len(y1)
    if n == 0:
        return {"diff": 0.0, "ci95_low": 0.0, "ci95_high": 0.0}

    a = sum(1 for a_i, b_i in zip(y1, y2) if a_i == 1 and b_i == 1)
    b = sum(1 for a_i, b_i in zip(y1, y2) if a_i == 1 and b_i == 0)
    c = sum(1 for a_i, b_i in zip(y1, y2) if a_i == 0 and b_i == 1)
    d = sum(1 for a_i, b_i in zip(y1, y2) if a_i == 0 and b_i == 0)

    p1 = (a + b) / n
    p2 = (a + c) / n
    diff = p1 - p2

    l1, u1 = wilson_interval(a + b, n, z)
    l2, u2 = wilson_interval(a + c, n, z)
    if l1 is None or l2 is None or u1 is None or u2 is None:
        return {"diff": diff, "ci95_low": None, "ci95_high": None}

    # Denominator for phi correlation coefficient
    prod = (a + b) * (c + d) * (a + c) * (b + d)
    if prod <= 0:
        phi = 0.0
    else:
        phi = (a * d - b * c) / math.sqrt(prod)

    # Newcombe lower & upper limits
    var_low = (p1 - l1) ** 2 - 2 * phi * (p1 - l1) * (u2 - p2) + (u2 - p2) ** 2
    var_high = (u1 - p1) ** 2 - 2 * phi * (u1 - p1) * (p2 - l2) + (p2 - l2) ** 2

    # Guard against float rounding precision issues
    var_low = max(0.0, var_low)
    var_high = max(0.0, var_high)

    low = max(-1.0, diff - math.sqrt(var_low))
    high = min(1.0, diff + math.sqrt(var_high))

    return {
        "diff": round(diff * 100.0, 2),
        "ci95_low": round(low * 100.0, 2),
        "ci95_high": round(high * 100.0, 2),
        "phi": round(phi, 4),
    }


def aggregate_case_repeats(repeat_scores: Sequence[int], threshold: int = 2) -> int:
    """Aggregate per-case repeat runs using pre-defined majority vote rule (>= threshold of repeats).

    For example, with 3 repeats: succeeds (1) if >= 2 out of 3 are 1, else 0.
    """
    if not repeat_scores:
        return 0
    return 1 if sum(repeat_scores) >= threshold else 0


def estimate_requests(n_cases: int, n_defenses: int, repeats: int, buffer_multiplier: float = 1.5) -> Dict[str, Any]:
    """Estimate Gemini API request counts for benchmark runs."""
    chats = n_cases * n_defenses * repeats
    typical_low = chats * 2
    typical_high = int(chats * 3 * buffer_multiplier)
    return {
        "chats": chats,
        "min_requests": chats,
        "typical_low": typical_low,
        "typical_high": typical_high,
        "buffer_multiplier": buffer_multiplier,
    }


def calculate_triplet_paired_bootstrap(
    triplets: dict[str, dict[str, list[int]]],
    n_bootstraps: int = 1000,
    confidence: float = 0.95,
    seed: Optional[int] = 42,
) -> dict[str, Any]:
    """Calculate paired triplet bootstrap confidence intervals and empirical p-value.

    Tests the paired cross-lingual difference: Delta = Score(TH) - Score(EN) per scenario.

    Args:
        triplets: Dictionary of scenario_id -> {"th": [...], "en": [...], "th-en": [...]}.
        n_bootstraps: Number of bootstrap iterations.
        confidence: Confidence level (e.g. 0.95 for 95% CI).
        seed: Random seed for deterministic reproducibility.

    Returns:
        dict with mean_delta, ci_lower, ci_upper, p_value, n_triplets, and n_bootstraps.
    """
    if not triplets:
        return {
            "mean_delta": 0.0,
            "ci_lower": 0.0,
            "ci_upper": 0.0,
            "p_value": 1.0,
            "n_triplets": 0,
            "n_bootstraps": n_bootstraps,
        }

    rng = random.Random(seed)
    deltas = []
    for scn_id, langs in triplets.items():
        th_scores = langs.get("th", [0])
        en_scores = langs.get("en", [0])
        th_mean = sum(th_scores) / len(th_scores) if th_scores else 0.0
        en_mean = sum(en_scores) / len(en_scores) if en_scores else 0.0
        deltas.append(th_mean - en_mean)

    n = len(deltas)
    mean_delta = sum(deltas) / n

    bootstrap_means = []
    for _ in range(n_bootstraps):
        sample = [rng.choice(deltas) for _ in range(n)]
        bootstrap_means.append(sum(sample) / n)

    bootstrap_means.sort()

    alpha = 1.0 - confidence
    lower_idx = int((alpha / 2.0) * n_bootstraps)
    upper_idx = int((1.0 - alpha / 2.0) * n_bootstraps)
    upper_idx = min(upper_idx, n_bootstraps - 1)

    ci_lower = bootstrap_means[lower_idx]
    ci_upper = bootstrap_means[upper_idx]

    # Two-sided empirical p-value for H0: delta == 0
    if mean_delta >= 0:
        count_le_zero = sum(1 for m in bootstrap_means if m <= 0.0)
        p_val = min(1.0, 2.0 * (count_le_zero / n_bootstraps))
    else:
        count_ge_zero = sum(1 for m in bootstrap_means if m >= 0.0)
        p_val = min(1.0, 2.0 * (count_ge_zero / n_bootstraps))

    return {
        "mean_delta": round(mean_delta, 4),
        "ci_lower": round(ci_lower, 4),
        "ci_upper": round(ci_upper, 4),
        "p_value": round(p_val, 4),
        "n_triplets": n,
        "n_bootstraps": n_bootstraps,
    }


def apply_fdr_correction(
    p_values: list[float],
    alpha: float = 0.05,
) -> list[dict[str, Any]]:
    """Apply Benjamini-Hochberg False Discovery Rate (FDR) adjustment to p-values.

    Args:
        p_values: List of nominal p-values across hypothesis family.
        alpha: Family-wise false discovery rate threshold.

    Returns:
        List of dicts containing original_p, adjusted_p, significant (bool), and rank.
    """
    m = len(p_values)
    if m == 0:
        return []

    # Pair with original indices
    indexed_p = sorted(enumerate(p_values), key=lambda x: x[1])

    # Calculate BH adjusted p-values
    # q_(i) = min_{j >= i} ( (m / j) * p_(j) )
    adj_values = [0.0] * m
    min_so_far = 1.0
    for rank_1_based in range(m, 0, -1):
        idx, p = indexed_p[rank_1_based - 1]
        adjusted = min(1.0, (m / rank_1_based) * p)
        min_so_far = min(min_so_far, adjusted)
        adj_values[rank_1_based - 1] = min_so_far

    # Reconstruct in original order
    results = [None] * m
    for rank_idx, (orig_idx, orig_p) in enumerate(indexed_p):
        adjusted_p = round(adj_values[rank_idx], 4)
        results[orig_idx] = {
            "rank": rank_idx + 1,
            "original_p": round(orig_p, 4),
            "adjusted_p": adjusted_p,
            "significant": adjusted_p <= alpha,
        }

    return results
