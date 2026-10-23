"""Small statistics helpers (no third-party dependencies)."""
import math

Z_95 = 1.959963984540054  # two-sided 95% normal quantile


def wilson_interval(successes: int, n: int, z: float = Z_95):
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
