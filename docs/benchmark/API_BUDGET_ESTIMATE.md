# API Budget & Token Telemetry Estimate

## 1. Executive Summary & Zero-Cost Certification
This document certifies that the **Thai Injection Eval v2.0 Benchmark** operates strictly within a **100% Free-Tier Policy** ($0.00 total expense). All benchmarked models, rate limits, and quota consumption metrics were empirically validated through a 10-triplet (30-case) pilot pipeline execution.

- **Primary Blue Target**: `gemini-3.5-flash-lite` (Google AI Studio Free Tier).
- **Adversarial Red / Cross-Family Target**: `openrouter:meta-llama/llama-3.3-70b-instruct:free` (OpenRouter Free Tier).
- **Fallback Target**: `gemini-3.1-flash-lite` (Google AI Studio Free Tier).
- **Paid Model Prohibition**: Absolute prohibition on heavy/paid endpoints (`gemini-3.8-flash`, paid Anthropic/OpenAI).

---

## 2. Empirical Pilot Telemetry (10 Triplet Scenarios / 30 Cases)

| Language | Cases Evaluated | Mean Input Tokens ($T_{\text{in}}$) | Mean Output Tokens ($T_{\text{out}}$) | Ratio vs English ($T_{\text{in}}$) |
|---|---|---|---|---|
| **English (EN)** | 10 | 25.3 | 25.7 | 1.00x |
| **Thai (TH)** | 10 | 36.5 | 41.1 | 1.44x |
| **Code-Switch (TH-EN)** | 10 | 28.6 | 30.4 | 1.13x |

> [!NOTE]
> Thai script exhibits a ~1.44x token inflation relative to English due to sub-word syllable tokenization in byte-pair encoding vocabularies. This is explicitly accounted for in our token budget.

---

## 3. Full Benchmark Quota & Capacity Projections

### Workload Scale
- **Dataset A (Triplets)**: 36 unique scenarios $\times$ 3 language variants = **108 test cases**.
- **Defense Tiers**: 5 tiers (`off`, `prompt`, `tools`, `all`, `spotlight`).
- **Total Invocations per Model**: $108 \times 5 = \mathbf{540\text{ API requests}}$.
- **Average Prompt + System Overhead**: ~61 tokens per call.
- **Estimated Input Volume**: ~33,282 tokens per model.
- **Estimated Output Volume**: ~17,496 tokens per model.

---

## 4. Quota Feasibility Gate & Verification

| Provider & Model | Free Quota Limit | Benchmark Demand | Safety Margin | Feasibility Status |
|---|---|---|---|---|
| **Google Gemini** (`gemini-3.5-flash-lite`) | 1,500 RPD / 15 RPM / 1M TPM | 540 RPD / ~10 RPM / ~1,200 TPM | **64% under daily limit** | **PASSED (100% Free)** |
| **OpenRouter** (`llama-3.3-70b-instruct:free`) | 20 RPM / Unlimited free credits | 10 RPM (paced via 6s inter-turn sleep) | **50% under RPM limit** | **PASSED (100% Free)** |

### Execution Pace & Throttling
To respect the 15 RPM rate ceiling without hitting HTTP 429 backoff penalties:
- Inter-request pacing: $\ge 4.5$ seconds between model calls.
- Total static benchmark wall-clock time: $540 \times 4.5\text{s} \approx 40.5$ minutes.
- Dollar cost: **$0.00**.
