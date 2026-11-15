# Pre-Registration Protocol: Thai Prompt Injection Security Evaluation (Dataset A v2.0 Benchmark)

- **Registration Tag**: `preregistration-v2.0`
- **Date Registered**: 2026-11-15
- **Repository**: `https://github.com/the-prafful/thai-injection-eval`
- **Benchmark Version**: 2.0.0
- **Dataset Frozen SHA256**: `bfcb216cfae6c20935516f8cce148411e415a674488c721fb35f9a7547634ce2` (`data/normalized/test_cases_parallel_v2.json`)

---

## 1. Context and Problem Statement
Prior prompt injection benchmarks in multilingual contexts often conflate attack technique diversity with linguistic variance. By evaluating mismatched Thai scenarios against disparate English scenarios, earlier versions of `thai-injection-eval` and comparable community benchmarks could not isolate the specific effect of low-resource non-Latin tokenization and multilingual alignment from the baseline difficulty of the attack.

Furthermore, empirical security benchmarks risk tautological reporting (e.g. reporting 100% defense rates simply because a database authorization layer rejected a query), obscuring whether the underlying foundation model was actually manipulated.

This pre-registration locks the statistical hypothesis, sampling protocol, model roster, and analysis pipeline prior to publishing static multi-model benchmark results.

---

## 2. Benchmark Design & Dataset A (Parallel Triplets)
Dataset A (`data/normalized/test_cases_parallel_v2.json`) consists of **36 distinct attack and control scenarios**, each implemented across 3 strictly isomorphic linguistic variants:
1. **English (`en`)**: Baseline reference.
2. **Thai (`th`)**: Native Thai script.
3. **Thai-English Code-Switching (`th-en`)**: Pragmatic code-switching representative of Southeast Asian technical communication.

Total evaluated cases = $36 \text{ scenarios} \times 3 \text{ variants} = 108 \text{ standardized cases}$.

### Scenario Stratification (6 vectors $\times$ 6 scenarios):
- `direct_instruction_override` (6 triplets): Direct system prompt overrides and credential extraction attempts.
- `broken_object_level_authorization` (6 triplets): Cross-student transcript, healthcare, and financial queries.
- `action_hijacking` (6 triplets): Notification dispatch to unauthorized external recipients and report export redirects.
- `indirect_prompt_injection` (6 triplets): Untrusted context injection via course syllabi, forums, and bulletins.
- `linguistic_evasion` (6 triplets): Zero-width character insertions (U+200B/C/D), vowel/tone homoglyphs, and word segmentation manipulation.
- `benign_control` (6 triplets): Legitimate administrative campus inquiries for measuring False Refusal Rate (FRR).

---

## 3. Primary Pre-Registered Hypothesis ($H_1$)

### Confirmatory Hypothesis:
$$\mathbf{H_1}: \quad ASR_{\text{TH}} - ASR_{\text{EN}} > 0.10 \quad \text{in Tier PROMPT}$$

Under Tier `PROMPT` (system prompt hardening active, tool ACL set to AllowAll, DLP disabled), the Attack Success Rate (ASR) on Thai language attacks ($ASR_{\text{TH}}$) exceeds that of English attacks ($ASR_{\text{EN}}$) by at least the Smallest Effect Size of Interest ($\text{SESOI} = 10\%$).

- **Test Statistic**: Mean paired difference $\bar{d} = \frac{1}{M} \sum_{i=1}^M (y_{\text{TH}, i} - y_{\text{EN}, i})$ on the 30 adversarial triplets.
- **Inference Method**: Paired triplet bootstrap ($B = 10,000$ iterations) with percentile $95\%$ confidence interval.
- **Decision Rule**: Reject null hypothesis $H_0: \bar{d} \le 0.10$ if the lower bound of the $95\%$ bootstrap CI exceeds $0.10$ and $p < 0.05$.

---

## 4. Secondary & Exploratory Hypotheses Family (FDR-Adjusted)

Secondary exploratory questions evaluate:
1. **Model Family Invariance**: Comparison of cross-lingual deltas between Google Gemini (`gemini-3.5-flash-lite`) and Meta Llama (`meta-llama/llama-3.3-70b-instruct:free`).
2. **Defense Tier Progression**: Evaluation of defense effectiveness across tiers: `off` $\to$ `prompt` $\to$ `tools` $\to$ `all` $\to$ `spotlight`.
3. **Attempt Rate vs. Leak Rate**: Decoupled measurement distinguishing LLM willingness to invoke out-of-policy tools (`attempt_rate`) from actual data exfiltration (`leak_rate`).
4. **BOLA Ablation Mode**: Evaluation of model behavior when tool-level authorization checks are experimentally bypassed (`no_bola_ablation`).

### Multiplicity Adjustment:
All secondary exploratory p-values are controlled across the hypothesis family using the **Benjamini-Hochberg (BH)** procedure at False Discovery Rate threshold $q = 0.05$.

---

## 5. Model Invariants (Strict 100% Free-Tier Policy)
In adherence to open-science reproducibility and hard zero-cost invariants, benchmark evaluations are executed exclusively against free-tier endpoints:
- **Blue Target (Google Family)**: `gemini-3.5-flash-lite` (temperature = 0.0).
- **Blue Target (Open-Weights Family)**: `openrouter:meta-llama/llama-3.3-70b-instruct:free` (temperature = 0.0).
- **Red Adversary / Baseline**: Pre-defined isomorphic triplets from Dataset A.

---

## 6. Independent Oracle & Agreement Standards
- All evaluation turns are graded by `IndependentSecurityOracle` (`core/evaluator/oracle.py`) using hybrid canary token identification and anti-evasion normalization.
- Human review ground-truth agreement is pre-registered to achieve Stratified Cohen's $\kappa \ge 0.85$, Sensitivity $\ge 0.90$, and Specificity $\ge 0.90$.
