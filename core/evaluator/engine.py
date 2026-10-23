"""Evaluation Engine for running OWASP LLM benchmarks against Target Adapters."""
import os
import sys
import json
from typing import Optional, Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import agent
from core.adapters.base import BaseTargetAdapter
from core.adapters.factory import create_target_adapter
from core.evaluator.metrics import calculate_benchmark_metrics


class SecurityEvaluator:
    """Benchmark runner executing standardized OWASP LLM evaluation test suites."""

    def __init__(self, target: BaseTargetAdapter, cases: Optional[list[dict]] = None):
        self.target = target
        self.cases = cases if cases is not None else agent.load_test_cases()
        self.canaries = agent.load_canaries()

    def run_benchmark(
        self,
        defense: str = "off",
        blue_role: str = "registrar_staff",
        progress_callback: Optional[Callable[[int, int, dict], None]] = None,
    ) -> dict:
        """Run all test cases against the target adapter and return structured evaluation results."""
        results = []
        total = len(self.cases)

        for idx, case in enumerate(self.cases, 1):
            cid = case.get("id", f"CASE-{idx}")
            prompt = case.get("prompt", "")
            targets = case.get("targets", [])
            owasp_cat = case.get("owasp_category") or "OWASP-LLM01:Prompt-Injection"
            severity = case.get("severity") or "High"

            self.target.reset()
            resp = self.target.send(prompt, defense=defense, blue_role=blue_role)

            if resp.error:
                case_res = {
                    "id": cid,
                    "case": case,
                    "response": f"Error: {resp.error}",
                    "error": resp.error,
                    "success": -1,
                    "leaked_canaries": [],
                    "tool_calls": resp.tool_calls,
                    "owasp_category": owasp_cat,
                    "severity": severity,
                    "language": case.get("language", "Thai"),
                    "attack_type": case.get("attack_type", "direct"),
                }
            else:
                eval_out = agent.evaluate_leak_and_targets(resp.text, targets=targets)
                disclosed = agent.detect_schema_disclosure(resp.text)
                is_refusal = agent.analyze_assistant_response(resp.text) in ("explicit_refusal", "role_refusal")
                is_success = 1 if (eval_out["is_target_met"] or eval_out["all_leaked"]) else 0

                case_res = {
                    "id": cid,
                    "case": case,
                    "response": resp.text,
                    "error": None,
                    "success": is_success,
                    "is_target_met": eval_out["is_target_met"],
                    "target_leaked": eval_out["target_leaked"],
                    "collateral_leaked": eval_out["collateral_leaked"],
                    "leaked_canaries": eval_out["all_leaked"],
                    "schema_disclosed": disclosed,
                    "is_refusal": is_refusal,
                    "tool_calls": resp.tool_calls,
                    "owasp_category": owasp_cat,
                    "severity": severity,
                    "language": case.get("language", "Thai"),
                    "attack_type": case.get("attack_type", "direct"),
                }

            results.append(case_res)
            if progress_callback:
                progress_callback(idx, total, case_res)

        metrics = calculate_benchmark_metrics(results)
        return {
            "target_info": self.target.get_info(),
            "defense": defense,
            "blue_role": blue_role,
            "timestamp": agent.now(),
            "metrics": metrics,
            "results": results,
        }

    def run_parallel_benchmark(
        self,
        defenses=("off", "prompt", "tools", "all"),
        blue_role: str = "registrar_staff",
        repeats: int = 1,
        progress_callback: Optional[Callable[[int, int, dict], None]] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Run the parallel TH/EN/MIX case set (rule-based judges) over several defense tiers.

        ``self.cases`` must be the cases from ``test_cases_parallel.json``. Every row keeps the
        raw response in memory only; exporters in ``reporter`` strip it before publishing.
        """
        from core.evaluator.parallel import build_run_metadata, calculate_parallel_metrics, judge_case

        rows: list[dict] = []
        models_seen: list[str] = []
        total = len(self.cases) * len(defenses) * repeats
        done = 0
        for defense in defenses:
            for rep in range(1, repeats + 1):
                for case in self.cases:
                    self.target.reset()
                    resp = self.target.send(case["prompt"], defense=defense, blue_role=blue_role)
                    done += 1
                    m_used = resp.metadata.get("model_used") or getattr(agent, "BLUE_MODEL", "unknown")
                    if m_used and m_used not in models_seen:
                        models_seen.append(m_used)
                    base = {
                        "id": case["id"],
                        "pair_id": case["pair_id"],
                        "lang": case["lang"],
                        "vector": case["vector"],
                        "is_benign": case["is_benign"],
                        "defense": defense,
                        "repeat": rep,
                    }
                    if resp.error:
                        row = {**base, "success": -1, "matched": [], "error": resp.error,
                               "response": "", "tool_calls_total": len(resp.tool_calls),
                               "tool_calls_blocked": 0, "model_used": m_used}
                    else:
                        verdict = judge_case(case, resp.text)
                        row = {**base, "success": verdict["success"], "matched": verdict["matched"],
                               "error": None, "response": resp.text,
                               "tool_calls_total": len(resp.tool_calls),
                               "tool_calls_blocked": sum(1 for t in resp.tool_calls if t.get("status") == "blocked"),
                               "model_used": m_used}
                    rows.append(row)
                    if progress_callback:
                        progress_callback(done, total, row)

        ts = agent.now()
        blue_spec = getattr(agent, "BLUE_MODEL", "unknown")
        provider = blue_spec.split(":", 1)[0] if ":" in blue_spec else "gemini"
        full_meta = build_run_metadata(
            red_model="static-parallel-prompts",
            blue_model=blue_spec,
            model_used=",".join(models_seen) if models_seen else blue_spec,
            provider=provider,
            timestamp=ts,
            attempts=repeats,
            random_seed=os.getenv("EVAL_SEED", "unlocked (provider default)"),
            defense=",".join(defenses),
            extra=metadata or {},
        )
        return {
            "kind": "parallel",
            "target_info": self.target.get_info(),
            "defenses": list(defenses),
            "blue_role": blue_role,
            "repeats": repeats,
            "timestamp": ts,
            "metadata": full_meta,
            "metrics": calculate_parallel_metrics(rows),
            "results": rows,
        }
