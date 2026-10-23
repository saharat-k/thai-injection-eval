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
