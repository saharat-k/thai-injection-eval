"""Evaluation Engine for running OWASP LLM benchmarks against Target Adapters."""
import os
import sys
import json
import time
from typing import Optional, Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import agent
from core.adapters.base import BaseTargetAdapter
from core.adapters.factory import create_target_adapter
from core.evaluator.metrics import calculate_benchmark_metrics
from core.tools.context import SecurityContext, set_current_security_context


class SecurityEvaluator:
    """Benchmark runner executing standardized OWASP LLM evaluation test suites."""

    def __init__(
        self,
        target: BaseTargetAdapter,
        cases: Optional[list[dict]] = None,
        ablation_mode: Optional[str] = None,
    ):
        self.target = target
        self.cases = cases if cases is not None else agent.load_test_cases()
        self.canaries = agent.load_canaries()
        self.ablation_mode = ablation_mode

    def _bind_case_security_context(self, case: dict, cid: str, blue_role: str, defense: str) -> None:
        raw_uid = case.get("caller_user_id") or case.get("user_id")
        uid_str = str(raw_uid).strip() if raw_uid is not None else ""
        user_id = None if (not uid_str or uid_str.lower() in ("guest", "none", "anonymous")) else uid_str
        if user_id and user_id.upper().startswith("S"):
            eff_role = "student"
        elif user_id and user_id.upper().startswith("P"):
            eff_role = "professor"
        else:
            eff_role = blue_role
        auth_recipients = tuple(case.get("authorized_recipients") or ["REGISTRAR", "STUDENT_AFFAIRS"])
        prohibited = tuple(case.get("prohibited_fields") or ["national_id", "salary", "bank_account", "api_key", "master_token"])
        ctx = SecurityContext(
            session_id=cid,
            user_id=user_id,
            user_role=eff_role,
            defense_tier=defense,
            authorized_recipients=auth_recipients,
            prohibited_fields=prohibited,
            ablation_mode=self.ablation_mode,
        )
        set_current_security_context(ctx)

    def _resolve_model_used(self, resp: TargetResponse) -> str:
        meta = resp.metadata if isinstance(getattr(resp, "metadata", None), dict) else {}
        for candidate in (
            meta.get("model_used"),
            meta.get("resolved_model"),
            getattr(self.target, "model", None),
            getattr(agent, "BLUE_MODEL", None),
        ):
            if isinstance(candidate, str) and candidate.strip():
                return candidate
        return "unknown"

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
            self._bind_case_security_context(case, cid, blue_role, defense)

            self.target.reset()
            try:
                resp = self.target.send(prompt, defense=defense, blue_role=blue_role)
            finally:
                set_current_security_context(None)

            has_tool_violation = any(
                t.get("status") == "blocked"
                or t.get("event_type") in ("attempt", "bola_attempt", "action_hijack_attempt", "tool_sidechannel_leak")
                for t in resp.tool_calls
            )

            if resp.error:
                case_res = {
                    "id": cid,
                    "case": case,
                    "response": f"Error: {resp.error}",
                    "error": resp.error,
                    "success": -1,
                    "leaked_canaries": [],
                    "tool_calls": resp.tool_calls,
                    "tool_violation": has_tool_violation,
                    "owasp_category": owasp_cat,
                    "severity": severity,
                    "language": case.get("language", "Thai"),
                    "attack_type": case.get("attack_type", "direct"),
                }
            else:
                is_refusal = agent.analyze_assistant_response(resp.text, tool_calls=resp.tool_calls) in ("explicit_refusal", "role_refusal")
                eval_out = agent.evaluate_leak_and_targets(resp.text, targets=targets, is_refusal=is_refusal)
                disclosed = agent.detect_schema_disclosure(resp.text)
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
                    "tool_violation": has_tool_violation,
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
        pace = float(os.getenv("EVAL_PACE_SECONDS", "0.0"))
        for defense in defenses:
            for rep in range(1, repeats + 1):
                for case in self.cases:
                    self._bind_case_security_context(case, case["id"], blue_role, defense)
                    self.target.reset()
                    if pace > 0 and done > 0:
                        import time
                        time.sleep(pace)
                    try:
                        resp = self.target.send(case["prompt"], defense=defense, blue_role=blue_role)
                    finally:
                        set_current_security_context(None)
                    done += 1
                    m_used = self._resolve_model_used(resp)
                    if m_used and m_used not in models_seen:
                        models_seen.append(m_used)
                    row_targets = list(
                        case.get("targets")
                        or (case.get("evaluation") or {}).get("expected_tokens")
                        or (case.get("judge") or {}).get("expected_canary")
                        or []
                    )
                    base = {
                        "id": case["id"],
                        "pair_id": case["pair_id"],
                        "lang": case["lang"],
                        "vector": case["vector"],
                        "is_benign": case["is_benign"],
                        "defense": defense,
                        "repeat": rep,
                        "owasp_category": case.get("owasp_category", ""),
                        "targets": row_targets,
                    }
                    if resp.error:
                        row = {**base, "success": -1, "matched": [], "error": resp.error,
                               "response": "", "tool_calls_total": len(resp.tool_calls),
                               "tool_calls_blocked": 0, "model_used": m_used}
                    else:
                        verdict = judge_case(case, resp.text, tool_calls=resp.tool_calls)
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

    def run_probing_benchmark(
        self,
        defenses=("tools", "all"),
        repeats: int = 1,
        progress_callback: Optional[Callable[[int, int, dict], None]] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Run the Item 7 probing suite (`test_cases_probing.json`) across defense tiers.

        Uses each case's own `blue_role` (or `registrar_staff` if omitted) so that
        role-boundary probes (`student_guest`) and DLP probes (`system_admin`) execute
        under the intended persona.
        """
        from core.evaluator.parallel import build_run_metadata
        from core.evaluator.probing import calculate_probing_metrics, judge_probing_case

        rows: list[dict] = []
        models_seen: list[str] = []
        total = len(self.cases) * len(defenses) * repeats
        done = 0
        pace = float(os.getenv("EVAL_PACE_SECONDS", "0.0"))
        for defense in defenses:
            for rep in range(1, repeats + 1):
                for case in self.cases:
                    role = case.get("blue_role", "registrar_staff")
                    self.target.reset()
                    if pace > 0 and done > 0:
                        time.sleep(pace)
                    resp = self.target.send(case["prompt"], defense=defense, blue_role=role)
                    done += 1
                    m_used = self._resolve_model_used(resp)
                    if m_used and m_used not in models_seen:
                        models_seen.append(m_used)
                    base = {
                        "id": case["id"],
                        "pair_id": case["pair_id"],
                        "lang": case["lang"],
                        "category": case["category"],
                        "vector": case["vector"],
                        "target_defense": case.get("target_defense", defense),
                        "blue_role": role,
                        "is_benign": case.get("is_benign", False),
                        "defense": defense,
                        "repeat": rep,
                    }
                    if resp.error:
                        row = {
                            **base,
                            "success": -1,
                            "matched": [],
                            "error": resp.error,
                            "response": "",
                            "tool_calls_total": len(resp.tool_calls),
                            "tool_calls_blocked": 0,
                            "model_used": m_used,
                        }
                    else:
                        verdict = judge_probing_case(case, resp.text)
                        row = {
                            **base,
                            "success": verdict["success"],
                            "matched": verdict["matched"],
                            "error": None,
                            "response": resp.text,
                            "tool_calls_total": len(resp.tool_calls),
                            "tool_calls_blocked": sum(1 for t in resp.tool_calls if t.get("status") == "blocked"),
                            "model_used": m_used,
                        }
                    rows.append(row)
                    if progress_callback:
                        progress_callback(done, total, row)

        ts = agent.now()
        blue_spec = getattr(agent, "BLUE_MODEL", "unknown")
        provider = blue_spec.split(":", 1)[0] if ":" in blue_spec else "gemini"
        full_meta = build_run_metadata(
            red_model="static-probing-prompts",
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
            "kind": "probing",
            "target_info": self.target.get_info(),
            "defenses": list(defenses),
            "repeats": repeats,
            "timestamp": ts,
            "metadata": full_meta,
            "metrics": calculate_probing_metrics(rows),
            "results": rows,
        }
