"""Thai Prompt Injection Evaluation Agent - Facade & CLI Entrypoint.

Delegates tool management to core.tools.legacy and runtime/evaluation to core.agent.runtime.
Preserves full backward compatibility and module attribute proxying for tests.
"""
import argparse
import sys

import core.tools.legacy as _legacy_tools
import core.agent.runtime as _agent_runtime

# Populate module globals from legacy tools and agent runtime (including private helpers)
for _mod in (_legacy_tools, _agent_runtime):
    for _name, _val in _mod.__dict__.items():
        if not _name.startswith("__"):
            globals()[_name] = _val


class _AgentModule(sys.modules[__name__].__class__):
    """Module proxy that syncs dynamic attributes to submodules and handles thread-local properties."""

    @property
    def _turn_tool_ceiling_enabled(self):
        return _legacy_tools._turn_tool_ceiling_enabled._val()

    @_turn_tool_ceiling_enabled.setter
    def _turn_tool_ceiling_enabled(self, val):
        _legacy_tools._turn_tool_ceiling_enabled._set(val)

    @property
    def _turn_tool_call_count(self):
        return _legacy_tools._turn_tool_call_count._val()

    @_turn_tool_call_count.setter
    def _turn_tool_call_count(self, val):
        _legacy_tools._turn_tool_call_count._set(val)

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if name == "_turn_tool_ceiling_enabled":
            _legacy_tools._turn_tool_ceiling_enabled._set(value)
            return
        if name == "_turn_tool_call_count":
            _legacy_tools._turn_tool_call_count._set(value)
            return
        if hasattr(_legacy_tools, name) or name in ("_uni_conn", "_res_conn"):
            setattr(_legacy_tools, name, value)
        if hasattr(_agent_runtime, name) or name in (
            "make_client",
            "BLUE_MODEL",
            "RED_MODEL",
            "MODEL_NAME",
            "_print_preflight",
            "_review_payload",
        ):
            setattr(_agent_runtime, name, value)

    def __delattr__(self, name):
        super().__delattr__(name)
        if hasattr(_legacy_tools, name):
            delattr(_legacy_tools, name)
        if hasattr(_agent_runtime, name):
            delattr(_agent_runtime, name)

    def __getattr__(self, name):
        if hasattr(_legacy_tools, name):
            return getattr(_legacy_tools, name)
        if hasattr(_agent_runtime, name):
            return getattr(_agent_runtime, name)
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


sys.modules[__name__].__class__ = _AgentModule


def interactive_menu():
    """Modern redirection: launch rich interactive CLI chat session."""
    try:
        from core.cli.commands.chat import run_chat

        dummy_args = argparse.Namespace(
            defense=None,
            role="registrar_staff",
            model=None,
            blue=None,
            red=None,
            profile="thai_nuanced_adversary",
            no_color=False,
            turns=3,
        )
        return run_chat(dummy_args)
    except (KeyboardInterrupt, EOFError):
        print("\nExiting interactive session.")
        return 0


def main():
    global RED_MODEL, BLUE_MODEL, MODEL_NAME
    p = argparse.ArgumentParser(description="Thai prompt-injection red/blue test")
    p.add_argument("--defense", choices=DEFENSE_LEVELS, default=None)
    p.add_argument("--attempts", type=int, default=None, help="max red attempts per case")
    p.add_argument("--case", default=None, help="specific test case ID (e.g., TH-1) or ALL")
    p.add_argument("--red", default=None, help="override RED_MODEL (e.g. openrouter:openrouter/free, gemini-3.5-flash-lite)")
    p.add_argument("--blue", default=None, help="override BLUE_MODEL (e.g. gemini-3.5-flash-lite, gemini-3.1-flash-lite)")
    p.add_argument("--blue-role", choices=list(BLUE_ROLES.keys()), default="registrar_staff", help="Blue agent role persona")
    p.add_argument("--red-profile", choices=list(RED_PROFILES.keys()), default="realistic_attacker", help="Red agent intelligence profile")
    p.add_argument("--eval-owasp", action="store_true", help="Run OWASP-aligned evaluation benchmark and export reports")
    a = p.parse_args()

    if a.red:
        RED_MODEL = a.red
        _agent_runtime.RED_MODEL = a.red
    if a.blue:
        BLUE_MODEL = a.blue
        _agent_runtime.BLUE_MODEL = a.blue
    MODEL_NAME = f"Red: {RED_MODEL} | Blue: {BLUE_MODEL}"
    _agent_runtime.MODEL_NAME = MODEL_NAME

    if a.eval_owasp:
        from core.adapters.factory import create_target_adapter
        from core.evaluator.engine import SecurityEvaluator
        from core.evaluator.reporter import export_report_files

        adapter = create_target_adapter("builtin", defense=a.defense or "all", blue_role=a.blue_role)
        evaluator = SecurityEvaluator(adapter)
        report = evaluator.run_benchmark(defense=a.defense or "all", blue_role=a.blue_role)
        md_p, js_p = export_report_files(report, output_dir="results", base_name="owasp_evaluation_report")
        m = report["metrics"]
        print(f"\n[OWASP Benchmark] ASR: {m['attack_success_rate']}% | FRR: {m['false_refusal_rate']}% | DES: {m['defense_efficiency_score']}%")
        print(f"Reports saved to {md_p} and {js_p}")
        return

    if a.defense is None and a.attempts is None and a.case is None:
        interactive_menu()  # no flags: show the mode menu
        return
    print_results(run_all(a.defense or "off", a.attempts or 3, case_id=a.case or "ALL", blue_role=a.blue_role, red_profile=a.red_profile))


if __name__ == "__main__":
    main()
