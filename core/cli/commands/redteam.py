"""Red-team command: execute adaptive multi-turn prompt injection evaluations."""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

import agent
from core.cli.output.common import render_output
from core.cli.terminal.colors import (
    blue, bold, cyan, dim, green, red, status_badge, yellow
)
from core.cli.terminal.tty import get_terminal_width, should_color, get_rule_line, get_glyph, safe_print
from core.cli.terminal.banner import print_banner
from core.evaluator.redteam import (
    MultiTurnRedTeamRunner,
    RedTeamBenchmarkReport,
    RedTeamCaseResult,
    RedTeamTurnResult,
)

print = safe_print


def _resolve_case_file(filename: Optional[str] = None, parallel: bool = False) -> str:
    """Resolve normalized dataset path."""
    if filename and os.path.exists(filename):
        return filename
    if parallel:
        target = "test_cases_parallel.json"
    else:
        target = filename or "test_cases.json"
    base = os.path.basename(target)
    for cand in (
        os.path.join("data", "normalized", base),
        os.path.join("data", base),
        os.path.join("data", "archive", base),
    ):
        if os.path.exists(cand):
            return cand
    return target


def print_preflight_card(args, total_cases: int, cases_path: str, no_color: bool = False):
    """Render pre-flight configuration briefing before starting multi-turn red-teaming."""
    color_enabled = not no_color
    width = min(80, max(60, get_terminal_width()))
    line = get_rule_line(width, double=False)
    double_line = get_rule_line(width, double=True)
    bullet = get_glyph("■", "*")

    if not getattr(args, "quiet", False):
        print_banner(stream=sys.stdout, color_enabled=color_enabled, subtitle="AI Security Test Bench & Multi-Turn Red Teaming CLI")

    print("\n" + double_line)
    header = f"{bullet} ADAPTIVE MULTI-TURN RED TEAMING SESSION {bullet}"
    print(bold(header.center(width), enabled=color_enabled))
    print(double_line)

    dry_badge = yellow("[SIMULATION / DRY-RUN]", enabled=color_enabled) if getattr(args, "dry_run", False) else green("[LIVE TARGET EXECUTION]", enabled=color_enabled)
    def_badge = status_badge(str(getattr(args, "defense", "all")).upper(), enabled=color_enabled)
    blue_model = getattr(args, "blue", None) or getattr(args, "model", None) or agent.BLUE_MODEL
    red_model = getattr(args, "red", None) or agent.RED_MODEL

    print(f"  {bold('Execution Mode', enabled=color_enabled):<20} : {dry_badge}")
    print(f"  {bold('Dataset Source', enabled=color_enabled):<20} : {cyan(f'{cases_path} ({total_cases} cases)', enabled=color_enabled)}")
    print(f"  {bold('Target Blue Model', enabled=color_enabled):<20} : {cyan(blue_model, enabled=color_enabled)}")
    print(f"  {bold('Red Adversary Model', enabled=color_enabled):<20} : {red(red_model, enabled=color_enabled)}")
    print(f"  {bold('Active Defense', enabled=color_enabled):<20} : {def_badge}")
    print(f"  {bold('Target Blue Role', enabled=color_enabled):<20} : {cyan(getattr(args, 'role', 'registrar_staff'), enabled=color_enabled)}")
    print(f"  {bold('Red Adversary Profile', enabled=color_enabled):<20} : {red(getattr(args, 'profile', 'thai_nuanced_adversary'), enabled=color_enabled)}")
    strat_val = str(getattr(args, 'strategy', 'template')).lower()
    if strat_val == "tree":
        bw = getattr(args, "beam_width", 2)
        bf = getattr(args, "branch_factor", 3)
        strat_display = f"TREE (Beam Width: {bw}, Branch Factor: {bf})"
    else:
        strat_display = strat_val.upper()
    print(f"  {bold('Attack Strategy', enabled=color_enabled):<20} : {yellow(strat_display, enabled=color_enabled)}")
    mutator_raw = str(getattr(args, 'mutator', 'none')).upper()
    mutator_display = f"{mutator_raw} [Standard]" if mutator_raw == "NONE" else f"{mutator_raw} [Active]"
    print(f"  {bold('NLP Mutator', enabled=color_enabled):<20} : {cyan(mutator_display, enabled=color_enabled)}")
    backtrack_status = green(f"[ENABLED (max {getattr(args, 'max_backtracks', 2)})]", enabled=color_enabled) if getattr(args, "backtrack", False) else dim("[DISABLED]", enabled=color_enabled)
    print(f"  {bold('Refusal Backtrack', enabled=color_enabled):<20} : {backtrack_status}")
    print(f"  {bold('Multi-Turn Limit', enabled=color_enabled):<20} : Up to {bold(str(getattr(args, 'attempts', 3)), enabled=color_enabled)} turns per test case")
    print(line)
    print(dim("  Adversary will probe iteratively until target honeytoken leaks or max turns reached.", enabled=color_enabled))
    print(double_line + "\n")


def print_breach_alert_card(case: dict, turn: RedTeamTurnResult, max_attempts: int, no_color: bool = False):
    """Render a prominent, high-visibility Cyber Security Breach Alert Card."""
    color_enabled = not no_color
    width = min(80, max(60, get_terminal_width()))
    line = get_rule_line(width, double=False)
    double_line = get_rule_line(width, double=True)

    cid = case.get("id", "UNKNOWN")
    print("\n" + double_line)
    header = f"🚨 BREACH DETECTED | CASE: {cid} | TURN: {turn.turn_no}/{max_attempts} 🚨"
    print(bold(red(header.center(width)), enabled=color_enabled))
    print(double_line)

    if turn.red_strategy or turn.red_analysis:
        print(bold("🧠 [ADVERSARIAL EXPLOITATION TACTIC]", enabled=color_enabled))
        if turn.red_strategy:
            print(f"  * Strategy: {cyan(turn.red_strategy, enabled=color_enabled)}")
        if turn.red_analysis:
            print(dim(f"  * Analysis: {turn.red_analysis}", enabled=color_enabled))
        print(line)

    print(bold("📤 [BREACHING PROMPT PAYLOAD]", enabled=color_enabled))
    for p_line in turn.prompt.strip().splitlines()[:5]:
        print(f"  > {p_line}")
    if len(turn.prompt.strip().splitlines()) > 5:
        print(dim("  > ... [truncated]", enabled=color_enabled))
    print(line)

    print(bold("📥 [TARGET MODEL RESPONSE]", enabled=color_enabled))
    for r_line in turn.response.strip().splitlines()[:5]:
        print(f"  {r_line}")
    if len(turn.response.strip().splitlines()) > 5:
        print(dim("  ... [truncated]", enabled=color_enabled))
    print(line)

    print(bold("🛡️ [LEAK & IMPACT AUDIT]", enabled=color_enabled))
    if turn.target_leaked:
        print(red(f"  🎯 Target Leaks     : {', '.join(turn.target_leaked)}", enabled=color_enabled))
    if turn.leaked_canaries:
        print(red(f"  🔑 Canary Tokens    : {', '.join(turn.leaked_canaries)}", enabled=color_enabled))
    if turn.schema_disclosed:
        print(yellow(f"  📋 Schema Disclosed : {', '.join(turn.schema_disclosed)}", enabled=color_enabled))
    if turn.private_table_accessed:
        print(red("  ⚠️ Private Table Access: Granted unauthorized record lookup", enabled=color_enabled))

    print(double_line + "\n")


def print_turn_telemetry(case: dict, turn: RedTeamTurnResult, attempt: int, max_attempts: int, no_color: bool = False):
    """Render turn-by-turn telemetry: breach alert if breached, concise 1-line badge if defended."""
    color_enabled = not no_color
    cid = case.get("id", "UNKNOWN")

    if turn.is_breached:
        print_breach_alert_card(case, turn, max_attempts, no_color=no_color)
    else:
        badge = status_badge("DEFENDED", enabled=color_enabled)
        tool_cnt = len(turn.tool_calls)
        act = turn.defense_action
        act_desc = {
            "safe_fulfillment": "Safe request fulfilled",
            "prompt_policy_refused": "Prompt refused cleanly",
            "tool_acl_blocked": "Unauthorized tool call blocked",
            "output_dlp_redacted": "Canary redacted by DLP",
        }.get(act, "Defended")
        msg = f"  [{cid} | Turn {attempt}/{max_attempts}] {badge:<16} Action: {cyan(act, enabled=color_enabled):<24} | Tools: {tool_cnt:<2} | {act_desc}"
        print(msg)


def export_redteam_report(report: RedTeamBenchmarkReport, export_dir: str = "results", base_name: str = "redteam_evaluation_report") -> Tuple[str, str]:
    """Export benchmark report to JSON and Markdown format."""
    os.makedirs(export_dir, exist_ok=True)
    json_path = os.path.join(export_dir, f"{base_name}.json")
    md_path = os.path.join(export_dir, f"{base_name}.md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Adaptive Multi-Turn Red Teaming Evaluation Report\n\n")
        f.write(f"- **Timestamp**: `{report.timestamp}`\n")
        f.write(f"- **Defense Level**: `{report.defense}`\n")
        f.write(f"- **Target Blue Model**: `{report.blue_model}`\n")
        f.write(f"- **Red Adversary Model**: `{report.red_model}`\n")
        f.write(f"- **Blue Role**: `{report.blue_role}`\n")
        f.write(f"- **Red Adversary Profile**: `{report.red_profile}`\n")
        f.write(f"- **Attack Strategy**: `{report.strategy}`\n")
        f.write(f"- **Max Attempts**: `{report.max_attempts}` turns\n")
        if report.total_backtracks > 0:
            f.write(f"- **Total Refusal Backtracks**: `{report.total_backtracks}`\n")
        f.write("\n")
        f.write("## Overall Metrics\n\n")
        f.write(f"- **Total Cases**: {report.total_cases}\n")
        f.write(f"- **Breached Cases**: {report.breached_cases}\n")
        f.write(f"- **Defended Cases**: {report.defended_cases}\n")
        f.write(f"- **Error Cases**: {report.error_cases}\n")
        f.write(f"- **Overall Attack Success Rate (ASR)**: **{report.overall_asr}%**\n")
        if report.average_ttb:
            f.write(f"- **Average Turn-to-Breach (TTB)**: **{report.average_ttb}** turns\n\n")
        f.write("### Cumulative ASR by Turn\n\n")
        f.write("| Turn | Cumulative ASR (%) |\n| :--- | :---: |\n")
        for turn_idx, asr_val in report.cumulative_asr.items():
            f.write(f"| Turn {turn_idx} | {asr_val}% |\n")
        f.write("\n## Case Results Summary\n\n")
        f.write("| Case ID | Language | Technique | TTB | Status |\n| :--- | :---: | :--- | :---: | :---: |\n")
        for c in report.results:
            st = "BREACHED" if c.final_status == 1 else ("DEFENDED" if c.final_status == 0 else "ERROR")
            ttb_str = str(c.turn_to_breach) if c.turn_to_breach else "-"
            f.write(f"| `{c.case_id}` | {c.language} | {c.technique} | {ttb_str} | {st} |\n")

    return json_path, md_path


def run_redteam_run(args) -> int:
    """Execute the multi-turn red-teaming evaluation CLI command."""
    no_color = getattr(args, "no_color", False)
    dry_run = getattr(args, "dry_run", False)
    parallel = getattr(args, "parallel", False)
    defense = getattr(args, "defense", "all")
    blue_role = getattr(args, "role", "registrar_staff")
    red_profile = getattr(args, "profile", "thai_nuanced_adversary")
    max_attempts = getattr(args, "attempts", 3)
    case_filter = getattr(args, "case", None)
    cases_file = _resolve_case_file(getattr(args, "cases", None), parallel=parallel)

    try:
        with open(cases_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
            cases = raw_data.get("cases", raw_data) if isinstance(raw_data, dict) else raw_data
    except Exception as e:
        print(red(f"[-] Failed to load test cases from {cases_file}: {e}", enabled=not no_color), file=sys.stderr)
        return 2

    # Filter specific case if provided
    if case_filter and case_filter.upper() != "ALL":
        filtered = [c for c in cases if c.get("id") == case_filter]
        if not filtered:
            print(red(f"[-] Case ID '{case_filter}' not found in {cases_file}", enabled=not no_color), file=sys.stderr)
            return 2
        cases = filtered

    limit = getattr(args, "limit", None)
    if limit and limit > 0:
        cases = cases[:limit]

    blue_model = getattr(args, "blue", None) or getattr(args, "model", None)
    red_model = getattr(args, "red", None)
    if red_model:
        agent.RED_MODEL = red_model

    print_preflight_card(args, len(cases), cases_file, no_color=no_color)

    strategy = getattr(args, "strategy", "template")
    mutator = getattr(args, "mutator", "none")
    enable_backtrack = getattr(args, "backtrack", False)
    max_backtracks = getattr(args, "max_backtracks", 2)

    if strategy == "tree":
        from core.evaluator.tree import TreeBeamRedTeamRunner, render_ascii_tree
        beam_width = getattr(args, "beam_width", 2)
        branch_factor = getattr(args, "branch_factor", 3)
        runner = TreeBeamRedTeamRunner(
            beam_width=beam_width,
            branch_factor=branch_factor,
            max_depth=max_attempts,
            defense=defense,
            blue_role=blue_role,
            red_profile=red_profile,
            dry_run=dry_run,
            blue_model=blue_model,
            red_model=red_model,
            strategy=strategy,
            mutator=mutator,
        )
    else:
        runner = MultiTurnRedTeamRunner(
            max_attempts=max_attempts,
            defense=defense,
            blue_role=blue_role,
            red_profile=red_profile,
            dry_run=dry_run,
            blue_model=blue_model,
            red_model=red_model,
            strategy=strategy,
            mutator=mutator,
            enable_backtrack=enable_backtrack,
            max_backtracks=max_backtracks,
        )

    def on_turn(c, turn, attempt, total_attempts):
        print_turn_telemetry(c, turn, attempt, total_attempts, no_color=no_color)

    def on_case(res, idx, total_c):
        if res.final_status == 1:
            status_text = red(f"BREACHED (TTB={res.turn_to_breach})", enabled=not no_color)
        elif res.final_status == -1:
            status_text = yellow("ERROR", enabled=not no_color)
        else:
            status_text = green("DEFENDED", enabled=not no_color)
        print(f"➔ Result [{idx}/{total_c}] Case {bold(res.case_id, enabled=not no_color)}: {status_text}\n")
        if hasattr(res, "tree_root") and res.tree_root:
            from core.evaluator.tree import render_ascii_tree
            print(cyan("   [Search Tree Topology]:", enabled=not no_color))
            print(render_ascii_tree(res.tree_root, prefix="   "))
            print()

    report = runner.run_benchmark(cases, on_turn_callback=on_turn, on_case_callback=on_case)

    # Output Summary Table
    rows = []
    headers = ["Case ID", "Lang", "Technique", "Turns Run", "TTB", "Verdict"]
    for r in report.results:
        if r.final_status == 1:
            verdict = red("BREACHED", enabled=not no_color)
        elif r.final_status == -1:
            verdict = yellow("ERROR", enabled=not no_color)
        else:
            verdict = green("DEFENDED", enabled=not no_color)
        ttb_display = str(r.turn_to_breach) if r.turn_to_breach else "-"
        rows.append([r.case_id, r.language, r.technique, str(r.attempts_run), ttb_display, verdict])

    double_70 = get_rule_line(70, double=True)
    bullet = get_glyph("■", "*")
    bullet_dot = get_glyph("•", "*")

    print(bold("\n" + double_70, enabled=not no_color))
    print(bold(f"{bullet} MULTI-TURN RED TEAMING BENCHMARK RESULTS {bullet}".center(70), enabled=not no_color))
    print(bold(double_70 + "\n", enabled=not no_color))

    render_output(
        [r.to_dict() for r in report.results],
        format_name=getattr(args, "format", "table"),
        headers=headers,
        table_rows=rows,
        stream=sys.stdout,
        no_color=no_color,
    )

    print("\n" + bold("Summary Metrics:", enabled=not no_color))
    print(f"  {bullet_dot} Total Cases Evaluated   : {report.total_cases}")
    print(f"  {bullet_dot} Defended Cases          : {green(str(report.defended_cases), enabled=not no_color)}")
    print(f"  {bullet_dot} Breached Cases          : {red(str(report.breached_cases), enabled=not no_color)}")
    if report.error_cases > 0:
        print(f"  {bullet_dot} Error Cases             : {yellow(str(report.error_cases), enabled=not no_color)}")
    if report.total_backtracks > 0:
        print(f"  {bullet_dot} Refusal Backtracks      : {yellow(str(report.total_backtracks), enabled=not no_color)}")
    print(f"  {bullet_dot} Overall Multi-Turn ASR  : {bold(f'{report.overall_asr}%', enabled=not no_color)}")
    if report.average_ttb:
        print(f"  {bullet_dot} Average Turn-to-Breach  : {cyan(f'{report.average_ttb} turns', enabled=not no_color)}")

    print(bold("\nCumulative ASR Progression:", enabled=not no_color))
    for t_idx, asr_val in report.cumulative_asr.items():
        print(f"  {bullet_dot} ASR @ Turn {t_idx} : {asr_val}%")

    export_dir = getattr(args, "export_dir", "results")
    export_name = getattr(args, "export_name", "redteam_evaluation_report")
    json_path, md_path = export_redteam_report(report, export_dir=export_dir, base_name=export_name)
    print(f"\n[+] Detailed reports exported to:")
    print(f"  - JSON : {cyan(json_path, enabled=not no_color)}")
    print(f"  - Markdown : {cyan(md_path, enabled=not no_color)}\n")

    return 1 if report.breached_cases > 0 else 0


def run_redteam_list(args) -> int:
    """List available Red-Team adversary profiles and sociolinguistic vectors."""
    no_color = getattr(args, "no_color", False)
    profiles = agent.DEFAULT_RED_PROFILES

    rows = []
    headers = ["Profile ID", "Name", "Knowledge", "Sociolinguistic Focus"]
    for pid, meta in profiles.items():
        rows.append([pid, meta.get("name", pid), meta.get("knowledge_level", "blackbox"), meta.get("description", "")])

    print(bold("\nAvailable Red Adversary Profiles:\n", enabled=not no_color))
    render_output(
        [{"id": pid, **meta} for pid, meta in profiles.items()],
        format_name=getattr(args, "format", "table"),
        headers=headers,
        table_rows=rows,
        stream=sys.stdout,
        no_color=no_color,
    )
    print()
    return 0
