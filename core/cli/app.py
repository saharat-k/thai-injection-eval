"""Root Application and Argument Dispatcher for Thai Injection Eval CLI."""
import argparse
import sys
from typing import List, Optional

from dotenv import load_dotenv

from core import __version__
from core.cli.terminal.colors import bold, cyan, dim, green, red, yellow
from core.cli.terminal.tty import is_tty, should_color
from core.cli.terminal.banner import get_banner, print_banner
from core.cli.commands.eval import (
    run_eval_run,
    run_eval_list,
    run_eval_info,
    run_benchmark_run,
    run_scan_dispatch,
    ALL_DEFENSES,
    PARALLEL_DEFENSES,
)
from core.cli.commands.probe import run_probe_run, run_probe_list
from core.cli.commands.dlp import run_dlp_audit
from core.cli.commands.test import run_test_run, run_test_list
from core.cli.commands.serve import run_serve
from core.cli.commands.doctor import run_doctor
from core.cli.commands.config import run_config
from core.cli.commands.check import run_check_dispatch
from core.cli.commands.version import run_version, get_version_info
from core.cli.commands.chat import run_chat
from core.cli.commands.redteam import (
    _apply_positional_attack_target,
    _resolve_attack_presets,
    run_attack_dispatch,
    run_redteam_list,
    run_redteam_run,
    run_redteam_techniques,
)

MUTATOR_CHOICES = (
    "none",
    "zero_width",
    "homoglyph",
    "code_switch",
    "thai_number_words",
    "thai_digits",
    "arithmetic_split",
    "caesar_shift",
    "base64",
    "hex",
    "syllable_spacing",
    "variation_selector",
    "thai_phonetic",
    "json_unicode_escape",
    "all",
)


RED_PROFILE_CHOICES = [
    "thai_nuanced_adversary",
    "realistic_attacker",
    "insider_threat",
    "security_auditor",
]
ATTACK_TYPE_CHOICES = ["direct", "indirect", "recon", "semantic", "roleplay", "fewshot", "obfuscation", "tree"]


def _add_attack_execution_flags(parser: argparse.ArgumentParser) -> None:
    """Register shared attack/redteam execution flags with None defaults for preset resolution."""
    parser.add_argument("-c", "--case", default=None, help="Target specific Case ID (default: all cases in dataset)")
    parser.add_argument("-f", "--cases", default=None, help="Custom test cases JSON file (default: data/normalized/test_cases.json)")
    parser.add_argument("--parallel", action="store_true", help="Use parallel 3-language dataset (test_cases_parallel.json)")
    parser.add_argument("-d", "--defense", choices=list(ALL_DEFENSES), default=None, help="Defense configuration tier (default: all)")
    parser.add_argument("-r", "--role", "--blue-role", dest="role", choices=["student_guest", "registrar_staff", "system_admin"], default=None, help="Target Blue Assistant role persona (default: registrar_staff)")
    parser.add_argument("--model", default=None, help="Target Blue model identifier")
    parser.add_argument("-b", "--blue", "--blue-model", dest="blue", default=None, help="Target Blue model (alias for --model)")
    parser.add_argument("-R", "--red", "--red-model", dest="red", default=None, help="Red adversary model (e.g. openrouter:openrouter/free)")
    parser.add_argument("-p", "--profile", "--red-profile", dest="profile", choices=RED_PROFILE_CHOICES, default=None, help="Red adversary profile (default: thai_nuanced_adversary)")
    parser.add_argument("-s", "--strategy", choices=["crescendo", "tap", "template", "tree"], default=None, help="Multi-turn attack strategy: template, crescendo, tap, or tree (default: template)")
    parser.add_argument("-t", "--technique", default=None, help="Red-team technique mode: none, auto, core (sweep 8), all (sweep 14), or comma-separated IDs")
    parser.add_argument("--beam-width", type=int, default=None, help="Beam search width for tree strategy (default: 2)")
    parser.add_argument("--branch-factor", type=int, default=None, help="Number of concurrent attack mutations per beam branch (default: 3)")
    parser.add_argument("-n", "--attempts", "--turns", dest="attempts", type=int, default=None, help="Maximum multi-turn attack rounds per case (default: 3)")
    parser.add_argument("-m", "--mutator", choices=MUTATOR_CHOICES, default=None, help="Dynamic Thai NLP mutator (default: none)")
    parser.add_argument("--backtrack", action="store_true", default=None, help="Enable Crescendo refusal backtracking (USENIX 2025 / PyRIT)")
    parser.add_argument("--max-backtracks", type=int, default=None, help="Maximum refusal backtracks per case (default: 2)")
    parser.add_argument("-P", "--preset", choices=["quick", "stealth", "aggressive", "sweep"], default=None, help="Attack preset: quick, stealth, aggressive, or sweep")
    parser.add_argument("-l", "--limit", type=int, default=None, help="Limit total cases to evaluate")
    parser.add_argument("--dry-run", action="store_true", help="Run simulation using rule-based mock runner without consuming API quota")
    parser.add_argument("-o", "--export-dir", default="results", help="Directory for exported reports")
    parser.add_argument("--export-name", default="redteam_evaluation_report", help="Report filename prefix")


def _add_chat_flags(parser: argparse.ArgumentParser) -> None:
    """Register shared interactive chat/manual flags."""
    parser.add_argument("-d", "--defense", choices=list(ALL_DEFENSES), default=None, help="Preset defense configuration tier (skips prompt)")
    parser.add_argument("-r", "--role", "--blue-role", dest="role", choices=["student_guest", "registrar_staff", "system_admin"], default=None, help="Preset Blue Assistant role persona")
    parser.add_argument("--model", default=None, help="Target Blue model identifier")
    parser.add_argument("-b", "--blue", "--blue-model", dest="blue", default=None, help="Target Blue model (alias for --model)")
    parser.add_argument("-R", "--red", "--red-model", dest="red", default=None, help="Red adversary model")
    parser.add_argument("-p", "--red-profile", dest="red_profile", choices=RED_PROFILE_CHOICES, default=None, help="Preset Red Attacker profile")
    parser.add_argument("--lang", choices=["Thai", "English", "Mixed"], default=None, help="Preset target language")
    parser.add_argument("--attack-type", choices=ATTACK_TYPE_CHOICES, default=None, help="Preset attack category (includes 'tree')")
    parser.add_argument("-m", "--mutator", choices=MUTATOR_CHOICES, default="none", help="Dynamic Thai NLP mutator (default: none)")
    parser.add_argument("-t", "--technique", default="none", help="Red-team technique mode: none, auto, core, all, technique ID, or comma-separated stack (default: none)")
    parser.add_argument("--targets", default=None, help="Target tables/keywords to monitor (comma-separated)")


def _add_ui_flags(parser: argparse.ArgumentParser) -> None:
    """Register shared Web UI server flags across ui, serve, and view."""
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    parser.add_argument("--open", action="store_true", help="Automatically open web browser upon launch")


class SecurityCLIParser(argparse.ArgumentParser):
    """Custom ArgumentParser with improved error messages and exit code 2 on syntax error."""

    show_banner_in_help: bool = False

    def parse_args(self, args=None, namespace=None):
        ns = super().parse_args(args=args, namespace=namespace)
        blue_val = getattr(ns, "blue", None)
        model_val = getattr(ns, "model", None)
        if blue_val and not model_val:
            ns.model = blue_val
        elif model_val and not blue_val:
            ns.blue = model_val
        cmd = getattr(ns, "command", None)
        if cmd == "attack":
            _apply_positional_attack_target(ns)
            _resolve_attack_presets(ns)
        elif cmd == "redteam" and getattr(ns, "subcommand", None) in ("run", None):
            _resolve_attack_presets(ns)
        return ns

    def format_help(self) -> str:
        text = super().format_help()
        if self.show_banner_in_help:
            args_list = getattr(self, "_active_argv", None) or sys.argv
            is_quiet = any(a in args_list for a in ("-q", "--quiet", "--json"))
            if not is_quiet:
                no_color = "--no-color" in args_list or not should_color(sys.stdout)
                banner = get_banner(color=not no_color)
                return f"{banner}\n{text}"
        return text

    def error(self, message):
        print(red(f"Error: {message}", enabled=should_color(sys.stderr)), file=sys.stderr)
        print(f"Run '{self.prog} --help' for usage instructions.", file=sys.stderr)
        sys.exit(2)


def build_parser() -> SecurityCLIParser:
    """Build the hierarchical argument parser."""
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logs")
    common_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode; suppress decorative output and progress")
    common_parser.add_argument("--json", action="store_true", help="Shorthand for --format json")
    common_parser.add_argument("--format", choices=["table", "json", "jsonl", "csv"], default="table", help="Output format contract")
    common_parser.add_argument("--no-color", action="store_true", help="Disable colored output (honors NO_COLOR env)")

    root = SecurityCLIParser(
        prog="thai-eval",
        description="Thai Prompt Injection Security Evaluator & Benchmark (OWASP LLM01 / LLM06)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common_parser],
        epilog="""Examples:
  thai-eval attack TH-1 -t auto               Run adaptive multi-turn attack on Case TH-1
  thai-eval attack -P stealth --parallel      Run stealth Crescendo preset across parallel cases
  thai-eval attack --list techniques          List all 14 registered red-team techniques
  thai-eval scan --parallel --dry-run         Estimate API requests for 3-language parallel set
  thai-eval scan --probing                    Run Item 7 probing suite against tools/all
  thai-eval scan --all --dry-run              Validate and estimate unified multi-suite benchmark
  thai-eval scan TH-1 --info                  Inspect specification of Case TH-1
  thai-eval chat -d tools -t auto             Interactive Red-Teaming playground with 'tools' defense
  thai-eval ui --open -p 5000                 Start interactive Red-Teaming Web UI and open browser
  thai-eval check                             Inspect environment, dependencies, and dataset health
  thai-eval check --dlp --fail-on-bypass      Audit regex DLP bypass encodings offline
  thai-eval check --all                       Run diagnostics, DLP audit, and unit tests sequentially

Exit Codes:
  0 = Success / Security Criteria Satisfied
  1 = Security Failure / Vulnerability Detected (Breach / ASR exceeded)
  2 = CLI Usage / Syntax Error / Validation Error
  3 = Runtime / Environment Error (Missing dependencies / API error)
""",
    )
    root.show_banner_in_help = True

    root.add_argument("-V", "--version", action="store_true", help="Show application version and exit")

    subparsers = root.add_subparsers(
        dest="command",
        title="Available Commands",
        metavar="{attack,scan,chat,ui,check}",
    )

    # Primary flat 5 commands (visible in root --help)
    # 1. ATTACK command
    attack_parser = subparsers.add_parser("attack", parents=[common_parser], help="Run adaptive multi-turn red-teaming attacks or list techniques/profiles/cases")
    attack_parser.add_argument("target", nargs="?", default=None, help="Optional target Case ID (e.g., TH-1, ALL) or cases .json path")
    _add_attack_execution_flags(attack_parser)
    attack_parser.add_argument("--list", choices=["techniques", "profiles", "cases"], default=None, help="List registered techniques, adversary profiles, or test cases and exit")
    attack_parser.add_argument("--category", choices=["framing", "structural", "agentic_adaptive", "evasion"], default=None, help="Filter --list techniques by category")
    attack_parser.add_argument("--tier", choices=["core", "advanced"], default=None, help="Filter --list techniques by tier")

    # 2. SCAN command (consolidates eval, probe, benchmark)
    scan_parser = subparsers.add_parser("scan", parents=[common_parser], help="Run security evaluation benchmarks, probing suites, or inspect cases")
    scan_parser.add_argument("scan_target", nargs="?", metavar="TARGET", default=None, help="Optional Case ID (with --info) or custom cases .json file path")
    scan_parser.add_argument("--parallel", action="store_true", help="Run parallel 3-language benchmark (test_cases_parallel.json)")
    scan_parser.add_argument("--linguistic", action="store_true", help="Run Thai linguistic & direct DLP evasion benchmark")
    scan_parser.add_argument("--indirect", action="store_true", help="Run Indirect prompt injection & Spotlighting benchmark")
    scan_parser.add_argument("--benign", action="store_true", help="Run benign control & utility baseline benchmark")
    scan_parser.add_argument("--probing", action="store_true", help="Run Item 7 probing suite against tools/all")
    scan_parser.add_argument("--all", action="store_true", help="Run all benchmark suites and generate leaderboard")
    scan_parser.add_argument("--suites", default=None, help="Comma-separated suites for unified benchmark (parallel,indirect,probing,linguistic,benign)")
    scan_parser.add_argument("--from-results", nargs="?", const="results", default=None, help="Generate leaderboard directly from cached JSON results")
    scan_parser.add_argument("--list", action="store_true", help="List test cases in the selected suite and exit")
    scan_parser.add_argument("--info", action="store_true", help="Inspect detailed specification of a test case by ID")
    scan_parser.add_argument("-c", "--case", default=None, help="Target Case ID to inspect with --info")
    scan_parser.add_argument("-f", "--cases", default=None, help="Custom test cases JSON file")
    scan_parser.add_argument("--parallel-cases", default=None, help="Path to parallel cases file")
    scan_parser.add_argument("--indirect-cases", default="data/normalized/test_cases_indirect.json", help="Path to indirect cases file")
    scan_parser.add_argument("--benign-cases", default="data/normalized/test_cases_benign.json", help="Path to benign cases file")
    scan_parser.add_argument("--probing-cases", default=None, help="Path to probing cases file")
    scan_parser.add_argument("--target", choices=["builtin", "openai", "callable"], default="builtin", help="Target system under test")
    scan_parser.add_argument("-d", "--defense", choices=list(ALL_DEFENSES), default="off", help="Defense configuration tier")
    scan_parser.add_argument("--defenses", default=None, help="Comma-separated defense tiers for multi-tier suites")
    scan_parser.add_argument("-r", "--role", "--blue-role", dest="role", choices=["student_guest", "registrar_staff", "system_admin"], default="registrar_staff", help="Target Blue Assistant role persona")
    scan_parser.add_argument("--repeats", type=int, default=1, help="Repetitions per case/tier")
    scan_parser.add_argument("-l", "--limit", type=int, default=None, help="Limit total cases to evaluate (cost control)")
    scan_parser.add_argument("--sample-per-vector", type=int, default=None, help="Sample N cases per attack vector (linguistic suite)")
    scan_parser.add_argument("-o", "--export-dir", default="results", help="Directory for exported reports")
    scan_parser.add_argument("--export-name", default=None, help="Report filename prefix")
    scan_parser.add_argument("--publish", action="store_true", help="Export sanitized published artifacts")
    scan_parser.add_argument("--dry-run", action="store_true", help="Validate inputs and estimate API calls without live execution")
    scan_parser.add_argument("--max-asr", type=float, default=5.0, help="Maximum acceptable Attack Success Rate (%%)")
    scan_parser.add_argument("--interactive", action="store_true", help="Launch interactive step-by-step TUI wizard")
    scan_parser.add_argument("--base-url", default="http://localhost:8000/v1", help="OpenAI-compatible base URL")
    scan_parser.add_argument("--model", default=None, help="Target Blue model identifier")
    scan_parser.add_argument("-b", "--blue", "--blue-model", dest="blue", default=None, help="Target Blue model (alias for --model)")
    scan_parser.add_argument("-R", "--red", "--red-model", dest="red", default=None, help="Red adversary model (optional override)")
    scan_parser.add_argument("--api-key", default="", help="API key for external target")

    # 3. CHAT command (consolidates chat, manual)
    chat_parser = subparsers.add_parser("chat", parents=[common_parser], help="Interactive Red-Teaming playground & manual chat session")
    _add_chat_flags(chat_parser)

    # 4. UI command (consolidates serve, view)
    ui_parser = subparsers.add_parser("ui", parents=[common_parser], help="Launch interactive Red-Teaming Web UI (Flask)")
    _add_ui_flags(ui_parser)

    # 5. CHECK command (consolidates doctor, dlp audit, test run, config show)
    check_parser = subparsers.add_parser("check", parents=[common_parser], help="Run environment diagnostics, DLP audit, unit tests, or inspect config")
    check_parser.add_argument("--dlp", action="store_true", help="Run offline deterministic DLP bypass probe audit")
    check_parser.add_argument("--fail-on-bypass", action="store_true", help="Exit code 1 if any DLP bypass encoding succeeds")
    check_parser.add_argument("--tests", action="store_true", help="Run or list offline internal verification unit tests")
    check_parser.add_argument("-k", "--pattern", default="test_*.py", help="Test file pattern for --tests (default: test_*.py)")
    check_parser.add_argument("-s", "--start-dir", default="tests", help="Directory to discover tests for --tests")
    check_parser.add_argument("--list", action="store_true", help="List discovered test cases instead of executing (with --tests)")
    check_parser.add_argument("--config", action="store_true", help="Display effective configuration with masked secrets")
    check_parser.add_argument("--all", action="store_true", help="Run diagnostics, DLP audit, and unit tests sequentially")

    # Legacy commands (omitted help= keeps them hidden from root --help while preserving full compatibility)
    # 1. EVAL command
    eval_parser = subparsers.add_parser("eval", parents=[common_parser])
    eval_subs = eval_parser.add_subparsers(dest="subcommand", title="Eval Actions", metavar="<action>")

    # eval run
    eval_run = eval_subs.add_parser("run", parents=[common_parser], help="Run security evaluation benchmark")
    eval_run.add_argument("--target", choices=["builtin", "openai", "callable"], default="builtin", help="Target system under test")
    eval_run.add_argument("--defense", choices=list(ALL_DEFENSES), default="off", help="Defense configuration tier")
    eval_run.add_argument("--role", "--blue-role", dest="role", choices=["student_guest", "registrar_staff", "system_admin"], default="registrar_staff", help="Target Blue Assistant role persona")
    eval_run.add_argument("--parallel", action="store_true", help="Run parallel 3-language benchmark (test_cases_parallel.json)")
    eval_run.add_argument("--linguistic", action="store_true", help="Run Thai linguistic & direct DLP evasion benchmark (test_cases_linguistic.json)")
    eval_run.add_argument("--indirect", action="store_true", help="Run Indirect prompt injection benchmark (test_cases_indirect.json)")
    eval_run.add_argument("--indirect-cases", default="data/normalized/test_cases_indirect.json", help="Path to indirect cases file")
    eval_run.add_argument("--benign", action="store_true", help="Run benign control benchmark (test_cases_benign.json)")
    eval_run.add_argument("--benign-cases", default="data/normalized/test_cases_benign.json", help="Path to benign cases file")
    eval_run.add_argument("--defenses", default=",".join(PARALLEL_DEFENSES), help="Comma-separated defense tiers for parallel run")
    eval_run.add_argument("--repeats", type=int, default=1, help="Repetitions per case/tier")
    eval_run.add_argument("--limit", type=int, default=None, help="Limit total cases to evaluate (cost control)")
    eval_run.add_argument("--sample-per-vector", type=int, default=None, help="Sample N cases per attack vector (cost control)")
    eval_run.add_argument("--cases", default=None, help="Custom test cases JSON file")
    eval_run.add_argument("--parallel-cases", default="data/test_cases_parallel.json", help="Path to parallel cases file")
    eval_run.add_argument("--dry-run", action="store_true", help="Validate inputs and estimate API calls without live execution")
    eval_run.add_argument("--publish", action="store_true", help="Export sanitized published artifacts")
    eval_run.add_argument("--export-dir", default="results", help="Directory for exported reports")
    eval_run.add_argument("--export-name", default="owasp_evaluation_report", help="Report filename prefix")
    eval_run.add_argument("--max-asr", type=float, default=5.0, help="Maximum acceptable Attack Success Rate (%%)")
    eval_run.add_argument("--interactive", action="store_true", help="Launch interactive step-by-step TUI wizard")
    eval_run.add_argument("--base-url", default="http://localhost:8000/v1", help="OpenAI-compatible base URL")
    eval_run.add_argument("--model", default=None, help="Target Blue model identifier")
    eval_run.add_argument("--blue", "--blue-model", dest="blue", default=None, help="Target Blue model (alias for --model)")
    eval_run.add_argument("--red", "--red-model", dest="red", default=None, help="Red adversary model (optional override)")
    eval_run.add_argument("--api-key", default="", help="API key for external target")

    # eval list
    eval_list = eval_subs.add_parser("list", parents=[common_parser], help="List evaluation test cases")
    eval_list.add_argument("--cases", default=None, help="Custom test cases JSON file")
    eval_list.add_argument("--parallel", action="store_true", help="List parallel 3-language cases")
    eval_list.add_argument("--linguistic", action="store_true", help="List linguistic benchmark cases")
    eval_list.add_argument("--indirect", action="store_true", help="List indirect benchmark cases")
    eval_list.add_argument("--benign", action="store_true", help="List benign control cases")

    # eval info
    eval_info = eval_subs.add_parser("info", parents=[common_parser], help="Inspect detailed specification of a test case")
    eval_info.add_argument("case_id", help="Case ID to inspect (e.g., TH-1, PAR-01-TH)")

    # 2. PROBE command
    probe_parser = subparsers.add_parser("probe", parents=[common_parser])
    probe_subs = probe_parser.add_subparsers(dest="subcommand", title="Probe Actions", metavar="<action>")

    # probe run
    probe_run = probe_subs.add_parser("run", parents=[common_parser], help="Run probing benchmark suite")
    probe_run.add_argument("--defenses", default="tools,all", help="Comma-separated defense tiers (default: tools,all)")
    probe_run.add_argument("--repeats", type=int, default=1, help="Repetitions per case")
    probe_run.add_argument("--limit", type=int, default=None, help="Limit total cases to evaluate")
    probe_run.add_argument("--probing-cases", default="data/test_cases_probing.json", help="Path to probing cases file")
    probe_run.add_argument("--target", choices=["builtin", "openai", "callable"], default="builtin", help="Target adapter")
    probe_run.add_argument("--role", default="registrar_staff", help="Target role")
    probe_run.add_argument("--model", default=None, help="Target Blue model identifier")
    probe_run.add_argument("--blue", "--blue-model", dest="blue", default=None, help="Target Blue model (alias for --model)")
    probe_run.add_argument("--dry-run", action="store_true", help="Estimate API requests without making live calls")
    probe_run.add_argument("--publish", action="store_true", help="Export sanitized published artifacts")
    probe_run.add_argument("--export-dir", default="results", help="Directory for exported reports")
    probe_run.add_argument("--export-name", default="probing_report", help="Report prefix")

    # probe list
    probe_list = probe_subs.add_parser("list", parents=[common_parser], help="List probing test cases")
    probe_list.add_argument("--probing-cases", default="data/test_cases_probing.json", help="Path to probing cases file")

    # 3. DLP command
    dlp_parser = subparsers.add_parser("dlp", parents=[common_parser])
    dlp_subs = dlp_parser.add_subparsers(dest="subcommand", title="DLP Actions", metavar="<action>")
    dlp_audit = dlp_subs.add_parser("audit", parents=[common_parser], help="Run offline deterministic DLP bypass probe audit")
    dlp_audit.add_argument("--fail-on-bypass", action="store_true", help="Exit code 1 if any bypass encoding succeeds")

    # 4. TEST command
    test_parser = subparsers.add_parser("test", parents=[common_parser])
    test_subs = test_parser.add_subparsers(dest="subcommand", title="Test Actions", metavar="<action>")
    test_run = test_subs.add_parser("run", parents=[common_parser], help="Run offline unit test suite")
    test_run.add_argument("-k", "--pattern", default="test_*.py", help="Test file pattern (default: test_*.py)")
    test_run.add_argument("-s", "--start-dir", default="tests", help="Directory to discover tests")

    test_list = test_subs.add_parser("list", parents=[common_parser], help="List discovered test cases")
    test_list.add_argument("-s", "--start-dir", default="tests", help="Directory to discover tests")

    # 5. SERVE / VIEW command
    for s_name in ("serve", "view"):
        s_parser = subparsers.add_parser(s_name, parents=[common_parser])
        _add_ui_flags(s_parser)

    # 6. DOCTOR command
    subparsers.add_parser("doctor", parents=[common_parser])

    # 7. CONFIG command
    config_parser = subparsers.add_parser("config", parents=[common_parser])
    config_subs = config_parser.add_subparsers(dest="subcommand", title="Config Actions", metavar="<action>")
    config_subs.add_parser("show", parents=[common_parser], help="Display effective configuration with masked secrets")

    # 8. VERSION command
    subparsers.add_parser("version", parents=[common_parser])

    # 9. MANUAL command (alias for chat)
    manual_parser = subparsers.add_parser("manual", parents=[common_parser])
    _add_chat_flags(manual_parser)

    # 10. REDTEAM command
    redteam_parser = subparsers.add_parser("redteam", parents=[common_parser])
    redteam_subs = redteam_parser.add_subparsers(dest="subcommand", title="Redteam Actions", metavar="<action>")

    # redteam run
    redteam_run = redteam_subs.add_parser("run", parents=[common_parser], help="Run multi-turn adversarial red-teaming evaluation")
    _add_attack_execution_flags(redteam_run)

    # redteam list
    redteam_subs.add_parser("list", parents=[common_parser], help="List available Red adversary profiles and sociolinguistic vectors")

    # redteam techniques
    redteam_techniques = redteam_subs.add_parser("techniques", parents=[common_parser], help="List registered red-team techniques")
    redteam_techniques.add_argument("--category", choices=["framing", "structural", "agentic_adaptive", "evasion"], default=None, help="Filter techniques by category")
    redteam_techniques.add_argument("--tier", choices=["core", "advanced"], default=None, help="Filter techniques by tier")

    # 11. BENCHMARK command
    bench_parser = subparsers.add_parser("benchmark", parents=[common_parser])
    bench_subs = bench_parser.add_subparsers(dest="subcommand", title="Benchmark Actions", metavar="<action>")
    bench_run = bench_subs.add_parser("run", parents=[common_parser], help="Execute benchmark suites and generate comparative scorecard")
    bench_run.add_argument("--all", action="store_true", help="Run all suites (parallel, indirect, probing, linguistic, benign)")
    bench_run.add_argument("--suites", default="parallel,indirect,probing,linguistic,benign", help="Comma-separated list of suites to evaluate")
    bench_run.add_argument("--defenses", default="off,prompt,tools,spotlight,all", help="Comma-separated defense tiers")
    bench_run.add_argument("--repeats", type=int, default=1, help="Repetitions per test case")
    bench_run.add_argument("--target", choices=["builtin", "openai", "callable"], default="builtin", help="Target adapter")
    bench_run.add_argument("--role", default="registrar_staff", help="Target assistant role")
    bench_run.add_argument("--base-url", default="http://localhost:8000/v1", help="OpenAI-compatible base URL")
    bench_run.add_argument("--model", default=None, help="Target Blue model identifier")
    bench_run.add_argument("--blue", "--blue-model", dest="blue", default=None, help="Target Blue model (alias for --model)")
    bench_run.add_argument("--red", "--red-model", dest="red", default=None, help="Red adversary model (optional override)")
    bench_run.add_argument("--api-key", default="", help="API key for target")
    bench_run.add_argument("--dry-run", action="store_true", help="Estimate total API calls and validate without execution")
    bench_run.add_argument("--export-dir", default="results", help="Directory for exported reports")
    bench_run.add_argument("--export-name", default="benchmark_leaderboard", help="Leaderboard output filename prefix")
    bench_run.add_argument("--from-results", nargs="?", const="results", default=None, help="Generate leaderboard directly from cached JSON results")
    bench_run.add_argument("--limit", type=int, default=None, help="Limit number of test cases evaluated per suite")

    return root


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    try:
        load_dotenv()
    except (PermissionError, OSError):
        pass

    # Ensure stdout/stderr handle UTF-8 cleanly without crashing on Windows cp1252
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    parser._active_argv = argv

    # If --version flag passed anywhere at root
    if "-V" in argv or "--version" in argv:
        args = parser.parse_args(argv)
        return run_version(args)

    # If no arguments provided
    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    # Normalize --json flag into format="json"
    if getattr(args, "json", False):
        args.format = "json"

    cmd = args.command
    subcmd = getattr(args, "subcommand", None)

    # Route commands
    if cmd == "version":
        return run_version(args)
    elif cmd == "doctor":
        return run_doctor(args)
    elif cmd == "config":
        return run_config(args)
    elif cmd == "check":
        return run_check_dispatch(args)
    elif cmd in ("ui", "serve", "view"):
        return run_serve(args)
    elif cmd in ("chat", "manual"):
        return run_chat(args)
    elif cmd == "attack":
        return run_attack_dispatch(args)
    elif cmd == "scan":
        return run_scan_dispatch(args)
    elif cmd == "dlp":
        if subcmd == "audit" or subcmd is None:
            return run_dlp_audit(args)
        parser.parse_args(["dlp", "--help"])
        return 2
    elif cmd == "test":
        if subcmd == "run" or subcmd is None:
            return run_test_run(args)
        elif subcmd == "list":
            return run_test_list(args)
        parser.parse_args(["test", "--help"])
        return 2
    elif cmd == "probe":
        if subcmd == "run":
            return run_probe_run(args)
        elif subcmd == "list":
            return run_probe_list(args)
        # default probe without subcmd shows probe help
        parser.parse_args(["probe", "--help"])
        return 2
    elif cmd == "eval":
        if subcmd == "run":
            return run_eval_run(args)
        elif subcmd == "list":
            return run_eval_list(args)
        elif subcmd == "info":
            return run_eval_info(args)
        parser.parse_args(["eval", "--help"])
        return 2
    elif cmd == "redteam":
        if subcmd == "run" or subcmd is None:
            return run_redteam_run(args)
        elif subcmd == "list":
            return run_redteam_list(args)
        elif subcmd == "techniques":
            return run_redteam_techniques(args)
        parser.parse_args(["redteam", "--help"])
        return 2
    elif cmd == "benchmark":
        if subcmd == "run" or subcmd is None:
            return run_benchmark_run(args)
        parser.parse_args(["benchmark", "--help"])
        return 2

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
