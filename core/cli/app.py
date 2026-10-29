"""Root Application and Argument Dispatcher for Thai Injection Eval CLI."""
import argparse
import sys
from typing import List, Optional

from core import __version__
from core.cli.terminal.colors import bold, cyan, dim, green, red, yellow
from core.cli.terminal.tty import is_tty, should_color
from core.cli.commands.eval import run_eval_run, run_eval_list, run_eval_info, ALL_DEFENSES, PARALLEL_DEFENSES
from core.cli.commands.probe import run_probe_run, run_probe_list
from core.cli.commands.dlp import run_dlp_audit
from core.cli.commands.test import run_test_run, run_test_list
from core.cli.commands.serve import run_serve
from core.cli.commands.doctor import run_doctor
from core.cli.commands.config import run_config
from core.cli.commands.version import run_version, get_version_info
from core.cli.commands.chat import run_chat


class SecurityCLIParser(argparse.ArgumentParser):
    """Custom ArgumentParser with improved error messages and exit code 2 on syntax error."""

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
  thai-eval doctor                            Check environment, dependencies, datasets
  thai-eval eval run --parallel --dry-run     Estimate API requests for 3-lang parallel set
  thai-eval eval run --parallel               Run 3-language parallel security benchmark
  thai-eval chat                              Interactive Red-Teaming playground & manual chat
  thai-eval chat --defense tools              Interactive chat directly with 'tools' defense
  thai-eval probe run                         Run Item 7 probing suite against tools/all
  thai-eval dlp audit                         Audit regex DLP bypass encodings offline
  thai-eval eval list --parallel              List test cases in parallel dataset
  thai-eval test run                          Run internal verification unit test suite
  thai-eval serve --port 5000                 Start interactive Red-Teaming Web UI
  thai-eval config show                       Display effective environment configuration

Exit Codes:
  0 = Success / Security Criteria Satisfied
  1 = Security Failure / Vulnerability Detected (Breach / ASR exceeded)
  2 = CLI Usage / Syntax Error / Validation Error
  3 = Runtime / Environment Error (Missing dependencies / API error)
""",
    )

    root.add_argument("-V", "--version", action="store_true", help="Show application version and exit")

    subparsers = root.add_subparsers(dest="command", title="Available Commands", metavar="<command>")

    # 1. EVAL command
    eval_parser = subparsers.add_parser("eval", parents=[common_parser], help="Security evaluation benchmark harness")
    eval_subs = eval_parser.add_subparsers(dest="subcommand", title="Eval Actions", metavar="<action>")

    # eval run
    eval_run = eval_subs.add_parser("run", parents=[common_parser], help="Run security evaluation benchmark")
    eval_run.add_argument("--target", choices=["builtin", "openai", "callable"], default="builtin", help="Target system under test")
    eval_run.add_argument("--defense", choices=list(ALL_DEFENSES), default="off", help="Defense configuration tier")
    eval_run.add_argument("--role", "--blue-role", dest="role", choices=["student_guest", "registrar_staff", "system_admin"], default="registrar_staff", help="Target Blue Assistant role persona")
    eval_run.add_argument("--parallel", action="store_true", help="Run parallel 3-language benchmark (test_cases_parallel.json)")
    eval_run.add_argument("--linguistic", action="store_true", help="Run Thai linguistic & direct DLP evasion benchmark (test_cases_linguistic.json)")
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
    eval_run.add_argument("--model", default="default", help="Model name for external target")
    eval_run.add_argument("--api-key", default="", help="API key for external target")

    # eval list
    eval_list = eval_subs.add_parser("list", parents=[common_parser], help="List evaluation test cases")
    eval_list.add_argument("--cases", default=None, help="Custom test cases JSON file")
    eval_list.add_argument("--parallel", action="store_true", help="List parallel 3-language cases")
    eval_list.add_argument("--linguistic", action="store_true", help="List linguistic benchmark cases")

    # eval info
    eval_info = eval_subs.add_parser("info", parents=[common_parser], help="Inspect detailed specification of a test case")
    eval_info.add_argument("case_id", help="Case ID to inspect (e.g., TH-1, PAR-01-TH)")

    # 2. PROBE command
    probe_parser = subparsers.add_parser("probe", parents=[common_parser], help="Item 7 Probing benchmark suite")
    probe_subs = probe_parser.add_subparsers(dest="subcommand", title="Probe Actions", metavar="<action>")

    # probe run
    probe_run = probe_subs.add_parser("run", parents=[common_parser], help="Run probing benchmark suite")
    probe_run.add_argument("--defenses", default="tools,all", help="Comma-separated defense tiers (default: tools,all)")
    probe_run.add_argument("--repeats", type=int, default=1, help="Repetitions per case")
    probe_run.add_argument("--probing-cases", default="data/test_cases_probing.json", help="Path to probing cases file")
    probe_run.add_argument("--target", choices=["builtin", "openai", "callable"], default="builtin", help="Target adapter")
    probe_run.add_argument("--role", default="registrar_staff", help="Target role")
    probe_run.add_argument("--dry-run", action="store_true", help="Estimate API requests without making live calls")
    probe_run.add_argument("--publish", action="store_true", help="Export sanitized published artifacts")
    probe_run.add_argument("--export-dir", default="results", help="Directory for exported reports")
    probe_run.add_argument("--export-name", default="probing_report", help="Report prefix")

    # probe list
    probe_list = probe_subs.add_parser("list", parents=[common_parser], help="List probing test cases")
    probe_list.add_argument("--probing-cases", default="data/test_cases_probing.json", help="Path to probing cases file")

    # 3. DLP command
    dlp_parser = subparsers.add_parser("dlp", parents=[common_parser], help="Data Loss Prevention (DLP) bypass audit")
    dlp_subs = dlp_parser.add_subparsers(dest="subcommand", title="DLP Actions", metavar="<action>")
    dlp_audit = dlp_subs.add_parser("audit", parents=[common_parser], help="Run offline deterministic DLP bypass probe audit")
    dlp_audit.add_argument("--fail-on-bypass", action="store_true", help="Exit code 1 if any bypass encoding succeeds")

    # 4. TEST command
    test_parser = subparsers.add_parser("test", parents=[common_parser], help="Internal verification and unit tests")
    test_subs = test_parser.add_subparsers(dest="subcommand", title="Test Actions", metavar="<action>")
    test_run = test_subs.add_parser("run", parents=[common_parser], help="Run offline unit test suite")
    test_run.add_argument("-k", "--pattern", default="test_*.py", help="Test file pattern (default: test_*.py)")
    test_run.add_argument("-s", "--start-dir", default="tests", help="Directory to discover tests")

    test_list = test_subs.add_parser("list", parents=[common_parser], help="List discovered test cases")
    test_list.add_argument("-s", "--start-dir", default="tests", help="Directory to discover tests")

    # 5. SERVE command
    serve_parser = subparsers.add_parser("serve", parents=[common_parser], help="Launch interactive Red-Teaming Web UI (Flask)")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    serve_parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")

    # 6. DOCTOR command
    subparsers.add_parser("doctor", parents=[common_parser], help="Inspect environment, dependencies, datasets, and runtime health")

    # 7. CONFIG command
    config_parser = subparsers.add_parser("config", parents=[common_parser], help="View and inspect system configuration securely")
    config_subs = config_parser.add_subparsers(dest="subcommand", title="Config Actions", metavar="<action>")
    config_subs.add_parser("show", parents=[common_parser], help="Display effective configuration with masked secrets")

    # 8. VERSION command
    subparsers.add_parser("version", parents=[common_parser], help="Display application version and system environment info")

    # 9. CHAT / MANUAL command (Interactive Red-Teaming Playground)
    chat_parser = subparsers.add_parser("chat", parents=[common_parser], help="Interactive Red-Teaming playground & manual chat session")
    chat_parser.add_argument("--defense", choices=list(ALL_DEFENSES), default=None, help="Preset defense configuration tier (skips prompt)")
    chat_parser.add_argument("--role", "--blue-role", dest="role", choices=["student_guest", "registrar_staff", "system_admin"], default=None, help="Preset Blue Assistant role persona")
    chat_parser.add_argument("--red-profile", choices=["script_kiddie", "realistic_attacker", "academic_auditor", "insider_threat", "blackbox_probe"], default=None, help="Preset Red Attacker profile")
    chat_parser.add_argument("--lang", choices=["Thai", "English", "Mixed"], default=None, help="Preset target language")
    chat_parser.add_argument("--attack-type", choices=["direct", "indirect", "recon", "semantic", "roleplay", "fewshot", "obfuscation"], default=None, help="Preset attack category")
    chat_parser.add_argument("--targets", default=None, help="Target tables/keywords to monitor (comma-separated)")

    manual_parser = subparsers.add_parser("manual", parents=[common_parser], help="Alias for 'chat' (Interactive manual testing)")
    manual_parser.add_argument("--defense", choices=list(ALL_DEFENSES), default=None, help="Preset defense configuration tier")
    manual_parser.add_argument("--role", "--blue-role", dest="role", choices=["student_guest", "registrar_staff", "system_admin"], default=None, help="Preset Blue Assistant role persona")
    manual_parser.add_argument("--red-profile", choices=["script_kiddie", "realistic_attacker", "academic_auditor", "insider_threat", "blackbox_probe"], default=None, help="Preset Red Attacker profile")
    manual_parser.add_argument("--lang", choices=["Thai", "English", "Mixed"], default=None, help="Preset target language")
    manual_parser.add_argument("--attack-type", choices=["direct", "indirect", "recon", "semantic", "roleplay", "fewshot", "obfuscation"], default=None, help="Preset attack category")
    manual_parser.add_argument("--targets", default=None, help="Target tables/keywords to monitor (comma-separated)")

    return root


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
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

    # If --version flag passed anywhere at root
    if "-V" in argv or "--version" in argv:
        args = parser.parse_args(argv)
        return run_version(args)

    # If no arguments provided
    if not argv:
        # If in interactive TTY terminal, print welcoming banner and root help
        if is_tty():
            print("\n" + bold("Thai Injection Eval", enabled=True) + f" v{__version__} - Security Benchmark CLI")
            print(dim("Run 'thai-eval --help' for options or 'thai-eval doctor' for health check.\n"))
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
    elif cmd == "serve":
        return run_serve(args)
    elif cmd in ("chat", "manual"):
        return run_chat(args)
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

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
