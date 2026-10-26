"""Command handlers for Thai Injection Eval CLI."""
from core.cli.commands.eval import run_eval_run, run_eval_list, run_eval_info
from core.cli.commands.probe import run_probe_run, run_probe_list
from core.cli.commands.dlp import run_dlp_audit
from core.cli.commands.test import run_test_run, run_test_list
from core.cli.commands.serve import run_serve
from core.cli.commands.doctor import run_doctor
from core.cli.commands.config import run_config
from core.cli.commands.version import run_version
from core.cli.commands.chat import (
    run_chat,
    print_security_turn_card,
    print_preflight_briefing_card,
    review_payload_card,
)

__all__ = [
    "run_eval_run",
    "run_eval_list",
    "run_eval_info",
    "run_probe_run",
    "run_probe_list",
    "run_dlp_audit",
    "run_test_run",
    "run_test_list",
    "run_serve",
    "run_doctor",
    "run_config",
    "run_version",
    "run_chat",
    "print_security_turn_card",
    "print_preflight_briefing_card",
    "review_payload_card",
]
