"""Check command: unified diagnostics, DLP audit, unit tests, and config inspection."""
from core.cli.commands.config import run_config
from core.cli.commands.dlp import run_dlp_audit
from core.cli.commands.doctor import run_doctor
from core.cli.commands.test import run_test_list, run_test_run


def run_check_dispatch(args) -> int:
    """Dispatch flat `check` command across diagnostics, DLP audit, tests, and config."""
    if getattr(args, "all", False):
        codes = [
            run_doctor(args),
            run_dlp_audit(args),
            run_test_list(args) if getattr(args, "list", False) else run_test_run(args),
        ]
        return next((c for c in codes if c != 0), 0)

    selected = []
    if getattr(args, "dlp", False):
        selected.append(run_dlp_audit)
    if getattr(args, "tests", False) or getattr(args, "list", False):
        selected.append(run_test_list if getattr(args, "list", False) else run_test_run)
    if getattr(args, "config", False):
        selected.append(run_config)

    if not selected:
        return run_doctor(args)

    codes = [fn(args) for fn in selected]
    return next((c for c in codes if c != 0), 0)
