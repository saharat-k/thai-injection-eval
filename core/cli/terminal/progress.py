"""Progress reporting and terminal indicators."""
import sys
from typing import Optional, Callable
from core.cli.terminal.colors import status_badge, style, DIM, RESET
from core.cli.terminal.tty import is_tty, should_color


class ProgressReporter:
    """Configurable progress reporter for evaluation and benchmarking runs."""

    def __init__(self, quiet: bool = False, no_color: bool = False, stream=None):
        self.quiet = quiet
        self.stream = stream or sys.stdout
        self.interactive = is_tty(self.stream)
        self.color_enabled = should_color(self.stream, force_no_color=no_color)

    def log(self, message: str):
        if not self.quiet:
            print(message, file=self.stream, flush=True)

    def step(self, label: str, status: str = "done"):
        """Print high-level steps like: [+] Loading benchmark ............. done"""
        if self.quiet:
            return
        dots = "." * max(2, 40 - len(label))
        badge = status_badge(status, enabled=self.color_enabled)
        prefix = style("[+]", DIM, enabled=self.color_enabled)
        print(f"{prefix} {label} {dots} {badge}", file=self.stream, flush=True)

    def make_eval_callback(self) -> Callable[[int, int, dict], None]:
        """Create a progress callback suitable for SecurityEvaluator."""
        def callback(idx: int, total: int, res: dict):
            if self.quiet:
                return
            succ = res.get("success", 0)
            if succ == 1:
                badge = status_badge("BREACH", enabled=self.color_enabled)
            elif succ == -1:
                badge = status_badge("ERROR", enabled=self.color_enabled)
            else:
                badge = status_badge("PASS", enabled=self.color_enabled)

            cid = res.get("id", f"#{idx}")
            owasp = res.get("owasp_category", res.get("category", "LLM01"))
            tier = res.get("defense", "")
            tier_str = f"| {tier:<7} " if tier else ""
            print(f"[{idx:02d}/{total:02d}] {cid:<14} {tier_str}| {badge} | {owasp}", file=self.stream, flush=True)

        return callback
