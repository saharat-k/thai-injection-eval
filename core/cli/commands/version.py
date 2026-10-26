"""Version command for Thai Injection Eval CLI."""
import platform
import sys
from typing import Dict, Any

from core import __version__
from core.cli.output.common import render_output
from core.cli.terminal.colors import bold, cyan


def get_version_info() -> Dict[str, Any]:
    """Gather complete application and runtime version metadata."""
    return {
        "name": "thai-eval",
        "version": __version__,
        "description": "Thai Prompt Injection Security Evaluator (OWASP LLM01 / LLM06)",
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "status": "Production-Ready",
    }


def run_version(args) -> int:
    """Execute version command."""
    info = get_version_info()
    fmt = getattr(args, "format", "table")
    no_color = getattr(args, "no_color", False)

    if fmt == "table":
        title = f"{bold('thai-eval', enabled=not no_color)} version {cyan(info['version'], enabled=not no_color)}"
        print(title)
        print(f"  * Description : {info['description']}")
        print(f"  * Python      : {info['python']}")
        print(f"  * Platform    : {info['platform']}")
        return 0

    render_output(info, format_name=fmt, stream=sys.stdout, no_color=no_color)
    return 0
