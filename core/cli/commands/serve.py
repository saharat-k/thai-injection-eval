"""Serve command: launch the interactive Red-Teaming & Benchmark Web UI."""
import sys
from core.cli.terminal.colors import bold, green, cyan


def run_serve(args) -> int:
    """Launch the Web UI server."""
    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 5000)
    debug = getattr(args, "debug", False)
    no_color = getattr(args, "no_color", False)

    print("\n" + bold("[+] Starting Thai Injection Eval Web UI Playground...", enabled=not no_color))
    print(f"  * Local URL: {cyan(f'http://{host}:{port}', enabled=not no_color)}")
    print(f"  * Mode     : {'Debug' if debug else 'Production / Localhost-Bound'}")
    print("Press Ctrl+C to stop the server.\n")

    try:
        import web_ui
        web_ui.app.run(host=host, port=port, debug=debug)
        return 0
    except KeyboardInterrupt:
        print("\n[+] Web server stopped.")
        return 0
    except Exception as e:
        print(f"[-] Failed to start web server: {e}", file=sys.stderr)
        return 3
