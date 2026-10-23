"""Offline repository hygiene and secret-pattern scanner for CI and local pre-push checks.

Checks:
1. No forbidden files (.env, .flask_secret, *.db, raw results/* outside results/published/) are tracked by git.
2. No real API key patterns (AIzaSy..., sk-or-v1-..., gsk_..., ghp_..., github_pat_...) appear in tracked files or git history, excluding explicit unit-test fixtures in tests/.
"""
import argparse
import re
import subprocess
import sys

SECRET_PATTERNS = [
    ("Google Gemini API Key", re.compile(r"AIzaSy[0-9A-Za-z\-_]{33}")),
    ("OpenRouter API Key", re.compile(r"sk-or-v1-[0-9a-fA-F]{64}")),
    ("Groq API Key", re.compile(r"gsk_[0-9A-Za-z]{24,}")),
    ("GitHub Classic PAT", re.compile(r"ghp_[0-9A-Za-z]{36}")),
    ("GitHub Fine-Grained PAT", re.compile(r"github_pat_[0-9A-Za-z_]{40,}")),
]

ALLOWED_DUMMY_TOKENS = {
    "AIza" + "SyDummyKeyForUnitTestRedaction12345",
    "AIza" + "Sy0123456789abcdefghijklmnopqrstuvw",
    "sk-or-v1-" + "a" * 64,
    "sk-or-v1-" + "0" * 64,
}


def get_tracked_files() -> list[str]:
    out = subprocess.check_output(["git", "ls-files"], text=True, encoding="utf-8")
    return [line.strip() for line in out.splitlines() if line.strip()]


def check_forbidden_tracked_files(files: list[str]) -> list[str]:
    problems = []
    for f in files:
        norm = f.replace("\\", "/")
        if norm in (".env", ".flask_secret", "results.md") or norm.endswith((".db", ".sqlite", ".db-wal", ".db-shm")):
            problems.append(f"Forbidden file tracked in git: {norm}")
        if norm.startswith("results/") and not norm.startswith("results/published/"):
            problems.append(f"Raw results file tracked outside results/published/: {norm}")
    return problems


def scan_text(text: str, source_label: str, allow_test_dummies: bool = False) -> list[str]:
    findings = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(0)
            if token in ALLOWED_DUMMY_TOKENS:
                continue
            if allow_test_dummies and ("test_" in source_label or "Dummy" in token or "123456789" in token or len(set(token[10:])) <= 3):
                continue
            findings.append(f"{source_label}: matched {label} pattern ({token[:10]}...)")
    return findings


def scan_working_tree(files: list[str]) -> list[str]:
    problems = []
    for f in files:
        norm = f.replace("\\", "/")
        if norm.endswith((".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf")):
            continue
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                content = fp.read()
        except OSError:
            continue
        is_test = norm.startswith("tests/")
        problems.extend(scan_text(content, norm, allow_test_dummies=is_test))
    return problems


def scan_git_history() -> list[str]:
    out = subprocess.check_output(
        ["git", "log", "--all", "-p", "--no-color"],
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    return scan_text(out, "git-history", allow_test_dummies=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check repo for tracked secrets or forbidden files")
    parser.add_argument("--history", action="store_true", help="Also scan full git commit history")
    args = parser.parse_args(argv)

    tracked = get_tracked_files()
    problems = check_forbidden_tracked_files(tracked)
    problems.extend(scan_working_tree(tracked))
    if args.history:
        problems.extend(scan_git_history())

    if problems:
        print("[-] Repository secret/hygiene check FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print(f"[OK] Secret & hygiene check passed ({len(tracked)} tracked files{' + git history' if args.history else ''}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
