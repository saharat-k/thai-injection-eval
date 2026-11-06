# UI/UX Modernization, Internationalization, and Terminal/Web Ergonomics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modernize both Terminal CLI and Web UI into a unified, distraction-free AI security benchmark workbench using Tech Innovation Slate styling, a Master Table + Slide-over Drawer pattern, 100% pure English UI terminology, model override selectors, and CLI `view`/`serve --open` ergonomics.

**Architecture:** Refactor the zero-dependency Flask web application (`web_ui.py` and `templates/index.html`) to replace noisy in-table accordion rows with a fast-scanning Master Table coupled with a smooth CSS/JS Slide-over Drawer. Standardize the visual design across Web and Terminal using the Tech Innovation Slate palette (`#0B0F17`, `#111827`, `#1E293B`, `#10B981`, `#EF4444`, `#06B6D4`), Inter + Noto Sans Thai + JetBrains Mono typography, and modern high-signal telemetry stream glyphs (`[✓]`, `[✗]`, `[!]`). Extend the CLI with `--open` auto-browser launch and the `view` command alias.

**Tech Stack:** Python 3.10+, Flask, Vanilla CSS & Modern JS (zero Node.js dependencies), SQLite3, ANSI escape sequences, JetBrains Mono & Inter typography.

**Spec:** `docs/superpowers/specs/2026-11-06-ui-ux-internationalization-design.md`

## Global Constraints

- **Strict Free-Tier Model Policy**: Never hardcode or default to paid/expensive models; preserve `gemini-3.5-flash-lite` (Blue Target) and `openrouter:openrouter/free` (Red Adversary).
- **Environment & Dependency Isolation**: Zero external npm/Node.js build steps; maintain pure Python distribution runnable with `python -m core.cli.app serve` or `python web_ui.py`.
- **Security & Secret Hygiene**: Never commit `.env`, `*.db`, or `results.md`. Preserve CSRF verification, rate-limiting, and security response headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`).
- **Data Integrity**: Never alter the original raw language of test case payloads or model responses; Thai prompts in datasets must render cleanly without mojibake or clipping.

## Review Focus

1. **Drawer State Handling**: Opening multiple rows rapidly or pressing ESC/backdrop click must cleanly close the active slide-over drawer without memory leaks or zombie event listeners.
2. **Model Parameter Pass-Through**: Submitting `/run` or starting manual session with custom `--blue` or `--red` values must accurately initialize `agent.run_all` and `agent.BlueSession` without falling back silently.
3. **Pure English UI Purity**: Verify no residual legacy Thai text remains in button labels, table headers, filter options, or error responses.
4. **ANSI & Unicode Table Alignment**: Ensure terminal tables and telemetry streams render without misaligned vertical borders on both Windows PowerShell and Linux terminals.
5. **CLI `--open` Backgrounding**: Running `serve --open` must not crash or block the Flask server start if the system default browser fails to open.

---

### Task 1: CLI Ergonomics & `view` / `serve --open` Command Support

**Files:**
- Modify: `core/cli/commands/serve.py`
- Modify: `core/cli/app.py`
- Test: `tests/test_cli_serve.py`

**Interfaces:**
- Consumes: `core.cli.app.SecurityCLIParser`
- Produces: `core.cli.commands.serve.run_serve(args) -> int` with `--open` flag support; `view` parser command alias.

- [ ] **Step 1: Write failing test in `tests/test_cli_serve.py`**

```python
import unittest
from unittest.mock import patch, MagicMock
from core.cli.app import build_parser
from core.cli.commands.serve import run_serve


class TestCLIServeCommands(unittest.TestCase):
    def test_parser_supports_view_command_and_open_flag(self):
        parser = build_parser()
        args = parser.parse_args(["view", "--open", "--port", "5055"])
        self.assertEqual(args.command, "view")
        self.assertTrue(args.open)
        self.assertEqual(args.port, 5055)

    @patch("webbrowser.open_new_tab")
    @patch("web_ui.app.run")
    def test_run_serve_with_open_flag_launches_browser(self, mock_flask_run, mock_browser_open):
        mock_args = MagicMock(host="127.0.0.1", port=5000, debug=False, no_color=True, open=True)
        res = run_serve(mock_args)
        self.assertEqual(res, 0)
        mock_browser_open.assert_called_once_with("http://127.0.0.1:5000")
        mock_flask_run.assert_called_once()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m unittest tests/test_cli_serve.py`
Expected: FAIL (unrecognized argument `--open` or `view`)

- [ ] **Step 3: Implement `--open` and `view` in `core/cli/app.py` and `core/cli/commands/serve.py`**

In `core/cli/app.py`:
- Add `view` subparser sharing the same arguments and handler as `serve`.
- Add `--open` flag (`action="store_true"`, help="Automatically open the default web browser upon server startup").

In `core/cli/commands/serve.py`:
- If `getattr(args, "open", False)`: use `threading.Timer(0.8, lambda: webbrowser.open_new_tab(url)).start()` before `web_ui.app.run()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m unittest tests/test_cli_serve.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/cli/app.py core/cli/commands/serve.py tests/test_cli_serve.py
git commit -m "feat(cli): add view alias and --open auto-browser flag to serve command"
```

---

### Task 2: Web Backend Model Selection & Internationalization Parity (`web_ui.py`)

**Files:**
- Modify: `web_ui.py`
- Test: `tests/test_web_ui.py`

**Interfaces:**
- Consumes: `agent.run_all(defense, max_attempts, case_id, blue_model=None, red_model=None)`, `agent.BlueSession(defense, role, model=None)`
- Produces: Updated `/run` and `/api/manual/start` handlers accepting `blue_model` and `red_model`.

- [ ] **Step 1: Write failing test in `tests/test_web_ui.py`**

```python
def test_run_endpoint_propagates_blue_and_red_model(self):
    # Verify /run accepts blue_model and red_model from POST data
    with patch("threading.Thread") as mock_thread:
        res = self.client.post("/run", data={
            "csrf_token": self.csrf_token,
            "defense": "tools",
            "case_id": "ALL",
            "attempts": "2",
            "blue_model": "gemini-3.5-flash-lite",
            "red_model": "openrouter:openrouter/free",
        })
        self.assertEqual(res.status_code, 302)
        mock_thread.assert_called_once()
```

- [ ] **Step 2: Run test to verify current behavior**

Run: `.venv\Scripts\python.exe -m unittest tests/test_web_ui.py`
Expected: Test runs, inspect if `blue_model`/`red_model` are parsed.

- [ ] **Step 3: Update `web_ui.py`**

- In `run()`: Extract `blue_model = request.form.get("blue_model", "").strip() or None` and `red_model = request.form.get("red_model", "").strip() or None`. Pass them into `agent.run_all(defense=defense, max_attempts=attempts, case_id=case_id, blue_model=blue_model, red_model=red_model)`.
- In `manual_start()`: Extract `blue_model = data.get("blue_model") or None` and pass `model=blue_model` to `agent.BlueSession(...)`.
- In `index()`: Pass `available_blue_models` and `available_red_models` to `render_template`.
- Standardize all error messages in `web_ui.py` to professional English (e.g. "Session or CSRF token expired. Please refresh the page (F5).").

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv\Scripts\python.exe -m unittest tests/test_web_ui.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web_ui.py tests/test_web_ui.py
git commit -m "feat(web): add blue and red model selection to web runner and manual session"
```

---

### Task 3: Modern Tech Innovation Slate Theme & Design System (`templates/index.html`)

**Files:**
- Modify: `templates/index.html`
- Test: `tests/test_web_ui.py`

**Interfaces:**
- Consumes: Design specification Section 2 (`Tech Innovation Slate`)
- Produces: Updated CSS custom properties (`:root`), font declarations, badges, cards, and scrollbars.

- [ ] **Step 1: Write test verifying CSS variables and typography in `tests/test_web_ui.py`**

```python
def test_index_renders_tech_innovation_theme_and_font_stack(self):
    res = self.client.get("/")
    self.assertEqual(res.status_code, 200)
    html = res.data.decode("utf-8")
    self.assertIn("--bg-base: #0b0f17", html.lower())
    self.assertIn("--color-emerald: #10b981", html.lower())
    self.assertIn("jetbrains mono", html.lower())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m unittest tests/test_web_ui.py`
Expected: FAIL (matches old variables like `--bg-base: #07090e`)

- [ ] **Step 3: Update CSS in `templates/index.html`**

- Update `:root` variables:
  - `--bg-base: #0b0f17;`
  - `--bg-surface: #111827;`
  - `--bg-surface-sub: #1f2937;`
  - `--border-subtle: #1e293b;`
  - `--border-light: #334155;`
  - `--border-focus: #38bdf8;`
  - `--color-emerald: #10b981;`
  - `--color-emerald-bg: rgba(16, 185, 129, 0.12);`
  - `--color-rose: #ef4444;`
  - `--color-rose-bg: rgba(239, 68, 68, 0.12);`
  - `--color-cyan: #06b6d4;`
  - `--font-ui: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans Thai", sans-serif;`
  - `--font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;`
- Update body and card styling to use smooth borders, rounded-lg (8px), and high-contrast typography.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m unittest tests/test_web_ui.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add templates/index.html tests/test_web_ui.py
git commit -m "style(web): apply Tech Innovation Slate design system and typography"
```

---

### Task 4: Master Table & Slide-Over Detail Drawer Refactoring (`templates/index.html`)

**Files:**
- Modify: `templates/index.html`
- Test: `tests/test_web_ui.py`

**Interfaces:**
- Consumes: Test case evaluation rows from `web_ui.latest_results()`
- Produces: Fast-scanning master data table; off-canvas slide-over drawer `#caseDetailDrawer` with tabbed inspector (Transcript, Telemetry, Metadata) and copy button.

- [ ] **Step 1: Write test verifying drawer container and master table in `tests/test_web_ui.py`**

```python
def test_index_contains_slide_over_drawer_structure(self):
    res = self.client.get("/")
    html = res.data.decode("utf-8")
    self.assertIn('id="caseDetailDrawer"', html)
    self.assertIn('id="drawerTranscriptTab"', html)
    self.assertIn('id="drawerTelemetryTab"', html)
    self.assertIn('btn-inspect-case', html)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m unittest tests/test_web_ui.py`
Expected: FAIL (drawer element not found)

- [ ] **Step 3: Implement Master Table and Slide-Over Drawer in `templates/index.html`**

- Replace the vertical expanding accordion row inside `.unified-audit-table` with clean clickable rows that trigger `openCaseDrawer(caseData)`.
- Create off-canvas drawer markup `#caseDetailDrawer`:
  - Drawer header: Case ID, Status Badge, Close button (`✕` / ESC key / backdrop click).
  - Drawer tab bar: `[Transcript]`, `[Security Telemetry]`, `[Case Metadata]`.
  - Transcript view: Multi-turn prompt bubbles with `[Copy Payload]` button, Blue response, thinking block.
  - Telemetry view: Canary token leak checklist, DB queries performed, defense policy action.
  - Metadata view: Source reference, attack technique, language tag.
- Implement JavaScript: `openCaseDrawer(data)`, `closeCaseDrawer()`, `copyPayloadText()`, with keyboard trap for ESC key and focus management.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m unittest tests/test_web_ui.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add templates/index.html tests/test_web_ui.py
git commit -m "feat(web): replace accordion with Master Table and Slide-over Detail Drawer"
```

---

### Task 5: 100% Pure English UI Standardization across all Web Tabs

**Files:**
- Modify: `templates/index.html`
- Test: `tests/test_web_ui.py`

**Interfaces:**
- Consumes: UI strings across all 3 tabs (`viewDashboard`, `viewPlayground`, `viewOwasp`)
- Produces: 100% pure English UI labels, headings, filter tags, placeholders, and action buttons.

- [ ] **Step 1: Write test verifying pure English labels in `tests/test_web_ui.py`**

```python
def test_index_has_pure_english_ui_labels(self):
    res = self.client.get("/")
    html = res.data.decode("utf-8")
    # Verify standard English tabs and buttons
    self.assertIn("Benchmark Evaluation", html)
    self.assertIn("Interactive Playground", html)
    self.assertIn("OWASP Benchmark Matrix", html)
    self.assertIn("Run Evaluation", html)
    # Ensure legacy Thai UI control phrases are replaced
    self.assertNotIn("ผลการทดสอบ & รันประเมิน", html)
    self.assertNotIn("โหมดควบคุมเอง / แชทสด", html)
    self.assertNotIn("เบนช์มาร์ก OWASP", html)
    self.assertNotIn("สั่งรันการทดสอบ", html)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m unittest tests/test_web_ui.py`
Expected: FAIL (legacy Thai strings found)

- [ ] **Step 3: Update all labels, placeholders, and tooltips across `templates/index.html`**

- Top Navigation:
  - Tab 1: `📊 Benchmark Evaluation`
  - Tab 2: `💬 Interactive Playground`
  - Tab 3: `🛡️ OWASP Benchmark Matrix`
- Dashboard Bar & KPI Cards:
  - `TOTAL EVALUATED`, `DEFENDED`, `BREACHED`, `ATTACK SUCCESS RATE (ASR)`, `ERROR`
  - Runner Controls: `Select Target Case: ALL (Run all N test cases)`, `Defense Level`, `Max Attempts`, `Run Evaluation`.
- Table Filter Bar:
  - Search placeholder: `Search by prompt, response, tool call, or case ID...`
  - Filter pills: `All Runs`, `Breached`, `Defended`, `Errors`
  - Secondary filters: `ORIGIN: All / Batch / Manual`, `DEFENSE: All / Off / Prompt / Tools / All`, `STRATEGY: All / Direct / Recon / Semantic / Indirect / Roleplay / Fewshot / Obfuscation`, `LANGUAGE: All / Thai / English / Mixed`
- Tab 2 (Playground):
  - `Session Setup (Interactive Playground)`
  - `Defense Level`, `Test Language`, `Target Blue Role`, `Adversary Red Profile`, `Send Prompt`, `Continue Red Attack`
- Tab 3 (OWASP Matrix):
  - `OWASP Top 10 for LLM Benchmark Evaluator`
  - Category cards: `LLM01: Prompt Injection`, `LLM06: Excessive Agency`, etc.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m unittest tests/test_web_ui.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add templates/index.html tests/test_web_ui.py
git commit -m "refactor(web): standardize 100% of UI labels and controls to international English"
```

---

### Task 6: Terminal High-Signal Stream Telemetry & Status Badges

**Files:**
- Modify: `core/cli/terminal/banner.py`
- Modify: `core/cli/terminal/colors.py`
- Modify: `core/cli/commands/redteam.py`
- Modify: `core/cli/commands/eval.py`
- Test: `tests/test_benchmark_cli.py`, `tests/test_redteam.py`

**Interfaces:**
- Consumes: ANSI color styling from `core.cli.terminal.colors`
- Produces: Standardized status glyphs `[✓] DEFENDED`, `[✗] BREACHED`, `[!] ERROR`, `[→] RUNNING`, clean fixed-width column streams, and summary grids.

- [ ] **Step 1: Write test verifying status glyphs in `tests/test_benchmark_cli.py`**

```python
def test_terminal_status_glyphs_and_banner_format(self):
    from core.cli.terminal.banner import get_banner
    banner = get_banner(color=False)
    self.assertIn("THAI INJECTION EVAL", banner.upper())
    self.assertIn("AI Security Test Bench", banner)
```

- [ ] **Step 2: Run test to verify current output**

Run: `.venv\Scripts\python.exe -m unittest tests/test_benchmark_cli.py`
Expected: Inspect pass/fail.

- [ ] **Step 3: Implement standardized stream formatting**

- In `core/cli/terminal/colors.py`: Ensure `status_badge` produces clean Linux-style glyphs:
  - `[✓] DEFENDED` (green)
  - `[✗] BREACHED` (red)
  - `[!] ERROR` (yellow)
  - `[→] RUNNING` (cyan)
- In `core/cli/commands/redteam.py`:
  - Telemetry output: Format each turn cleanly as `[ID] Turn X/Y | [✓] DEFENDED | Action: safe_fulfillment | Tools: 0`
  - Breach Alert Card: Clean box with target leaks, canaries, and unauthorized table access.
  - Final Performance Grid: Render formatted summary table with Total, Breached, Defended, ASR %, Avg TTB, and Duration.
- In `core/cli/terminal/banner.py`: Polish banner subtitle to `AI Security Test Bench & Multi-Turn Red Teaming CLI`.

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv\Scripts\python.exe -m unittest tests/test_benchmark_cli.py tests/test_redteam.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/cli/terminal/banner.py core/cli/terminal/colors.py core/cli/commands/redteam.py core/cli/commands/eval.py
git commit -m "feat(cli): standardize high-signal telemetry stream glyphs and performance summary grid"
```

---

### Task 7: Full Regression Verification & Live Sanity Check

**Files:**
- Test: All tests in `tests/`

- [ ] **Step 1: Run complete offline test suite**

Run: `.venv\Scripts\python.exe -m unittest discover tests/`
Expected: All 250+ unit tests pass without errors (`OK`).

- [ ] **Step 2: Check git status and secret hygiene**

Verify no `.env`, `*.db`, or `results.md` are staged or tracked.

- [ ] **Step 3: Commit and summarize**

```bash
git status
```
Ensure working tree is clean.
