# Design Specification: UI/UX Modernization, Internationalization, and Terminal/Web Ergonomics

**Date:** 2026-11-06  
**Topic:** Tech Innovation Slate Theme, Master Table + Slide-Over Drawer Architecture, 100% Pure English UI, and CLI `serve`/`view` Ergonomics  
**Target:** Transform `thai-injection-eval` into a world-class, distraction-free AI security benchmark workbench matching industry standards (Promptfoo, OpenCode, Snyk, Garak)  
**Status:** Approved  

---

## 1. Intent & Context (The "Why")

Currently, `thai-injection-eval` has several UI/UX frictions:
1. **Visual Clutter & Information Density**: The evaluation dashboard previously relied on an in-table accordion. Expanding a single row pushed the entire view down dozens of lines with raw conversation logs, tool calls, and canary audits, making high-level scanning of evaluation results cumbersome.
2. **Language Fragmentation**: UI controls, tabs, headers, status badges, and error messages mixed Thai and English arbitrarily (e.g. `📊 ผลการทดสอบ & รันประเมิน (Evaluation)`, `🚨 รั่วไหล`, `⤢ กางทั้งหมด`). Non-standard translation of cybersecurity concepts degrades professional readability.
3. **Aesthetic Inconsistencies**: The color system had muted slate badges for safe status (`#94a3b8`) rather than high-clarity emerald green, and lacked a unified design system between terminal and web.
4. **Model Configuration Disconnect**: While CLI commands now support `--blue` and `--red` flags, the Web UI runner (`/run`) and interactive playground (`/api/manual/start`) still defaulted to environment values without UI model selectors.
5. **CLI Server Ergonomics**: The `serve` command only printed `http://127.0.0.1:5000` without an auto-browser launch option (`--open`), and lacked the standard `view` alias popularized by modern AI eval tools like Promptfoo.

---

## 2. Design System: Tech Innovation Slate

### 2.1 Color Palette
- **Canvas Base**: `#0B0F17` (Deep dark slate, high contrast without OLED harshness)
- **Surfaces & Cards**: `#111827` (Card panels), `#1F2937` (Monospace payload blocks)
- **Borders**: `#1E293B` (Subtle dividers), `#38BDF8` (Focus cyan)
- **Typography & Text**: `#F8FAFC` (Headers), `#CBD5E1` (Body), `#94A3B8` (Muted labels)
- **Status Accents**:
  - `DEFENDED / SAFE`: `#10B981` (Emerald green, bg: `rgba(16, 185, 129, 0.12)`)
  - `BREACHED / COMPROMISED`: `#EF4444` (Crimson red, bg: `rgba(239, 68, 68, 0.12)`)
  - `ERROR / WARNING`: `#F59E0B` (Amber yellow, bg: `rgba(245, 158, 11, 0.12)`)
  - `ACTIVE / SYSTEM`: `#06B6D4` (Cyan system)

### 2.2 Typography Stack
- **UI Labels & Body**: `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans Thai", sans-serif`
- **Code, Transcripts & Tokens**: `"JetBrains Mono", ui-monospace, Menlo, Monaco, Consolas, monospace`

---

## 3. Web UI Architecture: Master Table + Slide-Over Drawer

### 3.1 Overview Architecture
- **Header**: Minimalist badge (`THAI-INJECTION-EVAL`), Target Model pills (`Blue: ... | Red: ...`), and Navigation Tabs:
  - `Benchmark Evaluation`
  - `Interactive Playground`
  - `OWASP Benchmark Matrix`
- **Executive Metric Cards (Top)**:
  - `Total Evaluated`
  - `Defended` (Emerald badge)
  - `Breached` (Crimson badge + ASR %)
  - `Error / Inconclusive` (Amber badge)
- **Runner Action Bar**:
  - Case selector (`ALL` or specific case ID)
  - Defense selector (`OFF`, `PROMPT`, `TOOLS`, `ALL`)
  - Max attempts number input
  - Model override inputs (`blue_model`, `red_model`)
  - `▶ Run Evaluation` button & `⏹ Stop` button
- **Master Evaluation Table**:
  - Compact, fixed-height, fast-scanning table.
  - Columns: `Case ID`, `Strategy & Category`, `Defense`, `Security Verdict` (`[✓] DEFENDED` / `[✗] BREACHED` / `[!] ERROR`), `Turns / TTB`, `Actions` (`[Inspect]`).
  - Search input + quick filter pills (`All`, `Breached`, `Defended`, `Errors`).
- **Slide-Over Detail Drawer**:
  - An off-canvas sidebar sliding in from the right edge with smooth CSS transition.
  - Clicking any row or `[Inspect]` opens the drawer.
  - Tabbed inspector inside the drawer:
    - **Transcript Tab**: Multi-turn conversation view with prompt payload, one-click `Copy Payload` button, and target response.
    - **Telemetry Tab**: Canary token leakage check, DB table queries, defense action triggers, latency.
    - **Metadata Tab**: Test case attack type, source reference, language, and technique description.

### 3.2 100% Pure English UI Standardization
All static and dynamic UI labels across all 3 tabs are converted to standard English. Original prompt payloads and LLM responses in Thai remain untouched in their raw language.

---

## 4. Backend & Model Selection Parity (`web_ui.py`)

1. **`/run` endpoint**:
   - Parse `blue_model = request.form.get("blue_model")` and `red_model = request.form.get("red_model")`.
   - Pass them to `agent.run_all(..., blue_model=blue_model, red_model=red_model)`.
2. **`/api/manual/start` endpoint**:
   - Parse `blue_model = data.get("blue_model")` and `red_model = data.get("red_model")`.
   - Initialize `agent.BlueSession(defense, role=blue_role, model=blue_model)`.
3. **State & CSRF Resilience**:
   - Retain session CSRF protection, error sanitization, and security response headers.

---

## 5. Terminal CLI & Ergonomics Modernization

1. **High-Signal Stream Telemetry**:
   - Slim ANSI slant banner in pure English.
   - Standardized status glyphs: `[✓] DEFENDED`, `[✗] BREACHED`, `[!] ERROR`, `[→] RUNNING`.
   - Standardized column alignment for case telemetry streams.
   - Clean Performance Summary Grid at benchmark completion.
2. **`serve` and `view` Command Enhancements**:
   - Add `--open` flag: Automatically launches the user's default browser using `webbrowser.open_new_tab(f"http://{host}:{port}")`.
   - Add `view` alias to `core/cli/app.py`: `thai-injection-eval view` launches the exact same web server as `serve`.

---

## 6. Verification Strategy

1. **Unit & Integration Tests**:
   - `tests/test_web_ui.py`:
     - Test that `/` renders pure English UI labels and contains the slide-over drawer structure.
     - Test that `/run` accepts and propagates `blue_model` and `red_model`.
     - Test that `/api/manual/start` accepts and initializes `blue_model`.
   - `tests/test_cli_serve.py`:
     - Test CLI parser accepts `view` and `serve --open`.
2. **Full Regression Test Suite**:
   - Ensure all 248+ tests continue to pass without regression.
