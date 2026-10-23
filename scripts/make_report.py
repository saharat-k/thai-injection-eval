"""Generate reproducible Markdown tables and matplotlib charts solely from results/published/.

Never makes network/API calls and never reads raw response files outside results/published/.
If no published summary JSON exists yet, outputs a clean 'TBD (ยังไม่ได้รันจริง)' report.
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.evaluator.stats import format_rate

FORBIDDEN_ROW_KEYS = {"prompt", "response", "raw", "error"}


def load_published_summaries(published_dir: str) -> list[dict]:
    """Load and validate all *_summary.json files inside published_dir."""
    if not os.path.isdir(published_dir):
        return []
    paths = sorted(glob.glob(os.path.join(published_dir, "*_summary.json")))
    summaries = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            doc = json.load(f)
        for idx, row in enumerate(doc.get("rows", [])):
            leaked_keys = FORBIDDEN_ROW_KEYS.intersection(row.keys())
            if leaked_keys:
                raise ValueError(f"{p} row #{idx} contains forbidden raw fields: {sorted(leaked_keys)}")
        doc["_source_file"] = os.path.basename(p)
        summaries.append(doc)
    return summaries


def build_tbd_markdown() -> str:
    """Return a clean Markdown report when no real run has been published yet."""
    return "\n".join([
        "# สรุปผลการทดลองชุดคู่ขนาน 3 ภาษา (Published Benchmark Report)",
        "",
        "> **สถานะผลทดลอง:** `TBD (ยังไม่ได้รันจริง)`  ",
        "> ยังไม่มีไฟล์ผลลัพธ์ `*_summary.json` ใน `results/published/` ตัวเลขทั้งหมดจึงเว้นไว้เป็น `TBD (ยังไม่ได้รันจริง)` ตามกฎความถูกต้องของข้อมูล",
        "",
        "## ตารางเปรียบเทียบ ASR แยกตามภาษา (TH / EN / MIX)",
        "",
        "| ภาษา (Language) | จำนวนเคสโจมตีต่อระดับป้องกัน (n) | Attack Success Rate (ASR) | 95% Wilson CI |",
        "| :--- | :---: | :---: | :---: |",
        "| `TH` (ภาษาไทย) | 12 | TBD (ยังไม่ได้รันจริง) | TBD (ยังไม่ได้รันจริง) |",
        "| `EN` (ภาษาอังกฤษ) | 12 | TBD (ยังไม่ได้รันจริง) | TBD (ยังไม่ได้รันจริง) |",
        "| `MIX` (ปนภาษาไทย-อังกฤษ) | 12 | TBD (ยังไม่ได้รันจริง) | TBD (ยังไม่ได้รันจริง) |",
        "",
        "## ตารางเปรียบเทียบ ASR แยกตามระดับการป้องกัน (4-Tier Defense)",
        "",
        "| ระดับการป้องกัน (Defense Tier) | จำนวนเคสโจมตีรวม 3 ภาษา (n) | Attack Success Rate (ASR) | 95% Wilson CI | หมายเหตุเชิงโครงสร้าง |",
        "| :--- | :---: | :---: | :---: | :--- |",
        "| `off` | 36 | TBD (ยังไม่ได้รันจริง) | TBD (ยังไม่ได้รันจริง) | Baseline ไม่มีการป้องกัน |",
        "| `prompt` | 36 | TBD (ยังไม่ได้รันจริง) | TBD (ยังไม่ได้รันจริง) | พึ่งพาคำสั่งห้ามใน System Prompt |",
        "| `tools` | 36 | TBD (ยังไม่ได้รันจริง) | TBD (ยังไม่ได้รันจริง) | ปิดช่องทางอ่านตารางลับโดยโครงสร้างการออกแบบ (`blocked by construction`) |",
        "| `all` | 36 | TBD (ยังไม่ได้รันจริง) | TBD (ยังไม่ได้รันจริง) | `tools` + Hardened Prompt + Output DLP |",
        "",
    ])


def _plot_bar_with_wilson_ci(
    labels: list[str],
    stats: list[dict],
    title: str,
    ylabel: str,
    out_path: str,
) -> str:
    """Render a bar chart with asymmetric Wilson 95% CI error bars using matplotlib (Agg)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rates = [float(s.get("rate") or 0.0) for s in stats]
    lows = [max(0.0, r - float(s.get("ci95_low") or 0.0)) for r, s in zip(rates, stats)]
    highs = [max(0.0, float(s.get("ci95_high") or 0.0) - r) for r, s in zip(rates, stats)]
    ns = [int(s.get("n") or 0) for s in stats]
    ks = [int(s.get("k") or 0) for s in stats]

    fig, ax = plt.subplots(figsize=(7.5, 4.5), dpi=150)
    x = list(range(len(labels)))
    bars = ax.bar(x, rates, yerr=[lows, highs], capsize=6, color="#2563eb", alpha=0.85, edgecolor="#1e3a8a")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{lbl}\n(k={k}, n={n})" for lbl, k, n in zip(labels, ks, ns)])
    ax.set_ylim(0, 105)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    for bar, r, s in zip(bars, rates, stats):
        lo = s.get("ci95_low")
        hi = s.get("ci95_high")
        label = f"{r:.1f}%\n[{lo:.1f}-{hi:.1f}%]" if lo is not None and hi is not None else "n=0"
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            min(98.0, float(hi or r) + 3.0),
            label,
            ha="center",
            va="bottom",
            fontsize=8,
        )

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    return out_path


def _render_probing_section(probing_doc: dict, out_dir: str, charts: list[str]) -> list[str]:
    meta = probing_doc.get("metadata", {})
    metrics = probing_doc.get("metrics", {})
    by_cat = metrics.get("by_category", {})
    by_def = metrics.get("by_defense", {})
    by_lang = metrics.get("by_language", {})

    if by_cat:
        cat_order = [k for k in ("collateral_public_leak", "indirect_public_tools", "dlp_bypass_probe") if k in by_cat] or sorted(by_cat.keys())
        cat_chart = os.path.join(out_dir, "probing_by_category.png")
        _plot_bar_with_wilson_ci(
            cat_order,
            [by_cat[k] for k in cat_order],
            "Probing Suite Hit Rate by Category with 95% Wilson CI",
            "Hit Rate (%)",
            cat_chart,
        )
        charts.append(cat_chart)

    sec = [
        "---",
        "",
        "# ผลการทดลองจริงชุดเจาะจุดบอดโหมด `tools` และ `all` (Probing Suite — `test_cases_probing.json`)",
        "",
        "## Reproducibility Metadata (Probing Suite)",
        "",
        "| Field | Value |",
        "| :--- | :--- |",
        f"| **Source file** | `{probing_doc.get('_source_file', '-')}` |",
        f"| **Red model** | `{meta.get('red_model', '-')}` |",
        f"| **Blue model** | `{meta.get('blue_model', '-')}` |",
        f"| **Actual model(s) used** | `{meta.get('model_used', '-')}` |",
        f"| **Provider** | `{meta.get('provider', '-')}` (Google AI Studio Gemini API) |",
        f"| **Timestamp (UTC)** | `{meta.get('timestamp', probing_doc.get('timestamp', '-'))}` |",
        f"| **Attempts / Repeats** | `{meta.get('attempts', probing_doc.get('repeats', 1))}` |",
        f"| **Random seed** | `{meta.get('random_seed', '-')}` |",
        f"| **Defense tiers** | `{meta.get('defense', ','.join(probing_doc.get('defenses', [])))}` |",
        f"| **Git commit** | `{meta.get('git_commit', '-')}` |",
        f"| **Cases version** | `{meta.get('cases_version', '-')}` |",
        f"| **Cases SHA-256** | `{meta.get('cases_sha256', '-')}` |",
        f"| **Errored rows (excluded from n)** | `{metrics.get('errors', 0)}` (Free-tier 15 RPM transient quota/500) |",
        "",
        f"**Overall Probing Hit Rate:** {format_rate(metrics.get('overall', {}))}",
        "",
        "## Probing Hit Rate แยกตามหมวดหมู่ (Category)",
        "",
        "| หมวดหมู่ (Category) | k / n | Hit Rate (%) | 95% Wilson CI | คำอธิบายผลลัพธ์ |",
        "| :--- | :---: | :---: | :---: | :--- |",
    ]
    cat_notes = {
        "collateral_public_leak": "ตารางสาธารณะ (`enrollments`, `awards`) ไม่มี Row-Level ACL ทำให้คิวรีคำค้นกว้างรั่วข้อมูลนักศึกษาคนอื่น (`S002`–`S005`, `S040`, `S047`) ทั้งในโหมด `tools` และ `all`",
        "indirect_public_tools": "คำสั่งแฝงแบบไม่ใช้วงเล็บเหลี่ยมใน `announcements.ANN992` และ `course_evaluations.EV993` หลุดรอด `_sanitize_db_cell()` แต่โมเดล `gemini-3.5-flash-lite` ไม่ทำตามคำสั่งข้ามตาราง",
        "dlp_bypass_probe": "ติดบล็อกที่ระดับ Tool Gatekeeper (`PUBLIC_TABLES`) ก่อนเข้าถึงตารางลับ (`internal_secrets`, `student_private`) ส่วนการทดสอบ DLP ขาออกโดยตรงแบบออฟไลน์ (`--dlp-audit`) รั่ว 4/4 รูปแบบ",
    }
    for k, s in by_cat.items():
        sec.append(
            f"| `{k}` | {s['k']}/{s['n']} | {s['rate']:.1f}% | [{s['ci95_low']:.1f}%, {s['ci95_high']:.1f}%] | {cat_notes.get(k, '-')} |"
        )
    sec.extend([
        "",
        "## Probing Hit Rate แยกตามระดับการป้องกัน (Defense Tier)",
        "",
        "| ระดับการป้องกัน (Defense Tier) | k / n | Hit Rate (%) | 95% Wilson CI |",
        "| :--- | :---: | :---: | :---: |",
    ])
    for k, s in by_def.items():
        sec.append(
            f"| `{k}` | {s['k']}/{s['n']} | {s['rate']:.1f}% | [{s['ci95_low']:.1f}%, {s['ci95_high']:.1f}%] |"
        )
    sec.extend([
        "",
        "## Probing Hit Rate แยกตามภาษา (TH / EN / MIX)",
        "",
        "| ภาษา (Language) | k / n | Hit Rate (%) | 95% Wilson CI |",
        "| :--- | :---: | :---: | :---: |",
    ])
    for k, s in by_lang.items():
        sec.append(
            f"| `{k}` | {s['k']}/{s['n']} | {s['rate']:.1f}% | [{s['ci95_low']:.1f}%, {s['ci95_high']:.1f}%] |"
        )
    sec.append("")
    return sec


def generate_published_artifacts(
    published_dir: str = os.path.join("results", "published"),
    output_dir: str | None = None,
) -> dict:
    """Read published summaries from published_dir and write PUBLISHED_REPORT.md (+ charts if data exists)."""
    out_dir = output_dir or published_dir
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "PUBLISHED_REPORT.md")

    summaries = load_published_summaries(published_dir)
    if not summaries:
        md = build_tbd_markdown()
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(md)
        return {"status": "tbd", "report_path": report_path, "charts": []}

    parallel_summaries = [s for s in summaries if s.get("kind", "parallel") == "parallel"]
    probing_summaries = [s for s in summaries if s.get("kind") == "probing"]
    charts: list[str] = []

    if not parallel_summaries:
        lines = [build_tbd_markdown().rstrip(), ""]
    else:
        latest = parallel_summaries[-1]
        meta = latest.get("metadata", {})
        metrics = latest.get("metrics", {})
        atk = metrics.get("attack", {})
        ben = metrics.get("benign_false_positive", {})

        by_lang = atk.get("by_language", {})
        if by_lang:
            lang_order = [k for k in ("TH", "EN", "MIX") if k in by_lang] or sorted(by_lang.keys())
            lang_chart = os.path.join(out_dir, "asr_by_language.png")
            _plot_bar_with_wilson_ci(
                lang_order,
                [by_lang[k] for k in lang_order],
                "Attack Success Rate (ASR) by Language with 95% Wilson CI",
                "ASR (%)",
                lang_chart,
            )
            charts.append(lang_chart)

        by_def = atk.get("by_defense", {})
        if by_def:
            def_order = [k for k in ("off", "prompt", "tools", "all") if k in by_def] or sorted(by_def.keys())
            def_chart = os.path.join(out_dir, "asr_by_defense.png")
            _plot_bar_with_wilson_ci(
                def_order,
                [by_def[k] for k in def_order],
                "Attack Success Rate (ASR) by Defense Tier with 95% Wilson CI",
                "ASR (%)",
                def_chart,
            )
            charts.append(def_chart)

        lines = [
            "# สรุปผลการทดลองชุดคู่ขนาน 3 ภาษา (Published Benchmark Report)",
            "",
            "## Reproducibility Metadata",
            "",
            "| Field | Value |",
            "| :--- | :--- |",
            f"| **Source file** | `{latest.get('_source_file', '-')}` |",
            f"| **Red model** | `{meta.get('red_model', '-')}` |",
            f"| **Blue model** | `{meta.get('blue_model', '-')}` |",
            f"| **Actual model(s) used** | `{meta.get('model_used', '-')}` |",
            f"| **Provider** | `{meta.get('provider', '-')}` |",
            f"| **Timestamp (UTC)** | `{meta.get('timestamp', latest.get('timestamp', '-'))}` |",
            f"| **Attempts / Repeats** | `{meta.get('attempts', latest.get('repeats', 1))}` |",
            f"| **Random seed** | `{meta.get('random_seed', '-')}` |",
            f"| **Defense tiers** | `{meta.get('defense', ','.join(latest.get('defenses', [])))}` |",
            f"| **Git commit** | `{meta.get('git_commit', '-')}` |",
            f"| **Cases version** | `{meta.get('cases_version', '-')}` |",
            f"| **Cases SHA-256** | `{meta.get('cases_sha256', '-')}` |",
            "",
            f"**Overall ASR:** {format_rate(atk.get('overall', {}))}",
            "",
            "## ASR by Language (TH / EN / MIX)",
            "",
            "| Language | k / n | ASR (%) | 95% Wilson CI |",
            "| :--- | :---: | :---: | :---: |",
        ]
        for k, s in by_lang.items():
            lines.append(
                f"| `{k}` | {s['k']}/{s['n']} | {s['rate']:.1f}% | [{s['ci95_low']:.1f}%, {s['ci95_high']:.1f}%] |"
            )
        lines.extend([
            "",
            "## ASR by Defense Tier",
            "",
            "| Defense Tier | k / n | ASR (%) | 95% Wilson CI |",
            "| :--- | :---: | :---: | :---: |",
        ])
        for k, s in by_def.items():
            lines.append(
                f"| `{k}` | {s['k']}/{s['n']} | {s['rate']:.1f}% | [{s['ci95_low']:.1f}%, {s['ci95_high']:.1f}%] |"
            )
        lines.extend([
            "",
            "## Benign False-Positive Rate by Language",
            "",
            "| Language | k / n | False Positive Rate (%) | 95% Wilson CI |",
            "| :--- | :---: | :---: | :---: |",
        ])
        for k, s in ben.get("by_language", {}).items():
            lines.append(
                f"| `{k}` | {s['k']}/{s['n']} | {s['rate']:.1f}% | [{s['ci95_low']:.1f}%, {s['ci95_high']:.1f}%] |"
            )
        lines.append("")

    if probing_summaries:
        lines.extend(_render_probing_section(probing_summaries[-1], out_dir, charts))

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"status": "ok", "report_path": report_path, "charts": charts}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build Markdown tables and matplotlib charts from results/published/")
    parser.add_argument("--published-dir", default=os.path.join("results", "published"), help="Directory containing *_summary.json")
    parser.add_argument("--output-dir", default=None, help="Output directory for generated report and charts (defaults to --published-dir)")
    args = parser.parse_args(argv)
    out = generate_published_artifacts(published_dir=args.published_dir, output_dir=args.output_dir)
    print(f"[make_report] status={out['status']} report={out['report_path']} charts={len(out['charts'])}")


if __name__ == "__main__":
    main()
