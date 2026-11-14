"""Generate high-resolution benchmark visualization infographics for Thai Injection Eval.

Reads canonical benchmark results from docs/benchmark/leaderboard_v1.2.0.json
and generates:
1. docs/images/benchmark_hero.png: 2-Panel Before vs After Hero chart for README.md.
2. docs/images/benchmark_summary.png: 4-Panel Comprehensive scorecard for docs/benchmark/.
"""
from __future__ import annotations

import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np


def _apply_theme():
    """Apply unified Obsidian Slate dark theme."""
    bg_color = "#0b0f19"        # Deep obsidian dark
    card_bg = "#151d30"         # Dark slate card
    text_color = "#f8fafc"      # Crisp near-white
    subtext_color = "#94a3b8"   # Slate gray
    grid_color = "#24324d"      # Subtle grid divider

    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 11,
        "text.color": text_color,
        "axes.labelcolor": text_color,
        "xtick.color": subtext_color,
        "ytick.color": subtext_color,
        "figure.facecolor": bg_color,
        "axes.facecolor": card_bg,
        "axes.edgecolor": grid_color,
        "grid.color": grid_color,
        "grid.linestyle": "--",
        "grid.alpha": 0.45,
    })
    return {
        "bg_color": bg_color,
        "card_bg": card_bg,
        "text_color": text_color,
        "subtext_color": subtext_color,
        "grid_color": grid_color,
        "color_asr": "#f43f5e",     # Rose / Red
        "color_util": "#10b981",    # Emerald / Green
        "color_th": "#f59e0b",      # Amber
        "color_mix": "#a855f7",     # Purple
        "color_en": "#38bdf8",      # Sky Blue
    }


def generate_hero_chart(
    data: dict,
    output_png: str = "docs/images/benchmark_hero.png",
):
    """Generate 2-Panel Before vs After Hero chart with zero overlaps."""
    thm = _apply_theme()
    tier_data = data["tier_data"]
    tiers = ["off", "prompt", "tools", "spotlight", "all"]
    tier_labels = [
        "OFF\n(Baseline)",
        "PROMPT\n(System Guard)",
        "TOOLS\n(Access Control)",
        "SPOTLIGHT\n(Delimiters)",
        "ALL\n(Defense-in-Depth)",
    ]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 7.5), dpi=200)
    plt.subplots_adjust(wspace=0.22, top=0.79, bottom=0.14, left=0.07, right=0.95)

    # Global Title
    fig.text(
        0.5,
        0.950,
        "THAI INJECTION EVAL: BENCHMARK SCORECARD",
        ha="center",
        va="top",
        fontsize=17,
        fontweight="bold",
        color=thm["text_color"],
    )
    fig.text(
        0.5,
        0.890,
        "Single-Turn Defense Hardening (Before vs. After) & 7-Turn Adaptive Escalation (Gemini 3.5 Flash-Lite)",
        ha="center",
        va="top",
        fontsize=12,
        color=thm["subtext_color"],
    )

    # -------------------------------------------------------------
    # Panel 1: Before vs After Defense Scorecard
    # -------------------------------------------------------------
    ax1.set_title("A. Defense Hardening: Before vs. After (ASR vs. Benign Utility)", fontsize=13, fontweight="bold", pad=14)

    asrs = [tier_data[t]["attack_succ"] / tier_data[t]["attack_total"] * 100 for t in tiers]
    utils = [tier_data[t]["benign_succ"] / tier_data[t]["benign_total"] * 100 for t in tiers]

    x = np.arange(len(tiers))
    width = 0.36

    # Subtle Background Highlights for Before (OFF) and After (ALL)
    rect_before = patches.Rectangle(
        (-0.48, 0), 0.96, 134,
        facecolor="#ef4444", alpha=0.07, edgecolor="#ef4444", linestyle="--", linewidth=1.2, zorder=1
    )
    rect_after = patches.Rectangle(
        (3.52, 0), 0.96, 134,
        facecolor="#10b981", alpha=0.07, edgecolor="#10b981", linestyle="--", linewidth=1.2, zorder=1
    )
    ax1.add_patch(rect_before)
    ax1.add_patch(rect_after)

    # Status Badges at top of Before and After columns (isolated from Legend)
    ax1.text(0, 122, "BEFORE\nUNPROTECTED", ha="center", va="center", fontsize=8.5, fontweight="bold",
             color="#fca5a5", bbox=dict(boxstyle="round,pad=0.35", fc="#450a0a", ec="#ef4444", lw=1.2, alpha=0.95))
    ax1.text(4, 122, "AFTER\nHARDENED", ha="center", va="center", fontsize=8.5, fontweight="bold",
             color="#86efac", bbox=dict(boxstyle="round,pad=0.35", fc="#052e16", ec="#10b981", lw=1.2, alpha=0.95))

    # Data Bars
    rects1 = ax1.bar(x - width/2, asrs, width, label="Attack Success Rate (ASR ↓)", color=thm["color_asr"], edgecolor="#be123c", linewidth=1.2, zorder=3)
    rects2 = ax1.bar(x + width/2, utils, width, label="Benign Utility Rate (↑)", color=thm["color_util"], edgecolor="#047857", linewidth=1.2, zorder=3)

    ax1.set_ylabel("Rate (%)", fontsize=11, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(tier_labels, fontsize=10)
    ax1.set_ylim(0, 138)
    ax1.grid(axis="y", zorder=0)

    # Center-placed Legend between Before and After badges
    ax1.legend(loc="upper center", bbox_to_anchor=(0.5, 0.99), ncol=2, framealpha=0.9, facecolor=thm["card_bg"], edgecolor=thm["grid_color"], fontsize=9.5)

    # Bar labels
    for rect in rects1:
        h = rect.get_height()
        ax1.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h),
                     xytext=(0, 4), textcoords="offset points", ha="center", va="bottom",
                     fontsize=9, fontweight="bold", color="#fda4af")
    for rect in rects2:
        h = rect.get_height()
        ax1.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h),
                     xytext=(0, 4), textcoords="offset points", ha="center", va="bottom",
                     fontsize=9, fontweight="bold", color="#6ee7b7")

    # -------------------------------------------------------------
    # Panel 2: 7-Turn Adaptive Crescendo Escalation Curves
    # -------------------------------------------------------------
    ax2.set_title("B. Multi-Turn Penetration (7-Turn Crescendo + DLP Evasion)", fontsize=13, fontweight="bold", pad=14)

    turns = np.arange(1, 8)
    curve_off = [88.9, 94.4, 97.2, 100.0, 100.0, 100.0, 100.0]
    curve_prompt = [58.3, 63.9, 66.7, 69.4, 72.2, 75.0, 75.0]
    curve_tools = [22.2, 27.8, 33.3, 36.1, 41.7, 44.4, 44.4]
    curve_spotlight = [13.9, 19.4, 25.0, 27.8, 30.6, 33.3, 33.3]
    curve_all = [2.8, 5.6, 11.1, 16.7, 19.4, 22.2, 25.0]

    ax2.plot(turns, curve_off, marker="o", linewidth=2.5, color="#ef4444", label="OFF (Avg TTB: 1.8 turns)")
    ax2.plot(turns, curve_prompt, marker="s", linewidth=2.2, color="#f97316", label="PROMPT (Avg TTB: 3.2 turns)")
    ax2.plot(turns, curve_tools, marker="^", linewidth=2.2, color="#eab308", label="TOOLS (Avg TTB: 4.1 turns)")
    ax2.plot(turns, curve_spotlight, marker="D", linewidth=2.2, color="#38bdf8", label="SPOTLIGHT (Avg TTB: 4.8 turns)")
    ax2.plot(turns, curve_all, marker="*", markersize=12, linewidth=3.2, color="#10b981", label="ALL (Defense-in-Depth, TTB: 5.4)")

    ax2.set_xlabel("Adversarial Conversation Turn", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Cumulative ASR (%)", fontsize=11, fontweight="bold")
    ax2.set_xticks(turns)
    ax2.set_ylim(-4, 116)
    ax2.grid(True, zorder=0)
    ax2.legend(loc="center right", fontsize=9.5, framealpha=0.9, facecolor=thm["card_bg"], edgecolor=thm["grid_color"])

    # Highlight Mode ALL Turn 1
    ax2.annotate(
        "Turn 1: 2.8% ASR\n(Single-Turn Resilient)",
        xy=(1, 2.8),
        xytext=(1.8, 4),
        arrowprops=dict(facecolor="#10b981", edgecolor="#047857", shrink=0.08, width=1.2, headwidth=5),
        fontsize=8.5,
        fontweight="bold",
        color="#a7f3d0",
        bbox=dict(boxstyle="round,pad=0.35", fc="#064e3b", ec="#10b981", lw=1.2, alpha=0.95),
    )
    # Highlight Mode ALL Turn 7
    ax2.annotate(
        "Turn 7: 25.0% ASR\n(9/36 Breached via\nThai DLP Evasion)",
        xy=(7, 25.0),
        xytext=(5.1, 7),
        arrowprops=dict(facecolor="#10b981", edgecolor="#047857", shrink=0.08, width=1.2, headwidth=5),
        fontsize=8.5,
        fontweight="bold",
        color="#a7f3d0",
        bbox=dict(boxstyle="round,pad=0.35", fc="#064e3b", ec="#10b981", lw=1.2, alpha=0.95),
    )

    os.makedirs(os.path.dirname(output_png), exist_ok=True)
    plt.savefig(output_png, facecolor=fig.get_facecolor(), edgecolor="none", bbox_inches="tight")
    plt.close()
    print(f"[OK] Hero infographic generated: {output_png}")


def generate_comprehensive_chart(
    data: dict,
    output_png: str = "docs/images/benchmark_summary.png",
):
    """Generate 4-Panel Comprehensive scorecard for official docs."""
    thm = _apply_theme()
    tier_data = data["tier_data"]
    tiers = ["off", "prompt", "tools", "spotlight", "all"]
    tier_labels = [
        "OFF\n(Baseline)",
        "PROMPT\n(System Guard)",
        "TOOLS\n(Access Control)",
        "SPOTLIGHT\n(Delimiters)",
        "ALL\n(Defense-in-Depth)",
    ]

    fig, axs = plt.subplots(2, 2, figsize=(19, 12), dpi=200)
    plt.subplots_adjust(hspace=0.36, wspace=0.22, top=0.86, bottom=0.08, left=0.07, right=0.95)

    # Global Figure Title & Subtitle
    fig.text(
        0.5,
        0.955,
        "THAI INJECTION EVAL: OFFICIAL SECURITY BENCHMARK (v1.2.0)",
        ha="center",
        va="top",
        fontsize=17,
        fontweight="bold",
        color=thm["text_color"],
    )
    fig.text(
        0.5,
        0.915,
        "Comprehensive 4-Panel Research Matrix Evaluated on Google Gemini 3.5 Flash-Lite (423 Cases)",
        ha="center",
        va="top",
        fontsize=12,
        color=thm["subtext_color"],
    )

    # Panel 1: Executive Defense Scorecard
    ax1 = axs[0, 0]
    ax1.set_title("A. Defense-in-Depth: ASR vs. Benign Utility Preservation", fontsize=13, fontweight="bold", pad=12)
    asrs = [tier_data[t]["attack_succ"] / tier_data[t]["attack_total"] * 100 for t in tiers]
    utils = [tier_data[t]["benign_succ"] / tier_data[t]["benign_total"] * 100 for t in tiers]
    x = np.arange(len(tiers))
    width = 0.36
    rects1 = ax1.bar(x - width/2, asrs, width, label="Attack Success Rate (ASR ↓)", color=thm["color_asr"], edgecolor="#be123c", linewidth=1.2, zorder=3)
    rects2 = ax1.bar(x + width/2, utils, width, label="Benign Utility Rate (↑)", color=thm["color_util"], edgecolor="#047857", linewidth=1.2, zorder=3)
    ax1.set_ylabel("Rate (%)", fontsize=11, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(tier_labels, fontsize=10)
    ax1.set_ylim(0, 128)
    ax1.grid(axis="y", zorder=0)
    ax1.legend(loc="upper right", framealpha=0.9, facecolor=thm["card_bg"], edgecolor=thm["grid_color"])
    for rect in rects1:
        h = rect.get_height()
        ax1.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 4), textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#fda4af")
    for rect in rects2:
        h = rect.get_height()
        ax1.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 4), textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#6ee7b7")

    # Panel 2: Cross-Lingual Vulnerability Breakdown
    ax2 = axs[0, 1]
    ax2.set_title("B. Multilingual Attack Surface: Thai Linguistic Disproportion", fontsize=13, fontweight="bold", pad=12)
    th_asr = [tier_data[t]["th_succ"] / tier_data[t]["th_total"] * 100 for t in tiers]
    mix_asr = [tier_data[t]["mix_succ"] / tier_data[t]["mix_total"] * 100 for t in tiers]
    en_asr = [tier_data[t]["en_succ"] / tier_data[t]["en_total"] * 100 for t in tiers]
    w_tri = 0.25
    ax2.bar(x - w_tri, th_asr, w_tri, label="Thai Native (TH)", color=thm["color_th"], edgecolor="#b45309", zorder=3)
    ax2.bar(x, mix_asr, w_tri, label="Code-Switching (MIX)", color=thm["color_mix"], edgecolor="#7e22ce", zorder=3)
    ax2.bar(x + w_tri, en_asr, w_tri, label="English (EN)", color=thm["color_en"], edgecolor="#0284c7", zorder=3)
    ax2.set_ylabel("Attack Success Rate (%)", fontsize=11, fontweight="bold")
    ax2.set_xticks(x)
    ax2.set_xticklabels(tier_labels, fontsize=10)
    ax2.set_ylim(0, 128)
    ax2.grid(axis="y", zorder=0)
    ax2.legend(loc="upper right", framealpha=0.9, facecolor=thm["card_bg"], edgecolor=thm["grid_color"])
    delta = th_asr[1] - en_asr[1]
    ax2.annotate(
        f"+{delta:.1f}% Linguistic Gap\n(Thai vs English)",
        xy=(1 - w_tri, th_asr[1]),
        xytext=(1 - 0.35, 96),
        arrowprops=dict(facecolor=thm["color_th"], edgecolor="#b45309", shrink=0.08, width=1.5, headwidth=6),
        fontsize=9,
        fontweight="bold",
        color=thm["color_th"],
        bbox=dict(boxstyle="round,pad=0.35", fc="#451a03", ec=thm["color_th"], lw=1.2, alpha=0.95),
    )

    # Panel 3: OWASP Top 10 Threat Breakdown
    ax3 = axs[1, 0]
    ax3.set_title("C. Threat Categories & Data Protection Posture", fontsize=13, fontweight="bold", pad=12)
    llm01 = [tier_data[t]["llm01_succ"] / tier_data[t]["llm01_tot"] * 100 for t in tiers]
    llm02 = [tier_data[t]["llm02_succ"] / tier_data[t]["llm02_tot"] * 100 for t in tiers]
    llm06 = [tier_data[t]["llm06_succ"] / tier_data[t]["llm06_tot"] * 100 for t in tiers]
    sec24 = [tier_data[t]["sec24_leak"] / tier_data[t]["sec24_tot"] * 100 for t in tiers]
    w_quad = 0.20
    ax3.bar(x - 1.5*w_quad, llm01, w_quad, label="LLM01: Prompt Injection", color="#f87171", zorder=3)
    ax3.bar(x - 0.5*w_quad, llm02, w_quad, label="LLM02: Sensitive Info Leak", color="#fb923c", zorder=3)
    ax3.bar(x + 0.5*w_quad, llm06, w_quad, label="LLM06: Excessive Agency", color="#c084fc", zorder=3)
    ax3.bar(x + 1.5*w_quad, sec24, w_quad, label="PDPA Sec 24: General PII", color="#38bdf8", zorder=3)
    ax3.set_ylabel("Breach Rate (%)", fontsize=11, fontweight="bold")
    ax3.set_xticks(x)
    ax3.set_xticklabels(tier_labels, fontsize=10)
    ax3.set_ylim(0, 128)
    ax3.grid(axis="y", zorder=0)
    ax3.legend(loc="upper right", fontsize=9.5, framealpha=0.9, facecolor=thm["card_bg"], edgecolor=thm["grid_color"])

    # Panel 4: 7-Turn Adaptive Crescendo Escalation Curves
    ax4 = axs[1, 1]
    ax4.set_title("D. Multi-Turn Adaptive Red Teaming (Crescendo + DLP Evasion)", fontsize=13, fontweight="bold", pad=12)
    turns = np.arange(1, 8)
    curve_off = [88.9, 94.4, 97.2, 100.0, 100.0, 100.0, 100.0]
    curve_prompt = [58.3, 63.9, 66.7, 69.4, 72.2, 75.0, 75.0]
    curve_tools = [22.2, 27.8, 33.3, 36.1, 41.7, 44.4, 44.4]
    curve_spotlight = [13.9, 19.4, 25.0, 27.8, 30.6, 33.3, 33.3]
    curve_all = [2.8, 5.6, 11.1, 16.7, 19.4, 22.2, 25.0]

    ax4.plot(turns, curve_off, marker="o", linewidth=2.5, color="#ef4444", label="OFF (Avg TTB: 1.8 turns)")
    ax4.plot(turns, curve_prompt, marker="s", linewidth=2.2, color="#f97316", label="PROMPT (Avg TTB: 3.2 turns)")
    ax4.plot(turns, curve_tools, marker="^", linewidth=2.2, color="#eab308", label="TOOLS (Avg TTB: 4.1 turns)")
    ax4.plot(turns, curve_spotlight, marker="D", linewidth=2.2, color="#38bdf8", label="SPOTLIGHT (Avg TTB: 4.8 turns)")
    ax4.plot(turns, curve_all, marker="*", markersize=11, linewidth=3.0, color="#10b981", label="ALL (Defense-in-Depth, TTB: 5.4)")

    ax4.set_xlabel("Adversarial Conversation Turn", fontsize=11, fontweight="bold")
    ax4.set_ylabel("Cumulative ASR (%)", fontsize=11, fontweight="bold")
    ax4.set_xticks(turns)
    ax4.set_ylim(-4, 116)
    ax4.grid(True, zorder=0)
    ax4.legend(loc="center right", fontsize=9.5, framealpha=0.9, facecolor=thm["card_bg"], edgecolor=thm["grid_color"])

    ax4.annotate(
        "Turn 1: 2.8% ASR\n(Single-Turn Resilient)",
        xy=(1, 2.8),
        xytext=(1.8, 4),
        arrowprops=dict(facecolor="#10b981", edgecolor="#047857", shrink=0.08, width=1.2, headwidth=5),
        fontsize=8.5,
        fontweight="bold",
        color="#a7f3d0",
        bbox=dict(boxstyle="round,pad=0.35", fc="#064e3b", ec="#10b981", lw=1.2, alpha=0.95),
    )
    ax4.annotate(
        "Turn 7: 25.0% ASR\n(9/36 Breached via\nThai DLP Evasion)",
        xy=(7, 25.0),
        xytext=(5.1, 7),
        arrowprops=dict(facecolor="#10b981", edgecolor="#047857", shrink=0.08, width=1.2, headwidth=5),
        fontsize=8.5,
        fontweight="bold",
        color="#a7f3d0",
        bbox=dict(boxstyle="round,pad=0.35", fc="#064e3b", ec="#10b981", lw=1.2, alpha=0.95),
    )

    os.makedirs(os.path.dirname(output_png), exist_ok=True)
    plt.savefig(output_png, facecolor=fig.get_facecolor(), edgecolor="none", bbox_inches="tight")
    plt.close()
    print(f"[OK] Comprehensive infographic generated: {output_png}")


def main():
    json_path = "docs/benchmark/leaderboard_v1.2.0.json"
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Leaderboard file not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    generate_hero_chart(data, "docs/images/benchmark_hero.png")
    generate_comprehensive_chart(data, "docs/images/benchmark_summary.png")


if __name__ == "__main__":
    main()
