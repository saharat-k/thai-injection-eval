"""Generate a Star-History style hand-drawn Grouped Bar Chart for README.md.

Visualizes Red Team Attack Efficacy across Languages:
- Target Models on X-axis: Meta Llama 3.3 70B, Google Gemini 3.5 Flash, Overall Average
- 3 Bars per group:
  * Thai (TH): #ff5d6c (Coral Red)
  * English (EN): #38bdf8 (Sky Blue)
  * Mixed Code-Switching (TH-EN): #fbbf24 (Amber Yellow)
- Star-History / Rough.js aesthetic:
  * Matte dark canvas (#0b0f19)
  * Dual-pass sketchy hand-drawn bar outlines and hatch textures
  * Hand-drawn typography and clean percentages atop bars
"""
from __future__ import annotations

import os
import random

# Fixed seed for deterministic, reproducible hand-drawn jitter
random.seed(42)


def jitter(val: float, amount: float = 1.0) -> float:
    return val + random.uniform(-amount, amount)


def rough_line(x1: float, y1: float, x2: float, y2: float, stroke: str, stroke_width: float = 1.8, opacity: float = 0.9, extra_jitter: float = 0.8) -> str:
    """Generate a dual-pass sketchy line simulating Rough.js."""
    mx = (x1 + x2) / 2
    my = (y1 + y2) / 2
    
    # Pass 1
    p1_start = f"{jitter(x1, extra_jitter):.1f},{jitter(y1, extra_jitter):.1f}"
    p1_mid = f"{jitter(mx, extra_jitter * 1.4):.1f},{jitter(my, extra_jitter * 1.4):.1f}"
    p1_end = f"{jitter(x2, extra_jitter):.1f},{jitter(y2, extra_jitter):.1f}"
    d1 = f"M {p1_start} Q {p1_mid} {p1_end}"

    # Pass 2
    p2_start = f"{jitter(x1, extra_jitter * 0.7):.1f},{jitter(y1, extra_jitter * 0.7):.1f}"
    p2_mid = f"{jitter(mx, extra_jitter * 1.1):.1f},{jitter(my, extra_jitter * 1.1):.1f}"
    p2_end = f"{jitter(x2, extra_jitter * 0.7):.1f},{jitter(y2, extra_jitter * 0.7):.1f}"
    d2 = f"M {p2_start} Q {p2_mid} {p2_end}"

    return f'''  <path d="{d1}" stroke="{stroke}" stroke-width="{stroke_width}" fill="none" stroke-linecap="round" opacity="{opacity}" />
  <path d="{d2}" stroke="{stroke}" stroke-width="{stroke_width * 0.8:.1f}" fill="none" stroke-linecap="round" opacity="{opacity * 0.7:.2f}" />'''


def rough_bar(x: float, y: float, w: float, h: float, color: str) -> str:
    """Generate a hand-drawn sketchy bar with semi-transparent fill and rough borders."""
    lines = []
    # Fill rectangle with subtle opacity
    lines.append(f'  <rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="4" fill="{color}" fill-opacity="0.82" />')
    
    # 4 Rough border lines
    lines.append(rough_line(x, y, x + w, y, color, stroke_width=2.0, extra_jitter=0.6))
    lines.append(rough_line(x + w, y, x + w, y + h, color, stroke_width=2.0, extra_jitter=0.6))
    lines.append(rough_line(x + w, y + h, x, y + h, color, stroke_width=2.0, extra_jitter=0.6))
    lines.append(rough_line(x, y + h, x, y, color, stroke_width=2.0, extra_jitter=0.6))
    
    return "\n".join(lines)


def generate_red_team_bar_chart(output_path: str = "docs/images/benchmark_trend_sketch.svg"):
    random.seed(1337)
    
    width = 960
    height = 540
    
    # Layout Bounds
    x_origin = 110
    y_origin = 450
    x_max = 890
    y_max = 110
    
    # Scaling: 0% -> 450, 100% -> 110 (Height = 340px, 3.4px per 1%)
    def y_coord(pct: float) -> float:
        return y_origin - (pct * 3.4)

    elements = []
    
    # Header & CSS Styles
    elements.append(f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="100%">
  <defs>
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Shantell+Sans:wght@400;600;700&amp;display=swap');
      .sketch-text {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', -apple-system, BlinkMacSystemFont, 'Segoe UI', cursive, sans-serif;
      }}
      .title-text {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', sans-serif;
        font-weight: 700;
        font-size: 21px;
        fill: #f0f6fc;
      }}
      .sub-text {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', sans-serif;
        font-size: 11.5px;
        fill: #8b949e;
      }}
      .axis-label {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', sans-serif;
        font-weight: 600;
        font-size: 13.5px;
        fill: #c9d1d9;
      }}
      .tick-text {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', sans-serif;
        font-size: 13px;
        fill: #8b949e;
      }}
      .group-title {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', sans-serif;
        font-weight: 700;
        font-size: 14px;
        fill: #f0f6fc;
      }}
      .group-sub {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', sans-serif;
        font-size: 11px;
        fill: #7d8590;
      }}
      .bar-val {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', sans-serif;
        font-weight: 700;
        font-size: 12.5px;
      }}
      .legend-text {{
        font-family: 'Shantell Sans', 'Virgil', 'Comic Sans MS', sans-serif;
        font-size: 13px;
        font-weight: 600;
        fill: #f0f6fc;
      }}
    </style>
  </defs>

  <!-- Matte Dark Background -->
  <rect x="0" y="0" width="{width}" height="{height}" fill="#0b0f19" />
''')

    # Top Title & Subtitle
    elements.append(f'''  <!-- Top Title & Subtitle -->
  <g transform="translate({width / 2}, 30)" text-anchor="middle">
    <text class="title-text">Red Team Attack Efficacy Across Languages</text>
    <text class="sub-text" y="20">Prompt Injection Success Rate (ASR %) on Dataset A v2.0 (108 Isomorphic Triplets • Tier PROMPT)</text>
  </g>
''')

    # Horizontal Top Legend Bar
    leg_y = 74
    elements.append(f'''  <!-- Top Legend -->
  <g transform="translate({width / 2}, {leg_y})" text-anchor="middle">
    <!-- Item 1: Thai (TH) -->
    <g transform="translate(-240, 0)">
      <rect x="-10" y="-10" width="14" height="14" rx="3" fill="#ff5d6c" />
      <text class="legend-text" x="12" y="2" text-anchor="start">Thai Attack (TH)</text>
    </g>
    
    <!-- Item 2: English (EN) -->
    <g transform="translate(-30, 0)">
      <rect x="-10" y="-10" width="14" height="14" rx="3" fill="#38bdf8" />
      <text class="legend-text" x="12" y="2" text-anchor="start">English Attack (EN)</text>
    </g>

    <!-- Item 3: Mixed (TH-EN) -->
    <g transform="translate(180, 0)">
      <rect x="-10" y="-10" width="14" height="14" rx="3" fill="#fbbf24" />
      <text class="legend-text" x="12" y="2" text-anchor="start">Mixed / Code-Switching (TH-EN)</text>
    </g>
  </g>
''')

    # Horizontal Grid Lines & Y Ticks (0%, 25%, 50%, 75%, 100%)
    grid_pcts = [0, 25, 50, 75, 100]
    for pct in grid_pcts:
        y = y_coord(pct)
        # Grid line
        elements.append(f'  <line x1="{x_origin}" y1="{y}" x2="{x_max}" y2="{y}" stroke="#1f2937" stroke-width="1.2" stroke-dasharray="4,4" />')
        # Y Tick text
        elements.append(f'  <text class="tick-text" x="{x_origin - 16}" y="{y + 5}" text-anchor="end">{pct}%</text>')
        # Rough tick mark on Y axis
        elements.append(rough_line(x_origin - 6, y, x_origin, y, "#e6edf3", stroke_width=1.5, extra_jitter=0.3))

    # Rough Axes (X and Y)
    elements.append("  <!-- Y Axis -->")
    elements.append(rough_line(x_origin, y_origin, x_origin, y_max - 15, "#e6edf3", stroke_width=2.4, extra_jitter=0.8))
    elements.append("  <!-- X Axis -->")
    elements.append(rough_line(x_origin, y_origin, x_max + 15, y_origin, "#e6edf3", stroke_width=2.4, extra_jitter=0.8))

    # Y Axis Title (Rotated on the left)
    elements.append(f'''  <!-- Y Axis Title -->
  <text class="axis-label" transform="rotate(-90)" x="{- (y_origin + y_max) / 2}" y="38" text-anchor="middle">Attack Success Rate / Vulnerability (ASR %)</text>
''')

    # X Axis Title (Bottom center)
    elements.append(f'''  <!-- X Axis Title -->
  <text class="axis-label" x="{(x_origin + x_max) / 2}" y="{y_origin + 66}" text-anchor="middle">Target Models</text>
''')

    # =========================================================================
    # Grouped Bar Data
    # 3 Groups: Meta Llama 3.3 70B, Google Gemini 3.5 Flash, Overall Average
    # =========================================================================
    groups = [
        {
            "title": "Meta Llama 3.3 70B",
            "sub": "Instruct (Open Model)",
            "center_x": 260,
            "th": 83.3,
            "en": 50.0,
            "mixed": 70.0,
        },
        {
            "title": "Google Gemini 3.5 Flash",
            "sub": "Lite (Cloud API)",
            "center_x": 515,
            "th": 73.3,
            "en": 60.0,
            "mixed": 73.3,
        },
        {
            "title": "Overall Red Team Average",
            "sub": "Benchmark Synthesis",
            "center_x": 770,
            "th": 78.3,
            "en": 55.0,
            "mixed": 71.7,
        },
    ]

    bar_width = 46
    bar_gap = 12
    total_group_width = (3 * bar_width) + (2 * bar_gap)  # 138 + 24 = 162

    col_thai = "#ff5d6c"     # Coral Red / Pink
    col_en = "#38bdf8"       # Sky Blue
    col_mixed = "#fbbf24"    # Amber Yellow

    for grp in groups:
        cx = grp["center_x"]
        
        # Group Label on X-Axis
        elements.append(f'  <text class="group-title" x="{cx}" y="{y_origin + 28}" text-anchor="middle">{grp["title"]}</text>')
        elements.append(f'  <text class="group-sub" x="{cx}" y="{y_origin + 44}" text-anchor="middle">{grp["sub"]}</text>')
        
        # X positions for the 3 bars
        start_x = cx - (total_group_width / 2)
        x_th = start_x
        x_en = start_x + bar_width + bar_gap
        x_mx = start_x + (2 * (bar_width + bar_gap))
        
        bars_data = [
            (x_th, grp["th"], col_thai, f"{grp['th']:.1f}%"),
            (x_en, grp["en"], col_en, f"{grp['en']:.1f}%"),
            (x_mx, grp["mixed"], col_mixed, f"{grp['mixed']:.1f}%"),
        ]
        
        for bx, pct, color, text_val in bars_data:
            bar_top = y_coord(pct)
            bar_height = y_origin - bar_top
            
            # Draw rough bar
            elements.append(rough_bar(bx, bar_top, bar_width, bar_height, color))
            
            # Value label atop bar
            elements.append(f'  <text class="bar-val" x="{bx + (bar_width / 2)}" y="{bar_top - 8}" fill="{color}" text-anchor="middle">{text_val}</text>')

    # Bottom Right Star-History Watermark Badge
    elements.append(f'''  <!-- Watermark badge -->
  <g transform="translate({width - 35}, {height - 20})" text-anchor="end">
    <text class="sketch-text" font-size="12" fill="#10b981" font-weight="600">★ thai-injection-eval</text>
  </g>
''')

    elements.append("</svg>")
    
    svg_content = "\n".join(elements)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(svg_content)
    print(f"[+] Successfully generated Red Team Bar Chart: {output_path}")


if __name__ == "__main__":
    generate_red_team_bar_chart()
