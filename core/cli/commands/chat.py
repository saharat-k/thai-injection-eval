"""Chat command: interactive manual red-teaming playground in terminal."""
import os
import sys
from datetime import datetime
from typing import Optional, List, Dict, Any

from core.cli.terminal.colors import (
    bold, dim, red, green, yellow, cyan, blue, style, status_badge
)
from core.cli.terminal.tty import get_terminal_width, is_tty, should_color
from core.cli.output.table import format_table


def print_security_turn_card(turn_no: int, sender: str, attack: str, res: dict, red_meta: Optional[dict] = None, no_color: bool = False):
    """Render a comprehensive Cyber Security Inspection Card for a chat turn."""
    color_enabled = not no_color
    width = min(80, max(60, get_terminal_width()))
    line = "─" * width
    double_line = "═" * width

    print("\n" + double_line)
    header = f" TURN {turn_no} | SENDER: {sender.upper()} "
    print(bold(header.center(width, "■"), enabled=color_enabled))
    print(double_line)

    if red_meta and (red_meta.get("analysis") or red_meta.get("strategy")):
        print(bold("🧠 [RED ATTACK STRATEGY & TACTIC]", enabled=color_enabled))
        if red_meta.get("analysis"):
            print(dim(f"  * Analysis: {red_meta['analysis']}", enabled=color_enabled))
        if red_meta.get("strategy"):
            print(dim(f"  * Counter-Strategy: {red_meta['strategy']}", enabled=color_enabled))
        print(line)

    # Prompt Section
    print(bold("📤 [SENT PROMPT PAYLOAD]", enabled=color_enabled))
    for p_line in attack.strip().splitlines():
        print(f"  > {p_line}")
    print(line)

    # Response Section
    if res.get("error"):
        print(bold("⚠️ [ERROR OCCURRED]", enabled=color_enabled))
        print(red(f"  {res['error']}", enabled=color_enabled))
    else:
        print(bold("📥 [BLUE ASSISTANT RESPONSE]", enabled=color_enabled))
        resp_text = res.get("response", "").strip() or "[EMPTY RESPONSE]"
        for r_line in resp_text.splitlines():
            print(f"  {r_line}")
    print(line)

    # Tool Calls Audit
    calls = res.get("tool_calls", [])
    print(bold(f"🔧 [TOOL EXECUTION AUDIT ({len(calls)} calls)]", enabled=color_enabled))
    if not calls:
        print(dim("  (No tool calls made in this turn)", enabled=color_enabled))
    else:
        for c in calls:
            t_name = c.get("tool", "unknown")
            t_args = c.get("args") if isinstance(c.get("args"), dict) else {}
            t_tbl = t_args.get("table", t_args.get("name", t_args.get("key_name", t_args.get("student_id", t_args.get("professor_id", "-"))))) if t_args else "-"
            t_status = c.get("status", "unknown").upper()
            badge = status_badge(t_status, enabled=color_enabled)
            extra = f" [reason: {c['reason']}]" if c.get("reason") else ""
            print(f"  • {bold(t_name, enabled=color_enabled)}(target={t_tbl}) ➔ {badge}{extra}")
    print(line)

    # Security Posture & Leak Analysis
    target_leaked = res.get("target_leaked", [])
    hits = res.get("hits", [])
    collateral = res.get("collateral_leaked", [])
    canary_leaked = res.get("leaked", [])
    schema_disclosed = res.get("schema_disclosed", [])

    is_breached = bool(target_leaked or hits or collateral or canary_leaked or schema_disclosed)

    print(bold("🛡️ [SECURITY POSTURE & DATA LEAK AUDIT]", enabled=color_enabled))
    if is_breached:
        badge = status_badge("BREACH DETECTED", enabled=color_enabled)
        print(f"  Post-Turn Status: {badge}")
        if target_leaked:
            print(red(f"  🚨 Target Leaked     : {', '.join(str(x) for x in target_leaked)}", enabled=color_enabled))
        if hits:
            print(red(f"  🎯 Target Hits       : {', '.join(str(x) for x in hits)}", enabled=color_enabled))
        if collateral:
            print(yellow(f"  ⚠️ Collateral Leaks  : {', '.join(str(x) for x in collateral)}", enabled=color_enabled))
        if canary_leaked:
            print(red(f"  🔑 Canary Tokens     : {', '.join(str(x) for x in canary_leaked)}", enabled=color_enabled))
        if schema_disclosed:
            print(yellow(f"  📋 Schema Disclosed  : {', '.join(str(x) for x in schema_disclosed)}", enabled=color_enabled))
    else:
        badge = status_badge("CLEAN / DEFENDED", enabled=color_enabled)
        print(f"  Post-Turn Status: {badge}")
        print(green("  ✔ No honeytoken canaries, target records, or schema disclosures detected.", enabled=color_enabled))

    print(double_line + "\n")


def print_preflight_briefing_card(
    session_id: str,
    defense: str,
    blue_role: str,
    red_profile: str,
    lang: str,
    attack_type: str,
    targets: Optional[List[str]] = None,
    canaries: Optional[List[str]] = None,
    no_color: bool = False,
):
    """Render a comprehensive Session Pre-Flight Briefing Card in Red/Cyan theme."""
    import agent
    color_enabled = not no_color
    width = min(80, max(60, get_terminal_width()))
    line = "─" * width
    double_line = "═" * width

    blue_meta = agent.get_blue_role(blue_role)
    red_meta = agent.get_red_profile(red_profile)

    b_name = blue_meta.get("name", blue_role)
    r_name = red_meta.get("name", red_profile)

    print("\n" + double_line)
    header = "■ SESSION PRE-FLIGHT BRIEFING ■"
    print(bold(header.center(width), enabled=color_enabled))
    print(double_line)

    print(f"  {bold('Session ID', enabled=color_enabled):<20} : {cyan(session_id, enabled=color_enabled)}")
    def_badge = status_badge(defense.upper(), enabled=color_enabled)
    print(f"  {bold('Target System', enabled=color_enabled):<20} : {cyan(f'Blue Assistant ({blue_role}: {b_name})', enabled=color_enabled)}")
    print(f"  {bold('Active Defense', enabled=color_enabled):<20} : {def_badge}")
    print(f"  {bold('Attack Surface', enabled=color_enabled):<20} : Language: {bold(lang.upper(), enabled=color_enabled)} | Vector: {bold(attack_type.upper(), enabled=color_enabled)}")
    print(f"  {bold('Red Operator', enabled=color_enabled):<20} : {red(f'{red_profile} ({r_name})', enabled=color_enabled)}")

    tgt_str = ", ".join(targets) if targets else "(Default targets monitored)"
    print(f"  {bold('Target Watchlist', enabled=color_enabled):<20} : {yellow(tgt_str, enabled=color_enabled)}")

    canary_cnt = len(canaries) if canaries else 0
    canary_status = f"{canary_cnt} Active Canary Traps Loaded" if canary_cnt > 0 else "No active canaries"
    print(f"  {bold('Defense Canaries', enabled=color_enabled):<20} : {green(f'✔ {canary_status}', enabled=color_enabled)}")

    print(line)
    print(dim("  Console ready. Select a delivery method below to begin red-teaming.", enabled=color_enabled))
    print(double_line + "\n")


def review_payload_card(
    attack: str,
    source: str = "Manual",
    meta: Optional[Dict[str, Any]] = None,
    no_color: bool = False,
) -> Optional[str]:
    """Render an aesthetic Prompt Composer Card with unified review actions."""
    import agent
    color_enabled = not no_color
    width = min(80, max(60, get_terminal_width()))
    line = "─" * width
    double_line = "═" * width

    curr_attack = attack

    while True:
        lines = curr_attack.strip().splitlines()
        chars_cnt = len(curr_attack)
        lines_cnt = len(lines)

        print("\n" + double_line)
        header = "🎯 [OUTGOING ATTACK PAYLOAD COMPOSER]"
        print(bold(header.center(width), enabled=color_enabled))
        sub_info = f"Source: {source} | Size: {chars_cnt} chars, {lines_cnt} lines"
        print(dim(sub_info.center(width), enabled=color_enabled))
        print(line)

        if meta and (meta.get("tactic") or meta.get("analysis")):
            if meta.get("tactic"):
                print(bold("🧠 [TACTIC & FRAMING]", enabled=color_enabled))
                print(dim(f"  {meta['tactic']}", enabled=color_enabled))
            if meta.get("analysis"):
                print(bold("🛡️ [SECURITY ANALYSIS]", enabled=color_enabled))
                print(dim(f"  {meta['analysis']}", enabled=color_enabled))
            print(line)

        print(bold("📝 [PAYLOAD PREVIEW]", enabled=color_enabled))
        for idx, p_line in enumerate(lines, 1):
            num = dim(f"{idx:2d} │", enabled=color_enabled)
            print(f"  {num} {red(p_line, enabled=color_enabled)}")
        print(double_line + "\n")

        # Unified Prompt Review Action
        action = agent._choose(
            "ดำเนินการอย่างไรกับ Payload นี้?",
            [
                "🚀 ส่ง Payload นี้ทันที (Dispatch)",
                "✏️ แก้ไขข้อความก่อนส่ง (Edit)",
                "❌ ยกเลิก (กลับไปเลือกใหม่)",
            ],
            1,
        )
        if action == 0:
            return curr_attack
        elif action == 1:
            edit_choice = agent._choose(
                "เลือกรูปแบบการแก้ไขข้อความ:",
                [
                    "🔍 ค้นหาและแทนที่คำ (Search & Replace)",
                    "➕ เพิ่มข้อความต่อท้าย (Append)",
                    "📝 พิมพ์ข้อความใหม่ทั้งก้อน (Rewrite)",
                ],
                1,
            )
            if edit_choice == 0:
                old_w = agent._ask("ระบุคำหรือข้อความเดิมที่ต้องการเปลี่ยน")
                if not old_w:
                    print("  ! ยกเลิกการแทนที่คำ")
                    continue
                if old_w not in curr_attack:
                    print(f"  ! ไม่พบคำว่า '{old_w}' ใน Payload ปัจจุบัน")
                    continue
                new_w = agent._ask(f"แทนที่ '{old_w}' ด้วยคำว่า", "")
                curr_attack = curr_attack.replace(old_w, new_w)
                source = f"{source} (Replaced '{old_w}')"
                continue
            elif edit_choice == 1:
                extra = agent._read_multiline("พิมพ์ข้อความที่ต้องการเพิ่มต่อท้าย")
                if extra:
                    curr_attack = f"{curr_attack}\n{extra}".strip()
                    source = f"{source} (Appended)"
                continue
            else:
                edited = agent._read_multiline("พิมพ์ข้อความใหม่ทั้งหมด")
                if edited:
                    curr_attack = edited
                    source = f"{source} (Rewritten)"
                continue
        else:
            return None


def run_chat(args) -> int:
    """Execute the interactive terminal red-teaming playground."""
    import agent

    # If flags passed, use them; otherwise let interactive wizard handle them
    defense = getattr(args, "defense", None)
    role = getattr(args, "role", None)
    lang = getattr(args, "lang", None)
    attack_type = getattr(args, "attack_type", None)
    targets_arg = getattr(args, "targets", None)
    no_color = getattr(args, "no_color", False)

    # Check API key before entering chat
    if not os.getenv("GEMINI_API_KEY"):
        print(yellow("\n[!] Warning: GEMINI_API_KEY is not set in environment or .env file.", enabled=not no_color))
        print("    Live model calls require an API key unless using a mock or external provider.\n")

    # Patch agent functions to use Cyber Security Card formatting
    orig_print_turn = agent._print_turn
    orig_print_preflight = getattr(agent, "_print_preflight", None)
    orig_review_payload = getattr(agent, "_review_payload", None)

    def patched_print_turn(turn_no, sender, attack, res, red_meta=None):
        print_security_turn_card(turn_no, sender, attack, res, red_meta=red_meta, no_color=no_color)

    def patched_print_preflight(session_id, defense, blue_role, red_profile, lang, attack_type, targets=None, canaries=None):
        print_preflight_briefing_card(
            session_id, defense, blue_role, red_profile, lang, attack_type, targets=targets, canaries=canaries, no_color=no_color
        )

    def patched_review_payload(attack, source="Manual", meta=None, **kwargs):
        return review_payload_card(attack, source=source, meta=meta, no_color=no_color)

    agent._print_turn = patched_print_turn
    agent._print_preflight = patched_print_preflight
    agent._review_payload = patched_review_payload

    try:
        targets = [t.strip() for t in targets_arg.split(",") if t.strip()] if targets_arg else None
        agent.manual_mode(
            defense=defense,
            blue_role=role,
            red_profile=getattr(args, "red_profile", None),
            lang=lang,
            attack_type=attack_type,
            targets=targets,
        )
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\n[+] Exited chat session.")
        return 0
    except Exception as e:
        print(red(f"[-] Chat session error: {e}", enabled=not no_color), file=sys.stderr)
        return 3
    finally:
        agent._print_turn = orig_print_turn
        if orig_print_preflight:
            agent._print_preflight = orig_print_preflight
        if orig_review_payload:
            agent._review_payload = orig_review_payload
