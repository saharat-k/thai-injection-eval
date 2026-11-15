#!/usr/bin/env python3
"""Build deterministic golden fixtures for tools and system prompts before refactoring."""
import hashlib
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
import agent

FIXTURES_DIR = os.path.join(BASE_DIR, "tests", "fixtures")
os.makedirs(FIXTURES_DIR, exist_ok=True)

def build_tool_fixtures():
    # Representative tool calls across diverse queries and argument combinations
    calls = [
        {"tool": "get_student", "args": {"name": "สมชาย"}},
        {"tool": "get_student", "args": {"name": "NonExistent"}},
        {"tool": "list_courses", "args": {}},
        {"tool": "lookup_student_directory", "args": {"name_or_id": "S001"}},
        {"tool": "lookup_student_directory", "args": {"name_or_id": "Jane"}},
        {"tool": "get_student_private_record", "args": {"student_id": "S001"}},
        {"tool": "get_student_private_record", "args": {"student_id": "S999"}},
        {"tool": "get_faculty_payroll", "args": {"professor_id": "P001"}},
        {"tool": "get_faculty_payroll", "args": {"professor_id": "P999"}},
        {"tool": "query_system_config", "args": {"key_name": "SEC-API-GATEWAY"}},
        {"tool": "search_records", "args": {"table": "students", "keyword": "วิศว"}},
        {"tool": "search_records", "args": {"table": "courses", "keyword": "Data"}},
        {"tool": "export_report", "args": {"title": "Campus Memo", "content": "Test content", "format": "markdown"}},
        {"tool": "send_campus_notification", "args": {"recipient_id": "REGISTRAR", "message_body": "Official memorandum"}},
    ]
    outputs = []
    for c in calls:
        fn = getattr(agent, c["tool"])
        res_str = fn(**c["args"])
        parsed = json.loads(res_str)
        outputs.append({
            "tool": c["tool"],
            "args": c["args"],
            "expected_output": parsed
        })
    
    out_path = os.path.join(FIXTURES_DIR, "golden_tool_outputs.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(outputs, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved {len(outputs)} tool call fixtures to {out_path}")

def build_prompt_fixtures():
    prompt_hashes = {}
    tiers = ("off", "prompt", "tools", "all", "spotlight")
    roles = ("registrar_staff", "student_guest", "system_admin")
    for tier in tiers:
        for role in roles:
            base_sys = agent.core_prompts.HARDENED_SYSTEM_PROMPT if tier in ("prompt", "all") else agent.core_prompts.BASE_SYSTEM_PROMPT
            schema_hint = agent.core_prompts.PUBLIC_SCHEMA_HINT if tier in ("prompt", "tools", "all") else agent.core_prompts.FULL_SCHEMA_HINT
            role_addon = agent.core_prompts.get_blue_role_prompt(role)
            system = f"{base_sys}\n\n{schema_hint}"
            if role_addon:
                system += f"\n\nROLE POLICY:\n{role_addon}"
            h = hashlib.sha256(system.encode("utf-8")).hexdigest()
            prompt_hashes[f"{tier}:{role}"] = h

    out_path = os.path.join(FIXTURES_DIR, "golden_prompt_hashes.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(prompt_hashes, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved {len(prompt_hashes)} prompt hash fixtures to {out_path}")

if __name__ == "__main__":
    build_tool_fixtures()
    build_prompt_fixtures()
