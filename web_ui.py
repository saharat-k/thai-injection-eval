import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for

import agent
from core.adapters.factory import create_target_adapter
from core.evaluator.engine import SecurityEvaluator
from core.evaluator.reporter import export_report_files, generate_markdown_report

def _get_or_create_flask_secret() -> str:
    key = os.getenv("FLASK_SECRET_KEY")
    if key:
        return key
    secret_file = os.path.join(os.path.dirname(__file__), ".flask_secret")
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r", encoding="utf-8") as f:
                saved = f.read().strip()
                if saved:
                    return saved
        except Exception:
            pass
    new_secret = secrets.token_hex(32)
    try:
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(new_secret)
    except Exception:
        pass
    return new_secret


app = Flask(__name__)
app.secret_key = _get_or_create_flask_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
_run_lock = threading.Lock()  # agent.py keeps module-level DB connections during a run
_run_status = {
    "running": False,
    "case_id": "ALL",
    "defense": "off",
    "attempts": 2,
    "started_at": None,
}


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def handle_http_error(e):
    code = getattr(e, "code", 500)
    desc = getattr(e, "description", str(e))
    if request.path.startswith("/api/") or request.path == "/status" or request.is_json:
        if code == 403 and "CSRF" in str(desc):
            desc = "เซสชันหรือความปลอดภัย (CSRF) หมดอายุ กรุณารีเฟรชหน้าเว็บ (F5) แล้วเริ่มเซสชันใหม่"
        return jsonify({"success": False, "error": desc}), code
    return e


@app.errorhandler(Exception)
def handle_unhandled_exception(e):
    agent.audit("unhandled_web_error", {"path": request.path, "error": str(e)[:300]})
    if request.path.startswith("/api/") or request.path == "/status" or request.is_json:
        clean_err = agent.sanitize_error(str(e))
        return jsonify({"success": False, "error": f"เซิร์ฟเวอร์เกิดข้อผิดพลาด: {clean_err}"}), 500
    raise e


@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'self'; form-action 'self';"
    )
    return response


def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _parse_result_rows(rows):
    parsed = []
    for r in rows:
        d = dict(r)
        try:
            d["canaries_list"] = json.loads(d.get("leaked_canaries") or "[]")
        except Exception:
            d["canaries_list"] = []
        try:
            d["raw_canaries_list"] = json.loads(d.get("raw_leaked_canaries") or "[]")
        except Exception:
            d["raw_canaries_list"] = []
        try:
            d["schema_disclosed_list"] = json.loads(d.get("schema_disclosed") or "[]")
        except Exception:
            d["schema_disclosed_list"] = []
        try:
            d["tool_calls_list"] = json.loads(d.get("tool_calls_json") or "[]")
        except Exception:
            d["tool_calls_list"] = []
        d["output_intercepted"] = bool(d["raw_canaries_list"]) and not bool(d["canaries_list"])
        parsed.append(d)
    return parsed


def latest_results(limit=100):
    if not os.path.exists(agent.RESULTS_DB_PATH):
        return []
    conn = agent.init_results_db(agent.RESULTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, language, attack_type, source_reference, technique, prompt, "
            "injected_prompt, response, success, private_table_accessed, private_table_blocked, "
            "leaked_canaries, raw_leaked_canaries, schema_disclosed, tool_calls_json, red_analysis, red_strategy, "
            "defense_level, attempt, red_model, blue_model, run_timestamp "
            "FROM test_results ORDER BY run_timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return _parse_result_rows(rows)
    finally:
        conn.close()


def manual_history(limit=50):
    if not os.path.exists(agent.RESULTS_DB_PATH):
        return []
    conn = agent.init_results_db(agent.RESULTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, language, attack_type, source_reference, technique, prompt, "
            "injected_prompt, response, success, private_table_accessed, private_table_blocked, "
            "leaked_canaries, raw_leaked_canaries, schema_disclosed, tool_calls_json, red_analysis, red_strategy, "
            "defense_level, attempt, red_model, blue_model, run_timestamp "
            "FROM test_results "
            "WHERE id LIKE 'MANUAL-%' OR source_reference = 'manual' "
            "ORDER BY run_timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return _parse_result_rows(rows)
    finally:
        conn.close()


@app.route("/")
def index():
    all_results = latest_results(limit=100)
    manual_results = manual_history(limit=50)
    leaked_results = [r for r in all_results if r["success"] == 1]
    safe_results = [r for r in all_results if r["success"] == 0]
    error_results = [r for r in all_results if r["success"] == -1]

    total_runs = len(all_results)
    valid_runs = len(leaked_results) + len(safe_results)
    leak_rate = round((len(leaked_results) / valid_runs * 100), 1) if valid_runs > 0 else 0.0

    try:
        test_cases = agent.load_test_cases()
    except Exception:
        test_cases = []

    return render_template(
        "index.html",
        results=all_results,
        manual_results=manual_results,
        leaked_results=leaked_results,
        safe_results=safe_results,
        error_results=error_results,
        total_runs=total_runs,
        leaked_count=len(leaked_results),
        safe_count=len(safe_results),
        error_count=len(error_results),
        leak_rate=leak_rate,
        model=agent.MODEL_NAME,
        red_model=agent.RED_MODEL,
        blue_model=agent.BLUE_MODEL,
        defense_levels=agent.DEFENSE_LEVELS,
        blue_roles=agent.BLUE_ROLES,
        red_profiles=agent.RED_PROFILES,
        test_cases=test_cases,
        run_status= dict(_run_status, is_locked=_run_lock.locked()),
        csrf_token=get_csrf_token(),
    )


@app.route("/status")
def status():
    return jsonify({
        "running": _run_lock.locked(),
        "case_id": _run_status.get("case_id"),
        "defense": _run_status.get("defense"),
        "attempts": _run_status.get("attempts"),
        "started_at": _run_status.get("started_at"),
    })


@app.route("/run", methods=["POST"])
def run():
    # Validate anti-CSRF token before making external API calls
    token = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not token or not expected or not secrets.compare_digest(token, expected):
        abort(403, description="Invalid or missing CSRF token.")

    defense = request.form.get("defense", "off")
    if defense not in agent.DEFENSE_LEVELS:
        defense = "off"

    case_id = request.form.get("case_id", "ALL").strip() or "ALL"
    valid_case_ids = {"ALL"} | {c["id"] for c in agent.load_test_cases()}
    if case_id not in valid_case_ids:
        case_id = "ALL"

    try:
        attempts = max(1, min(5, int(request.form.get("attempts", "2"))))
    except ValueError:
        attempts = 2

    if not _run_lock.acquire(blocking=False):
        return redirect(url_for("index"))

    _run_status["running"] = True
    _run_status["case_id"] = case_id
    _run_status["defense"] = defense
    _run_status["attempts"] = attempts
    _run_status["started_at"] = agent.now()

    def _worker():
        try:
            agent.run_all(defense=defense, max_attempts=attempts, case_id=case_id)
        finally:
            _run_status["running"] = False
            _run_lock.release()

    threading.Thread(target=_worker, daemon=True).start()
    return redirect(url_for("index"))


# ------------------------------------------------------------------ Manual Mode API
MAX_PROMPT_LENGTH = 10_000
MAX_MANUAL_SESSIONS = 50
_manual_sessions = {}
_manual_lock = threading.Lock()


def verify_csrf():
    token = (
        request.headers.get("X-CSRFToken")
        or request.form.get("csrf_token")
        or (request.get_json(silent=True) or {}).get("csrf_token")
    )
    expected = session.get("csrf_token", "")
    if not token or not expected or not secrets.compare_digest(token, expected):
        abort(403, description="Invalid or missing CSRF token.")


@app.route("/api/manual/templates")
def manual_templates():
    try:
        cases = agent.load_test_cases()
        return jsonify({"success": True, "templates": cases})
    except Exception as e:
        return jsonify({"success": False, "error": agent.sanitize_error(str(e))}), 500


@app.route("/api/manual/history")
def api_manual_history():
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 200))
    history = manual_history(limit=limit)
    return jsonify({
        "success": True,
        "history": history,
        "count": len(history),
    })


def cleanup_stale_sessions(max_age_seconds: int = 7200):
    """Remove manual sessions created more than max_age_seconds ago to prevent memory leaks."""
    now_ts = datetime.now(timezone.utc).timestamp()
    with _manual_lock:
        to_delete = []
        for sid, s in _manual_sessions.items():
            created_at = s.get("created_at")
            if created_at:
                try:
                    dt = datetime.fromisoformat(created_at)
                    if (now_ts - dt.timestamp()) > max_age_seconds:
                        to_delete.append(sid)
                except Exception:
                    pass
        for sid in to_delete:
            _manual_sessions.pop(sid, None)


@app.route("/api/manual/start", methods=["POST"])
def manual_start():
    cleanup_stale_sessions()
    verify_csrf()
    data = request.get_json(silent=True) or request.form
    defense = data.get("defense", "off")
    if defense not in agent.DEFENSE_LEVELS:
        defense = "off"
    language = data.get("language", "Thai")
    if language not in ("Thai", "English", "Mixed"):
        language = "Thai"
    attack_type = data.get("attack_type", "direct")
    if attack_type not in ("direct", "indirect", "recon", "semantic", "roleplay", "fewshot", "obfuscation"):
        attack_type = "direct"

    blue_role = data.get("blue_role", "registrar_staff")
    if blue_role not in agent.BLUE_ROLES:
        blue_role = "registrar_staff"
    red_profile = data.get("red_profile", "realistic_attacker")
    if red_profile not in agent.RED_PROFILES:
        red_profile = "realistic_attacker"

    raw_targets = data.get("targets", "")
    targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

    session_id = f"MANUAL-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"

    with _manual_lock:
        if len(_manual_sessions) >= MAX_MANUAL_SESSIONS:
            sorted_sids = sorted(
                _manual_sessions.keys(),
                key=lambda k: _manual_sessions[k].get("created_at", ""),
            )
            while len(_manual_sessions) >= MAX_MANUAL_SESSIONS and sorted_sids:
                _manual_sessions.pop(sorted_sids.pop(0), None)

        blue_session = agent.BlueSession(defense, role=blue_role)
        canaries = agent.load_canaries()
        case = {
            "id": session_id,
            "language": language,
            "attack_type": attack_type,
            "prompt": "",
            "source_reference": "manual",
            "targets": targets,
        }
        _manual_sessions[session_id] = {
            "session_id": session_id,
            "defense": defense,
            "language": language,
            "attack_type": attack_type,
            "blue_role": blue_role,
            "red_profile": red_profile,
            "blue_session": blue_session,
            "canaries": canaries,
            "case": case,
            "history": [],
            "turn_no": 1,
            "created_at": agent.now(),
        }
        agent.audit("manual_start", {
            "id": session_id,
            "defense": defense,
            "language": language,
            "attack_type": attack_type,
            "blue_role": blue_role,
            "red_profile": red_profile,
            "targets": targets,
            "source": "web_ui",
        })

    return jsonify({
        "success": True,
        "session_id": session_id,
        "defense": defense,
        "language": language,
        "attack_type": attack_type,
        "targets": targets,
        "blue_role": blue_role,
        "red_profile": red_profile,
    })


@app.route("/api/manual/send", methods=["POST"])
def manual_send():
    verify_csrf()
    data = request.get_json(silent=True) or request.form
    session_id = data.get("session_id")
    prompt = (data.get("prompt") or "").strip()

    if not session_id or session_id not in _manual_sessions:
        return jsonify({"success": False, "error": "เซสชันไม่ถูกต้อง หรือหมดอายุแล้ว"}), 400
    if not prompt:
        return jsonify({"success": False, "error": "กรุณากรอกข้อความ Prompt"}), 400
    if len(prompt) > MAX_PROMPT_LENGTH:
        return jsonify({"success": False, "error": f"ความยาวข้อความ Prompt ต้องไม่เกิน {MAX_PROMPT_LENGTH:,} ตัวอักษร"}), 400

    with _manual_lock:
        sess = _manual_sessions[session_id]
        sess["case"]["prompt"] = sess["case"]["prompt"] or prompt
        turn_no = sess["turn_no"]

    res = agent.execute_manual_turn(
        session=sess["blue_session"],
        case=sess["case"],
        canaries=sess["canaries"],
        defense=sess["defense"],
        turn_no=turn_no,
        sender="Human",
        attack=prompt,
        red_meta=None,
        session_id=session_id,
        blue_role=sess.get("blue_role", "registrar_staff"),
        red_profile=sess.get("red_profile", "realistic_attacker"),
    )

    with _manual_lock:
        if not res.get("error"):
            sess["history"].append((prompt, res.get("response", "")))
        sess["turn_no"] += 1

    return jsonify({
        "success": True,
        "turn_no": turn_no,
        "sender": "Human",
        "attack": prompt,
        "response": res.get("response", ""),
        "tool_calls": res.get("tool_calls", []),
        "leaked": res.get("leaked", []),
        "raw_leaked": res.get("raw_leaked", []),
        "output_intercepted": res.get("output_intercepted", False),
        "private_table_accessed": res.get("private_table_accessed", False),
        "private_table_blocked": res.get("private_table_blocked", False),
        "defense": sess.get("defense", "off"),
        "blue_role": sess.get("blue_role", "registrar_staff"),
        "red_profile": sess.get("red_profile", "realistic_attacker"),
        "target_leaked": res.get("target_leaked", []),
        "collateral_leaked": res.get("collateral_leaked", []),
        "schema_disclosed": res.get("schema_disclosed", []),
        "hits": res.get("hits", []),
        "is_target_met": res.get("is_target_met", False),
        "error": res.get("error"),
    })


@app.route("/api/manual/ai-step", methods=["POST"])
def manual_ai_step():
    verify_csrf()
    data = request.get_json(silent=True) or request.form
    session_id = data.get("session_id")

    if not session_id or session_id not in _manual_sessions:
        return jsonify({"success": False, "error": "เซสชันไม่ถูกต้อง หรือหมดอายุแล้ว"}), 400

    sess = _manual_sessions[session_id]
    if not sess["history"]:
        return jsonify({
            "success": False,
            "error": "ยังไม่มีคำตอบในบทสนทนาให้ AI วิเคราะห์ กรุณาส่ง Prompt แรกก่อนเริ่มให้ AI ทำงาน",
        }), 400

    with _manual_lock:
        turn_no = sess["turn_no"]
        last_resp = sess["history"][-1][1] if sess["history"] else ""
        blue_role = sess.get("blue_role", "registrar_staff")
        red_profile = sess.get("red_profile", "realistic_attacker")

    try:
        attack, meta = agent.ask_red(sess["case"], sess["history"], turn_no, red_profile=red_profile, blue_role=blue_role)
    except Exception as e:
        agent.audit("red_error", {"id": session_id, "turn": turn_no, "error": str(e)[:300]})
        attack, meta = agent.build_fallback_attack(sess["case"], turn_no, last_resp)

    res = agent.execute_manual_turn(
        session=sess["blue_session"],
        case=sess["case"],
        canaries=sess["canaries"],
        defense=sess["defense"],
        turn_no=turn_no,
        sender="AI (Red)",
        attack=attack,
        red_meta=meta,
        session_id=session_id,
        blue_role=blue_role,
        red_profile=red_profile,
    )

    with _manual_lock:
        if not res.get("error"):
            sess["history"].append((attack, res.get("response", "")))
        sess["turn_no"] += 1

    has_targets = bool(sess["case"].get("targets"))
    is_target_met = res.get("is_target_met", False)
    should_stop = False
    stop_reason = ""
    if res.get("error"):
        should_stop = True
        stop_reason = f"เกิดข้อผิดพลาด API: {res['error']}"
    elif is_target_met:
        should_stop = True
        target_desc = res.get("target_leaked") or res.get("hits") or res.get("leaked")
        stop_reason = f"🎯 สำเร็จ! ตรวจพบข้อมูลเป้าหมายที่ตั้งไว้: {target_desc}"
    elif not has_targets and res.get("leaked"):
        should_stop = True
        stop_reason = f"🚨 พบข้อมูล Canary รั่วไหลในคำตอบ: {res['leaked']}"

    return jsonify({
        "success": True,
        "turn_no": turn_no,
        "sender": "AI (Red)",
        "attack": attack,
        "response": res.get("response", ""),
        "tool_calls": res.get("tool_calls", []),
        "leaked": res.get("leaked", []),
        "raw_leaked": res.get("raw_leaked", []),
        "output_intercepted": res.get("output_intercepted", False),
        "private_table_accessed": res.get("private_table_accessed", False),
        "private_table_blocked": res.get("private_table_blocked", False),
        "defense": sess.get("defense", "off"),
        "blue_role": sess.get("blue_role", "registrar_staff"),
        "red_profile": sess.get("red_profile", "realistic_attacker"),
        "target_leaked": res.get("target_leaked", []),
        "collateral_leaked": res.get("collateral_leaked", []),
        "schema_disclosed": res.get("schema_disclosed", []),
        "hits": res.get("hits", []),
        "is_target_met": is_target_met,
        "error": res.get("error"),
        "meta": meta,
        "should_stop": should_stop,
        "stop_reason": stop_reason,
    })


@app.route("/api/manual/session/<session_id>")
def api_manual_session_turns(session_id):
    """Retrieve all turns for a specific manual red-teaming session in sequential order."""
    if not session_id:
        return jsonify({"success": False, "error": "Missing session_id"}), 400
    if not os.path.exists(agent.RESULTS_DB_PATH):
        return jsonify({"success": False, "error": "Database not found"}), 404
    conn = agent.init_results_db(agent.RESULTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, language, attack_type, source_reference, technique, prompt, "
            "injected_prompt, response, success, private_table_accessed, private_table_blocked, "
            "leaked_canaries, raw_leaked_canaries, schema_disclosed, tool_calls_json, red_analysis, red_strategy, "
            "defense_level, attempt, red_model, blue_model, run_timestamp "
            "FROM test_results WHERE id = ? ORDER BY attempt ASC",
            (session_id,),
        ).fetchall()
        turns = _parse_result_rows(rows)
        return jsonify({"success": True, "session_id": session_id, "turns": turns, "count": len(turns)})
    finally:
        conn.close()


@app.route("/api/manual/reset", methods=["POST"])
def manual_reset():
    verify_csrf()
    data = request.get_json(silent=True) or request.form
    session_id = data.get("session_id")
    with _manual_lock:
        sess = _manual_sessions.pop(session_id, None)
        if sess:
            agent.audit("manual_end", {"id": session_id, "turns": sess["turn_no"] - 1, "source": "web_ui"})
    return jsonify({"success": True})


@app.route("/api/manual/generate-prompt", methods=["POST"])
def manual_generate_prompt():
    verify_csrf()
    data = request.get_json(silent=True) or request.form
    description = (data.get("description") or "").strip()
    session_id = data.get("session_id")
    technique = (data.get("technique") or "auto").strip()

    if not description:
        return jsonify({"success": False, "error": "กรุณากรอกคำอธิบายหรือไอเดียของ Prompt ที่ต้องการให้ AI สร้าง"}), 400

    if len(description) > MAX_PROMPT_LENGTH:
        return jsonify({"success": False, "error": f"ความยาวคำอธิบายต้องไม่เกิน {MAX_PROMPT_LENGTH:,} ตัวอักษร"}), 400

    defense = data.get("defense", "off")
    language = data.get("language", "Thai")
    raw_targets = data.get("targets", "")
    targets = [t.strip() for t in raw_targets.split(",") if t.strip()] if isinstance(raw_targets, str) else (raw_targets or [])

    blue_role = data.get("blue_role")
    red_profile = data.get("red_profile")
    if session_id and session_id in _manual_sessions:
        sess = _manual_sessions[session_id]
        defense = sess.get("defense", defense)
        language = sess.get("language", language)
        blue_role = blue_role or sess.get("blue_role")
        red_profile = red_profile or sess.get("red_profile")
        if not targets:
            targets = sess.get("case", {}).get("targets", [])
    blue_role = blue_role or "registrar_staff"
    red_profile = red_profile or "realistic_attacker"

    try:
        res = agent.generate_attack_prompt(
            description=description,
            defense=defense,
            language=language,
            technique=technique,
            targets=targets,
            red_profile=red_profile,
            blue_role=blue_role,
        )
        return jsonify({
            "success": True,
            "prompt": res.get("prompt", ""),
            "analysis": res.get("analysis", ""),
            "tactic": res.get("tactic", ""),
            "technique": res.get("technique", technique),
            "source": res.get("source", "fallback"),
            "blue_role": blue_role,
            "red_profile": red_profile,
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"เกิดข้อผิดพลาดในการสร้าง Prompt: {agent.sanitize_error(str(e))}"}), 500


@app.route("/api/eval/run", methods=["POST"])
def api_eval_run():
    verify_csrf()

    data = request.get_json(silent=True) or request.form
    target_type = (data.get("target_type") or "builtin").strip()
    defense = (data.get("defense") or "off").strip()
    blue_role = (data.get("blue_role") or "registrar_staff").strip()
    base_url = (data.get("base_url") or "http://localhost:8000/v1").strip()
    model = (data.get("model") or "default").strip()
    api_key = (data.get("api_key") or "").strip()

    cfg = {
        "defense": defense,
        "blue_role": blue_role,
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
    }

    try:
        adapter = create_target_adapter(target_type, config=cfg)
        evaluator = SecurityEvaluator(adapter)
        report = evaluator.run_benchmark(defense=defense, blue_role=blue_role)
        export_report_files(report, output_dir="results", base_name="owasp_evaluation_report")
        return jsonify({"success": True, "report": report})
    except Exception as e:
        return jsonify({"success": False, "error": f"Evaluation failed: {agent.sanitize_error(str(e))}"}), 500


@app.route("/api/eval/latest", methods=["GET"])
def api_eval_latest():
    report_path = os.path.join(os.path.dirname(__file__), "results", "owasp_evaluation_report.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return jsonify({"success": True, "report": data})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    return jsonify({"success": False, "error": "No previous evaluation report found"}), 404


if __name__ == "__main__":
    # Bind strictly to localhost so the test runner is not exposed on the network
    app.run(host="127.0.0.1", port=5000, debug=False)
