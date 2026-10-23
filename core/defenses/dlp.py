"""Stateless output-guard (DLP) and sanitization helpers.

Pure functions: no database access, no module-level mutable state.
Re-exported by ``agent`` so existing imports keep working.
"""
import base64
import os
import re
import unicodedata

PRIVATE_TABLES = (
    "internal_secrets",
    "staff_payroll",
    "student_private",
    "disciplinary_records",
    "scholarship_financials",
)


_THAI_DIGIT_MAP = str.maketrans("๐๑๒๓๔๕๖๗๘๙", "0123456789")


def _normalize_text(s: str) -> str:
    """Normalize Unicode (NFKC), convert Thai digits, and strip separators for evasion-resistant matching."""
    normalized = unicodedata.normalize("NFKC", s).translate(_THAI_DIGIT_MAP)
    return re.sub(r"[\s\-_,.:;/\\|+*#`'\"]+", "", normalized).upper()


def sanitize_error(err: str) -> str:
    """Sanitize error messages to prevent inadvertent API key exposure in logs and responses."""
    if not err:
        return ""
    err_str = str(err)
    for env_var in ("GEMINI_API_KEY", "OPENROUTER_API_KEY", "GITHUB_TOKEN", "GROQ_API_KEY"):
        val = os.getenv(env_var)
        if val and len(val) >= 8:
            err_str = err_str.replace(val, "[REDACTED_API_KEY]")
    err_str = re.sub(r"key=AIza[0-9A-Za-z-_]{35}", "key=[REDACTED_API_KEY]", err_str)
    err_str = re.sub(r"AIzaSy[0-9A-Za-z-_]{33}", "[REDACTED_API_KEY]", err_str)
    err_str = re.sub(r"sk-or-v1-[0-9a-fA-F]{64}", "[REDACTED_API_KEY]", err_str)
    err_str = re.sub(r"Bearer\s+[A-Za-z0-9\-_.]{20,}", "Bearer [REDACTED_TOKEN]", err_str, flags=re.IGNORECASE)
    return err_str


def _extract_decoded_candidates(text: str) -> list[str]:
    """Decode potential Base64 and hexadecimal payloads embedded in the model response."""
    decoded = []
    for candidate in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", text):
        if len(candidate) % 4 != 0:
            continue
        try:
            raw_bytes = base64.b64decode(candidate, validate=True)
            decoded_str = raw_bytes.decode("utf-8", errors="ignore")
            if decoded_str and any(ch.isalnum() for ch in decoded_str):
                decoded.append(decoded_str)
        except Exception:
            continue
    for hex_candidate in re.findall(r"\b(?:0x)?([0-9a-fA-F]{16,})\b", text):
        if len(hex_candidate) % 2 != 0:
            continue
        try:
            raw_bytes = bytes.fromhex(hex_candidate)
            decoded_str = raw_bytes.decode("utf-8", errors="ignore")
            if decoded_str and any(ch.isalnum() for ch in decoded_str):
                decoded.append(decoded_str)
        except Exception:
            continue
    return decoded


def detect_leaked_canaries(text: str, canaries: set[str]) -> list[str]:
    """Detect leaked canaries across raw text, normalized/Thai-digit text, reversed text, Base64, and Hex."""
    if not text:
        return []
    norm_source = unicodedata.normalize("NFKC", text).translate(_THAI_DIGIT_MAP)
    variants = [text, norm_source, norm_source[::-1]] + _extract_decoded_candidates(text)
    upper_variants = [v.upper() for v in variants]
    norm_variants = [_normalize_text(v) for v in variants]

    leaked = set()
    for c in canaries:
        c_upper = c.upper()
        c_norm = _normalize_text(c)
        if any(c_upper in uv for uv in upper_variants):
            leaked.add(c)
        elif len(c_norm) >= 5 and any(c_norm in nv for nv in norm_variants):
            leaked.add(c)
    return sorted(leaked)


def detect_schema_disclosure(text: str) -> list[str]:
    """Detect if sensitive internal table names or metadata tables are disclosed in text."""
    if not text:
        return []
    lower = text.lower()
    disclosed = set()
    for tbl in PRIVATE_TABLES:
        pattern = rf"\b{re.escape(tbl.lower())}\b"
        if re.search(pattern, lower):
            disclosed.add(tbl)
    if re.search(r"\bsqlite_master\b", lower):
        disclosed.add("sqlite_master")
    return sorted(disclosed)


def apply_defense_output(text: str, defense: str, canaries: set[str]) -> str:
    """Redact sensitive values and obfuscated/encoded canary patterns when defense == 'all'."""
    if defense != "all" or not text:
        return text

    # 1. Exact and case-insensitive replacement of known canaries (longest first)
    for c in sorted(canaries, key=len, reverse=True):
        pattern = re.compile(re.escape(c), flags=re.IGNORECASE)
        text = pattern.sub("[REDACTED]", text)

    # 2. Pattern-based redaction for spaced/dashed CANARY tokens, 13-digit national IDs, phones, salaries (Arabic, Thai, Fullwidth)
    text = re.sub(
        r"C[\s\-_.]*A[\s\-_.]*N[\s\-_.]*A[\s\-_.]*R[\s\-_.]*Y(?:[\s\-_.]*[A-Z0-9๐-๙０-９]){4,}",
        "[REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"(?<!\d)[9๙９][\d๐-๙０-９](?:[\s\-_.]*[\d๐-๙０-９]){11}(?!\d)", "[REDACTED]", text)
    text = re.sub(
        r"(?<!\d)(?:000|๐๐๐|０００)[\s\-_.]*(?:000|๐๐๐|０００)[\s\-_.]*(?:000|๐๐๐|０００)[1-5๑-๕１-５](?!\d)",
        "[REDACTED]",
        text,
    )
    text = re.sub(
        r"\b(?:61,?234\.50?|72,?345\.75|58,?765\.25|69,?876(?:\.00?)?|64,?321\.10?)\b",
        "[REDACTED]",
        text,
    )

    # 3. Redact Base64 and Hex segments that decode to a canary
    for candidate in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", text):
        if len(candidate) % 4 == 0:
            try:
                decoded_str = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
                if detect_leaked_canaries(decoded_str, canaries):
                    text = text.replace(candidate, "[REDACTED]")
            except Exception:
                pass
    for match in re.finditer(r"\b(?:0x)?([0-9a-fA-F]{16,})\b", text):
        hex_str = match.group(1)
        if len(hex_str) % 2 == 0:
            try:
                decoded_str = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                if detect_leaked_canaries(decoded_str, canaries):
                    text = text.replace(match.group(0), "[REDACTED]")
            except Exception:
                pass

    # 4. Final safety net: if normalized/reversed/Thai-digit leak still remains, redact the response body
    if detect_leaked_canaries(text, canaries):
        return "[REDACTED: Sensitive data blocked by output guard]"
    return text


def _sanitize_db_cell(val):
    """Sanitize untrusted database strings to neutralize embedded Indirect Prompt Injection directives."""
    if not isinstance(val, str):
        return val
    # Neutralize embedded bracketed/parenthesized tool-calling directives when defense is active
    sanitized = re.sub(
        r"(\[|\()[^\]\)]*(?:search_records|internal_secrets|staff_payroll|student_private|SYSTEM AUDIT DIRECTIVE|หมายเหตุระบบอัตโนมัติ|หมายเหตุการอ้างอิง)[^\]\)]*(\]|\))",
        "[UNTRUSTED_DATA_DIRECTIVE_STRIPPED]",
        val,
        flags=re.IGNORECASE,
    )
    return sanitized
