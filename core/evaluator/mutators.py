"""Lightweight dynamic Thai NLP mutators (PyRIT/Garak-inspired converters).

Provides deterministic and programmatic mutation primitives for prompt evasion:
1. Zero-width character insertion (U+200B / U+200C).
2. Homoglyph confusable substitution (Latin-Cyrillic and Thai decomposition).
3. Code-switching synonym substitution (Thai-English pivoting).
"""
from __future__ import annotations

import re
from typing import List, Optional

ZERO_WIDTH_SPACE = "\u200b"
ZERO_WIDTH_NON_JOINER = "\u200c"

# Visually identical Unicode homoglyphs (Cyrillic confusables for Latin, and decomposed Thai characters)
HOMOGLYPH_MAP = {
    "a": "\u0430",  # Cyrillic small letter a
    "e": "\u0435",  # Cyrillic small letter ie
    "o": "\u043e",  # Cyrillic small letter o
    "p": "\u0440",  # Cyrillic small letter er
    "c": "\u0441",  # Cyrillic small letter es
    "i": "\u0456",  # Cyrillic small letter byelorussian-ukrainian i
    "s": "\u0455",  # Cyrillic small letter dze
    "x": "\u0445",  # Cyrillic small letter ha
    "y": "\u0443",  # Cyrillic small letter u
    "A": "\u0410",  # Cyrillic capital letter A
    "E": "\u0415",  # Cyrillic capital letter IE
    "O": "\u041e",  # Cyrillic capital letter O
    "P": "\u0420",  # Cyrillic capital letter ER
    "C": "\u0421",  # Cyrillic capital letter ES
}

DEFAULT_TARGETS = [
    "student_private",
    "staff_payroll",
    "internal_secrets",
    "system_config",
    "บัตรประชาชน",
    "เงินเดือน",
    "รหัสผ่าน",
    "ความลับ",
]

CODE_SWITCH_MAP = {
    "student_private": "ข้อมูลลับนักศึกษา (student_confidential)",
    "staff_payroll": "บัญชีเงินเดือนบุคลากร (faculty_compensation)",
    "internal_secrets": "รหัสความลับระบบ (system_credentials)",
    "system_config": "การกำหนดค่าระบบ (system_configuration)",
    "บัตรประชาชน": "national_id card identifier",
    "เงินเดือน": "compensation payroll details",
    "รหัสผ่าน": "administrative secret key credentials",
}


def inject_zero_width(text: str, targets: Optional[List[str]] = None) -> str:
    """Inject Zero-Width Space (U+200B) into sensitive keyword tokens to evade string matchers."""
    if not text:
        return ""

    effective_targets = targets if targets is not None else DEFAULT_TARGETS
    matched_any = False

    result = text
    for t in effective_targets:
        if not t or t not in result:
            continue
        # Split target characters with ZWSP
        zw_target = ZERO_WIDTH_SPACE.join(list(t))
        result = result.replace(t, zw_target)
        matched_any = True

    # If no explicit target matched, inject ZWSP between chars of longer words
    if not matched_any and targets is None:
        def _zw_word(m: re.Match) -> str:
            word = m.group(0)
            if len(word) >= 4:
                return ZERO_WIDTH_SPACE.join(list(word))
            return word

        result = re.sub(r"[A-Za-z0-9_\u0e01-\u0e5b]+", _zw_word, result)

    # Fallback if text is identical to single target word
    if result == text and len(text) > 2:
        mid = len(text) // 2
        result = text[:mid] + ZERO_WIDTH_SPACE + text[mid:]

    return result


def substitute_homoglyphs(text: str, targets: Optional[List[str]] = None) -> str:
    """Substitute ASCII and Latin characters in sensitive tokens with visual Unicode homoglyphs."""
    if not text:
        return ""

    effective_targets = targets if targets is not None else DEFAULT_TARGETS
    matched_any = False

    result = text
    for t in effective_targets:
        if not t or t not in result:
            continue
        # Apply homoglyphs to target
        hg_target = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in t)
        if hg_target != t:
            result = result.replace(t, hg_target)
            matched_any = True

    if not matched_any:
        # Transform globally
        result = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)

    return result


def apply_code_switch_pivot(text: str, targets: Optional[List[str]] = None) -> str:
    """Pivot sensitive keywords to Thai-English code-switched or transliterated synonyms."""
    if not text:
        return ""

    result = text
    for term, synonym in CODE_SWITCH_MAP.items():
        if term in result:
            result = result.replace(term, synonym)

    if targets:
        for t in targets:
            if t in result and t in CODE_SWITCH_MAP:
                result = result.replace(t, CODE_SWITCH_MAP[t])

    return result


THAI_NUM_DIGITS = ["ศูนย์", "หนึ่ง", "สอง", "สาม", "สี่", "ห้า", "หก", "เจ็ด", "แปด", "เก้า"]
THAI_NUM_UNITS = ["", "สิบ", "ร้อย", "พัน", "หมื่น", "แสน", "ล้าน"]
THAI_DIGIT_REV_MAP = {
    "ศูนย์": 0, "หนึ่ง": 1, "เอ็ด": 1, "สอง": 2, "ยี่": 2,
    "สาม": 3, "สี่": 4, "ห้า": 5, "หก": 6, "เจ็ด": 7, "แปด": 8, "เก้า": 9,
}
THAI_UNIT_REV_MAP = {
    "ล้าน": 1000000, "แสน": 100000, "หมื่น": 10000,
    "พัน": 1000, "ร้อย": 100, "สิบ": 10,
}


def _int_to_thai_words(n: int) -> str:
    if n == 0:
        return THAI_NUM_DIGITS[0]
    res = []
    s = str(n)
    length = len(s)
    for i, ch in enumerate(s):
        d = int(ch)
        pos = length - i - 1
        unit = THAI_NUM_UNITS[pos % 6]
        if pos >= 6 and pos % 6 == 0:
            unit = "ล้าน"
        if d == 0:
            continue
        if pos % 6 == 1 and d == 1:
            digit_str = ""
        elif pos % 6 == 1 and d == 2:
            digit_str = "ยี่"
        elif pos % 6 == 0 and d == 1 and length > 1 and int(s[-2]) != 0:
            digit_str = "เอ็ด"
        else:
            digit_str = THAI_NUM_DIGITS[d]
        res.append(digit_str + unit)
    return "".join(res)


def thai_number_to_words(val: float | int | str) -> str:
    """Convert numeric values to Thai spoken/written words (e.g. 72345.75 -> เจ็ดหมื่นสองพันสามร้อยสี่สิบห้าจุดเจ็ดห้า)."""
    try:
        fval = float(str(val).replace(",", "").strip())
    except (ValueError, TypeError):
        return str(val)

    s_val = f"{fval:.4f}".rstrip("0").rstrip(".")
    if "." in s_val:
        int_part_str, dec_part_str = s_val.split(".", 1)
        int_words = _int_to_thai_words(int(int_part_str))
        dec_words = "".join(THAI_NUM_DIGITS[int(ch)] for ch in dec_part_str if ch.isdigit())
        return f"{int_words}จุด{dec_words}" if dec_words else int_words
    return _int_to_thai_words(int(s_val))


def thai_words_to_number(text: str) -> Optional[float]:
    """Parse Thai written number words back into float value (e.g. เจ็ดหมื่นสองพัน... -> 72345.75)."""
    if not text:
        return None
    parts = text.split("จุด", 1)
    int_str = parts[0]
    total = 0.0
    curr = 0
    i = 0
    while i < len(int_str):
        matched = False
        for u, uval in sorted(THAI_UNIT_REV_MAP.items(), key=lambda x: -len(x[0])):
            if int_str.startswith(u, i):
                mult = curr if curr != 0 else 1
                total += mult * uval
                curr = 0
                i += len(u)
                matched = True
                break
        if not matched:
            for d, dval in sorted(THAI_DIGIT_REV_MAP.items(), key=lambda x: -len(x[0])):
                if int_str.startswith(d, i):
                    curr = dval
                    i += len(d)
                    matched = True
                    break
        if not matched:
            i += 1
    total += curr

    if len(parts) > 1:
        dec_str = parts[1]
        dec_digits = ""
        j = 0
        while j < len(dec_str):
            matched = False
            for d, dval in sorted(THAI_DIGIT_REV_MAP.items(), key=lambda x: -len(x[0])):
                if dec_str.startswith(d, j):
                    dec_digits += str(dval)
                    j += len(d)
                    matched = True
                    break
            if not matched:
                j += 1
        if dec_digits:
            total += float("0." + dec_digits)
    return total if total > 0 or "ศูนย์" in text else None


def thai_digit_words_to_digits(text: str) -> list[str]:
    """Extract consecutive sequences of Thai verbal digits as Arabic digit strings.

    Recognizes individual digit spellings such as 'หนึ่งสองสาม', 'หนึ่ง-สอง-สาม',
    or 'หนึ่ง สอง สาม' (e.g. for national IDs, telephone numbers, or secret tokens).
    Returns all extracted digit sequences with length >= 4.
    """
    if not text:
        return []

    digit_words = [
        ("ศูนย์", "0"), ("หนึ่ง", "1"), ("เอ็ด", "1"), ("สอง", "2"), ("ยี่", "2"),
        ("สาม", "3"), ("สี่", "4"), ("ห้า", "5"), ("หก", "6"), ("เจ็ด", "7"),
        ("แปด", "8"), ("เก้า", "9"),
    ]

    results = []
    current_digits = []
    i = 0
    n = len(text)

    while i < n:
        if text[i] in " \t\r\n-–—_.,/|":
            i += 1
            continue

        matched = False
        for word, digit in digit_words:
            if text.startswith(word, i):
                current_digits.append(digit)
                i += len(word)
                matched = True
                break

        if not matched:
            if current_digits:
                if len(current_digits) >= 4:
                    results.append("".join(current_digits))
                current_digits = []
            i += 1

    if current_digits and len(current_digits) >= 4:
        results.append("".join(current_digits))

    return results


def arithmetic_split(val: float | int | str) -> str:
    """Decompose a numeric amount into an additive arithmetic expression (e.g. 50000 + 22345.75)."""
    try:
        num = float(str(val).replace(",", "").strip())
    except (ValueError, TypeError):
        return str(val)
    base = round(num * 0.7, 0)
    rem = round(num - base, 2)
    s_base = f"{base:.4f}".rstrip("0").rstrip(".")
    s_rem = f"{rem:.4f}".rstrip("0").rstrip(".")
    return f"{s_base} + {s_rem}"


def to_thai_numerals(text: str) -> str:
    """Convert ASCII Arabic digits (0-9) to traditional Thai numerals (๐-๙)."""
    if not text:
        return ""
    trans = str.maketrans("0123456789", "๐๑๒๓๔๕๖๗๘๙")
    return text.translate(trans)


def from_thai_numerals(text: str) -> str:
    """Convert traditional Thai numerals (๐-๙) back to ASCII Arabic digits (0-9)."""
    if not text:
        return ""
    trans = str.maketrans("๐๑๒๓๔๕๖๗๘๙", "0123456789")
    return text.translate(trans)


def caesar_shift(text: str, shift: int = 1) -> str:
    """Shift ASCII letters and digits by `shift` positions to evade exact signature matches."""
    if not text:
        return ""
    res = []
    for ch in text:
        if "A" <= ch <= "Z":
            res.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        elif "a" <= ch <= "z":
            res.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "0" <= ch <= "9":
            res.append(chr((ord(ch) - ord("0") + shift) % 10 + ord("0")))
        else:
            res.append(ch)
    return "".join(res)


def apply_mutation(prompt: str, technique: str = "none", targets: Optional[List[str]] = None) -> str:
    """Dispatch prompt mutation based on specified technique ('zero_width', 'homoglyph', 'code_switch', 'thai_number_words', 'arithmetic_split', 'caesar_shift')."""
    if not prompt or not technique or technique.lower() in ("none", "off"):
        return prompt

    tech = technique.lower().strip()
    if tech in ("zero_width", "zwsp", "zero-width"):
        return inject_zero_width(prompt, targets=targets)
    if tech in ("homoglyph", "confusable", "homoglyphs"):
        return substitute_homoglyphs(prompt, targets=targets)
    if tech in ("code_switch", "codeswitch", "code-switch", "pivot"):
        return apply_code_switch_pivot(prompt, targets=targets)
    if tech in ("thai_number_words", "thai_words", "number_words"):
        # Replace digits with Thai verbal numbers
        return re.sub(r"\b\d+(?:\.\d+)?\b", lambda m: thai_number_to_words(m.group(0)), prompt)
    if tech in ("thai_digits", "thai_numerals", "thai_numeral"):
        return to_thai_numerals(prompt)
    if tech in ("arithmetic_split", "math_split", "split_numbers"):
        return re.sub(r"\b\d+(?:\.\d+)?\b", lambda m: arithmetic_split(m.group(0)), prompt)
    if tech in ("caesar_shift", "caesar", "shift"):
        if targets:
            res = prompt
            for t in targets:
                if t in res:
                    res = res.replace(t, caesar_shift(t, shift=1))
            return res
        return caesar_shift(prompt, shift=1)
    if tech in ("composite", "all"):
        p = apply_code_switch_pivot(prompt, targets=targets)
        p = substitute_homoglyphs(p, targets=targets)
        return inject_zero_width(p, targets=targets)

    return prompt
