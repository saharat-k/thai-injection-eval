"""Security Context and Session Isolation for Tool Invocations.

Binds user identity, role, defense tier, and authorized operational scopes to the
active thread/session, eliminating global mutable state and tautological ACL assumptions.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional, Tuple

_context_store = threading.local()


@dataclass(frozen=True)
class SecurityContext:
    """Session-bound security context enforcing non-tautological least-privilege policies."""

    session_id: str = "default_session"
    user_id: Optional[str] = None
    user_role: str = "guest"
    defense_tier: str = "off"
    authorized_recipients: Tuple[str, ...] = ("REGISTRAR", "STUDENT_AFFAIRS")
    prohibited_fields: Tuple[str, ...] = (
        "national_id",
        "salary",
        "bank_account",
        "api_key",
        "master_token",
        "token",
        "password",
    )
    ablation_mode: Optional[str] = None  # None, "no_bola_ablation"


def get_current_security_context() -> SecurityContext:
    """Retrieve the active SecurityContext for the current thread/session."""
    ctx = getattr(_context_store, "context", None)
    if ctx is None:
        ctx = SecurityContext()
        _context_store.context = ctx
    return ctx


def set_current_security_context(ctx: Optional[SecurityContext]) -> None:
    """Bind a SecurityContext to the current thread/session."""
    _context_store.context = ctx
