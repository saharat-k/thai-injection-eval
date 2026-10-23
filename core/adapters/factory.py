"""Adapter factory for creating Target Adapters."""
from typing import Optional
from core.adapters.base import BaseTargetAdapter
from core.adapters.builtin import BuiltinTargetAdapter
from core.adapters.openai_like import OpenAILikeTargetAdapter
from core.adapters.callable import CallableTargetAdapter


def create_target_adapter(target_type: str = "builtin", config: Optional[dict] = None, **kwargs) -> BaseTargetAdapter:
    """Factory helper to instantiate a Target Adapter by name."""
    cfg = dict(config or {})
    cfg.update(kwargs)
    t = target_type.lower()

    if t in ("builtin", "reference", "local"):
        return BuiltinTargetAdapter(target_id=cfg.get("target_id", "builtin_reference"), config=cfg)
    elif t in ("openai", "openai_like", "vllm", "ollama", "groq", "openrouter"):
        return OpenAILikeTargetAdapter(target_id=cfg.get("target_id", f"{t}_target"), config=cfg)
    elif t == "callable":
        fn = kwargs.get("callable_fn") or cfg.get("callable_fn")
        if not callable(fn):
            raise ValueError("CallableTargetAdapter requires a callable 'callable_fn'")
        return CallableTargetAdapter(target_id=cfg.get("target_id", "callable_target"), callable_fn=fn, config=cfg)
    else:
        raise ValueError(f"Unknown target adapter type '{target_type}'. Supported: builtin, openai, callable")
