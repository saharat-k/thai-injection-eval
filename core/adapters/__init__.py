"""Core Adapters Package."""
from core.adapters.base import BaseTargetAdapter, TargetResponse
from core.adapters.builtin import BuiltinTargetAdapter
from core.adapters.openai_like import OpenAILikeTargetAdapter
from core.adapters.callable import CallableTargetAdapter
from core.adapters.factory import create_target_adapter

__all__ = [
    "BaseTargetAdapter",
    "TargetResponse",
    "BuiltinTargetAdapter",
    "OpenAILikeTargetAdapter",
    "CallableTargetAdapter",
    "create_target_adapter",
]
