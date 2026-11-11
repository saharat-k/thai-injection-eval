"""Core Adapters Package."""
from core.adapters.base import BaseTargetAdapter, TargetResponse
from core.adapters.builtin import BuiltinTargetAdapter
from core.adapters.openai_like import OpenAILikeTargetAdapter
from core.adapters.callable import CallableTargetAdapter
from core.adapters.client import (
    OpenAILikeChatSession,
    OpenAILikeChats,
    OpenAILikeClient,
    OpenAILikeModels,
    OpenAILikeResponse,
    make_client,
    parse_model_spec,
)
from core.adapters.factory import create_target_adapter

__all__ = [
    "BaseTargetAdapter",
    "TargetResponse",
    "BuiltinTargetAdapter",
    "OpenAILikeTargetAdapter",
    "CallableTargetAdapter",
    "create_target_adapter",
    "OpenAILikeClient",
    "OpenAILikeModels",
    "OpenAILikeChatSession",
    "OpenAILikeChats",
    "OpenAILikeResponse",
    "make_client",
    "parse_model_spec",
]
