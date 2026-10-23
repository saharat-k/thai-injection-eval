"""Pluggable Target Adapter interfaces for LLM Security Evaluator."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TargetResponse:
    text: str
    tool_calls: list[dict] = field(default_factory=list)
    raw: Any = None
    metadata: dict = field(default_factory=dict)
    error: Optional[str] = None


class BaseTargetAdapter(ABC):
    """Abstract base class for all Evaluator Target Adapters."""

    def __init__(self, target_id: str, config: Optional[dict] = None):
        self.target_id = target_id
        self.config = config or {}

    @abstractmethod
    def send(self, prompt: str, **kwargs) -> TargetResponse:
        """Send a single prompt to the target system under test and return a TargetResponse."""
        pass

    @abstractmethod
    def reset(self):
        """Reset conversation memory/session context for stateless evaluation."""
        pass

    def get_info(self) -> dict:
        """Return metadata describing the target adapter."""
        return {
            "target_id": self.target_id,
            "adapter_type": self.__class__.__name__,
            "config": {k: v for k, v in self.config.items() if "key" not in k.lower() and "token" not in k.lower()},
        }
