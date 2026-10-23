"""Python Callable Target Adapter for testing custom functions and framework agents."""
from typing import Callable, Optional
from core.adapters.base import BaseTargetAdapter, TargetResponse


class CallableTargetAdapter(BaseTargetAdapter):
    """Adapter wrapping any arbitrary Python callable: fn(prompt) -> str or TargetResponse."""

    def __init__(self, target_id: str, callable_fn: Callable[[str], str], config: Optional[dict] = None):
        super().__init__(target_id, config)
        self.callable_fn = callable_fn

    def send(self, prompt: str, **kwargs) -> TargetResponse:
        try:
            res = self.callable_fn(prompt)
            if isinstance(res, TargetResponse):
                return res
            return TargetResponse(text=str(res))
        except Exception as e:
            return TargetResponse(text="", error=f"Callable error: {e}")

    def reset(self):
        pass
