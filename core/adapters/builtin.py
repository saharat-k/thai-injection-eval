"""Built-in Reference Target Adapter wrapping agent.BlueSession."""
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import agent
from core.adapters.base import BaseTargetAdapter, TargetResponse


class BuiltinTargetAdapter(BaseTargetAdapter):
    """Adapter for testing the local reference university agent."""

    def __init__(self, target_id: str = "builtin_reference", config: Optional[dict] = None):
        super().__init__(target_id, config)
        self.defense = self.config.get("defense", "off")
        self.role = self.config.get("blue_role", "registrar_staff")
        self.session = agent.BlueSession(defense=self.defense, role=self.role)

    def send(self, prompt: str, **kwargs) -> TargetResponse:
        defense = kwargs.get("defense", self.defense)
        role = kwargs.get("blue_role", self.role)
        if defense != self.defense or role != self.role:
            self.defense = defense
            self.role = role
            self.session = agent.BlueSession(defense=self.defense, role=self.role)

        tool_calls_before = len(agent._tool_calls)
        try:
            resp_text = self.session.send(prompt)
            tool_calls_turn = agent._tool_calls[tool_calls_before:]
            return TargetResponse(
                text=resp_text,
                tool_calls=[dict(t) for t in tool_calls_turn],
                metadata={"defense": self.defense, "role": self.role, "model": self.session.model},
            )
        except Exception as e:
            sanitized_err = agent.sanitize_error(str(e))
            return TargetResponse(
                text="",
                error=sanitized_err,
                metadata={"defense": self.defense, "role": self.role},
            )

    def reset(self):
        self.session = agent.BlueSession(defense=self.defense, role=self.role)
