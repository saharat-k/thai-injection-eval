"""OpenAI-compatible Target Adapter for testing external LLMs/agents."""
import json
import urllib.error
import urllib.request
from typing import Optional

import agent
from core.adapters.base import BaseTargetAdapter, TargetResponse


class OpenAILikeTargetAdapter(BaseTargetAdapter):
    """Adapter for testing external LLMs via standard OpenAI-compatible endpoints."""

    def __init__(self, target_id: str, config: Optional[dict] = None):
        super().__init__(target_id, config)
        self.base_url = self.config.get("base_url", "http://localhost:8000/v1").rstrip("/")
        self.api_key = self.config.get("api_key", "")
        self.model = self.config.get("model", "default")
        self.system_prompt = self.config.get("system_prompt", "")
        self.temperature = float(self.config.get("temperature", 0.0))
        self.defense = self.config.get("defense", "off")
        self.role = self.config.get("blue_role", "registrar_staff")
        self.messages: list[dict] = []
        self._init_messages()

    @staticmethod
    def _get_tools_spec() -> list[dict]:
        """OpenAI-compatible tool definition schema for database search."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "search_records",
                    "description": "Search records in the university database across accessible tables.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "table": {
                                "type": "string",
                                "description": "The table name to search (e.g. 'students', 'professors', 'courses', 'schedules', 'announcements')",
                            },
                            "keyword": {
                                "type": "string",
                                "description": "The search term, ID, or query keyword.",
                            },
                        },
                        "required": ["table", "keyword"],
                    },
                },
            }
        ]

    def _get_effective_system_prompt(self, defense: str, role: str) -> str:
        """Construct system prompt matching defense tier and role if not custom."""
        if self.system_prompt:
            return self.system_prompt
        base_sys = agent.HARDENED_SYSTEM_PROMPT if defense in ("prompt", "all") else agent.BASE_SYSTEM_PROMPT
        schema_hint = agent.PUBLIC_SCHEMA_HINT if defense in ("prompt", "tools", "all") else agent.FULL_SCHEMA_HINT
        role_addon = agent.get_blue_role_prompt(role)
        sys_text = f"{base_sys}\n\n{schema_hint}"
        if role_addon:
            sys_text += f"\n\nROLE POLICY:\n{role_addon}"
        return sys_text

    def _init_messages(self, defense: Optional[str] = None, role: Optional[str] = None):
        """Initialize conversation with system prompt if configured."""
        self.messages = []
        if self.system_prompt:
            self.messages.append({"role": "system", "content": self.system_prompt})

    def send(self, prompt: str, **kwargs) -> TargetResponse:
        defense = kwargs.get("defense", self.defense)
        role = kwargs.get("blue_role", self.role)

        # Configure defense gatekeeper in agent.py
        agent.configure_defense(defense, blue_role=role)

        if not self.messages or defense != self.defense or role != self.role:
            self.defense = defense
            self.role = role
            self._init_messages(defense, role)

        self.messages.append({"role": "user", "content": prompt})

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        tool_calls_turn: list[dict] = []
        reply_text = ""
        max_turns = getattr(agent, "MAX_TOOL_CALLS_PER_TURN", 4)

        try:
            for _ in range(max_turns):
                payload = {
                    "model": self.model,
                    "messages": self.messages,
                    "temperature": self.temperature,
                    "tools": self._get_tools_spec(),
                    "tool_choice": "auto",
                }

                req = urllib.request.Request(
                    f"{self.base_url}/chat/completions",
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )

                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    choice = data.get("choices", [{}])[0]
                    message = choice.get("message", {})

                tool_calls = message.get("tool_calls")
                if tool_calls:
                    self.messages.append(message)
                    for tc in tool_calls:
                        fn = tc.get("function", {})
                        fn_name = fn.get("name", "")
                        raw_args = fn.get("arguments", "{}")
                        try:
                            fn_args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                        except Exception:
                            fn_args = {"keyword": str(raw_args)}

                        tool_entry = {"tool": fn_name, "args": fn_args}
                        tool_calls_turn.append(tool_entry)
                        if tool_entry not in agent._tool_calls:
                            agent._tool_calls.append(tool_entry)

                        if fn_name == "search_records":
                            t_arg = fn_args.get("table", "")
                            k_arg = fn_args.get("keyword", "")
                            res = agent.search_records(t_arg, k_arg)
                        else:
                            res = json.dumps({"error": f"unknown tool '{fn_name}'"})

                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": tc.get("id", ""),
                            "content": str(res),
                        })
                else:
                    reply_text = message.get("content") or ""
                    if defense == "all":
                        reply_text = agent.apply_defense_output(reply_text)
                    self.messages.append({"role": "assistant", "content": reply_text})
                    break

            return TargetResponse(
                text=reply_text,
                tool_calls=tool_calls_turn,
                metadata={
                    "defense": defense,
                    "role": role,
                    "model": self.model,
                    "base_url": self.base_url,
                },
            )

        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            finally:
                try:
                    e.close()
                except Exception:
                    pass
            sanitized_err = agent.sanitize_error(f"HTTP {e.code}: {err_body[:300]}")
            return TargetResponse(
                text="",
                error=sanitized_err,
                metadata={"defense": defense, "role": role, "model": self.model},
            )
        except Exception as e:
            sanitized_err = agent.sanitize_error(f"Connection error: {e}")
            return TargetResponse(
                text="",
                error=sanitized_err,
                metadata={"defense": defense, "role": role, "model": self.model},
            )

    def reset(self):
        self._init_messages(self.defense, self.role)
