"""OpenRouter target adapter for multi-family LLM evaluation with backend telemetry."""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

import agent
from core.adapters.base import TargetResponse
from core.adapters.openai_like import OpenAILikeTargetAdapter

# Approved Free-Tier Models on OpenRouter (Hard Quota Invariant - GEMINI.md Rule 2)
APPROVED_OPENROUTER_MODELS = {
    "openrouter/free",
    "meta-llama/llama-3.1-8b-instruct:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
    "google/gemini-2.0-flash-lite-preview:free",
    "google/gemini-2.0-flash-exp:free",
}


class OpenRouterTargetAdapter(OpenAILikeTargetAdapter):
    """Target adapter dispatching to OpenRouter API with provider telemetry."""

    def __init__(
        self,
        target_id: str = "openrouter_target",
        config: Optional[dict] = None,
        **kwargs,
    ):
        cfg = dict(config or {})
        cfg.update(kwargs)

        # Allow passing model directly as kwarg or config
        if "model" in kwargs and "model" not in cfg:
            cfg["model"] = kwargs["model"]
        if "model" not in cfg or not cfg["model"]:
            cfg["model"] = "openrouter/free"

        # Strip routing prefix ("openrouter:openrouter/free" -> "openrouter/free")
        model_name = str(cfg["model"]).strip()
        if model_name.startswith("openrouter:"):
            model_name = model_name.split(":", 1)[1].strip()
            cfg["model"] = model_name

        # Quota Protection Gate: Enforce approved free-tier roster strictly
        if model_name not in APPROVED_OPENROUTER_MODELS or "llama-3.3-70b-instruct" in model_name.lower():
            raise ValueError(
                f"Quota Protection Gate: Model '{model_name}' is not in approved free-tier roster. "
                f"Approved models: {sorted(list(APPROVED_OPENROUTER_MODELS))}"
            )

        if "base_url" not in cfg:
            cfg["base_url"] = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        if "api_key" not in cfg:
            cfg["api_key"] = os.getenv("OPENROUTER_API_KEY", "")

        super().__init__(target_id=target_id, config=cfg)
        self.last_provider_metadata: dict[str, Any] = {}

    def get_info(self) -> dict:
        info = super().get_info()
        info["provider"] = "openrouter"
        info["model"] = self.model
        info["last_provider_metadata"] = dict(self.last_provider_metadata)
        return info

    def send(self, prompt: str, **kwargs) -> TargetResponse:
        """Send prompt to OpenRouter endpoint and capture provider response metadata."""
        if "defense" in kwargs or "blue_role" in kwargs:
            self._has_explicit_defense = True
        defense = kwargs.get("defense", self.defense)
        role = kwargs.get("blue_role", self.role)

        agent.configure_defense(defense, blue_role=role)

        if not self.messages or defense != self.defense or role != self.role:
            self.defense = defense
            self.role = role
            self._init_messages(defense, role)
        elif self._has_explicit_defense and (not self.messages or self.messages[0].get("role") != "system"):
            self.messages.insert(0, {
                "role": "system",
                "content": self._get_effective_system_prompt(defense, role),
            })

        self.messages.append({"role": "user", "content": prompt})

        headers = {
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/saharat-k/thai-injection-eval",
            "X-Title": "Thai Injection Eval v2.0 Benchmark",
        }
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
                    resp_headers = dict(resp.headers) if hasattr(resp, "headers") and resp.headers else {}
                    # Capture OpenRouter telemetry headers
                    self.last_provider_metadata = {
                        "provider_backend": resp_headers.get("x-provider") or resp_headers.get("x-provider-name"),
                        "quantization": resp_headers.get("x-quantization"),
                        "model_snapshot": resp_headers.get("x-model-snapshot"),
                        "ratelimit_remaining": resp_headers.get("x-ratelimit-remaining"),
                    }

                    data = json.loads(resp.read().decode("utf-8"))
                    if isinstance(data, dict):
                        if data.get("model"):
                            self.last_provider_metadata["resolved_model"] = data.get("model")
                        if data.get("system_fingerprint"):
                            self.last_provider_metadata["system_fingerprint"] = data.get("system_fingerprint")

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

                        res = self._execute_and_record_tool(fn_name, fn_args, tool_calls_turn)

                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": tc.get("id", ""),
                            "content": str(res),
                        })
                else:
                    reply_text = message.get("content") or ""
                    raw_reply = reply_text
                    if defense == "all":
                        canaries = agent.load_canaries() if hasattr(agent, "load_canaries") else set()
                        reply_text = agent.apply_defense_output(reply_text, defense, canaries)
                    break

            self.messages.append({"role": "assistant", "content": reply_text})
            meta = dict(self.last_provider_metadata)
            meta["raw_text"] = raw_reply if "raw_reply" in locals() else reply_text
            return TargetResponse(
                text=reply_text,
                tool_calls=tool_calls_turn,
                metadata=meta,
            )
        except Exception as e:
            return TargetResponse(
                text="",
                error=f"OpenRouter API request failed: {str(e)}",
                tool_calls=tool_calls_turn,
                metadata=dict(self.last_provider_metadata),
            )
