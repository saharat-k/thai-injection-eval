"""OpenRouter target adapter for multi-family LLM evaluation with backend telemetry."""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

import agent
from core.adapters.base import TargetResponse
from core.adapters.openai_like import OpenAILikeTargetAdapter

# Approved Free-Tier Models on OpenRouter (Hard Quota Invariant)
APPROVED_OPENROUTER_MODELS = {
    "openrouter/free",
    "meta-llama/llama-3.3-70b-instruct:free",
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
            cfg["model"] = "meta-llama/llama-3.3-70b-instruct:free"

        # Quota Protection Gate: Enforce free tier model invariant in live calls
        # (Allows testing mock models if prefixed with meta-llama or free)
        model_name = cfg["model"]
        if not (model_name.endswith(":free") or model_name == "openrouter/free" or "meta-llama" in model_name):
            # In testing/benchmarking, fail-fast on paid endpoints
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
            "HTTP-Referer": "https://github.com/the-prafful/thai-injection-eval",
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

                        tool_entry = {"tool": fn_name, "args": fn_args}
                        tool_calls_turn.append(tool_entry)
                        if tool_entry not in agent._tool_calls:
                            agent._tool_calls.append(tool_entry)

                        if fn_name == "search_records":
                            t_arg = fn_args.get("table", "")
                            k_arg = fn_args.get("keyword", "")
                            res = agent.search_records(t_arg, k_arg)
                        elif fn_name == "export_report":
                            t_arg = fn_args.get("title", "")
                            c_arg = fn_args.get("content", "")
                            f_arg = fn_args.get("format", "markdown")
                            res = agent.export_report(t_arg, c_arg, f_arg)
                        elif fn_name == "send_campus_notification":
                            r_arg = fn_args.get("recipient_id", "")
                            b_arg = fn_args.get("message_body", "")
                            res = agent.send_campus_notification(r_arg, b_arg)
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
                        reply_text = agent.apply_defense_output(reply_text, defense)
                    break

            self.messages.append({"role": "assistant", "content": reply_text})
            return TargetResponse(
                text=reply_text,
                tool_calls=tool_calls_turn,
                metadata=dict(self.last_provider_metadata),
            )
        except Exception as e:
            return TargetResponse(
                text="",
                error=f"OpenRouter API request failed: {str(e)}",
                tool_calls=tool_calls_turn,
                metadata=dict(self.last_provider_metadata),
            )
