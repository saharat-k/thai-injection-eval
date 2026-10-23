"""OpenAI-compatible Target Adapter for testing external LLMs/agents."""
import json
import urllib.request
import urllib.error
from typing import Optional
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
        self.messages: list[dict] = []
        if self.system_prompt:
            self.messages.append({"role": "system", "content": self.system_prompt})

    def send(self, prompt: str, **kwargs) -> TargetResponse:
        self.messages.append({"role": "user", "content": prompt})

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": self.messages,
            "temperature": self.temperature,
        }

        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choice = data.get("choices", [{}])[0]
                message = choice.get("message", {})
                reply_text = message.get("content") or ""
                self.messages.append({"role": "assistant", "content": reply_text})
                return TargetResponse(
                    text=reply_text,
                    raw=data,
                    metadata={"model": self.model, "base_url": self.base_url},
                )
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            finally:
                try:
                    e.close()
                except Exception:
                    pass
            return TargetResponse(
                text="",
                error=f"HTTP {e.code}: {err_body[:300]}",
                metadata={"model": self.model},
            )
        except Exception as e:
            return TargetResponse(
                text="",
                error=f"Connection error: {e}",
                metadata={"model": self.model},
            )

    def reset(self):
        self.messages = []
        if self.system_prompt:
            self.messages.append({"role": "system", "content": self.system_prompt})
