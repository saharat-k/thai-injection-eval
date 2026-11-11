"""Multi-provider LLM client factory and OpenAI-compatible client adapter.

Provides duck-typed client interface matching Google GenAI client (generate_content and chats.create)
for OpenRouter, GitHub Models, and Groq providers.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional, Tuple

from google import genai

from core.defenses.dlp import sanitize_error


class OpenAILikeResponse:
    """Minimal response wrapper matching Gemini response.text interface."""

    def __init__(self, text: str = ""):
        self.text = text


class OpenAILikeModels:
    """Minimal models service implementing generate_content for OpenAI-compatible HTTP APIs."""

    def __init__(self, provider: str, base_url: str, api_key: str, default_model: str):
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.default_model = default_model

    def generate_content(self, model: str = None, contents: str = "", config=None) -> OpenAILikeResponse:
        target_model = model or self.default_model
        system_instruction = ""
        if config is not None:
            if hasattr(config, "system_instruction") and config.system_instruction:
                system_instruction = str(config.system_instruction)
            elif isinstance(config, dict) and config.get("system_instruction"):
                system_instruction = str(config["system_instruction"])

        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        if isinstance(contents, list):
            for msg in contents:
                if isinstance(msg, dict) and "role" in msg and "content" in msg:
                    messages.append({"role": str(msg["role"]), "content": str(msg["content"])})
                else:
                    messages.append({"role": "user", "content": str(msg)})
        else:
            messages.append({"role": "user", "content": str(contents)})

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/saharat-k/thai-injection-eval"
            headers["X-Title"] = "thai-injection-eval"

        payload = {
            "model": target_model,
            "messages": messages,
            "temperature": 0.7,
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
                text = message.get("content") or message.get("reasoning_content") or ""
                return OpenAILikeResponse(text)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{self.provider} API error ({e.code}): {sanitize_error(err_body)}") from e
        except Exception as e:
            raise RuntimeError(f"{self.provider} connection error: {sanitize_error(str(e))}") from e


class OpenAILikeChatSession:
    """Multi-turn chat session wrapper for OpenAI-compatible providers."""

    def __init__(self, models: OpenAILikeModels, model: str, config=None):
        self._models = models
        self.model = model
        self.config = config
        self.history = []

    def send_message(self, prompt: str) -> OpenAILikeResponse:
        self.history.append({"role": "user", "content": str(prompt)})
        resp = self._models.generate_content(
            model=self.model,
            contents=list(self.history),
            config=self.config,
        )
        self.history.append({"role": "assistant", "content": resp.text or ""})
        return resp


class OpenAILikeChats:
    """Chats namespace matching Gemini client.chats.create(...) interface."""

    def __init__(self, models: OpenAILikeModels):
        self._models = models

    def create(self, model: str = None, config=None, history=None) -> OpenAILikeChatSession:
        chat = OpenAILikeChatSession(self._models, model or self._models.default_model, config=config)
        if history:
            chat.history = list(history)
        return chat


class OpenAILikeClient:
    """Client wrapper presenting a Gemini-like client.models.generate_content and client.chats interface."""

    def __init__(self, provider: str, base_url: str, api_key: str, default_model: str):
        self.provider = provider
        self.models = OpenAILikeModels(provider, base_url, api_key, default_model)
        self.chats = OpenAILikeChats(self.models)


def parse_model_spec(spec: str) -> tuple[str, str]:
    """Parse 'provider:model' or bare 'model' string."""
    spec = (spec or "").strip()
    if ":" in spec:
        prefix, _, rest = spec.partition(":")
        return prefix.strip().lower(), rest.strip()
    return "gemini", spec


def make_client(spec: str = "gemini-3.5-flash-lite") -> Tuple[Any, str]:
    """Return (client, model_name) for a 'provider:model' or 'model' spec.
    Supported providers:
      - 'gemini' (default): Google AI Studio (uses GEMINI_API_KEY)
      - 'openrouter': OpenRouter API (uses OPENROUTER_API_KEY)
      - 'github': GitHub Models (uses GITHUB_TOKEN)
      - 'groq': Groq Cloud (uses GROQ_API_KEY)
    """
    provider, clean_model = parse_model_spec(spec)

    if provider == "gemini":
        norm_model = clean_model.lower().replace(" ", "-")
        if norm_model.startswith("models/"):
            norm_model = norm_model[7:]
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set. Please set it in your environment or .env file.")
        return genai.Client(api_key=api_key), norm_model
    elif provider == "openrouter":
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY is not set. Please set it in your environment or .env file.")
        return OpenAILikeClient("openrouter", "https://openrouter.ai/api/v1", api_key, clean_model), clean_model
    elif provider == "github":
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            raise ValueError("GITHUB_TOKEN is not set. Please set it in your environment or .env file.")
        return OpenAILikeClient("github", "https://models.inference.ai.azure.com", token, clean_model), clean_model
    elif provider == "groq":
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY is not set. Please set it in your environment or .env file.")
        return OpenAILikeClient("groq", "https://api.groq.com/openai/v1", api_key, clean_model), clean_model
    else:
        raise NotImplementedError(
            f"Provider '{provider}' is not supported. Supported providers are: 'gemini', 'openrouter', 'github', 'groq'."
        )
