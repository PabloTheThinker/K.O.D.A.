"""OpenAI-compatible adapter.

One adapter, many providers. Every backend that speaks the OpenAI
``/v1/chat/completions`` dialect — OpenAI itself, Groq, Together,
OpenRouter, DeepSeek, xAI (Grok), Mistral, Fireworks, Cerebras,
plus self-hosted vLLM / LM Studio — routes through here. Pick the
provider by name (``provider: "groq"``), override the endpoint
explicitly (``base_url: "http://vllm.internal"``), or both.

Design:
  - Endpoints + env vars come from :mod:`koda.providers.catalog`.
  - Tool-calls round-trip as OpenAI-shape: request carries ``tools`` +
    ``tool_choice``, response emits ``message.tool_calls[].function``.
  - Errors surface as ``stop_reason="error"`` with the status code and
    a short excerpt — the TurnLoop aborts cleanly on that.
  - No SDK dependency. httpx.AsyncClient is enough; this keeps Koda's
    install surface small and lets any future provider join without a
    package bump.
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from ..providers.catalog import by_id as _catalog_entry
from .base import Message, Provider, ProviderResponse, Role, ToolCall, ToolChoice, ToolSpec


def _resolve_api_key(config: dict[str, Any], provider_id: str) -> str:
    direct = config.get("api_key") or config.get("apiKey")
    if direct:
        return str(direct)
    entry = _catalog_entry(provider_id)
    if entry is not None:
        for env_name in entry.env_keys:
            val = os.environ.get(env_name)
            if val:
                return val
    return ""


def _resolve_base_url(config: dict[str, Any], provider_id: str) -> str:
    explicit = config.get("base_url") or config.get("baseUrl") or config.get("endpoint")
    if explicit:
        return str(explicit).rstrip("/")
    entry = _catalog_entry(provider_id)
    if entry is None:
        return ""
    if entry.base_url_env:
        override = os.environ.get(entry.base_url_env, "").strip()
        if override:
            return override.rstrip("/")
    return entry.base_url.rstrip("/")


def _translate_messages(messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == Role.SYSTEM:
            out.append({"role": "system", "content": msg.content})
        elif msg.role == Role.USER:
            out.append({"role": "user", "content": msg.content})
        elif msg.role == Role.ASSISTANT:
            entry: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(
                                tc.arguments or {},
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        },
                    }
                    for tc in msg.tool_calls
                ]
            out.append(entry)
        elif msg.role == Role.TOOL:
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": msg.tool_call_id or "",
                    "content": msg.content or "",
                }
            )
    return out


def _format_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.input_schema,
            },
        }
        for t in tools
    ]


def _format_tool_choice(choice: ToolChoice) -> Any:
    if choice is None:
        return None
    if choice == "auto":
        return "auto"
    if choice == "any":
        return "required"
    if isinstance(choice, dict) and choice.get("type") == "tool" and "name" in choice:
        return {"type": "function", "function": {"name": choice["name"]}}
    return None


class OpenAICompatProvider(Provider):
    """Any OpenAI-shaped ``/chat/completions`` endpoint."""

    supports_tools: bool = True

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._provider_id = (config.get("provider_name") or config.get("provider") or "openai").lower()
        self._model = config.get("model") or ""
        self._api_key = _resolve_api_key(config, self._provider_id)
        self._base_url = _resolve_base_url(config, self._provider_id)
        self._extra_headers = dict(config.get("extra_headers") or {})
        self._timeout = float(config.get("timeout", 120.0))

    def get_model(self) -> str:
        return self._model

    def _auth_headers(self) -> dict[str, str]:
        hdrs = {"Content-Type": "application/json"}
        if self._api_key:
            hdrs["Authorization"] = f"Bearer {self._api_key}"
        # OpenRouter expects X-Title / HTTP-Referer for attribution.
        if self._provider_id == "openrouter":
            hdrs.setdefault("HTTP-Referer", "https://vektra.industries/koda")
            hdrs.setdefault("X-Title", "K.O.D.A.")
        hdrs.update(self._extra_headers)
        return hdrs

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        if not self._base_url:
            return ProviderResponse(
                text=f"No endpoint configured for provider {self._provider_id!r}.",
                stop_reason="error",
            )

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": _translate_messages(messages),
            "stream": False,
        }
        if tools:
            payload["tools"] = _format_tools(tools)
        tc = _format_tool_choice(tool_choice)
        if tc is not None:
            payload["tool_choice"] = tc
        for k in ("temperature", "top_p", "max_tokens"):
            if k in self.config:
                payload[k] = self.config[k]

        url = self._base_url + "/chat/completions"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url,
                    content=json.dumps(payload),
                    headers=self._auth_headers(),
                )
        except httpx.HTTPError as exc:
            return ProviderResponse(
                text=f"{self._provider_id} transport error: {exc}",
                stop_reason="error",
            )

        if resp.status_code >= 400:
            excerpt = resp.text[:300].replace("\n", " ")
            return ProviderResponse(
                text=f"{self._provider_id} HTTP {resp.status_code}: {excerpt}",
                stop_reason="error",
            )

        try:
            data = resp.json()
        except ValueError:
            return ProviderResponse(
                text=f"{self._provider_id} returned non-JSON response.",
                stop_reason="error",
            )

        choice0 = (data.get("choices") or [{}])[0]
        message = choice0.get("message") or {}
        tool_calls: list[ToolCall] = []
        for tc_raw in message.get("tool_calls") or []:
            fn = tc_raw.get("function") or {}
            args_raw = fn.get("arguments", "{}")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else (args_raw or {})
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(
                ToolCall(
                    id=tc_raw.get("id") or "",
                    name=fn.get("name") or "",
                    arguments=args if isinstance(args, dict) else {},
                )
            )

        return ProviderResponse(
            text=message.get("content") or "",
            tool_calls=tool_calls,
            stop_reason=choice0.get("finish_reason") or "",
            usage=data.get("usage") or {},
            raw=data,
        )


__all__ = ["OpenAICompatProvider"]
