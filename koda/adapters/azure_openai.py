"""Azure OpenAI adapter.

Azure's OpenAI-compatible endpoint differs from vanilla OpenAI in four
ways:
  1. URL embeds the deployment name, not the model in the payload.
  2. Auth header is ``api-key: <key>`` instead of ``Authorization: Bearer``.
  3. ``api-version`` query parameter is mandatory.
  4. ``model`` field in the payload is ignored (deployment drives routing)
     but we pass it anyway for logging transparency.

Tool calls and finish-reason handling are identical to the OpenAI wire
protocol, so we reuse the translation helpers from openai_compat.
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from .base import Message, Provider, ProviderResponse, ToolCall, ToolChoice, ToolSpec
from .openai_compat import (
    _format_tool_choice,
    _format_tools,
    _translate_messages,
)

_DEFAULT_API_VERSION = "2024-08-01-preview"


class AzureOpenAIProvider(Provider):
    """Azure OpenAI deployment via the Azure-specific chat completions URL."""

    supports_tools: bool = True

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._endpoint = (config.get("endpoint") or "").rstrip("/")
        self._deployment = config.get("deployment") or ""
        self._api_version = config.get("api_version") or _DEFAULT_API_VERSION
        self._api_key = (
            config.get("api_key")
            or os.environ.get("AZURE_OPENAI_API_KEY")
            or ""
        )
        self._model = config.get("model") or self._deployment
        self._timeout = float(config.get("timeout", 120.0))

    def get_model(self) -> str:
        return self._model or self._deployment

    def _chat_url(self) -> str:
        return (
            f"{self._endpoint}/openai/deployments/{self._deployment}"
            f"/chat/completions?api-version={self._api_version}"
        )

    def _auth_headers(self) -> dict[str, str]:
        hdrs: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            hdrs["api-key"] = self._api_key
        return hdrs

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        if not self._endpoint:
            return ProviderResponse(
                text="Azure OpenAI: no endpoint configured.",
                stop_reason="error",
            )
        if not self._deployment:
            return ProviderResponse(
                text="Azure OpenAI: no deployment configured.",
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

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._chat_url(),
                    content=json.dumps(payload),
                    headers=self._auth_headers(),
                )
        except httpx.HTTPError as exc:
            return ProviderResponse(
                text=f"azure_openai transport error: {exc}",
                stop_reason="error",
            )

        if resp.status_code >= 400:
            excerpt = resp.text[:300].replace("\n", " ")
            return ProviderResponse(
                text=f"azure_openai HTTP {resp.status_code}: {excerpt}",
                stop_reason="error",
            )

        try:
            data = resp.json()
        except ValueError:
            return ProviderResponse(
                text="azure_openai returned non-JSON response.",
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


__all__ = ["AzureOpenAIProvider"]
