"""llama.cpp server adapter.

Talks to a local ``./server`` binary started in OpenAI-compatible mode.
The server exposes ``/v1/chat/completions`` on a configurable host:port.

Tool-call support in llama.cpp depends on the build and the loaded model.
If the server signals it doesn't support tools (HTTP 501, or any 4xx/5xx
error while tools are in the payload), the adapter surfaces a clean error
message rather than silently producing garbage output.

Config keys:
    host       — default ``127.0.0.1``
    port       — default 8080
    api_key    — optional bearer token (llama.cpp ``--api-key`` flag)
    model      — cosmetic label; the loaded model is decided server-side
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from .base import Message, Provider, ProviderResponse, ToolCall, ToolChoice, ToolSpec
from .openai_compat import (
    _format_tool_choice,
    _format_tools,
    _translate_messages,
)

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8080


class LlamaCppProvider(Provider):
    """Local llama.cpp server via its OpenAI-compatible ``/v1`` endpoint."""

    supports_tools: bool = True

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._host = config.get("host") or _DEFAULT_HOST
        self._port = int(config.get("port") or _DEFAULT_PORT)
        self._api_key = config.get("api_key") or ""
        self._model = config.get("model") or ""
        self._timeout = float(config.get("timeout", 300.0))

    def get_model(self) -> str:
        return self._model

    def _chat_url(self) -> str:
        return f"http://{self._host}:{self._port}/v1/chat/completions"

    def _auth_headers(self) -> dict[str, str]:
        hdrs: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            hdrs["Authorization"] = f"Bearer {self._api_key}"
        return hdrs

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        payload: dict[str, Any] = {
            "messages": _translate_messages(messages),
            "stream": False,
        }
        if self._model:
            payload["model"] = self._model
        if tools:
            payload["tools"] = _format_tools(tools)
        tc = _format_tool_choice(tool_choice)
        if tc is not None:
            payload["tool_choice"] = tc
        for k in ("temperature", "top_p", "max_tokens"):
            if k in self.config:
                payload[k] = self.config[k]

        url = self._chat_url()
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url,
                    content=json.dumps(payload),
                    headers=self._auth_headers(),
                )
        except httpx.ConnectError as exc:
            return ProviderResponse(
                text=(
                    f"llama.cpp server unreachable at {self._host}:{self._port}. "
                    f"Start it with `./server -m <model> --port {self._port}`. "
                    f"Detail: {exc}"
                ),
                stop_reason="error",
            )
        except httpx.HTTPError as exc:
            return ProviderResponse(
                text=f"llama.cpp transport error: {exc}",
                stop_reason="error",
            )

        # 501 = tool calls not implemented by this build/model.
        if resp.status_code == 501:
            return ProviderResponse(
                text=(
                    "llama.cpp server returned 501 Not Implemented for tool calls. "
                    "Rebuild llama.cpp with tool-call support or use a model that "
                    "includes function-calling fine-tuning."
                ),
                stop_reason="error",
            )

        if resp.status_code >= 400:
            excerpt = resp.text[:300].replace("\n", " ")
            return ProviderResponse(
                text=f"llama.cpp HTTP {resp.status_code}: {excerpt}",
                stop_reason="error",
            )

        try:
            data = resp.json()
        except ValueError:
            return ProviderResponse(
                text="llama.cpp returned non-JSON response.",
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


__all__ = ["LlamaCppProvider"]
