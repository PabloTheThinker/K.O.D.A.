"""Ollama adapter. Talks to a local Ollama server via its OpenAI-compatible chat endpoint."""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from .base import Message, Provider, ProviderResponse, Role, ToolCall, ToolChoice, ToolSpec

_DEFAULT_MODEL = "qwen3:14b"
_DEFAULT_URL = "http://127.0.0.1:11434"


class OllamaProvider(Provider):
    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._base_url = config.get("base_url") or os.environ.get("OLLAMA_HOST") or _DEFAULT_URL
        self._model = config.get("model") or _DEFAULT_MODEL

    def get_model(self) -> str:
        return self._model

    def _translate_messages(self, messages: list[Message]) -> list[dict[str, Any]]:
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
                            "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                        }
                        for tc in msg.tool_calls
                    ]
                out.append(entry)
            elif msg.role == Role.TOOL:
                out.append({
                    "role": "tool",
                    "tool_call_id": msg.tool_call_id or "",
                    "content": msg.content,
                })
        return out

    def _format_tools(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
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

    def _format_tool_choice(self, choice: ToolChoice) -> Any:
        if choice is None:
            return None
        if choice == "auto":
            return "auto"
        if choice == "any":
            return "required"
        if isinstance(choice, dict) and choice.get("type") == "tool" and "name" in choice:
            return {"type": "function", "function": {"name": choice["name"]}}
        return None

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": self._translate_messages(messages),
            "stream": False,
        }
        if tools:
            payload["tools"] = self._format_tools(tools)
        tc = self._format_tool_choice(tool_choice)
        if tc is not None:
            payload["tool_choice"] = tc

        url = self._base_url.rstrip("/") + "/v1/chat/completions"
        async with httpx.AsyncClient(timeout=kwargs.get("timeout", 300.0)) as client:
            resp = await client.post(url, content=json.dumps(payload), headers={"Content-Type": "application/json"})

        if resp.status_code >= 400:
            return ProviderResponse(
                text=f"Ollama error {resp.status_code}: {resp.text}",
                stop_reason="error",
            )
        data = resp.json()
        choice0 = (data.get("choices") or [{}])[0]
        message = choice0.get("message", {})
        tool_calls: list[ToolCall] = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function", {})
            args_raw = fn.get("arguments", "{}")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else (args_raw or {})
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(id=tc.get("id", ""), name=fn.get("name", ""), arguments=args))
        return ProviderResponse(
            text=message.get("content") or "",
            tool_calls=tool_calls,
            stop_reason=choice0.get("finish_reason", ""),
            usage=data.get("usage", {}),
            raw=data,
        )
