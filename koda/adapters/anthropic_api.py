"""Anthropic API adapter. Direct HTTPS to api.anthropic.com using the user's API key."""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import httpx

from .base import Message, Provider, ProviderResponse, Role, ToolCall, ToolChoice, ToolSpec

_DEFAULT_MODEL = "claude-sonnet-4-6"
_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"
_MAX_OUTPUT = {
    "opus": 32768,
    "sonnet": 16384,
    "haiku": 8192,
}


def _sanitize_tool_name(name: str) -> str:
    return name.replace(".", "_")


def _max_output_tokens(model: str) -> int:
    m = model.lower()
    for family, limit in _MAX_OUTPUT.items():
        if family in m:
            return limit
    return 8192


class AnthropicAPIProvider(Provider):
    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._tool_name_map: dict[str, str] = {}

    def get_model(self) -> str:
        return self.config.get("model") or os.environ.get("ANTHROPIC_MODEL") or _DEFAULT_MODEL

    def _api_key(self) -> str:
        key = self.config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set. Run `koda login anthropic` or export the env var.")
        return key

    def _format_tools(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
        self._tool_name_map = {}
        out: list[dict[str, Any]] = []
        for t in tools:
            safe = _sanitize_tool_name(t.name)
            self._tool_name_map[safe] = t.name
            out.append({"name": safe, "description": t.description, "input_schema": t.input_schema})
        return out

    def _format_tool_choice(self, choice: ToolChoice) -> dict[str, Any] | None:
        if choice is None:
            return None
        if choice == "auto":
            return {"type": "auto"}
        if choice == "any":
            return {"type": "any"}
        if isinstance(choice, dict) and choice.get("type") == "tool" and "name" in choice:
            return {"type": "tool", "name": _sanitize_tool_name(choice["name"])}
        return None

    def _translate_messages(self, messages: list[Message]) -> tuple[str, list[dict[str, Any]]]:
        system_text = ""
        api_messages: list[dict[str, Any]] = []
        pending_tool_results: list[dict[str, Any]] = []

        def flush_tool_results() -> None:
            nonlocal pending_tool_results
            if pending_tool_results:
                api_messages.append({"role": "user", "content": pending_tool_results})
                pending_tool_results = []

        for msg in messages:
            if msg.role == Role.SYSTEM:
                system_text = (system_text + "\n" + msg.content).strip()
                continue
            if msg.role == Role.TOOL:
                pending_tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": msg.tool_call_id or "",
                    "content": msg.content,
                })
                continue
            flush_tool_results()
            if msg.role == Role.ASSISTANT:
                blocks: list[dict[str, Any]] = []
                if msg.content:
                    blocks.append({"type": "text", "text": msg.content})
                for tc in msg.tool_calls or []:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": _sanitize_tool_name(tc.name),
                        "input": tc.arguments,
                    })
                api_messages.append({"role": "assistant", "content": blocks or msg.content})
            else:
                api_messages.append({"role": "user", "content": msg.content})

        flush_tool_results()
        return system_text, api_messages

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        model = self.get_model()
        system_text, api_messages = self._translate_messages(messages)
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": kwargs.get("max_tokens", _max_output_tokens(model)),
            "messages": api_messages,
        }
        if system_text:
            payload["system"] = system_text
        if tools:
            payload["tools"] = self._format_tools(tools)
        tc = self._format_tool_choice(tool_choice)
        if tc is not None:
            payload["tool_choice"] = tc

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self._api_key(),
            "anthropic-version": _API_VERSION,
        }

        async with httpx.AsyncClient(timeout=kwargs.get("timeout", 120.0)) as client:
            resp = await client.post(_API_URL, headers=headers, content=json.dumps(payload))
        if resp.status_code >= 400:
            return ProviderResponse(
                text=f"Anthropic API error {resp.status_code}: {resp.text}",
                stop_reason="error",
            )
        data = resp.json()

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in data.get("content", []):
            btype = block.get("type")
            if btype == "text":
                text_parts.append(block.get("text", ""))
            elif btype == "tool_use":
                original = self._tool_name_map.get(block.get("name", ""), block.get("name", ""))
                args = block.get("input", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                tool_calls.append(ToolCall(id=block.get("id", ""), name=original, arguments=args))
        return ProviderResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=data.get("stop_reason", ""),
            usage=data.get("usage", {}),
            raw=data,
        )


async def _self_check() -> None:
    """Tiny smoke test; requires ANTHROPIC_API_KEY."""
    provider = AnthropicAPIProvider({"model": _DEFAULT_MODEL})
    resp = await provider.chat([Message(role=Role.USER, content="Say 'pong' and nothing else.")])
    print(resp.text, resp.stop_reason)


if __name__ == "__main__":
    asyncio.run(_self_check())
