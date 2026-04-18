"""Google Gemini adapter.

Gemini's ``generateContent`` API is shaped differently from both
OpenAI and Anthropic:

  - Messages are ``contents``; roles are ``user`` / ``model`` (not
    ``assistant``); no ``system`` role — system instruction is a
    separate top-level ``systemInstruction`` field.
  - Tool schemas are ``functionDeclarations``; calls come back as
    ``functionCall`` parts on a model message; results go back as a
    ``user`` message containing a ``functionResponse`` part.
  - Function calls carry no tool-call id — the function *name* is
    the de-facto identifier. We synthesize a stable id from the name
    + argument hash so Koda's message pipeline still sees a non-empty
    ``tool_call_id`` to match results against.

Key lookup falls back through config → ``GEMINI_API_KEY`` →
``GOOGLE_API_KEY`` → ``~/.config/gcloud/api-key.txt`` so the adapter
works in all the common local dev layouts without ceremony.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import httpx

from .base import Message, Provider, ProviderResponse, Role, ToolCall, ToolChoice, ToolSpec


_DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


def _resolve_api_key(config: dict[str, Any]) -> str:
    explicit = config.get("api_key") or config.get("apiKey")
    if explicit:
        return str(explicit)
    for env_name in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY"):
        val = os.environ.get(env_name)
        if val:
            return val
    fallback = Path.home() / ".config" / "gcloud" / "api-key.txt"
    if fallback.is_file():
        try:
            return fallback.read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return ""


def _synth_call_id(name: str, arguments: dict[str, Any]) -> str:
    """Build a deterministic id for a tool call missing one.

    Gemini's functionCall has no id. Koda's internal plumbing expects
    a stable tool_call_id per invocation so tool results can be matched
    back to the call. Hashing name + canonical-JSON args is stable
    across the request/response cycle without the model needing to
    remember anything extra.
    """
    payload = name + "|" + json.dumps(arguments or {}, sort_keys=True, default=str)
    return "g-" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _translate_tool_result(content: str) -> dict[str, Any]:
    """Gemini expects functionResponse content as a dict. Accept JSON
    strings, wrap anything else in ``{"result": ...}``."""
    if not content:
        return {"result": ""}
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return {"result": content}
    if isinstance(parsed, dict):
        return parsed
    return {"result": parsed}


def _translate_messages(messages: list[Message]) -> tuple[list[dict[str, Any]], str]:
    contents: list[dict[str, Any]] = []
    system_parts: list[str] = []
    for msg in messages:
        if msg.role == Role.SYSTEM:
            if msg.content:
                system_parts.append(msg.content)
            continue

        if msg.role == Role.USER:
            contents.append({"role": "user", "parts": [{"text": msg.content or ""}]})

        elif msg.role == Role.ASSISTANT:
            parts: list[dict[str, Any]] = []
            if msg.content:
                parts.append({"text": msg.content})
            for tc in msg.tool_calls or []:
                parts.append(
                    {
                        "functionCall": {
                            "name": tc.name,
                            "args": tc.arguments or {},
                        }
                    }
                )
            if parts:
                contents.append({"role": "model", "parts": parts})

        elif msg.role == Role.TOOL:
            # Gemini wants the original function name, not the call id.
            fn_name = (msg.metadata or {}).get("tool_name") or ""
            contents.append(
                {
                    "role": "user",
                    "parts": [
                        {
                            "functionResponse": {
                                "name": fn_name,
                                "response": _translate_tool_result(msg.content or ""),
                            }
                        }
                    ],
                }
            )

    return contents, "\n\n".join(p for p in system_parts if p).strip()


def _format_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    """Wrap our ToolSpec list into the single ``tools`` block Gemini expects."""
    declarations: list[dict[str, Any]] = []
    for t in tools:
        declarations.append(
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.input_schema,
            }
        )
    return [{"functionDeclarations": declarations}] if declarations else []


def _tool_config(choice: ToolChoice) -> dict[str, Any] | None:
    if choice is None:
        return None
    if choice == "auto":
        return {"functionCallingConfig": {"mode": "AUTO"}}
    if choice == "any":
        return {"functionCallingConfig": {"mode": "ANY"}}
    if isinstance(choice, dict) and choice.get("type") == "tool" and "name" in choice:
        return {
            "functionCallingConfig": {
                "mode": "ANY",
                "allowedFunctionNames": [choice["name"]],
            }
        }
    return None


class GeminiProvider(Provider):
    """Google Gemini via the generativelanguage REST API."""

    supports_tools: bool = True

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._model = config.get("model") or "gemini-2.5-flash"
        self._api_key = _resolve_api_key(config)
        self._base_url = (config.get("base_url") or _DEFAULT_BASE_URL).rstrip("/")
        self._timeout = float(config.get("timeout", 120.0))

    def get_model(self) -> str:
        return self._model

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        if not self._api_key:
            return ProviderResponse(
                text="Gemini API key missing. Set GEMINI_API_KEY or configure api_key.",
                stop_reason="error",
            )

        contents, system_text = _translate_messages(messages)
        payload: dict[str, Any] = {"contents": contents}
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}
        if tools:
            formatted = _format_tools(tools)
            if formatted:
                payload["tools"] = formatted
        tc = _tool_config(tool_choice)
        if tc is not None:
            payload["toolConfig"] = tc

        gen_cfg: dict[str, Any] = {}
        for k in ("temperature", "topP", "topK", "maxOutputTokens"):
            src_key = {"topP": "top_p", "topK": "top_k", "maxOutputTokens": "max_tokens"}.get(k, k)
            if src_key in self.config:
                gen_cfg[k] = self.config[src_key]
        if gen_cfg:
            payload["generationConfig"] = gen_cfg

        url = f"{self._base_url}/models/{self._model}:generateContent"
        params = {"key": self._api_key}

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url,
                    params=params,
                    content=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
        except httpx.HTTPError as exc:
            return ProviderResponse(text=f"gemini transport error: {exc}", stop_reason="error")

        if resp.status_code >= 400:
            excerpt = resp.text[:300].replace("\n", " ")
            return ProviderResponse(
                text=f"gemini HTTP {resp.status_code}: {excerpt}",
                stop_reason="error",
            )

        try:
            data = resp.json()
        except ValueError:
            return ProviderResponse(text="gemini returned non-JSON response.", stop_reason="error")

        candidates = data.get("candidates") or []
        if not candidates:
            block = data.get("promptFeedback", {}).get("blockReason", "")
            return ProviderResponse(
                text=f"gemini returned no candidates (block: {block or 'unknown'}).",
                stop_reason="error" if block else "end_turn",
                raw=data,
            )

        cand = candidates[0]
        parts = (cand.get("content") or {}).get("parts") or []
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for part in parts:
            if "text" in part and part["text"]:
                text_parts.append(part["text"])
            fn_call = part.get("functionCall")
            if isinstance(fn_call, dict):
                name = fn_call.get("name") or ""
                args = fn_call.get("args") or {}
                if not isinstance(args, dict):
                    args = {}
                tool_calls.append(
                    ToolCall(id=_synth_call_id(name, args), name=name, arguments=args)
                )

        usage_raw = data.get("usageMetadata") or {}
        usage = {
            "prompt_tokens": usage_raw.get("promptTokenCount", 0),
            "completion_tokens": usage_raw.get("candidatesTokenCount", 0),
            "total_tokens": usage_raw.get("totalTokenCount", 0),
        }
        return ProviderResponse(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=cand.get("finishReason") or "",
            usage=usage,
            raw=data,
        )


__all__ = ["GeminiProvider"]
