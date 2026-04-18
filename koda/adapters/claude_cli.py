"""Claude CLI shell-out adapter. Uses the user's locally installed `claude` binary via JSON stream."""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from .base import Message, Provider, ProviderResponse, Role, ToolCall, ToolChoice, ToolSpec


def _sanitize(name: str) -> str:
    return name.replace(".", "_")


def _build_transcript(messages: list[Message]) -> tuple[str, str]:
    """Concatenate the conversation into (system_prompt, user_prompt) strings.

    Claude CLI's non-interactive mode takes a single prompt. We fold the
    conversation history into the prompt so the model sees context.
    """
    system_parts: list[str] = []
    chat_parts: list[str] = []
    for msg in messages:
        if msg.role == Role.SYSTEM:
            system_parts.append(msg.content)
        elif msg.role == Role.USER:
            chat_parts.append(f"[User]\n{msg.content}")
        elif msg.role == Role.ASSISTANT:
            if msg.content:
                chat_parts.append(f"[Assistant]\n{msg.content}")
            for tc in msg.tool_calls or []:
                chat_parts.append(f"[Assistant tool_use]\n{tc.name}({json.dumps(tc.arguments)})")
        elif msg.role == Role.TOOL:
            chat_parts.append(f"[Tool result id={msg.tool_call_id}]\n{msg.content}")
    return "\n\n".join(system_parts).strip(), "\n\n".join(chat_parts).strip()


class ClaudeCLIProvider(Provider):
    """Provider that delegates to the user's installed `claude` CLI.

    This is the zero-config backend: if the user already uses Claude Code, they
    don't need to provide an API key to run K.O.D.A. The binary carries its own
    auth and quota. Requires `claude` on PATH.
    """

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._binary = config.get("binary") or shutil.which("claude") or "claude"
        self._model = config.get("model", "")

    def get_model(self) -> str:
        return self._model or "claude-cli"

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        system_text, user_text = _build_transcript(messages)
        full_prompt = f"{system_text}\n\n---\n\n{user_text}" if system_text else user_text

        args = [self._binary, "--output-format", "json", "--print", full_prompt]
        if self._model:
            args.extend(["--model", self._model])

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=kwargs.get("timeout", 300.0))
        except FileNotFoundError:
            return ProviderResponse(
                text="Claude CLI not found. Install with `npm i -g @anthropic-ai/claude-code` or choose a different provider.",
                stop_reason="error",
            )
        except asyncio.TimeoutError:
            return ProviderResponse(text="Claude CLI call timed out.", stop_reason="timeout")

        if proc.returncode != 0:
            return ProviderResponse(
                text=f"Claude CLI error (code {proc.returncode}): {stderr.decode(errors='ignore').strip()}",
                stop_reason="error",
            )

        raw_out = stdout.decode(errors="ignore").strip()
        text = raw_out
        raw_json: dict[str, Any] | None = None
        try:
            parsed = json.loads(raw_out)
            raw_json = parsed
            if isinstance(parsed, dict):
                text = parsed.get("result") or parsed.get("response") or parsed.get("content") or raw_out
        except json.JSONDecodeError:
            pass

        _ = tools, tool_choice  # Tool calls aren't forwarded through CLI mode yet.
        return ProviderResponse(text=text, raw=raw_json, stop_reason="end_turn")
