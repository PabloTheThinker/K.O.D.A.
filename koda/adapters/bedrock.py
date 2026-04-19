"""AWS Bedrock provider adapter.

Uses the Bedrock Runtime ``converse`` API, which provides a normalized
message/tool interface across all hosted model families. First-class support
targets Anthropic Claude models (same content-block semantics as the direct
Anthropic API), but the converse API's unified shape means other families
(Meta, Cohere, Mistral, Amazon Titan) can be added by changing only the model
ID.

Auth follows the standard AWS credential chain via ``boto3``:
  - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
  - ~/.aws/credentials profiles
  - IAM instance roles / ECS task roles / etc.

boto3 is **not** a hard dependency.  Import succeeds with boto3 absent; the
error is raised with install instructions only when ``chat()`` is first called.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from .base import Message, Provider, ProviderResponse, Role, ToolCall, ToolChoice, ToolSpec

_DEFAULT_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"
_DEFAULT_REGION = "us-east-1"

# Bedrock stopReason values that indicate a tool-use turn.
_TOOL_USE_STOP_REASONS = {"tool_use"}


def _sanitize_tool_name(name: str) -> str:
    """Bedrock tool names follow the same rules as Anthropic: no dots."""
    return name.replace(".", "_")


class BedrockProvider(Provider):
    """AWS Bedrock Runtime adapter using the ``converse`` API."""

    supports_tools: bool = True

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._model = config.get("model") or _DEFAULT_MODEL
        self._region = config.get("region") or _DEFAULT_REGION
        self._profile = config.get("aws_profile") or None
        self._tool_name_map: dict[str, str] = {}

    def get_model(self) -> str:
        return self._model

    # ------------------------------------------------------------------
    # boto3 lazy-import
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Lazily import boto3 and return a bedrock-runtime client.

        Raises ImportError with install instructions if boto3 is absent.
        """
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for the AWS Bedrock provider but is not installed.\n"
                "Install it with:  pip install boto3\n"
                "Then re-run your command."
            ) from exc

        kwargs: dict[str, Any] = {"region_name": self._region}
        if self._profile:
            session = boto3.Session(profile_name=self._profile)
            return session.client("bedrock-runtime", **kwargs)
        return boto3.client("bedrock-runtime", **kwargs)

    # ------------------------------------------------------------------
    # Message translation  (harness format → Bedrock converse shape)
    # ------------------------------------------------------------------

    def _format_tools(self, tools: list[ToolSpec]) -> dict[str, Any]:
        """Return the ``toolConfig`` block expected by the converse API."""
        self._tool_name_map = {}
        tool_specs: list[dict[str, Any]] = []
        for t in tools:
            safe = _sanitize_tool_name(t.name)
            self._tool_name_map[safe] = t.name
            tool_specs.append({
                "toolSpec": {
                    "name": safe,
                    "description": t.description,
                    "inputSchema": {"json": t.input_schema},
                }
            })
        return {"tools": tool_specs}

    def _translate_messages(
        self,
        messages: list[Message],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Translate harness messages into (bedrock_messages, system_list).

        Bedrock converse separates system prompts from the message list:
          - ``system`` is a top-level list of ``{text: ...}`` blocks.
          - ``messages`` is a list of ``{role, content:[...]}`` dicts.

        Tool results must be bundled as a ``user`` role message containing
        ``toolResult`` content blocks (same grouping rule as Anthropic direct).
        """
        system_parts: list[str] = []
        bedrock_messages: list[dict[str, Any]] = []
        pending_tool_results: list[dict[str, Any]] = []

        def flush_tool_results() -> None:
            nonlocal pending_tool_results
            if pending_tool_results:
                bedrock_messages.append({
                    "role": "user",
                    "content": pending_tool_results,
                })
                pending_tool_results = []

        for msg in messages:
            if msg.role == Role.SYSTEM:
                system_parts.append(msg.content)
                continue

            if msg.role == Role.TOOL:
                # Tool results accumulate then flush as a single user message.
                content_value: Any
                try:
                    content_value = json.loads(msg.content)
                    if not isinstance(content_value, (dict, list)):
                        content_value = [{"text": msg.content}]
                    else:
                        # Wrap plain JSON as a text block for safety
                        content_value = [{"text": msg.content}]
                except (json.JSONDecodeError, TypeError):
                    content_value = [{"text": msg.content}]

                pending_tool_results.append({
                    "toolResult": {
                        "toolUseId": msg.tool_call_id or "",
                        "content": content_value,
                    }
                })
                continue

            # Non-tool message: flush any accumulated tool results first.
            flush_tool_results()

            if msg.role == Role.ASSISTANT:
                content_blocks: list[dict[str, Any]] = []
                if msg.content:
                    content_blocks.append({"text": msg.content})
                for tc in msg.tool_calls or []:
                    content_blocks.append({
                        "toolUse": {
                            "toolUseId": tc.id,
                            "name": _sanitize_tool_name(tc.name),
                            "input": tc.arguments,
                        }
                    })
                bedrock_messages.append({
                    "role": "assistant",
                    "content": content_blocks or [{"text": ""}],
                })
            else:
                # USER role
                bedrock_messages.append({
                    "role": "user",
                    "content": [{"text": msg.content}],
                })

        flush_tool_results()

        system_list = [{"text": t} for t in system_parts if t]
        return bedrock_messages, system_list

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, raw: dict[str, Any]) -> ProviderResponse:
        """Extract text + tool calls from a Bedrock converse response."""
        output_msg = raw.get("output", {}).get("message", {})
        content_blocks = output_msg.get("content") or []
        stop_reason = raw.get("stopReason", "")
        usage = raw.get("usage", {})

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []

        for block in content_blocks:
            if "text" in block:
                text_parts.append(block["text"])
            elif "toolUse" in block:
                tu = block["toolUse"]
                safe_name = tu.get("name", "")
                original = self._tool_name_map.get(safe_name, safe_name)
                args = tu.get("input", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                tool_calls.append(ToolCall(
                    id=tu.get("toolUseId", ""),
                    name=original,
                    arguments=args if isinstance(args, dict) else {},
                ))

        return ProviderResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=usage,
            raw=raw,
        )

    # ------------------------------------------------------------------
    # chat()
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,  # noqa: ARG002 — Bedrock converse auto-handles
        **kwargs: Any,
    ) -> ProviderResponse:
        # Lazy boto3 import — raises ImportError with instructions if absent.
        try:
            client = self._get_client()
        except ImportError as exc:
            return ProviderResponse(text=str(exc), stop_reason="error")

        bedrock_messages, system_list = self._translate_messages(messages)

        converse_kwargs: dict[str, Any] = {
            "modelId": self._model,
            "messages": bedrock_messages,
        }
        if system_list:
            converse_kwargs["system"] = system_list
        if tools:
            converse_kwargs["toolConfig"] = self._format_tools(tools)

        # Optional inference config overrides from kwargs / config.
        inf_cfg: dict[str, Any] = {}
        max_tokens = kwargs.get("max_tokens") or self.config.get("max_tokens")
        if max_tokens:
            inf_cfg["maxTokens"] = int(max_tokens)
        temperature = kwargs.get("temperature") or self.config.get("temperature")
        if temperature is not None:
            inf_cfg["temperature"] = float(temperature)
        if inf_cfg:
            converse_kwargs["inferenceConfig"] = inf_cfg

        # Run the synchronous boto3 call in a thread pool so we don't block
        # the event loop.
        try:
            raw = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.converse(**converse_kwargs),
            )
        except Exception as exc:  # noqa: BLE001
            return self._handle_boto_exception(exc)

        return self._parse_response(raw)

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def _handle_boto_exception(self, exc: Exception) -> ProviderResponse:
        """Convert botocore ClientError codes into actionable messages."""
        exc_type = type(exc).__name__
        exc_str = str(exc)

        # botocore.exceptions.ClientError has a .response dict with Error.Code
        response_data = getattr(exc, "response", None)
        if isinstance(response_data, dict):
            error = response_data.get("Error", {})
            code = error.get("Code", exc_type)
            message = error.get("Message", exc_str)

            if code == "AccessDeniedException":
                return ProviderResponse(
                    text=(
                        f"AWS Bedrock AccessDeniedException: {message}\n"
                        "Check that your IAM principal has bedrock:InvokeModel permission "
                        f"and that model {self._model!r} is enabled in region {self._region!r}."
                    ),
                    stop_reason="error",
                )
            if code == "ValidationException":
                return ProviderResponse(
                    text=f"AWS Bedrock ValidationException: {message}\n"
                         f"Verify model ID {self._model!r} is valid and the request shape is correct.",
                    stop_reason="error",
                )
            if code == "ThrottlingException":
                return ProviderResponse(
                    text=f"AWS Bedrock ThrottlingException: {message}\n"
                         "Request rate or token quota exceeded. Back off and retry.",
                    stop_reason="error",
                )
            if code == "ModelStreamErrorException":
                return ProviderResponse(
                    text=f"AWS Bedrock ModelStreamErrorException: {message}",
                    stop_reason="error",
                )
            # Generic ClientError
            return ProviderResponse(
                text=f"AWS Bedrock {code}: {message}",
                stop_reason="error",
            )

        # Non-ClientError (e.g. NoCredentialsError, EndpointResolutionError)
        return ProviderResponse(
            text=f"AWS Bedrock error ({exc_type}): {exc_str}",
            stop_reason="error",
        )


async def _self_check() -> None:
    """Tiny smoke test; requires valid AWS credentials and Bedrock access."""
    provider = BedrockProvider({})
    resp = await provider.chat([Message(role=Role.USER, content="Say 'pong' and nothing else.")])
    print(resp.text, resp.stop_reason)


if __name__ == "__main__":
    asyncio.run(_self_check())


__all__ = ["BedrockProvider"]
