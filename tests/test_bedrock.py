"""Tests for the AWS Bedrock provider adapter.

All network / boto3 calls are mocked — no real AWS endpoints are contacted.
boto3 is injected via monkeypatch so the tests run even without boto3
installed system-wide.
"""
from __future__ import annotations

import asyncio
import sys
import types
from typing import Any
from unittest.mock import MagicMock

from koda.adapters import create_provider
from koda.adapters.base import Message, Role, ToolSpec
from koda.adapters.bedrock import (
    _DEFAULT_MODEL,
    _DEFAULT_REGION,
    BedrockProvider,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run a coroutine synchronously."""
    return asyncio.run(coro)


def _messages(content: str = "ping") -> list[Message]:
    return [Message(role=Role.USER, content=content)]


def _converse_response(
    text: str = "pong",
    stop_reason: str = "end_turn",
    tool_uses: list[dict] | None = None,
) -> dict[str, Any]:
    """Minimal Bedrock converse success payload."""
    content: list[dict[str, Any]] = []
    if text:
        content.append({"text": text})
    for tu in tool_uses or []:
        content.append({"toolUse": tu})
    return {
        "output": {"message": {"role": "assistant", "content": content}},
        "stopReason": stop_reason,
        "usage": {"inputTokens": 10, "outputTokens": 5},
    }


def _client_error(code: str, message: str = "details") -> Exception:
    """Build a minimal botocore ClientError shape."""
    exc = Exception(f"An error occurred ({code}): {message}")
    exc.response = {"Error": {"Code": code, "Message": message}}  # type: ignore[attr-defined]
    return exc


def _make_fake_boto3(converse_return=None, converse_side_effect=None):
    """Return a fake boto3 module that yields a mock bedrock-runtime client."""
    fake_client = MagicMock()
    if converse_side_effect is not None:
        fake_client.converse = MagicMock(side_effect=converse_side_effect)
    else:
        fake_client.converse = MagicMock(return_value=converse_return)

    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = MagicMock(return_value=fake_client)  # type: ignore[attr-defined]

    fake_session = MagicMock()
    fake_session.client = MagicMock(return_value=fake_client)
    fake_boto3.Session = MagicMock(return_value=fake_session)  # type: ignore[attr-defined]

    return fake_boto3, fake_client


# ---------------------------------------------------------------------------
# 1. boto3 absent — import-time safety + runtime error message
# ---------------------------------------------------------------------------


def test_import_succeeds_without_boto3():
    """Importing bedrock module must not raise even if boto3 is absent."""
    # The module is already loaded; just verify the class is accessible.
    assert BedrockProvider is not None


def test_missing_boto3_returns_helpful_error(monkeypatch):
    """chat() returns a clear ImportError message when boto3 is missing."""
    # Remove boto3 from sys.modules if present and block re-import.
    monkeypatch.setitem(sys.modules, "boto3", None)  # type: ignore[call-overload]

    provider = BedrockProvider({})
    result = _run(provider.chat(_messages()))

    assert result.stop_reason == "error"
    assert "boto3" in result.text
    assert "pip install boto3" in result.text


# ---------------------------------------------------------------------------
# 2. Defaults — model and region
# ---------------------------------------------------------------------------


def test_default_model_id():
    p = BedrockProvider({})
    assert p.get_model() == _DEFAULT_MODEL
    assert "claude-3-5-sonnet" in p.get_model()


def test_default_region():
    p = BedrockProvider({})
    assert p._region == _DEFAULT_REGION
    assert p._region == "us-east-1"


def test_model_override():
    custom = "anthropic.claude-3-opus-20240229-v1:0"
    p = BedrockProvider({"model": custom})
    assert p.get_model() == custom


def test_region_override():
    p = BedrockProvider({"region": "us-west-2"})
    assert p._region == "us-west-2"


# ---------------------------------------------------------------------------
# 3. Successful converse round-trip
# ---------------------------------------------------------------------------


def test_chat_success(monkeypatch):
    fake_boto3, _ = _make_fake_boto3(converse_return=_converse_response("pong"))
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(_messages()))

    assert result.stop_reason == "end_turn"
    assert result.text == "pong"
    assert result.tool_calls == []


def test_chat_passes_model_id_and_region(monkeypatch):
    """converse() must be called with the configured modelId."""
    fake_boto3, fake_client = _make_fake_boto3(
        converse_return=_converse_response("ok")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({
        "model": "anthropic.claude-3-5-haiku-20241022-v1:0",
        "region": "us-west-2",
    })
    _run(provider.chat(_messages()))

    call_kwargs = fake_client.converse.call_args[1]
    assert call_kwargs["modelId"] == "anthropic.claude-3-5-haiku-20241022-v1:0"


# ---------------------------------------------------------------------------
# 4. System-message extraction
# ---------------------------------------------------------------------------


def test_system_message_goes_to_top_level_field(monkeypatch):
    """System prompt must appear in the top-level ``system`` arg, not messages."""
    fake_boto3, fake_client = _make_fake_boto3(
        converse_return=_converse_response("ok")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    messages = [
        Message(role=Role.SYSTEM, content="You are a security agent."),
        Message(role=Role.USER, content="ping"),
    ]
    provider = BedrockProvider({})
    _run(provider.chat(messages))

    call_kwargs = fake_client.converse.call_args[1]
    # system is a top-level list of {text: ...} blocks
    system = call_kwargs.get("system", [])
    assert len(system) == 1
    assert system[0]["text"] == "You are a security agent."

    # system prompt must NOT appear in the messages array
    bedrock_messages = call_kwargs["messages"]
    for m in bedrock_messages:
        for block in m.get("content", []):
            assert block.get("text") != "You are a security agent."


def test_no_system_field_when_no_system_message(monkeypatch):
    """When there's no system message, ``system`` key must not be passed."""
    fake_boto3, fake_client = _make_fake_boto3(
        converse_return=_converse_response("ok")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    _run(provider.chat(_messages()))

    call_kwargs = fake_client.converse.call_args[1]
    assert "system" not in call_kwargs


# ---------------------------------------------------------------------------
# 5. Tool-use parsing
# ---------------------------------------------------------------------------


def test_tool_use_parsed_from_response(monkeypatch):
    """toolUse content blocks → ToolCall objects on the response."""
    fake_boto3, _ = _make_fake_boto3(
        converse_return=_converse_response(
            text="",
            stop_reason="tool_use",
            tool_uses=[{
                "toolUseId": "tid_001",
                "name": "run_semgrep",
                "input": {"path": "/app", "rules": "python"},
            }],
        )
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(
        _messages(),
        tools=[ToolSpec(name="run_semgrep", description="run semgrep", input_schema={})],
    ))

    assert result.stop_reason == "tool_use"
    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    assert tc.id == "tid_001"
    assert tc.name == "run_semgrep"
    assert tc.arguments == {"path": "/app", "rules": "python"}


def test_tool_call_name_desanitized(monkeypatch):
    """Dot-in-name sanitization is reversed on parse (safe_name → original)."""
    fake_boto3, _ = _make_fake_boto3(
        converse_return=_converse_response(
            text="",
            stop_reason="tool_use",
            tool_uses=[{
                "toolUseId": "x",
                "name": "koda_nmap_scan",  # sanitized form
                "input": {},
            }],
        )
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(
        _messages(),
        tools=[ToolSpec(name="koda.nmap_scan", description="nmap", input_schema={})],
    ))

    assert result.tool_calls[0].name == "koda.nmap_scan"


def test_tool_config_sent_to_converse(monkeypatch):
    """When tools are passed, toolConfig must appear in the converse call."""
    fake_boto3, fake_client = _make_fake_boto3(
        converse_return=_converse_response("ok")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    tools = [ToolSpec(name="nmap_scan", description="scan", input_schema={"type": "object"})]
    provider = BedrockProvider({})
    _run(provider.chat(_messages(), tools=tools))

    call_kwargs = fake_client.converse.call_args[1]
    assert "toolConfig" in call_kwargs
    specs = call_kwargs["toolConfig"]["tools"]
    assert len(specs) == 1
    assert specs[0]["toolSpec"]["name"] == "nmap_scan"
    assert specs[0]["toolSpec"]["inputSchema"]["json"] == {"type": "object"}


# ---------------------------------------------------------------------------
# 6. Tool-result messages
# ---------------------------------------------------------------------------


def test_tool_result_bundled_as_user_message(monkeypatch):
    """TOOL role messages must be bundled into a user-role message with toolResult blocks."""
    fake_boto3, fake_client = _make_fake_boto3(
        converse_return=_converse_response("ok")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    messages = [
        Message(role=Role.USER, content="run scan"),
        Message(role=Role.ASSISTANT, content=""),
        Message(role=Role.TOOL, content="scan output", tool_call_id="tid_001"),
    ]
    provider = BedrockProvider({})
    _run(provider.chat(messages))

    call_kwargs = fake_client.converse.call_args[1]
    bedrock_messages = call_kwargs["messages"]

    # Last message should be a user-role message with a toolResult block
    last = bedrock_messages[-1]
    assert last["role"] == "user"
    assert any("toolResult" in blk for blk in last["content"])
    tool_result_block = next(blk["toolResult"] for blk in last["content"] if "toolResult" in blk)
    assert tool_result_block["toolUseId"] == "tid_001"


# ---------------------------------------------------------------------------
# 7. Error handling — AWS exception codes
# ---------------------------------------------------------------------------


def test_access_denied_exception(monkeypatch):
    fake_boto3, _ = _make_fake_boto3(
        converse_side_effect=_client_error("AccessDeniedException", "Not authorized")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(_messages()))

    assert result.stop_reason == "error"
    assert "AccessDeniedException" in result.text
    assert "bedrock:InvokeModel" in result.text


def test_validation_exception(monkeypatch):
    fake_boto3, _ = _make_fake_boto3(
        converse_side_effect=_client_error("ValidationException", "Bad model id")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(_messages()))

    assert result.stop_reason == "error"
    assert "ValidationException" in result.text


def test_throttling_exception(monkeypatch):
    fake_boto3, _ = _make_fake_boto3(
        converse_side_effect=_client_error("ThrottlingException", "Rate exceeded")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(_messages()))

    assert result.stop_reason == "error"
    assert "ThrottlingException" in result.text
    assert "Back off" in result.text or "retry" in result.text.lower()


def test_model_stream_error_exception(monkeypatch):
    fake_boto3, _ = _make_fake_boto3(
        converse_side_effect=_client_error("ModelStreamErrorException", "Stream error")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(_messages()))

    assert result.stop_reason == "error"
    assert "ModelStreamErrorException" in result.text


def test_generic_client_error(monkeypatch):
    fake_boto3, _ = _make_fake_boto3(
        converse_side_effect=_client_error("ServiceUnavailableException", "Temporarily down")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(_messages()))

    assert result.stop_reason == "error"
    assert "ServiceUnavailableException" in result.text


def test_no_credentials_error(monkeypatch):
    """Non-ClientError (e.g. NoCredentialsError) is surfaced cleanly."""
    fake_boto3, _ = _make_fake_boto3(
        converse_side_effect=Exception("Unable to locate credentials")
    )
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({})
    result = _run(provider.chat(_messages()))

    assert result.stop_reason == "error"
    assert "error" in result.text.lower() or "credentials" in result.text.lower()


# ---------------------------------------------------------------------------
# 8. create_provider factory
# ---------------------------------------------------------------------------


def test_create_provider_bedrock():
    p = create_provider("bedrock", {})
    assert isinstance(p, BedrockProvider)


def test_create_provider_aws_bedrock_alias():
    p = create_provider("aws_bedrock", {})
    assert isinstance(p, BedrockProvider)


# ---------------------------------------------------------------------------
# 9. supports_tools flag
# ---------------------------------------------------------------------------


def test_supports_tools():
    p = BedrockProvider({})
    assert p.supports_tools is True


# ---------------------------------------------------------------------------
# 10. AWS profile forwarded to Session
# ---------------------------------------------------------------------------


def test_aws_profile_uses_session(monkeypatch):
    """When aws_profile is set, a boto3.Session is created with that profile."""
    fake_boto3, _ = _make_fake_boto3(converse_return=_converse_response("ok"))
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    provider = BedrockProvider({"aws_profile": "prod-role"})
    _run(provider.chat(_messages()))

    fake_boto3.Session.assert_called_once_with(profile_name="prod-role")
