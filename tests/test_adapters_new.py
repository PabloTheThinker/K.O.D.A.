"""Tests for the Azure OpenAI and llama.cpp adapters.

All network calls are mocked — no real endpoints are contacted.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from koda.adapters import create_provider
from koda.adapters.azure_openai import AzureOpenAIProvider
from koda.adapters.base import Message, Role, ToolSpec
from koda.adapters.llamacpp import LlamaCppProvider

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Execute a coroutine synchronously."""
    return asyncio.run(coro)


def _ok_response(content: str = "pong", tool_calls: list[dict] | None = None) -> dict[str, Any]:
    """Minimal OpenAI-shape success payload."""
    msg: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return {
        "choices": [{"message": msg, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


def _http_response(status: int, body: dict | str = "") -> MagicMock:
    """Build a fake httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    if isinstance(body, dict):
        resp.json.return_value = body
        resp.text = json.dumps(body)
    else:
        resp.json.side_effect = ValueError("not json")
        resp.text = body
    return resp


def _messages() -> list[Message]:
    return [Message(role=Role.USER, content="ping")]


def _mock_client(post_return=None, post_side_effect=None):
    """Return a context-manager-compatible AsyncMock for httpx.AsyncClient."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    if post_side_effect is not None:
        mock_client.post = AsyncMock(side_effect=post_side_effect)
    else:
        mock_client.post = AsyncMock(return_value=post_return)
    return mock_client


# ---------------------------------------------------------------------------
# Azure OpenAI — URL construction
# ---------------------------------------------------------------------------


def test_azure_url_construction():
    p = AzureOpenAIProvider({
        "endpoint": "https://my-resource.openai.azure.com",
        "deployment": "gpt-4o",
        "api_version": "2024-08-01-preview",
        "api_key": "test-key",
    })
    url = p._chat_url()
    assert url == (
        "https://my-resource.openai.azure.com"
        "/openai/deployments/gpt-4o"
        "/chat/completions?api-version=2024-08-01-preview"
    )


def test_azure_url_strips_trailing_slash():
    p = AzureOpenAIProvider({
        "endpoint": "https://my-resource.openai.azure.com/",
        "deployment": "gpt-4o-mini",
        "api_version": "2024-06-01",
        "api_key": "key",
    })
    url = p._chat_url()
    assert "azure.com/" not in url.split("/openai")[0]
    assert "/openai/deployments/gpt-4o-mini/chat/completions" in url


def test_azure_default_api_version():
    """No api_version in config → default applied."""
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "gpt-4o",
        "api_key": "key",
    })
    assert "2024-08-01-preview" in p._chat_url()


# ---------------------------------------------------------------------------
# Azure OpenAI — auth header
# ---------------------------------------------------------------------------


def test_azure_uses_api_key_header():
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "d1",
        "api_key": "my-secret-key",
    })
    hdrs = p._auth_headers()
    assert hdrs.get("api-key") == "my-secret-key"
    assert "Authorization" not in hdrs


def test_azure_no_bearer_in_headers():
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "d1",
        "api_key": "sk-abc",
    })
    hdrs = p._auth_headers()
    assert not any("Bearer" in str(v) for v in hdrs.values())


# ---------------------------------------------------------------------------
# Azure OpenAI — chat round-trip (mocked)
# ---------------------------------------------------------------------------


def test_azure_chat_success():
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "gpt-4o",
        "api_key": "key",
    })
    mock_resp = _http_response(200, _ok_response("pong"))
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(_messages()))

    assert result.stop_reason != "error"
    assert result.text == "pong"


def test_azure_401_returns_error():
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "gpt-4o",
        "api_key": "bad-key",
    })
    mock_resp = _http_response(401, {"error": {"message": "Access denied"}})
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "401" in result.text


def test_azure_403_returns_error():
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "gpt-4o",
        "api_key": "key",
    })
    mock_resp = _http_response(403, {"error": {"message": "Forbidden"}})
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "403" in result.text


def test_azure_5xx_returns_error():
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "gpt-4o",
        "api_key": "key",
    })
    mock_resp = _http_response(503, "Service Unavailable")
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "503" in result.text


def test_azure_missing_endpoint_returns_error():
    p = AzureOpenAIProvider({"deployment": "gpt-4o", "api_key": "key"})
    result = _run(p.chat(_messages()))
    assert result.stop_reason == "error"
    assert "endpoint" in result.text.lower()


def test_azure_missing_deployment_returns_error():
    p = AzureOpenAIProvider({"endpoint": "https://x.openai.azure.com", "api_key": "key"})
    result = _run(p.chat(_messages()))
    assert result.stop_reason == "error"
    assert "deployment" in result.text.lower()


def test_azure_tool_calls_parsed():
    tool_payload = [
        {
            "id": "call_abc",
            "type": "function",
            "function": {"name": "run_scan", "arguments": '{"target": "10.0.0.1"}'},
        }
    ]
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "gpt-4o",
        "api_key": "key",
    })
    mock_resp = _http_response(200, _ok_response("", tool_calls=tool_payload))
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(
            _messages(),
            tools=[ToolSpec(name="run_scan", description="scan", input_schema={})],
        ))

    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "run_scan"
    assert result.tool_calls[0].arguments == {"target": "10.0.0.1"}


# ---------------------------------------------------------------------------
# Azure — create_provider factory
# ---------------------------------------------------------------------------


def test_create_provider_azure_openai():
    p = create_provider("azure_openai", {"endpoint": "https://x.openai.azure.com", "deployment": "gpt-4o"})
    assert isinstance(p, AzureOpenAIProvider)


def test_create_provider_azure_alias():
    p = create_provider("azure", {"endpoint": "https://x.openai.azure.com", "deployment": "gpt-4o"})
    assert isinstance(p, AzureOpenAIProvider)


# ---------------------------------------------------------------------------
# llama.cpp — URL construction
# ---------------------------------------------------------------------------


def test_llamacpp_default_url():
    p = LlamaCppProvider({})
    assert p._chat_url() == "http://127.0.0.1:8080/v1/chat/completions"


def test_llamacpp_custom_host_port():
    p = LlamaCppProvider({"host": "192.168.1.10", "port": 9000})
    assert p._chat_url() == "http://192.168.1.10:9000/v1/chat/completions"


def test_llamacpp_port_as_string():
    """Config may arrive as a string from YAML."""
    p = LlamaCppProvider({"host": "localhost", "port": "8081"})
    assert ":8081" in p._chat_url()


# ---------------------------------------------------------------------------
# llama.cpp — auth header
# ---------------------------------------------------------------------------


def test_llamacpp_no_key_no_auth_header():
    p = LlamaCppProvider({})
    hdrs = p._auth_headers()
    assert "Authorization" not in hdrs


def test_llamacpp_with_key_sets_bearer():
    p = LlamaCppProvider({"api_key": "my-token"})
    hdrs = p._auth_headers()
    assert hdrs.get("Authorization") == "Bearer my-token"


# ---------------------------------------------------------------------------
# llama.cpp — chat round-trip (mocked)
# ---------------------------------------------------------------------------


def test_llamacpp_chat_success():
    p = LlamaCppProvider({"host": "127.0.0.1", "port": 8080})
    mock_resp = _http_response(200, _ok_response("pong"))
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(_messages()))

    assert result.stop_reason != "error"
    assert result.text == "pong"


def test_llamacpp_401_returns_error():
    p = LlamaCppProvider({"api_key": "wrong"})
    mock_resp = _http_response(401, {"error": "Unauthorized"})
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "401" in result.text


def test_llamacpp_501_tool_call_error():
    """501 from llama.cpp = tool calls not supported by this build."""
    p = LlamaCppProvider({})
    mock_resp = _http_response(501, "Not Implemented")
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(
            _messages(),
            tools=[ToolSpec(name="test", description="test", input_schema={})],
        ))

    assert result.stop_reason == "error"
    assert "501" in result.text or "Not Implemented" in result.text


def test_llamacpp_5xx_returns_error():
    p = LlamaCppProvider({})
    mock_resp = _http_response(500, "Internal Server Error")
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "500" in result.text


def test_llamacpp_connect_error_returns_error():
    """ConnectError → clean message mentioning how to start the server."""
    p = LlamaCppProvider({"host": "127.0.0.1", "port": 8080})
    with patch(
        "httpx.AsyncClient",
        return_value=_mock_client(post_side_effect=httpx.ConnectError("Connection refused")),
    ):
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "unreachable" in result.text.lower() or "llama.cpp" in result.text.lower()


def test_llamacpp_tool_calls_parsed():
    tool_payload = [
        {
            "id": "call_xyz",
            "type": "function",
            "function": {"name": "nmap_scan", "arguments": '{"host": "192.168.1.1"}'},
        }
    ]
    p = LlamaCppProvider({})
    mock_resp = _http_response(200, _ok_response("", tool_calls=tool_payload))
    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        result = _run(p.chat(
            _messages(),
            tools=[ToolSpec(name="nmap_scan", description="scan", input_schema={})],
        ))

    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "nmap_scan"
    assert result.tool_calls[0].arguments == {"host": "192.168.1.1"}


# ---------------------------------------------------------------------------
# llama.cpp — create_provider factory
# ---------------------------------------------------------------------------


def test_create_provider_llamacpp():
    p = create_provider("llamacpp", {})
    assert isinstance(p, LlamaCppProvider)


def test_create_provider_llama_cpp_alias():
    p = create_provider("llama_cpp", {})
    assert isinstance(p, LlamaCppProvider)


def test_create_provider_llama_cpp_dot_alias():
    p = create_provider("llama.cpp", {})
    assert isinstance(p, LlamaCppProvider)


# ---------------------------------------------------------------------------
# Provider contract — get_model
# ---------------------------------------------------------------------------


def test_azure_get_model_falls_back_to_deployment():
    p = AzureOpenAIProvider({"endpoint": "https://x.openai.azure.com", "deployment": "gpt-4o"})
    assert p.get_model() == "gpt-4o"


def test_azure_get_model_prefers_explicit_model():
    p = AzureOpenAIProvider({
        "endpoint": "https://x.openai.azure.com",
        "deployment": "my-deploy",
        "model": "gpt-4.1",
    })
    assert p.get_model() == "gpt-4.1"


def test_llamacpp_get_model_empty_by_default():
    p = LlamaCppProvider({})
    assert p.get_model() == ""


def test_llamacpp_get_model_from_config():
    p = LlamaCppProvider({"model": "llama-3.1-8b-q4"})
    assert p.get_model() == "llama-3.1-8b-q4"
