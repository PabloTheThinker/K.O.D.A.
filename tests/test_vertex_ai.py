"""Tests for the Vertex AI adapter.

All network calls are mocked — no real GCP endpoints are contacted.
google.auth is mocked by patching ``koda.adapters.vertex_ai._try_adc_token``
directly (cleaner than fighting sys.modules namespace packing).  The
google-auth-absent path is covered via monkeypatch on the import itself.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from koda.adapters import create_provider
from koda.adapters.base import Message, Role, ToolSpec
from koda.adapters.vertex_ai import VertexAIProvider, _build_endpoint

# ---------------------------------------------------------------------------
# Helpers (mirrored from test_adapters_new.py style)
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


def _gemini_ok_response(
    text: str = "pong",
    tool_calls: list[dict] | None = None,
    finish_reason: str = "STOP",
) -> dict[str, Any]:
    """Minimal Vertex/Gemini-shape success payload."""
    parts: list[dict] = []
    if text:
        parts.append({"text": text})
    for tc in tool_calls or []:
        parts.append({"functionCall": {"name": tc["name"], "args": tc.get("args", {})}})
    return {
        "candidates": [
            {
                "content": {"role": "model", "parts": parts},
                "finishReason": finish_reason,
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 5,
            "totalTokenCount": 15,
        },
    }


def _http_response(status: int, body: dict | str = "") -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    if isinstance(body, dict):
        resp.json.return_value = body
        resp.text = json.dumps(body)
    else:
        resp.json.side_effect = ValueError("not json")
        resp.text = body
    return resp


def _messages(content: str = "ping") -> list[Message]:
    return [Message(role=Role.USER, content=content)]


def _mock_client(post_return=None, post_side_effect=None):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    if post_side_effect is not None:
        mock_client.post = AsyncMock(side_effect=post_side_effect)
    else:
        mock_client.post = AsyncMock(return_value=post_return)
    return mock_client


def _patch_adc(token: str = "fake-adc-token"):
    """Patch _try_adc_token to return a fixed token string."""
    return patch("koda.adapters.vertex_ai._try_adc_token", return_value=token)


# ---------------------------------------------------------------------------
# Endpoint construction
# ---------------------------------------------------------------------------


def test_build_endpoint_structure():
    url = _build_endpoint("my-proj", "us-central1", "gemini-1.5-pro-002")
    assert "us-central1-aiplatform.googleapis.com" in url
    assert "/projects/my-proj/" in url
    assert "/locations/us-central1/" in url
    assert "/publishers/google/models/gemini-1.5-pro-002:generateContent" in url


def test_build_endpoint_custom_location():
    url = _build_endpoint("proj", "europe-west4", "gemini-1.5-flash-002")
    assert url.startswith("https://europe-west4-aiplatform.googleapis.com")
    assert "gemini-1.5-flash-002:generateContent" in url


def test_default_model_and_location():
    p = VertexAIProvider({"project": "my-proj"})
    assert p.get_model() == "gemini-1.5-pro-002"
    assert p._location == "us-central1"


def test_model_override():
    p = VertexAIProvider({"project": "p", "model": "gemini-2.0-flash-001"})
    assert p.get_model() == "gemini-2.0-flash-001"


def test_location_override():
    p = VertexAIProvider({"project": "p", "location": "europe-west4"})
    assert p._location == "europe-west4"


# ---------------------------------------------------------------------------
# Missing project — early error (no auth needed)
# ---------------------------------------------------------------------------


def test_missing_project_returns_error():
    p = VertexAIProvider({})
    result = _run(p.chat(_messages()))
    assert result.stop_reason == "error"
    assert "project" in result.text.lower()


# ---------------------------------------------------------------------------
# Auth: ADC path (google-auth available — patched at function level)
# ---------------------------------------------------------------------------


def test_adc_path_success():
    """ADC credentials flow end-to-end with mocked httpx."""
    resp_body = _gemini_ok_response("hello from vertex")
    mock_resp = _http_response(200, resp_body)

    with (
        _patch_adc("adc-token-xyz"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "my-proj"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason != "error"
    assert result.text == "hello from vertex"


def test_adc_bearer_header_sent():
    """Verify the Bearer token lands in the Authorization header."""
    resp_body = _gemini_ok_response("ok")
    mock_resp = _http_response(200, resp_body)
    captured_headers: dict = {}

    async def _capture_post(url, content, headers):
        captured_headers.update(headers)
        return mock_resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = _capture_post

    with (
        _patch_adc("tok-abc123"),
        patch("httpx.AsyncClient", return_value=mock_client),
    ):
        p = VertexAIProvider({"project": "proj"})
        _run(p.chat(_messages()))

    assert captured_headers.get("Authorization") == "Bearer tok-abc123"
    assert "key" not in str(captured_headers)  # no ?key= leaked as query param


# ---------------------------------------------------------------------------
# Auth: explicit token path
# ---------------------------------------------------------------------------


def test_explicit_token_used_when_google_auth_absent(monkeypatch):
    """When google-auth raises ImportError, explicit access_token is used."""
    monkeypatch.setattr(
        "koda.adapters.vertex_ai._try_adc_token",
        lambda: (_ for _ in ()).throw(ImportError("no google-auth")),
    )

    resp_body = _gemini_ok_response("explicit-token-response")
    mock_resp = _http_response(200, resp_body)

    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        p = VertexAIProvider({"project": "proj", "access_token": "my-explicit-token"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason != "error"
    assert result.text == "explicit-token-response"


def test_no_auth_at_all_returns_error(monkeypatch):
    """Neither ADC nor explicit token → clear error message, no network call."""
    monkeypatch.setattr(
        "koda.adapters.vertex_ai._try_adc_token",
        lambda: (_ for _ in ()).throw(ImportError("no google-auth")),
    )

    p = VertexAIProvider({"project": "proj"})
    result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "google-auth" in result.text or "access_token" in result.text


def test_adc_exception_falls_back_to_explicit_token(monkeypatch):
    """If ADC is installed but fails (e.g. not configured), explicit token is used."""

    def _bad_adc():
        raise RuntimeError("ADC not configured")

    monkeypatch.setattr("koda.adapters.vertex_ai._try_adc_token", _bad_adc)

    resp_body = _gemini_ok_response("fallback-response")
    mock_resp = _http_response(200, resp_body)

    with patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)):
        p = VertexAIProvider({"project": "proj", "access_token": "fallback-token"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason != "error"
    assert result.text == "fallback-response"


# ---------------------------------------------------------------------------
# HTTP error surfaces
# ---------------------------------------------------------------------------


def test_401_returns_clear_error():
    mock_resp = _http_response(401, {"error": {"message": "Request had invalid authentication"}})

    with (
        _patch_adc("token"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "proj"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "401" in result.text
    # Should hint at token refresh
    assert "token" in result.text.lower() or "gcloud" in result.text.lower()


def test_403_returns_clear_error():
    mock_resp = _http_response(403, {"error": {"message": "Permission denied"}})

    with (
        _patch_adc("token"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "proj"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "403" in result.text
    assert (
        "iam" in result.text.lower()
        or "permission" in result.text.lower()
        or "access" in result.text.lower()
    )


def test_404_includes_model_and_project_hint():
    mock_resp = _http_response(404, {"error": {"message": "Model not found"}})

    with (
        _patch_adc("token"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "proj", "model": "gemini-bad-model"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "404" in result.text
    assert "gemini-bad-model" in result.text
    assert "proj" in result.text


def test_5xx_returns_server_error():
    mock_resp = _http_response(503, "Service Unavailable")

    with (
        _patch_adc("token"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "proj"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "503" in result.text


def test_transport_error_returns_error():
    with (
        _patch_adc("token"),
        patch(
            "httpx.AsyncClient",
            return_value=_mock_client(
                post_side_effect=httpx.ConnectError("Connection refused")
            ),
        ),
    ):
        p = VertexAIProvider({"project": "proj"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "transport" in result.text.lower() or "vertex_ai" in result.text.lower()


# ---------------------------------------------------------------------------
# Tool call emission and parsing
# ---------------------------------------------------------------------------


def test_tool_calls_parsed():
    resp_body = _gemini_ok_response(
        text="",
        tool_calls=[{"name": "run_nmap", "args": {"host": "10.0.0.1", "ports": "80,443"}}],
        finish_reason="FUNCTION_CALL",
    )
    mock_resp = _http_response(200, resp_body)

    with (
        _patch_adc("token"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "proj"})
        result = _run(p.chat(
            _messages(),
            tools=[ToolSpec(name="run_nmap", description="nmap scan", input_schema={})],
        ))

    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    assert tc.name == "run_nmap"
    assert tc.arguments == {"host": "10.0.0.1", "ports": "80,443"}
    # Synthesised id must be stable and non-empty
    assert tc.id.startswith("g-")
    assert len(tc.id) > 3


def test_tool_call_id_stable():
    """Same name+args always produce the same synthetic id."""
    resp_body = _gemini_ok_response(
        text="",
        tool_calls=[{"name": "scan", "args": {"target": "192.168.1.1"}}],
    )

    def _single_call():
        mock_resp = _http_response(200, resp_body)
        with (
            _patch_adc("token"),
            patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
        ):
            p = VertexAIProvider({"project": "proj"})
            return _run(p.chat(_messages()))

    r1 = _single_call()
    r2 = _single_call()
    assert r1.tool_calls[0].id == r2.tool_calls[0].id


# ---------------------------------------------------------------------------
# Token/usage extraction
# ---------------------------------------------------------------------------


def test_usage_extracted():
    resp_body = _gemini_ok_response("hi")
    resp_body["usageMetadata"] = {
        "promptTokenCount": 42,
        "candidatesTokenCount": 17,
        "totalTokenCount": 59,
    }
    mock_resp = _http_response(200, resp_body)

    with (
        _patch_adc("token"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "proj"})
        result = _run(p.chat(_messages()))

    assert result.usage["prompt_tokens"] == 42
    assert result.usage["completion_tokens"] == 17
    assert result.usage["total_tokens"] == 59


# ---------------------------------------------------------------------------
# Registry / factory
# ---------------------------------------------------------------------------


def test_create_provider_vertex_ai():
    p = create_provider("vertex_ai", {"project": "p"})
    assert isinstance(p, VertexAIProvider)


def test_create_provider_vertex_alias():
    p = create_provider("vertex", {"project": "p"})
    assert isinstance(p, VertexAIProvider)


def test_supports_tools_flag():
    p = VertexAIProvider({"project": "p"})
    assert p.supports_tools is True


# ---------------------------------------------------------------------------
# No-candidates / blocked response
# ---------------------------------------------------------------------------


def test_no_candidates_returns_error():
    resp_body: dict = {
        "candidates": [],
        "promptFeedback": {"blockReason": "SAFETY"},
    }
    mock_resp = _http_response(200, resp_body)

    with (
        _patch_adc("token"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "proj"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "SAFETY" in result.text or "block" in result.text.lower()


def test_non_json_response_returns_error():
    mock_resp = _http_response(200, "not-json-at-all")

    with (
        _patch_adc("token"),
        patch("httpx.AsyncClient", return_value=_mock_client(post_return=mock_resp)),
    ):
        p = VertexAIProvider({"project": "proj"})
        result = _run(p.chat(_messages()))

    assert result.stop_reason == "error"
    assert "non-JSON" in result.text or "json" in result.text.lower()
