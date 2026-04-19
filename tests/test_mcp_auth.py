"""Tests for MCP SSE bearer-token authentication and config management.

Run with:
    env -u PYTHONHASHSEED pytest tests/test_mcp_auth.py -v
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import stat
import tomllib
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_home(tmp_path):
    """A temporary KODA_HOME directory, isolated per test."""
    return tmp_path / "koda_home"


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Ensure KODA_MCP_TOKEN and KODA_MCP_NO_AUDIT don't leak between tests."""
    monkeypatch.delenv("KODA_MCP_TOKEN", raising=False)
    monkeypatch.delenv("KODA_MCP_NO_AUDIT", raising=False)


# ---------------------------------------------------------------------------
# koda.mcp.auth — unit tests
# ---------------------------------------------------------------------------


class TestVerifyBearer:
    """verify_bearer — constant-time comparison of Authorization header."""

    def test_correct_token_returns_true(self):
        from koda.mcp.auth import verify_bearer
        assert verify_bearer("Bearer secret123", "secret123") is True

    def test_wrong_token_returns_false(self):
        from koda.mcp.auth import verify_bearer
        assert verify_bearer("Bearer wrongtoken", "secret123") is False

    def test_missing_header_returns_false(self):
        from koda.mcp.auth import verify_bearer
        assert verify_bearer(None, "secret123") is False

    def test_empty_string_returns_false(self):
        from koda.mcp.auth import verify_bearer
        assert verify_bearer("", "secret123") is False

    def test_bearer_prefix_case_insensitive_lower(self):
        """RFC 6750: 'bearer' prefix is case-insensitive."""
        from koda.mcp.auth import verify_bearer
        assert verify_bearer("bearer mytoken", "mytoken") is True

    def test_bearer_prefix_case_insensitive_mixed(self):
        from koda.mcp.auth import verify_bearer
        assert verify_bearer("BEARER mytoken", "mytoken") is True

    def test_bearer_prefix_case_insensitive_title(self):
        from koda.mcp.auth import verify_bearer
        assert verify_bearer("Bearer mytoken", "mytoken") is True

    def test_malformed_header_no_space(self):
        from koda.mcp.auth import verify_bearer
        assert verify_bearer("Bearertoken", "token") is False

    def test_uses_hmac_compare_digest(self):
        """Smoke-test: hmac.compare_digest is called during verification."""
        from koda.mcp.auth import verify_bearer
        with patch("hmac.compare_digest", wraps=hmac.compare_digest) as mock_cd:
            verify_bearer("Bearer tok", "tok")
        mock_cd.assert_called_once()

    def test_compare_digest_called_with_bytes(self):
        """verify_bearer must pass bytes (not str) to compare_digest."""
        from koda.mcp.auth import verify_bearer
        seen_args = []

        def capturing_compare(a, b):
            seen_args.extend([a, b])
            return hmac.compare_digest(a, b)

        with patch("hmac.compare_digest", side_effect=capturing_compare):
            verify_bearer("Bearer abc", "abc")

        assert all(isinstance(a, bytes) for a in seen_args), (
            "compare_digest must receive bytes arguments"
        )


class TestTokenFingerprint:
    def test_returns_8_hex_chars(self):
        from koda.mcp.auth import _token_fingerprint
        fp = _token_fingerprint("sometoken")
        assert len(fp) == 8
        assert all(c in "0123456789abcdef" for c in fp)

    def test_consistent_with_sha256(self):
        from koda.mcp.auth import _token_fingerprint
        token = "testtoken"
        expected = hashlib.sha256(token.encode()).hexdigest()[:8]
        assert _token_fingerprint(token) == expected


class TestLoadMcpConfig:
    def test_returns_empty_dict_when_missing(self, tmp_home):
        from koda.mcp.auth import load_mcp_config
        result = load_mcp_config(tmp_home)
        assert result == {}

    def test_reads_existing_toml(self, tmp_home):
        from koda.mcp.auth import load_mcp_config
        tmp_home.mkdir(parents=True)
        (tmp_home / "mcp.toml").write_text(
            '[auth]\nbearer_token = "abc123"\n', encoding="utf-8"
        )
        cfg = load_mcp_config(tmp_home)
        assert cfg["auth"]["bearer_token"] == "abc123"


class TestEnsureBearerToken:
    def test_env_var_takes_priority(self, tmp_home, monkeypatch):
        from koda.mcp.auth import ensure_bearer_token
        monkeypatch.setenv("KODA_MCP_TOKEN", "env_token_xyz")
        token = ensure_bearer_token(tmp_home)
        assert token == "env_token_xyz"
        # Should NOT create a config file (env takes priority, no need to persist)
        assert not (tmp_home / "mcp.toml").exists()

    def test_reads_existing_toml_token(self, tmp_home):
        from koda.mcp.auth import ensure_bearer_token
        tmp_home.mkdir(parents=True)
        (tmp_home / "mcp.toml").write_text(
            '[auth]\nbearer_token = "stored_tok"\n', encoding="utf-8"
        )
        os.chmod(tmp_home / "mcp.toml", 0o600)
        token = ensure_bearer_token(tmp_home)
        assert token == "stored_tok"

    def test_auto_generates_and_persists(self, tmp_home, capsys):
        from koda.mcp.auth import ensure_bearer_token
        token = ensure_bearer_token(tmp_home)
        assert len(token) > 20  # secrets.token_urlsafe(32) is ~43 chars

        # Verify it was written to disk
        cfg_path = tmp_home / "mcp.toml"
        assert cfg_path.exists()
        cfg = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
        assert cfg["auth"]["bearer_token"] == token

    def test_auto_generated_file_has_0600_perms(self, tmp_home):
        from koda.mcp.auth import ensure_bearer_token
        ensure_bearer_token(tmp_home)
        cfg_path = tmp_home / "mcp.toml"
        file_stat = cfg_path.stat()
        # Check owner read/write only (0o600)
        perms = stat.S_IMODE(file_stat.st_mode)
        assert perms == 0o600, f"expected 0600, got {oct(perms)}"

    def test_auto_generated_token_printed_once(self, tmp_home, capsys):
        from koda.mcp.auth import ensure_bearer_token
        token = ensure_bearer_token(tmp_home)
        captured = capsys.readouterr()
        assert token in captured.err, "generated token must be printed to stderr"

    def test_idempotent_returns_same_token(self, tmp_home, capsys):
        from koda.mcp.auth import ensure_bearer_token
        token1 = ensure_bearer_token(tmp_home)
        token2 = ensure_bearer_token(tmp_home)
        assert token1 == token2, "second call must return the same persisted token"

    def test_second_call_does_not_reprint(self, tmp_home, capsys):
        from koda.mcp.auth import ensure_bearer_token
        token = ensure_bearer_token(tmp_home)
        _ = capsys.readouterr()  # consume first print
        ensure_bearer_token(tmp_home)
        second_out = capsys.readouterr()
        assert token not in second_out.err, "token must not be printed on second call"


# ---------------------------------------------------------------------------
# Bearer middleware — integration via a minimal Starlette app
# ---------------------------------------------------------------------------


def _make_test_app(token: str):
    """Build a minimal Starlette app wrapped with bearer middleware, for testing."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from koda.mcp.server import _make_bearer_middleware

    async def homepage(request):
        return PlainTextResponse("ok")

    inner_app = Starlette(routes=[Route("/sse", homepage), Route("/", homepage)])
    protected_app = _make_bearer_middleware(inner_app, token)
    client = TestClient(protected_app, raise_server_exceptions=False)
    return client


class TestBearerMiddleware:
    TOKEN = "test-token-abc123"

    def test_missing_header_returns_401(self):
        client = _make_test_app(self.TOKEN)
        resp = client.get("/sse")
        assert resp.status_code == 401

    def test_wrong_token_returns_401(self):
        client = _make_test_app(self.TOKEN)
        resp = client.get("/sse", headers={"Authorization": "Bearer wrongtoken"})
        assert resp.status_code == 401

    def test_correct_token_returns_200(self):
        client = _make_test_app(self.TOKEN)
        resp = client.get("/sse", headers={"Authorization": f"Bearer {self.TOKEN}"})
        assert resp.status_code == 200

    def test_401_body_never_echoes_sent_token(self):
        client = _make_test_app(self.TOKEN)
        sent = "leaked_secret_token"
        resp = client.get("/sse", headers={"Authorization": f"Bearer {sent}"})
        assert resp.status_code == 401
        assert sent not in resp.text

    def test_401_body_is_generic(self):
        client = _make_test_app(self.TOKEN)
        resp = client.get("/sse")
        assert "unauthorized" in resp.text.lower()

    def test_missing_header_emits_denied_audit(self, monkeypatch):
        emitted = []
        monkeypatch.setattr(
            "koda.mcp.auth.emit_auth_event",
            lambda event, **fields: emitted.append((event, fields)),
        )
        client = _make_test_app(self.TOKEN)
        client.get("/sse")
        assert any(e == "mcp.auth.denied" for e, _ in emitted)
        denied = [f for e, f in emitted if e == "mcp.auth.denied"]
        assert denied[0]["reason"] == "missing Authorization header"

    def test_wrong_token_emits_denied_audit(self, monkeypatch):
        emitted = []
        monkeypatch.setattr(
            "koda.mcp.auth.emit_auth_event",
            lambda event, **fields: emitted.append((event, fields)),
        )
        client = _make_test_app(self.TOKEN)
        client.get("/sse", headers={"Authorization": "Bearer wrongtoken"})
        assert any(e == "mcp.auth.denied" for e, _ in emitted)

    def test_correct_token_emits_ok_audit(self, monkeypatch):
        emitted = []
        monkeypatch.setattr(
            "koda.mcp.auth.emit_auth_event",
            lambda event, **fields: emitted.append((event, fields)),
        )
        client = _make_test_app(self.TOKEN)
        client.get("/sse", headers={"Authorization": f"Bearer {self.TOKEN}"})
        assert any(e == "mcp.auth.ok" for e, _ in emitted)

    def test_ok_audit_includes_fingerprint(self, monkeypatch):
        emitted = []
        monkeypatch.setattr(
            "koda.mcp.auth.emit_auth_event",
            lambda event, **fields: emitted.append((event, fields)),
        )
        client = _make_test_app(self.TOKEN)
        client.get("/sse", headers={"Authorization": f"Bearer {self.TOKEN}"})
        ok_events = [f for e, f in emitted if e == "mcp.auth.ok"]
        assert ok_events, "no mcp.auth.ok event emitted"
        fp = ok_events[0].get("token_fingerprint", "")
        assert len(fp) == 8
        expected = hashlib.sha256(self.TOKEN.encode()).hexdigest()[:8]
        assert fp == expected


# ---------------------------------------------------------------------------
# CLI validation — no-auth + host binding
# ---------------------------------------------------------------------------


class TestCLINoAuth:
    def test_no_auth_with_non_loopback_refuses(self):
        """--no-auth + --host 0.0.0.0 must exit non-zero with a clear message."""
        from koda.mcp.server import main as mcp_main
        rc = mcp_main(["--transport", "sse", "--no-auth", "--host", "0.0.0.0"])
        assert rc != 0

    def test_no_auth_with_loopback_is_accepted(self, tmp_home, monkeypatch):
        """--no-auth + --host 127.0.0.1 must not be refused (rc == 0, no error output)."""
        monkeypatch.setenv("KODA_HOME", str(tmp_home))

        # The test only verifies that main() does not return 1 (the refusal exit code).
        # We intercept asyncio.run so no server actually starts.
        rc = mcp_main_wrapper(["--transport", "sse", "--no-auth", "--host", "127.0.0.1"])
        # rc should be 0 — the loopback check passed; the server would have started
        assert rc == 0


def mcp_main_wrapper(argv):
    """Call mcp_main but patch asyncio.run to avoid real server start."""
    from koda.mcp import server as mcp_server

    def fake_asyncio_run(coro, **kwargs):
        # Close the coroutine to avoid RuntimeWarning
        coro.close()
        return None

    orig = asyncio.run
    try:
        asyncio.run = fake_asyncio_run
        rc = mcp_server.main(argv)
    finally:
        asyncio.run = orig
    return rc


class TestClientCaValidation:
    def test_client_ca_without_cert_key_errors(self):
        """--client-ca without --tls-cert/--tls-key must fail cleanly."""
        from koda.mcp.server import _build_ssl_context
        with pytest.raises(SystemExit) as exc_info:
            _build_ssl_context(None, None, "/fake/ca.pem")
        assert exc_info.value.code == 1

    def test_tls_cert_without_key_errors(self):
        from koda.mcp.server import _build_ssl_context
        with pytest.raises(SystemExit) as exc_info:
            _build_ssl_context("/fake/cert.pem", None, None)
        assert exc_info.value.code == 1

    def test_no_tls_returns_none(self):
        from koda.mcp.server import _build_ssl_context
        result = _build_ssl_context(None, None, None)
        assert result is None
