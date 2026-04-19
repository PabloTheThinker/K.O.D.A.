"""Expose every K.O.D.A. tool over Model Context Protocol.

Any MCP-capable client — Claude Code, Cursor, other agents — can connect and
call K.O.D.A.'s security tools. Tools keep their risk metadata in the
description so remote callers know what they're invoking.

Usage:
    koda mcp                               # stdio transport (default, for Claude Code)
    koda mcp --transport sse               # SSE, auto-generates bearer token
    koda mcp --transport sse --no-auth --host 127.0.0.1   # local-dev, no auth

    # TLS (server-only):
    koda mcp --transport sse --tls-cert server.pem --tls-key server.key

    # mTLS (client cert required):
    koda mcp --transport sse --tls-cert server.pem --tls-key server.key \\
             --client-ca ca-bundle.pem

Claude Code / similar MCP host config snippet (stdio):
    {
      "mcpServers": {
        "koda": { "command": "koda", "args": ["mcp"] }
      }
    }
"""
from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
from pathlib import Path
from typing import Any

from ..tools import builtins as _builtins  # triggers tool registration
from ..tools.registry import Tool, global_registry

_ = _builtins

# Loopback addresses that are acceptable for --no-auth
_LOOPBACK_ADDRS = frozenset({"127.0.0.1", "::1", "localhost"})


def _ensure_mcp():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # noqa: BLE001
        print(
            "koda mcp requires the optional 'mcp' extra. Install with:\n"
            "  pip install 'koda[mcp]'\n"
            "or\n"
            "  pip install mcp",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    return FastMCP


def _mcp_tool_name(koda_name: str) -> str:
    """MCP tool names cannot contain dots; mirror the Anthropic sanitizer."""
    return koda_name.replace(".", "_")


def _describe_tool(tool: Tool) -> str:
    lines = [tool.description]
    schema = tool.input_schema or {}
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    if props:
        lines.append("")
        lines.append("Parameters:")
        for name, spec in props.items():
            req = " (required)" if name in required else ""
            desc = spec.get("description", "")
            lines.append(f"- {name}: {desc}{req}")
    lines.append("")
    lines.append(f"Risk: {tool.risk.value}   Category: {tool.category}")
    return "\n".join(lines)


def _bind_tool(mcp, tool: Tool) -> None:
    registry = global_registry()
    captured_name = tool.name

    async def handler(**kwargs: Any) -> str:
        result = await registry.invoke(captured_name, kwargs)
        payload: dict[str, Any] = {
            "content": result.content,
            "is_error": result.is_error,
        }
        if result.metadata:
            payload["metadata"] = result.metadata
        return json.dumps(payload, default=str)

    mcp.add_tool(
        handler,
        name=_mcp_tool_name(tool.name),
        description=_describe_tool(tool),
    )


def create_mcp_server():
    FastMCP = _ensure_mcp()
    mcp = FastMCP(
        "koda",
        instructions=(
            "K.O.D.A. — Kinetic Operative Defense Agent. Security specialist tools "
            "grouped by category: fs (filesystem), scan (orchestrated scanners), "
            "net (port/SSL/HTTP/DNS), host (auth log, file integrity, dep CVE). "
            "Every tool has a risk level. The scan.* and security.findings tools "
            "share a findings store; call security.findings after running scans to "
            "query without re-scanning. Do NOT invent CVEs, paths, or line numbers — "
            "quote only what the tool results contain."
        ),
    )

    registry = global_registry()
    for name in registry.names():
        tool = registry.get(name)
        if tool is None:
            continue
        _bind_tool(mcp, tool)
    return mcp


async def run_stdio() -> None:
    server = create_mcp_server()
    await server.run_stdio_async()


# ---------------------------------------------------------------------------
# SSE bearer-auth middleware
# ---------------------------------------------------------------------------

def _make_bearer_middleware(app, token: str):
    """Wrap a Starlette app with bearer-token authentication.

    Every request must carry ``Authorization: Bearer <token>``.
    Failures emit ``mcp.auth.denied``; successes emit ``mcp.auth.ok``.
    """
    from starlette.requests import Request
    from starlette.responses import Response

    from .auth import _token_fingerprint, emit_auth_event, verify_bearer

    async def middleware(scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await app(scope, receive, send)
            return

        request = Request(scope)
        remote_addr = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (scope.get("client") or ("unknown", 0))[0]
        )
        path = scope.get("path", "")
        auth_header = request.headers.get("authorization")

        if verify_bearer(auth_header, token):
            emit_auth_event(
                "mcp.auth.ok",
                remote_addr=remote_addr,
                path=path,
                token_fingerprint=_token_fingerprint(token),
            )
            await app(scope, receive, send)
            return

        # Determine a safe reason string — never echo back what was sent
        if not auth_header:
            reason = "missing Authorization header"
        elif not auth_header.lower().startswith("bearer "):
            reason = "malformed Authorization header"
        else:
            reason = "invalid token"

        emit_auth_event(
            "mcp.auth.denied",
            remote_addr=remote_addr,
            path=path,
            reason=reason,
        )

        body = b'{"error":"unauthorized"}'
        response = Response(
            content=body,
            status_code=401,
            media_type="application/json",
            headers={"www-authenticate": "Bearer realm=\"koda-mcp\""},
        )
        await response(scope, receive, send)

    return middleware


# ---------------------------------------------------------------------------
# SSL context builder (no 'cryptography' dep — stdlib ssl only)
# ---------------------------------------------------------------------------

def _build_ssl_context(
    tls_cert: str | None,
    tls_key: str | None,
    client_ca: str | None,
) -> ssl.SSLContext | None:
    """Return an ssl.SSLContext for uvicorn, or None if TLS is not requested.

    Raises SystemExit with a clear message on misconfiguration.
    """
    if not tls_cert and not tls_key and not client_ca:
        return None

    if client_ca and not (tls_cert and tls_key):
        print(
            "error: --client-ca requires both --tls-cert and --tls-key to be set.\n"
            "       You must provide a server certificate when enabling mTLS.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    if not tls_cert or not tls_key:
        print(
            "error: both --tls-cert and --tls-key must be provided together.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
    except (ssl.SSLError, OSError) as exc:
        print(f"error: could not load TLS cert/key: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if client_ca:
        try:
            ctx.load_verify_locations(cafile=client_ca)
        except (ssl.SSLError, OSError) as exc:
            print(f"error: could not load client CA bundle: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        ctx.verify_mode = ssl.CERT_REQUIRED

    return ctx


# ---------------------------------------------------------------------------
# SSE runner
# ---------------------------------------------------------------------------

async def run_sse(
    host: str = "127.0.0.1",
    port: int = 7655,
    *,
    no_auth: bool = False,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    client_ca: str | None = None,
) -> None:
    """Start the MCP SSE server with optional bearer auth and TLS.

    When *no_auth* is True the caller must have already verified that
    *host* is loopback-only (enforced in main()).
    """
    import uvicorn

    from ..config import KODA_HOME

    server = create_mcp_server()

    # Resolve the underlying Starlette app from FastMCP
    # FastMCP exposes .app (or similar); fall back to running via its own async helper
    # if we can't get the raw app.  We prefer direct uvicorn so we can inject middleware.
    starlette_app = getattr(server, "app", None) or getattr(server, "_app", None)

    if starlette_app is None:
        # FastMCP doesn't expose the raw app — fall back to its own runner
        # (no middleware injection possible; bearer auth unavailable in this mode)
        print(
            "warning: FastMCP version does not expose .app — "
            "bearer auth middleware cannot be injected. "
            "Upgrade to mcp>=1.3 or run stdio.",
            file=sys.stderr,
        )
        await server.run_sse_async(host=host, port=port)
        return

    if not no_auth:
        token = _load_or_generate_token(KODA_HOME)
        starlette_app = _make_bearer_middleware(starlette_app, token)

    ssl_ctx = _build_ssl_context(tls_cert, tls_key, client_ca)

    uvicorn_kwargs: dict[str, Any] = {
        "host": host,
        "port": port,
        "log_level": "warning",
    }
    if ssl_ctx is not None:
        uvicorn_kwargs["ssl_certfile"] = tls_cert
        uvicorn_kwargs["ssl_keyfile"] = tls_key
        if client_ca:
            uvicorn_kwargs["ssl_ca_certs"] = client_ca
            uvicorn_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED

    config = uvicorn.Config(starlette_app, **uvicorn_kwargs)
    uv_server = uvicorn.Server(config)
    await uv_server.serve()


def _load_or_generate_token(home: Path) -> str:
    """Load or auto-generate the MCP bearer token."""
    from .auth import ensure_bearer_token
    return ensure_bearer_token(home)


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="koda mcp", description="K.O.D.A. MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio",
                        help="transport to use (default: stdio)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind host for SSE transport (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=7655,
                        help="bind port for SSE transport (default: 7655)")

    # TLS / mTLS
    parser.add_argument("--tls-cert", metavar="PATH",
                        help="server TLS certificate PEM file (SSE only)")
    parser.add_argument("--tls-key", metavar="PATH",
                        help="server TLS key PEM file (SSE only)")
    parser.add_argument("--client-ca", metavar="PATH",
                        help="CA bundle for validating client certs — enables mTLS (SSE only)")

    # Auth control
    parser.add_argument(
        "--no-auth",
        action="store_true",
        default=False,
        help=(
            "Disable bearer token authentication. "
            "Only allowed when --host is a loopback address (127.0.0.1 / ::1 / localhost). "
            "Intended for local-dev workflows."
        ),
    )

    args = parser.parse_args(argv)

    if args.transport == "sse":
        # Enforce: --no-auth requires loopback bind
        if args.no_auth and args.host not in _LOOPBACK_ADDRS:
            print(
                f"error: --no-auth is only permitted when binding to a loopback address.\n"
                f"  current --host: {args.host}\n"
                f"  --no-auth exposes the MCP surface without authentication. Binding to\n"
                f"  a non-loopback address without auth would allow any reachable client\n"
                f"  to drive K.O.D.A. scanners without a credential.\n"
                f"  To proceed: change --host to 127.0.0.1 (or ::1 / localhost),\n"
                f"  or remove --no-auth to use bearer token authentication.",
                file=sys.stderr,
            )
            return 1

        asyncio.run(
            run_sse(
                host=args.host,
                port=args.port,
                no_auth=args.no_auth,
                tls_cert=args.tls_cert,
                tls_key=args.tls_key,
                client_ca=args.client_ca,
            )
        )
    else:
        asyncio.run(run_stdio())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
