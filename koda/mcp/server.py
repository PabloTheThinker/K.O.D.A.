"""Expose every K.O.D.A. tool over Model Context Protocol.

Any MCP-capable client — Claude Code, Cursor, other agents — can connect and
call K.O.D.A.'s security tools. Tools keep their risk metadata in the
description so remote callers know what they're invoking.

Usage:
    koda mcp                     # stdio transport (default, for Claude Code)
    koda mcp --transport sse     # SSE transport for remote clients

Claude Code / similar MCP host config snippet:
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
import sys
from typing import Any

from ..tools import builtins as _builtins  # triggers tool registration
from ..tools.registry import Tool, global_registry

_ = _builtins


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


async def run_sse(host: str = "127.0.0.1", port: int = 7655) -> None:
    server = create_mcp_server()
    await server.run_sse_async(host=host, port=port)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="koda mcp", description="K.O.D.A. MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1", help="SSE host")
    parser.add_argument("--port", type=int, default=7655, help="SSE port")
    args = parser.parse_args(argv)

    if args.transport == "sse":
        asyncio.run(run_sse(host=args.host, port=args.port))
    else:
        asyncio.run(run_stdio())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
