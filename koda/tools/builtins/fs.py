"""Filesystem tools: fs.list and fs.read. Read-only, SAFE risk."""
from __future__ import annotations

import os
from pathlib import Path

from ..registry import RiskLevel, Tool, ToolResult, register

_MAX_READ_BYTES = 200_000
_MAX_LIST_ENTRIES = 500


def _fs_list(path: str, pattern: str = "*", recursive: bool = False) -> ToolResult:
    p = Path(path).expanduser()
    if not p.exists():
        return ToolResult(content=f"Path does not exist: {p}", is_error=True)
    if not p.is_dir():
        return ToolResult(content=f"Not a directory: {p}", is_error=True)
    entries: list[str] = []
    iterator = p.rglob(pattern) if recursive else p.glob(pattern)
    for entry in iterator:
        if len(entries) >= _MAX_LIST_ENTRIES:
            entries.append(f"... truncated at {_MAX_LIST_ENTRIES} entries")
            break
        try:
            stat = entry.stat()
        except OSError:
            continue
        kind = "d" if entry.is_dir() else "f"
        entries.append(f"{kind} {stat.st_size:>10}  {entry}")
    body = "\n".join(entries) if entries else "(no matches)"
    return ToolResult(content=body)


def _fs_read(path: str, max_bytes: int = _MAX_READ_BYTES) -> ToolResult:
    p = Path(path).expanduser()
    if not p.exists():
        return ToolResult(content=f"Path does not exist: {p}", is_error=True)
    if p.is_dir():
        return ToolResult(content=f"Cannot read a directory: {p}", is_error=True)
    try:
        size = p.stat().st_size
        limit = min(max_bytes, _MAX_READ_BYTES)
        with p.open("rb") as fh:
            data = fh.read(limit)
        text = data.decode("utf-8", errors="replace")
        header = f"# {p} ({size} bytes, showing {len(data)})\n"
        return ToolResult(content=header + text)
    except OSError as e:
        return ToolResult(content=f"{type(e).__name__}: {e}", is_error=True)


register(Tool(
    name="fs.list",
    description="List files and directories under a path. Use this before claiming any file exists.",
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Absolute or ~-expanded path to list."},
            "pattern": {"type": "string", "default": "*", "description": "Glob pattern (default '*')."},
            "recursive": {"type": "boolean", "default": False, "description": "Recurse into subdirectories."},
        },
        "required": ["path"],
    },
    handler=_fs_list,
    risk=RiskLevel.SAFE,
    category="fs",
))

register(Tool(
    name="fs.read",
    description="Read a text file. Use this before quoting any file content, line number, or code reference.",
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Absolute or ~-expanded path to read."},
            "max_bytes": {"type": "integer", "default": _MAX_READ_BYTES, "description": "Byte cap for the response."},
        },
        "required": ["path"],
    },
    handler=_fs_read,
    risk=RiskLevel.SAFE,
    category="fs",
))

_ = os  # keep os import for future expansion (env-scoped reads, etc.)
