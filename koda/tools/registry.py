"""Tool registry. Tools self-register at import time and the turn loop dispatches by name."""
from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable

from ..adapters.base import ToolSpec


class RiskLevel(str, Enum):
    SAFE = "safe"
    SENSITIVE = "sensitive"
    DANGEROUS = "dangerous"


@dataclass
class ToolResult:
    content: str
    is_error: bool = False
    metadata: dict[str, Any] | None = None


Handler = Callable[..., Awaitable[ToolResult] | ToolResult]


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler
    risk: RiskLevel = RiskLevel.SAFE
    category: str = "general"
    # Whether the tool's output should land in the evidence store.
    # Default chosen by category so chain-of-custody covers real pentest
    # output (scans, network probes, host recon) but doesn't bloat the
    # store with fs.list / fs.read noise. Individual tools can override.
    capture_evidence: bool | None = None

    def should_capture(self) -> bool:
        if self.capture_evidence is not None:
            return self.capture_evidence
        return self.category in {"security", "network", "host"}

    def content_type_for_capture(self) -> str:
        # Rough heuristic — SARIF lands as JSON, everything else as text.
        if self.category == "security" and self.name.endswith(("sarif", "trivy", "grype", "syft")):
            return "sarif"
        return "text"

    def to_spec(self) -> ToolSpec:
        return ToolSpec(name=self.name, description=self.description, input_schema=self.input_schema)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools.keys())

    def specs(self, include: list[str] | None = None, exclude: list[str] | None = None) -> list[ToolSpec]:
        tools = list(self._tools.values())
        if include:
            tools = [t for t in tools if t.name in set(include)]
        if exclude:
            tools = [t for t in tools if t.name not in set(exclude)]
        return [t.to_spec() for t in tools]

    def by_category(self, category: str) -> list[Tool]:
        return [t for t in self._tools.values() if t.category == category]

    async def invoke(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(content=f"Unknown tool: {name}", is_error=True)
        try:
            result = tool.handler(**arguments)
            if inspect.isawaitable(result):
                result = await result
            if isinstance(result, ToolResult):
                return result
            return ToolResult(content=_stringify(result))
        except Exception as e:
            return ToolResult(content=f"{type(e).__name__}: {e}", is_error=True)


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str, indent=2)
    except Exception:
        return repr(value)


_GLOBAL = ToolRegistry()


def global_registry() -> ToolRegistry:
    return _GLOBAL


def register(tool: Tool) -> Tool:
    _GLOBAL.register(tool)
    return tool
