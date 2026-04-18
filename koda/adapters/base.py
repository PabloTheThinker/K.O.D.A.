"""Provider base class. Model backends (Anthropic API, Claude CLI, Ollama) implement this contract."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]  # always a parsed dict, never a JSON string


@dataclass
class Message:
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] | None = None
    tool_call_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]  # JSON Schema


@dataclass
class ProviderResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] | None = None


ToolChoice = str | dict[str, Any] | None  # 'auto' | 'any' | {'type':'tool','name':...} | None


class Provider(ABC):
    supports_tools: bool = True

    def __init__(self, config: dict[str, Any]):
        self.config = config or {}

    @abstractmethod
    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        ...

    def get_model(self) -> str:
        return self.config.get("model", "")
