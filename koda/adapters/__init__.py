"""Provider adapters. Each model backend implements the Provider contract in base.py."""
from __future__ import annotations

from typing import Any

from .anthropic_api import AnthropicAPIProvider
from .base import Message, Provider, ProviderResponse, Role, ToolCall, ToolChoice, ToolSpec
from .claude_cli import ClaudeCLIProvider
from .ollama import OllamaProvider

_PROVIDERS: dict[str, type[Provider]] = {
    "anthropic": AnthropicAPIProvider,
    "claude_cli": ClaudeCLIProvider,
    "ollama": OllamaProvider,
}


def create_provider(name: str, config: dict[str, Any] | None = None) -> Provider:
    key = (name or "").lower().strip()
    cls = _PROVIDERS.get(key)
    if cls is None:
        raise ValueError(f"Unknown provider '{name}'. Options: {sorted(_PROVIDERS)}")
    return cls(config or {})


__all__ = [
    "Message",
    "Provider",
    "ProviderResponse",
    "Role",
    "ToolCall",
    "ToolChoice",
    "ToolSpec",
    "AnthropicAPIProvider",
    "ClaudeCLIProvider",
    "OllamaProvider",
    "create_provider",
]
