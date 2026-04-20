"""Provider adapters. Each model backend implements the Provider contract in base.py."""
from __future__ import annotations

from typing import Any

from .anthropic_api import AnthropicAPIProvider
from .azure_openai import AzureOpenAIProvider
from .base import Message, Provider, ProviderResponse, Role, ToolCall, ToolChoice, ToolSpec
from .bedrock import BedrockProvider
from .gemini import GeminiProvider
from .llamacpp import LlamaCppProvider
from .ollama import OllamaProvider
from .openai_compat import OpenAICompatProvider
from .vertex_ai import VertexAIProvider

# Providers that share the OpenAI-compat adapter differ only in their
# endpoint + env var. Listing them here lets create_provider inject the
# right ``provider_name`` so the adapter routes correctly.
_OPENAI_COMPAT_ALIASES: tuple[str, ...] = (
    "openai",
    "groq",
    "together",
    "openrouter",
    "deepseek",
    "xai",
    "grok",
    "mistral",
    "fireworks",
    "cerebras",
    "perplexity",
    "openai_compat",
)

_DIRECT: dict[str, type[Provider]] = {
    "anthropic": AnthropicAPIProvider,
    "azure_openai": AzureOpenAIProvider,
    "azure": AzureOpenAIProvider,
    "gemini": GeminiProvider,
    "google": GeminiProvider,
    "llamacpp": LlamaCppProvider,
    "llama_cpp": LlamaCppProvider,
    "ollama": OllamaProvider,
    "vertex_ai": VertexAIProvider,
    "vertex": VertexAIProvider,
    "bedrock": BedrockProvider,
    "aws_bedrock": BedrockProvider,
}

# Friendly aliases for providers where the user might use a common name.
_ALIASES: dict[str, str] = {
    "claude": "anthropic",
    "claude-api": "anthropic",
    "anthropic_api": "anthropic",
    "google_gemini": "gemini",
    "googleai": "gemini",
    "grok": "xai",
    "llama.cpp": "llamacpp",
}


def create_provider(name: str, config: dict[str, Any] | None = None) -> Provider:
    key = (name or "").lower().strip()
    key = _ALIASES.get(key, key)
    cfg = dict(config or {})

    if key in _DIRECT:
        return _DIRECT[key](cfg)

    if key in _OPENAI_COMPAT_ALIASES:
        # Normalize xAI naming — both "grok" and "xai" resolve to xai endpoint.
        provider_id = "xai" if key in ("grok", "xai") else key
        if provider_id == "openai_compat":
            # Raw compat mode — caller supplies base_url explicitly.
            cfg.setdefault("provider_name", "openai")
        else:
            cfg["provider_name"] = provider_id
        return OpenAICompatProvider(cfg)

    options = sorted(set(_DIRECT) | set(_OPENAI_COMPAT_ALIASES) | set(_ALIASES))
    raise ValueError(f"Unknown provider '{name}'. Options: {options}")


__all__ = [
    "Message",
    "Provider",
    "ProviderResponse",
    "Role",
    "ToolCall",
    "ToolChoice",
    "ToolSpec",
    "AnthropicAPIProvider",
    "AzureOpenAIProvider",
    "LlamaCppProvider",
    "OllamaProvider",
    "OpenAICompatProvider",
    "GeminiProvider",
    "VertexAIProvider",
    "BedrockProvider",
    "create_provider",
]
