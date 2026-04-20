"""Provider catalog — single source of truth for the list of supported backends.

The wizard menu, OpenAI-compat routing, and adapter aliases all read from
:data:`koda.providers.catalog.PROVIDER_CATALOG`. Adding a new
OpenAI-compatible provider is a one-entry append — no code changes in the
adapters or wizard.
"""
from .catalog import PROVIDER_CATALOG, ProviderEntry, openai_compat_ids

__all__ = ["PROVIDER_CATALOG", "ProviderEntry", "openai_compat_ids"]
