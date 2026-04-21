"""Typed schema for ``koda.plugin.json`` manifests.

Modeled after OpenClaw's ``src/plugins/manifest.ts`` with the subset
KODA actually needs for its first pass: providers, channels, memory
backends, and command-aliased skill packs. Everything else stays in
metadata and is forwarded untouched.

The critical property (per the DNA comparison): core can read the
manifest to route activation **without importing the plugin's Python
module**. That means model-prefix routing, channel validation, and
onboarding UI shape all come from JSON, not runtime imports.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    """Raised when a ``koda.plugin.json`` is malformed."""


class PluginKind(str, Enum):
    PROVIDER = "provider"
    CHANNEL = "channel"
    MEMORY = "memory"
    SKILL_PACK = "skill_pack"
    TOOL_PACK = "tool_pack"
    OTHER = "other"


@dataclass(frozen=True)
class PluginModelSupport:
    """Cold-routing hints so core can resolve a provider without importing it."""

    model_prefixes: tuple[str, ...] = ()
    model_patterns: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> PluginModelSupport:
        if not data:
            return cls()
        return cls(
            model_prefixes=tuple(data.get("model_prefixes") or ()),
            model_patterns=tuple(data.get("model_patterns") or ()),
        )


@dataclass(frozen=True)
class PluginActivation:
    """Conditions under which the loader should import the plugin's runtime."""

    on_providers: tuple[str, ...] = ()
    on_channels: tuple[str, ...] = ()
    on_commands: tuple[str, ...] = ()
    on_capabilities: tuple[str, ...] = ()
    auto_enable: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> PluginActivation:
        if not data:
            return cls()
        return cls(
            on_providers=tuple(data.get("on_providers") or ()),
            on_channels=tuple(data.get("on_channels") or ()),
            on_commands=tuple(data.get("on_commands") or ()),
            on_capabilities=tuple(data.get("on_capabilities") or ()),
            auto_enable=bool(data.get("auto_enable", False)),
        )


@dataclass(frozen=True)
class PluginManifest:
    """Canonical manifest record.

    Instances are frozen — once discovered, core should not mutate them.
    Mutation lives in :class:`PluginRegistry` only.
    """

    id: str
    name: str
    version: str
    kinds: tuple[PluginKind, ...]
    runtime_entry: str
    """Python dotted path to the module implementing the plugin runtime."""

    description: str = ""
    providers: tuple[str, ...] = ()
    channels: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    model_support: PluginModelSupport = field(default_factory=PluginModelSupport)
    activation: PluginActivation = field(default_factory=PluginActivation)
    env_vars: tuple[str, ...] = ()
    legacy_ids: tuple[str, ...] = ()
    config_schema: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    source_path: Path | None = None

    @classmethod
    def from_path(cls, manifest_path: Path) -> PluginManifest:
        """Parse a ``koda.plugin.json`` from disk. Raises :class:`ManifestError`."""
        if not manifest_path.is_file():
            raise ManifestError(f"not a file: {manifest_path}")
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ManifestError(f"could not parse {manifest_path}: {e}") from e
        return cls.from_dict(raw, source_path=manifest_path)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        source_path: Path | None = None,
    ) -> PluginManifest:
        if not isinstance(data, dict):
            raise ManifestError("manifest must be a JSON object")

        plugin_id = data.get("id")
        if not isinstance(plugin_id, str) or not plugin_id.strip():
            raise ManifestError("manifest missing required string 'id'")
        # Canonicalize: lowercase, dash-only — keeps routing keys deterministic.
        if plugin_id != plugin_id.lower() or " " in plugin_id:
            raise ManifestError(
                f"'id' must be lowercase and space-free: got {plugin_id!r}"
            )

        runtime_entry = data.get("runtime_entry")
        if not isinstance(runtime_entry, str) or not runtime_entry.strip():
            raise ManifestError("manifest missing required string 'runtime_entry'")

        raw_kinds = data.get("kinds") or data.get("kind")
        if isinstance(raw_kinds, str):
            raw_kinds = [raw_kinds]
        if not raw_kinds:
            raise ManifestError("manifest missing 'kinds' (non-empty list or string)")
        parsed_kinds: list[PluginKind] = []
        for k in raw_kinds:
            try:
                parsed_kinds.append(PluginKind(k))
            except ValueError as e:
                raise ManifestError(f"unknown plugin kind: {k!r}") from e

        return cls(
            id=plugin_id,
            name=str(data.get("name") or plugin_id),
            version=str(data.get("version") or "0.0.0"),
            kinds=tuple(parsed_kinds),
            runtime_entry=runtime_entry,
            description=str(data.get("description") or ""),
            providers=tuple(data.get("providers") or ()),
            channels=tuple(data.get("channels") or ()),
            skills=tuple(data.get("skills") or ()),
            model_support=PluginModelSupport.from_dict(data.get("model_support")),
            activation=PluginActivation.from_dict(data.get("activation")),
            env_vars=tuple(data.get("env_vars") or ()),
            legacy_ids=tuple(data.get("legacy_ids") or ()),
            config_schema=dict(data.get("config_schema") or {}),
            metadata=dict(data.get("metadata") or {}),
            source_path=source_path,
        )

    def matches_model(self, model_id: str) -> bool:
        """Cold check — does this plugin claim to support ``model_id``?

        Checked against ``model_support.model_prefixes`` (literal prefix
        match). ``model_patterns`` is reserved for a future globbing layer
        and is intentionally ignored here so cold routing stays O(1).
        """
        if not model_id:
            return False
        for prefix in self.model_support.model_prefixes:
            if model_id.startswith(prefix):
                return True
        return False

    def matches_channel(self, channel: str) -> bool:
        return channel in self.channels

    def matches_provider(self, provider: str) -> bool:
        return provider in self.providers

    def matches_id(self, candidate_id: str) -> bool:
        """Accept either the canonical ``id`` or any listed ``legacy_ids``."""
        return candidate_id == self.id or candidate_id in self.legacy_ids
