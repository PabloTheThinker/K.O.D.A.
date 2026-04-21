"""Plugin control plane.

Manifest-first plugin system modeled after OpenClaw's
``openclaw.plugin.json`` pattern (see
``brain/research/codebase-dna/openclaw-dna.md`` §6).

Core reads ``koda.plugin.json`` manifests to route activation without
importing plugin runtime code. The runtime entry is only loaded when
an activation trigger (provider match, channel bind, CLI command,
capability request) fires.

Public surface:

* :class:`PluginManifest` — typed schema, parsed from JSON.
* :class:`PluginDiscovery` — walks bundled / user / workspace dirs.
* :class:`PluginRegistry` — tracks activated plugins in-process.
"""
from __future__ import annotations

from koda.plugins.manifest import (
    ManifestError,
    PluginActivation,
    PluginKind,
    PluginManifest,
    PluginModelSupport,
)
from koda.plugins.discovery import PluginCandidate, PluginDiscovery
from koda.plugins.registry import PluginRegistry, PluginRegistryError

__all__ = [
    "ManifestError",
    "PluginActivation",
    "PluginCandidate",
    "PluginDiscovery",
    "PluginKind",
    "PluginManifest",
    "PluginModelSupport",
    "PluginRegistry",
    "PluginRegistryError",
]
