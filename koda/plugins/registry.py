"""In-process registry of activated plugins.

Holds activation state — which plugin ids are live, which runtime
modules have been imported — so repeat activations are idempotent and
so ``koda doctor`` / ``koda plugins list`` can inspect live state.

The registry does NOT own the manifests themselves; it references
:class:`PluginCandidate` objects produced by :class:`PluginDiscovery`.
That keeps the "manifest is the control plane" invariant: the registry
is strictly *derived* state.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any

from koda.plugins.discovery import PluginCandidate


class PluginRegistryError(RuntimeError):
    """Raised when activation fails — bad entry point, duplicate, etc."""


@dataclass
class _ActiveRecord:
    candidate: PluginCandidate
    module: ModuleType | None = None
    state: dict[str, Any] = field(default_factory=dict)


class PluginRegistry:
    """Tracks activated plugins. One instance per runtime process."""

    def __init__(self) -> None:
        self._active: dict[str, _ActiveRecord] = {}

    # --- introspection ---------------------------------------------------
    def is_active(self, plugin_id: str) -> bool:
        return plugin_id in self._active

    def active_ids(self) -> list[str]:
        return sorted(self._active)

    def candidate(self, plugin_id: str) -> PluginCandidate | None:
        rec = self._active.get(plugin_id)
        return rec.candidate if rec else None

    def module(self, plugin_id: str) -> ModuleType | None:
        rec = self._active.get(plugin_id)
        return rec.module if rec else None

    def state(self, plugin_id: str) -> dict[str, Any]:
        rec = self._active.get(plugin_id)
        if rec is None:
            raise PluginRegistryError(f"plugin not active: {plugin_id}")
        return rec.state

    # --- activation ------------------------------------------------------
    def activate(
        self,
        candidate: PluginCandidate,
        *,
        import_module: bool = True,
    ) -> None:
        """Mark a plugin active. Optionally import its runtime entry.

        Idempotent — re-activating an already-active plugin is a no-op
        provided the candidate's ``id`` matches the existing record.
        """
        plugin_id = candidate.manifest.id
        if plugin_id in self._active:
            existing = self._active[plugin_id]
            if existing.candidate.dir != candidate.dir:
                raise PluginRegistryError(
                    f"plugin {plugin_id!r} already active from "
                    f"{existing.candidate.dir}, refusing to re-activate "
                    f"from {candidate.dir}"
                )
            return

        record = _ActiveRecord(candidate=candidate)
        if import_module:
            entry = candidate.manifest.runtime_entry
            try:
                record.module = importlib.import_module(entry)
            except ImportError as e:
                raise PluginRegistryError(
                    f"plugin {plugin_id!r}: could not import runtime_entry "
                    f"{entry!r}: {e}"
                ) from e
        self._active[plugin_id] = record

    def deactivate(self, plugin_id: str) -> None:
        """Drop a plugin's active record. The Python module stays imported
        (sys.modules is a process-wide cache); if a plugin ships a
        ``deactivate()`` hook we call it here before dropping state."""
        rec = self._active.pop(plugin_id, None)
        if rec is None:
            return
        if rec.module is not None:
            hook = getattr(rec.module, "deactivate", None)
            if callable(hook):
                try:
                    hook()
                except Exception:
                    # Deactivation must never crash the host.
                    pass


# Module-level default registry — mirrors the ``DEFAULT_REGISTRY`` pattern
# already used by ``koda.security.skills.registry``. CLI code can either
# use this or build its own for test isolation.
DEFAULT_REGISTRY: PluginRegistry = PluginRegistry()
