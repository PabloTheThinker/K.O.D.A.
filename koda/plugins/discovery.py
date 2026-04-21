"""Plugin discovery — walks search paths for ``koda.plugin.json`` files.

Search order (first-wins by canonical id):
  1. Bundled (inside the installed ``koda`` package distribution).
  2. Workspace (``./plugins`` relative to CWD).
  3. Per-user (``~/.koda/plugins``).
  4. ``$KODA_PLUGINS_PATH`` (colon-separated).

Malformed manifests never take down discovery — errors are collected and
returned alongside the candidates so ``koda doctor`` can surface them.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from koda.plugins.manifest import ManifestError, PluginManifest


@dataclass(frozen=True)
class PluginCandidate:
    """A manifest located on disk, ready to be activated.

    ``dir`` is the directory containing ``koda.plugin.json``; the runtime
    entry path is resolved relative to it by the loader.
    """

    manifest: PluginManifest
    dir: Path
    origin: str
    """One of ``bundled`` | ``workspace`` | ``user`` | ``env``."""


class PluginDiscovery:
    _MANIFEST_FILENAME = "koda.plugin.json"

    def __init__(self, search_paths: list[tuple[Path, str]] | None = None) -> None:
        if search_paths is not None:
            self._search_paths = search_paths
        else:
            self._search_paths = self._default_search_paths()

    @classmethod
    def _default_search_paths(cls) -> list[tuple[Path, str]]:
        paths: list[tuple[Path, str]] = []

        # 1. Bundled: <koda package dir>/../plugins_bundled/*
        try:
            import koda

            koda_root = Path(koda.__file__).resolve().parent.parent
            bundled = koda_root / "plugins_bundled"
            if bundled.is_dir():
                paths.append((bundled, "bundled"))
        except Exception:
            pass

        # 2. Workspace
        paths.append((Path("plugins").resolve(), "workspace"))

        # 3. Per-user
        paths.append((Path.home() / ".koda" / "plugins", "user"))

        # 4. Env override
        env_var = os.environ.get("KODA_PLUGINS_PATH", "")
        if env_var:
            for raw in env_var.split(":"):
                raw = raw.strip()
                if raw:
                    paths.append((Path(raw).expanduser(), "env"))

        return paths

    def discover(
        self,
    ) -> tuple[list[PluginCandidate], list[tuple[Path, str]]]:
        """Return ``(candidates, errors)``.

        Errors are ``(path, message)`` pairs. First-win on plugin id keeps
        bundled defaults overridable by workspace/user installs — matching
        how OpenClaw lets users shadow built-ins.
        """
        seen: dict[str, PluginCandidate] = {}
        errors: list[tuple[Path, str]] = []
        for root, origin in self._search_paths:
            if not root.is_dir():
                continue
            for manifest_path in root.rglob(self._MANIFEST_FILENAME):
                try:
                    manifest = PluginManifest.from_path(manifest_path)
                except ManifestError as e:
                    errors.append((manifest_path, str(e)))
                    continue
                if manifest.id in seen:
                    # First win; note the shadow so doctor can warn.
                    errors.append(
                        (
                            manifest_path,
                            f"shadowed by {seen[manifest.id].dir} (id={manifest.id})",
                        )
                    )
                    continue
                seen[manifest.id] = PluginCandidate(
                    manifest=manifest,
                    dir=manifest_path.parent,
                    origin=origin,
                )
        return list(seen.values()), errors

    def find_by_model(self, model_id: str) -> list[PluginCandidate]:
        """Cold lookup — which plugins claim this model's prefix?

        Does NOT import any plugin runtime. Safe to call at startup.
        """
        candidates, _ = self.discover()
        return [c for c in candidates if c.manifest.matches_model(model_id)]

    def find_by_channel(self, channel: str) -> list[PluginCandidate]:
        candidates, _ = self.discover()
        return [c for c in candidates if c.manifest.matches_channel(channel)]

    def find_by_provider(self, provider: str) -> list[PluginCandidate]:
        candidates, _ = self.discover()
        return [c for c in candidates if c.manifest.matches_provider(provider)]
