"""Skill pack loader.

Discovers ``SKILL.md`` files in configured search paths, parses each via
:meth:`SkillPack.from_path`, and registers the resulting :class:`Skill`
records into :data:`DEFAULT_REGISTRY` so the existing phase/mode lookup
keeps working unchanged.

Search order, first-wins:
  1. ``./skills`` (project-local packs)
  2. ``~/.koda/skills`` (per-user packs)
  3. Any paths in ``$KODA_SKILLS_PATH`` (colon-separated, OS-path style)

Errors never propagate — callers get a list of ``(path, message)`` pairs.
"""
from __future__ import annotations

import os
from pathlib import Path

from koda.security.skills.registry import DEFAULT_REGISTRY, SkillRegistry
from koda.skills.pack import SkillPack, SkillPackError

__all__ = ["SkillLoader", "load_default_packs"]


class SkillLoader:
    def __init__(
        self,
        registry: SkillRegistry = DEFAULT_REGISTRY,
        search_paths: list[Path] | None = None,
    ) -> None:
        self._registry = registry
        if search_paths is not None:
            self._search_paths = search_paths
        else:
            default_paths = [Path("skills"), Path.home() / ".koda" / "skills"]
            env_paths = self._parse_env_paths()
            self._search_paths = default_paths + env_paths

    def _parse_env_paths(self) -> list[Path]:
        env_var = os.environ.get("KODA_SKILLS_PATH", "")
        if not env_var:
            return []
        return [Path(p.strip()) for p in env_var.split(":") if p.strip()]

    def discover(self) -> list[Path]:
        found: dict[str, Path] = {}
        for search_path in self._search_paths:
            if not search_path.is_dir():
                continue
            for sk in search_path.rglob("SKILL.md"):
                resolved = str(sk.resolve())
                if resolved not in found:
                    found[resolved] = sk
        return list(found.values())

    def load(self) -> tuple[list[SkillPack], list[tuple[Path, str]]]:
        discovered = self.discover()
        packs: list[SkillPack] = []
        errors: list[tuple[Path, str]] = []
        for skill_path in discovered:
            try:
                pack = SkillPack.from_path(skill_path)
                packs.append(pack)
            except SkillPackError as e:
                errors.append((skill_path, str(e)))
        return packs, errors

    def register_all(self) -> tuple[int, list[tuple[Path, str]]]:
        packs, errors = self.load()
        registered_count = 0
        for pack in packs:
            try:
                skill = pack.to_skill()
                self._registry.register(skill)
                registered_count += 1
            except SkillPackError as e:
                errors.append((pack.path, str(e)))
        return registered_count, errors


def load_default_packs() -> tuple[int, list[tuple[Path, str]]]:
    """Convenience: build a default :class:`SkillLoader` and register all packs."""
    loader = SkillLoader()
    return loader.register_all()
