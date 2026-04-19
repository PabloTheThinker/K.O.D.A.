"""Skill registry: lookup skills by mode/phase/technique/name.

The default registry is populated with every ``ALL_RED_SKILLS`` and
``ALL_BLUE_SKILLS`` entry at import time. The purple pack will register
itself into ``DEFAULT_REGISTRY`` the same way when Phase 4 ships.
"""
from __future__ import annotations

from koda.security.modes import SecurityMode
from koda.security.skills.base import Skill
from koda.security.skills.blue import ALL_BLUE_SKILLS
from koda.security.skills.red import ALL_RED_SKILLS


class SkillRegistry:
    """In-memory index of skills, keyed for the three common lookups."""

    def __init__(self) -> None:
        self._by_name: dict[str, Skill] = {}
        self._by_mode_phase: dict[tuple[SecurityMode, str], list[Skill]] = {}
        self._by_technique: dict[str, list[Skill]] = {}
        for skill in ALL_RED_SKILLS:
            self.register(skill)
        for skill in ALL_BLUE_SKILLS:
            self.register(skill)

    def register(self, skill: Skill) -> None:
        """Register a skill. Re-registering the same name replaces it."""
        # If we're replacing, purge old entries from the secondary indexes.
        existing = self._by_name.get(skill.name)
        if existing is not None:
            self._remove_from_indexes(existing)

        self._by_name[skill.name] = skill
        key = (skill.mode, skill.phase)
        self._by_mode_phase.setdefault(key, []).append(skill)
        for tid in skill.attack_techniques:
            self._by_technique.setdefault(tid.upper(), []).append(skill)

    def _remove_from_indexes(self, skill: Skill) -> None:
        key = (skill.mode, skill.phase)
        bucket = self._by_mode_phase.get(key)
        if bucket is not None:
            self._by_mode_phase[key] = [s for s in bucket if s.name != skill.name]
            if not self._by_mode_phase[key]:
                del self._by_mode_phase[key]
        for tid in skill.attack_techniques:
            tk = tid.upper()
            tbucket = self._by_technique.get(tk)
            if tbucket is not None:
                self._by_technique[tk] = [s for s in tbucket if s.name != skill.name]
                if not self._by_technique[tk]:
                    del self._by_technique[tk]

    def skills_for(self, mode: SecurityMode, phase: str) -> list[Skill]:
        """All skills registered for this (mode, phase) pair."""
        return list(self._by_mode_phase.get((mode, phase), ()))

    def skill_by_name(self, name: str) -> Skill | None:
        return self._by_name.get(name)

    def skills_by_attack_technique(self, tid: str) -> list[Skill]:
        if not tid:
            return []
        return list(self._by_technique.get(tid.strip().upper(), ()))

    def all_modes(self) -> set[SecurityMode]:
        return {skill.mode for skill in self._by_name.values()}

    def phases_for_mode(self, mode: SecurityMode) -> list[str]:
        seen: list[str] = []
        for m, phase in self._by_mode_phase.keys():
            if m is mode and phase not in seen:
                seen.append(phase)
        return seen

    def all_skills(self) -> list[Skill]:
        return list(self._by_name.values())


# Module-level singleton. Phase 3 blue pack will call
# DEFAULT_REGISTRY.register(...) at its own import time.
DEFAULT_REGISTRY = SkillRegistry()


__all__ = ["SkillRegistry", "DEFAULT_REGISTRY"]
