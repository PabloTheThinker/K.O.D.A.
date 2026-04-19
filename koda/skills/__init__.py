"""External skill pack loader.

Skill packs live on disk as ``<dir>/SKILL.md`` with YAML frontmatter and a
markdown body. The loader parses them into :class:`SkillPack` records and
registers them with :data:`koda.security.skills.registry.DEFAULT_REGISTRY`
so the existing phase/mode lookup works unchanged.

This is the extensibility seam: community security skills ship as SKILL.md
packs, drop into a search path, get picked up at startup.
"""
from __future__ import annotations

from koda.skills.loader import SkillLoader, load_default_packs
from koda.skills.pack import SkillPack, SkillPackError

__all__ = ["SkillPack", "SkillPackError", "SkillLoader", "load_default_packs"]
