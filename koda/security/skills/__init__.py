"""Red/blue/purple skill packs.

A skill bundles:
  - ATT&CK techniques in scope for a phase,
  - internal Koda tool names the agent should prefer,
  - a prompt fragment the harness injects when the skill is active.

The package exports the ``Skill`` dataclass and the default registry so
callers can import from ``koda.security.skills`` without descending into
the per-mode modules.
"""
from __future__ import annotations

from koda.security.skills.base import Skill
from koda.security.skills.registry import DEFAULT_REGISTRY, SkillRegistry

__all__ = ["Skill", "SkillRegistry", "DEFAULT_REGISTRY"]
