"""SkillPack: the on-disk representation of a loadable skill.

A pack is a directory containing a single ``SKILL.md`` file whose head is a
YAML frontmatter block delimited by ``---`` lines, followed by the markdown
procedure that becomes the skill's ``prompt_fragment``.

Frontmatter schema (only ``name`` and ``description`` are required):

    name: sherlock                          # unique within the registry
    description: one-line summary           # shown in skill catalog
    version: 1.0.0
    mode: red                               # red | blue | purple
    phase: recon                            # EngagementContext.phase value
    attack_techniques: [T1589.001]          # MITRE ATT&CK ids
    relevant_cwe: []                        # CWE ids
    tools_required: [sherlock]              # tool names the agent should prefer
    prerequisites:
      commands: [sherlock]                  # binaries that must be on PATH

Anything else is passed through as ``metadata`` and ignored by the core.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from koda.security.modes import SecurityMode
from koda.security.skills.base import Skill


class SkillPackError(ValueError):
    """Raised when a SKILL.md file is malformed."""


_FRONTMATTER_RE = re.compile(
    r"\A---\s*\n(?P<fm>.*?)\n---\s*\n(?P<body>.*)\Z",
    re.DOTALL,
)


@dataclass(frozen=True)
class SkillPack:
    """A parsed SKILL.md on disk."""

    name: str
    description: str
    path: Path
    frontmatter: dict[str, Any] = field(default_factory=dict)
    body: str = ""

    @classmethod
    def from_path(cls, skill_md: Path) -> SkillPack:
        """Parse a SKILL.md file. Raises SkillPackError on malformed input."""
        if not skill_md.is_file():
            raise SkillPackError(f"not a file: {skill_md}")
        raw = skill_md.read_text(encoding="utf-8")
        match = _FRONTMATTER_RE.match(raw)
        if match is None:
            raise SkillPackError(
                f"{skill_md}: missing YAML frontmatter (expected '---' delimited header)"
            )
        try:
            fm = yaml.safe_load(match.group("fm")) or {}
        except yaml.YAMLError as exc:
            raise SkillPackError(f"{skill_md}: invalid YAML frontmatter: {exc}") from exc
        if not isinstance(fm, dict):
            raise SkillPackError(f"{skill_md}: frontmatter must be a mapping")

        name = fm.get("name")
        description = fm.get("description")
        if not isinstance(name, str) or not name.strip():
            raise SkillPackError(f"{skill_md}: frontmatter missing required 'name'")
        if not isinstance(description, str) or not description.strip():
            raise SkillPackError(f"{skill_md}: frontmatter missing required 'description'")

        return cls(
            name=name.strip(),
            description=description.strip(),
            path=skill_md.parent,
            frontmatter=fm,
            body=match.group("body").strip(),
        )

    def prerequisite_commands(self) -> tuple[str, ...]:
        prereqs = self.frontmatter.get("prerequisites") or {}
        if not isinstance(prereqs, dict):
            return ()
        cmds = prereqs.get("commands") or []
        return tuple(str(c) for c in cmds if isinstance(c, str))

    def to_skill(self, *, default_mode: SecurityMode = SecurityMode.RED) -> Skill:
        """Materialize as an internal :class:`Skill` record.

        Frontmatter fields drive the Skill; the markdown body becomes the
        injected prompt_fragment. Mode/phase default to red/recon which is
        the common OSINT case — packs override via frontmatter.
        """
        fm = self.frontmatter
        mode = _coerce_mode(fm.get("mode"), default_mode)
        phase = str(fm.get("phase", "recon")).strip() or "recon"
        techniques = _coerce_tuple(fm.get("attack_techniques"))
        cwe = _coerce_tuple(fm.get("relevant_cwe"))
        tools = _coerce_tuple(fm.get("tools_required"))
        prompt_fragment = self._render_prompt_fragment()
        example_plays = _coerce_tuple(fm.get("example_plays"))

        return Skill(
            name=self.name,
            phase=phase,
            mode=mode,
            attack_techniques=techniques,
            relevant_cwe=cwe,
            tools_required=tools,
            prompt_fragment=prompt_fragment,
            example_plays=example_plays,
        )

    def _render_prompt_fragment(self) -> str:
        """Combine description + body into a single operator-voice fragment."""
        parts = [f"## {self.name} — {self.description}"]
        if self.body:
            parts.append(self.body)
        return "\n\n".join(parts).strip()


def _coerce_mode(raw: Any, default: SecurityMode) -> SecurityMode:
    if raw is None:
        return default
    if isinstance(raw, SecurityMode):
        return raw
    try:
        return SecurityMode(str(raw).strip().lower())
    except ValueError as exc:
        raise SkillPackError(f"unknown mode {raw!r}") from exc


def _coerce_tuple(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw.strip(),) if raw.strip() else ()
    if isinstance(raw, (list, tuple)):
        return tuple(str(x).strip() for x in raw if str(x).strip())
    return ()


__all__ = ["SkillPack", "SkillPackError"]
