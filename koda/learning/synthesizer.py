"""Synthesize a SKILL.md draft from a Helix concept + its evidence episodes.

Deterministic template-based generation. An LLM-backed synthesizer can slot
in later behind the same :func:`draft_skill_from_concept` contract — the
caller doesn't need to know which path produced the draft.

Structural rules:
  * Name is derived from the concept title — slugified, ≤ 40 chars.
  * Description is the concept title (first sentence) trimmed.
  * Body is a Markdown document with four sections:
      ## When it applies
      ## Observations (from {N} episodes)
      ## Procedure (draft)
      ## Provenance
  * Frontmatter mirrors the SkillPack schema so SkillLoader can parse it
    with zero changes.

The draft is always marked ``status: learned-draft`` in frontmatter so a
reviewer can filter learned vs. hand-authored packs.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import yaml

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_SENTENCE_RE = re.compile(r"[.!?]\s")
_MAX_NAME_LEN = 40


@dataclass
class SkillDraft:
    """A concept's promotion to a SKILL.md, pre-guard."""

    name: str
    description: str
    frontmatter: dict[str, Any]
    body: str

    def render(self) -> str:
        """Return the full SKILL.md text (frontmatter + body)."""
        fm_yaml = yaml.safe_dump(
            self.frontmatter,
            sort_keys=False,
            default_flow_style=False,
        ).strip()
        return f"---\n{fm_yaml}\n---\n\n{self.body.strip()}\n"


def draft_skill_from_concept(
    *,
    concept: Any,
    evidence_episodes: Iterable[Any],
    mode: str = "purple",
    phase: str = "recon",
) -> SkillDraft:
    """Build a draft SKILL.md from a Helix concept and its evidence.

    ``concept`` is a ``koda.memory.helix.Concept``; ``evidence_episodes`` is
    any iterable of ``koda.memory.helix.Episode``. We duck-type the fields
    we need (``title``, ``description``, ``category``, ``confidence``,
    ``evidence_count``, ``evidence_ids``, ``last_reinforced`` on the concept;
    ``content``, ``outcome``, ``timestamp``, ``severity``, ``event_type`` on
    episodes) so tests don't need to import the full Helix stack.
    """
    title = str(getattr(concept, "title", "")).strip() or "unnamed-pattern"
    description = str(getattr(concept, "description", "")).strip() or title
    category = str(getattr(concept, "category", "pattern")).strip() or "pattern"
    confidence = float(getattr(concept, "confidence", 0.0))
    evidence_count = int(getattr(concept, "evidence_count", 0))
    concept_id = str(getattr(concept, "id", "")) or "unknown"
    last_reinforced = str(getattr(concept, "last_reinforced", "")) or _now()

    name = _slugify(title)[:_MAX_NAME_LEN] or "learned-skill"
    short_desc = _first_sentence(description) or title
    if len(short_desc) > 180:
        short_desc = short_desc[:177] + "…"

    episodes = list(evidence_episodes)

    frontmatter: dict[str, Any] = {
        "name": name,
        "description": short_desc,
        "version": "0.1.0",
        "mode": mode,
        "phase": phase,
        "status": "learned-draft",
        "source": {
            "kind": "helix-concept",
            "concept_id": concept_id,
            "category": category,
            "confidence": round(confidence, 3),
            "evidence_count": evidence_count,
            "last_reinforced": last_reinforced,
            "drafted_at": _now(),
        },
    }

    tools = _infer_tools(episodes)
    if tools:
        frontmatter["tools_required"] = sorted(tools)

    body = _render_body(
        description=description,
        category=category,
        confidence=confidence,
        episodes=episodes,
    )

    return SkillDraft(
        name=name,
        description=short_desc,
        frontmatter=frontmatter,
        body=body,
    )


def _render_body(
    *,
    description: str,
    category: str,
    confidence: float,
    episodes: list[Any],
) -> str:
    parts: list[str] = []

    parts.append("## When it applies")
    parts.append(
        f"This pattern was learned from {len(episodes)} episode"
        f"{'s' if len(episodes) != 1 else ''} consolidated into a "
        f"{category} concept (confidence {confidence:.0%}). "
        f"{description}"
    )

    if episodes:
        parts.append(f"## Observations (from {len(episodes)} episodes)")
        bullets: list[str] = []
        for ep in episodes[:8]:
            ts = str(getattr(ep, "timestamp", ""))[:16]
            sev = str(getattr(ep, "severity", ""))
            content = str(getattr(ep, "content", "")).strip()
            if not content:
                continue
            if len(content) > 180:
                content = content[:177] + "…"
            lead = f"[{ts}]" if ts else "-"
            if sev:
                lead += f" **{sev}**"
            bullets.append(f"- {lead} {content}")
        if bullets:
            parts.append("\n".join(bullets))

    parts.append("## Procedure (draft)")
    parts.append(
        "> This section is a starting point generated from observations. "
        "Edit before approving the skill."
    )
    steps = _infer_steps(episodes)
    if steps:
        parts.append("\n".join(f"{i}. {step}" for i, step in enumerate(steps, 1)))
    else:
        parts.append("1. Verify the pattern applies to the current engagement.")
        parts.append("2. Collect evidence comparable to the observations above.")
        parts.append("3. Record findings as new episodes so Helix can reinforce this concept.")

    parts.append("## Provenance")
    parts.append(
        "Generated automatically by the KODA learning layer from recurring "
        "episodes in Helix. Review the observations, adjust the procedure, "
        "then approve with `koda learn approve <name>`."
    )

    return "\n\n".join(parts)


def _slugify(value: str) -> str:
    slug = _SLUG_RE.sub("-", value.lower()).strip("-")
    return slug or "skill"


def _first_sentence(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    match = _SENTENCE_RE.search(value)
    if match:
        return value[: match.start() + 1].strip()
    return value


def _infer_tools(episodes: list[Any]) -> set[str]:
    """Pull tool names out of episode metadata when present."""
    tools: set[str] = set()
    for ep in episodes:
        meta = getattr(ep, "metadata", None) or {}
        tool = meta.get("tool") if isinstance(meta, dict) else None
        if isinstance(tool, str) and tool.strip():
            tools.add(tool.strip())
    return tools


def _infer_steps(episodes: list[Any]) -> list[str]:
    """Order episodes by timestamp and convert outcomes into rough steps."""
    sortable = [
        ep for ep in episodes if str(getattr(ep, "timestamp", "")).strip()
    ]
    sortable.sort(key=lambda ep: str(ep.timestamp))
    steps: list[str] = []
    for ep in sortable[:6]:
        content = str(getattr(ep, "content", "")).strip()
        outcome = str(getattr(ep, "outcome", "")).strip()
        if not content:
            continue
        if len(content) > 140:
            content = content[:137] + "…"
        if outcome:
            if len(outcome) > 80:
                outcome = outcome[:77] + "…"
            steps.append(f"{content} → {outcome}")
        else:
            steps.append(content)
    return steps


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
