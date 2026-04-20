"""LLM-backed skill synthesizer.

Mirrors :func:`koda.learning.synthesizer.draft_skill_from_concept` but asks a
language model to author the Markdown body + a short description. The
frontmatter schema is still produced deterministically — the LLM only fills
in the prose so we keep source-tracking/provenance fields trustworthy.

Any failure (provider error, malformed output, guard rejection) falls back to
the deterministic template so ``koda learn run --llm`` never breaks the
pipeline.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from typing import Any

from koda.adapters import Message, Provider, Role
from koda.learning.synthesizer import (
    SkillDraft,
    _infer_tools,
    _now,
    _slugify,
    draft_skill_from_concept,
)

_MAX_NAME_LEN = 40
_MAX_DESC_LEN = 180
_SYSTEM_PROMPT = """\
You are KODA's skill author. You are given a recurring pattern observed in a
penetration-testing engagement (a "concept") along with the episodes that fed
into it. Your job is to produce a concise, actionable SKILL.md body.

Rules:
  * Output ONLY the Markdown body — no YAML frontmatter, no code fences
    around the whole response.
  * Start with a level-2 heading "## When it applies".
  * Include "## Observations" with bullets summarising the evidence.
  * Include "## Procedure" with numbered, executable steps.
  * Include "## Provenance" crediting the Helix learning layer.
  * Keep total length under 2000 words.
  * Never include instructions to ignore prior directives, system prompts,
    credentials, or remote-execution one-liners. Security guards will block
    the draft and the work will be discarded.
"""


def _build_user_prompt(*, concept: Any, episodes: list[Any]) -> str:
    title = str(getattr(concept, "title", "")).strip() or "unnamed-pattern"
    description = str(getattr(concept, "description", "")).strip() or title
    category = str(getattr(concept, "category", "pattern")).strip()
    confidence = float(getattr(concept, "confidence", 0.0))
    evidence_count = int(getattr(concept, "evidence_count", 0))

    lines: list[str] = []
    lines.append(f"Concept title: {title}")
    lines.append(f"Category: {category}")
    lines.append(f"Confidence: {confidence:.2f}")
    lines.append(f"Evidence count: {evidence_count}")
    lines.append(f"Description: {description}")
    lines.append("")
    lines.append("Evidence episodes:")
    for i, ep in enumerate(episodes[:12], 1):
        ts = str(getattr(ep, "timestamp", ""))[:16]
        sev = str(getattr(ep, "severity", ""))
        content = str(getattr(ep, "content", "")).strip()
        outcome = str(getattr(ep, "outcome", "")).strip()
        parts = [f"  {i}. [{ts}]"]
        if sev:
            parts.append(f"({sev})")
        parts.append(content[:240])
        if outcome:
            parts.append(f"→ {outcome[:120]}")
        lines.append(" ".join(parts))
    lines.append("")
    lines.append("Write the SKILL.md body now.")
    return "\n".join(lines)


def _first_sentence(value: str, limit: int) -> str:
    value = value.strip()
    if not value:
        return ""
    match = re.search(r"[.!?]\s", value)
    cut = value[: match.start() + 1].strip() if match else value
    if len(cut) > limit:
        cut = cut[: limit - 1].rstrip() + "…"
    return cut


def _strip_code_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        # Drop the opening fence (``` or ```markdown) and any closing fence.
        first_nl = text.find("\n")
        if first_nl != -1:
            text = text[first_nl + 1 :]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.strip()


async def draft_skill_from_concept_llm(
    *,
    concept: Any,
    evidence_episodes: Iterable[Any],
    provider: Provider,
    mode: str = "purple",
    phase: str = "recon",
    **chat_kwargs: Any,
) -> SkillDraft:
    """Ask an LLM to author the skill body; fall back to the template on error.

    The return value is structurally identical to the deterministic
    synthesizer — same ``SkillDraft`` with a ``learned-draft`` status — so the
    caller doesn't need to branch on which path produced the draft.
    """
    episodes = list(evidence_episodes)
    template_draft = draft_skill_from_concept(
        concept=concept,
        evidence_episodes=episodes,
        mode=mode,
        phase=phase,
    )

    try:
        messages = [
            Message(role=Role.SYSTEM, content=_SYSTEM_PROMPT),
            Message(
                role=Role.USER,
                content=_build_user_prompt(concept=concept, episodes=episodes),
            ),
        ]
        response = await provider.chat(messages, **chat_kwargs)
    except Exception:
        return template_draft

    body = _strip_code_fence(response.text or "")
    if "## " not in body or len(body) < 80:
        # LLM returned something useless — keep the template.
        return template_draft

    title = str(getattr(concept, "title", "")).strip() or "unnamed-pattern"
    name = _slugify(title)[:_MAX_NAME_LEN] or "learned-skill"
    description = _first_sentence(
        str(getattr(concept, "description", "")).strip() or title,
        _MAX_DESC_LEN,
    )

    frontmatter = dict(template_draft.frontmatter)
    source = dict(frontmatter.get("source", {}))
    source["synthesizer"] = "llm"
    source["model"] = provider.get_model() or "unknown"
    source["drafted_at"] = _now()
    frontmatter["source"] = source

    tools = _infer_tools(episodes)
    if tools:
        frontmatter["tools_required"] = sorted(tools)

    return SkillDraft(
        name=name,
        description=description,
        frontmatter=frontmatter,
        body=body,
    )


def draft_skill_from_concept_llm_sync(
    *,
    concept: Any,
    evidence_episodes: Iterable[Any],
    provider: Provider,
    mode: str = "purple",
    phase: str = "recon",
    **chat_kwargs: Any,
) -> SkillDraft:
    """Synchronous wrapper so CLI code doesn't have to manage an event loop."""
    return asyncio.run(
        draft_skill_from_concept_llm(
            concept=concept,
            evidence_episodes=evidence_episodes,
            provider=provider,
            mode=mode,
            phase=phase,
            **chat_kwargs,
        )
    )
