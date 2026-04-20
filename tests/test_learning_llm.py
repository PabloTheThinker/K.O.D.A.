"""Tests for the LLM-backed skill synthesizer."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import yaml

from koda.adapters.base import Provider, ProviderResponse
from koda.learning.synthesizer_llm import (
    draft_skill_from_concept_llm,
    draft_skill_from_concept_llm_sync,
)


@dataclass
class FakeConcept:
    id: str = "c-abc"
    title: str = "SSH root login exposed on engagement hosts"
    description: str = "Hosts expose sshd with PermitRootLogin yes."
    category: str = "pattern"
    confidence: float = 0.9
    evidence_count: int = 7
    evidence_ids: list = field(default_factory=list)
    last_reinforced: str = "2026-04-20T00:00:00+00:00"


@dataclass
class FakeEpisode:
    id: str
    timestamp: str = "2026-04-15T10:00:00"
    event_type: str = "finding"
    content: str = "host exposes SSH"
    outcome: str = "flagged"
    severity: str = "high"
    metadata: dict = field(default_factory=lambda: {"tool": "nmap"})


class FakeProvider(Provider):
    def __init__(self, text: str = "", *, fail: bool = False) -> None:
        super().__init__({"model": "fake-1"})
        self._text = text
        self._fail = fail
        self.calls: list[list[Any]] = []

    async def chat(self, messages, tools=None, tool_choice=None, **kwargs):
        self.calls.append(messages)
        if self._fail:
            raise RuntimeError("provider exploded")
        return ProviderResponse(text=self._text, stop_reason="end_turn")


_GOOD_BODY = """\
## When it applies
Hosts in the engagement allow direct SSH root login via PermitRootLogin yes.

## Observations
- host-0 exposes SSH with PermitRootLogin yes
- host-1 exposes SSH with PermitRootLogin yes

## Procedure
1. Enumerate sshd_config for PermitRootLogin.
2. Record findings.

## Provenance
Authored from Helix-consolidated concept by the KODA learning layer.
"""


def test_llm_synth_uses_provider_body() -> None:
    provider = FakeProvider(text=_GOOD_BODY)
    concept = FakeConcept()
    episodes = [FakeEpisode(id=f"e{i}") for i in range(3)]

    draft = asyncio.run(draft_skill_from_concept_llm(
        concept=concept, evidence_episodes=episodes, provider=provider,
    ))

    assert "## When it applies" in draft.body
    assert "PermitRootLogin" in draft.body
    rendered = draft.render()
    _, fm_text, body = rendered.split("---", 2)
    fm = yaml.safe_load(fm_text)
    assert fm["status"] == "learned-draft"
    assert fm["source"]["synthesizer"] == "llm"
    assert fm["source"]["model"] == "fake-1"
    assert fm["tools_required"] == ["nmap"]
    assert "PermitRootLogin" in body
    assert len(provider.calls) == 1


def test_llm_synth_falls_back_on_provider_error() -> None:
    provider = FakeProvider(fail=True)
    concept = FakeConcept()
    episodes = [FakeEpisode(id="e0")]

    draft = asyncio.run(draft_skill_from_concept_llm(
        concept=concept, evidence_episodes=episodes, provider=provider,
    ))
    assert "Generated automatically by the KODA learning layer" in draft.body
    assert draft.frontmatter["source"].get("synthesizer") != "llm"


def test_llm_synth_falls_back_on_garbage_output() -> None:
    provider = FakeProvider(text="nope")
    concept = FakeConcept()
    draft = asyncio.run(draft_skill_from_concept_llm(
        concept=concept, evidence_episodes=[], provider=provider,
    ))
    assert "## Procedure" in draft.body


def test_llm_synth_strips_code_fences() -> None:
    fenced = f"```markdown\n{_GOOD_BODY}```"
    provider = FakeProvider(text=fenced)
    draft = asyncio.run(draft_skill_from_concept_llm(
        concept=FakeConcept(), evidence_episodes=[FakeEpisode(id="e0")],
        provider=provider,
    ))
    assert not draft.body.startswith("```")
    assert "## When it applies" in draft.body


def test_sync_wrapper_runs_loop() -> None:
    provider = FakeProvider(text=_GOOD_BODY)
    draft = draft_skill_from_concept_llm_sync(
        concept=FakeConcept(),
        evidence_episodes=[FakeEpisode(id="e0")],
        provider=provider,
    )
    assert "PermitRootLogin" in draft.body
