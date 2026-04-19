"""Smoke tests for the rule-based intent router."""
from __future__ import annotations

import pytest

from koda.nlu.router import (
    Intent,
    IntentRouter,
    RiskTier,
    classify_intent,
    extract_targets,
)
from koda.security.skills.registry import SkillRegistry


@pytest.fixture()
def empty_registry() -> SkillRegistry:
    reg = SkillRegistry()
    # Strip the defaults registered at import so rank_skills results don't
    # depend on the shipping blue/red packs.
    for skill in list(reg.all_skills()):
        reg._by_name.pop(skill.name, None)  # type: ignore[attr-defined]
    reg._by_mode_phase.clear()  # type: ignore[attr-defined]
    reg._by_technique.clear()  # type: ignore[attr-defined]
    return reg


def test_extract_targets_pulls_domains_ips_cves() -> None:
    t = extract_targets("scan example.com and 10.0.0.5 for CVE-2024-12345")
    assert "example.com" in t.domains
    assert "10.0.0.5" in t.ipv4s
    assert "CVE-2024-12345" in t.cves


def test_classify_recon_wins_on_nmap() -> None:
    intent, conf, _ = classify_intent("run nmap on 10.0.0.1")
    assert intent == Intent.RECON
    assert conf > 0.3


def test_classify_exploit_on_pwn_verb() -> None:
    intent, _, _ = classify_intent("pwn the box and give me a shell")
    assert intent == Intent.EXPLOIT


def test_classify_ir_on_breach_language() -> None:
    intent, _, _ = classify_intent("we think we have a breach, investigate")
    assert intent == Intent.IR


def test_classify_chat_on_short_no_keywords() -> None:
    intent, _, _ = classify_intent("hi there")
    assert intent == Intent.CHAT


def test_router_marks_exploit_dangerous(empty_registry: SkillRegistry) -> None:
    router = IntentRouter(registry=empty_registry)
    d = router.route("exploit the target and get a reverse shell")
    assert d.intent == Intent.EXPLOIT
    assert d.risk == RiskTier.DANGEROUS


def test_router_asks_clarify_when_recon_has_no_target(empty_registry: SkillRegistry) -> None:
    router = IntentRouter(registry=empty_registry)
    d = router.route("please run a scan")
    assert d.intent == Intent.RECON
    assert d.clarify is not None
    assert "target" in d.clarify.lower()
