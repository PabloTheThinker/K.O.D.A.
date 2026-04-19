"""Unit tests for koda.tools.approval — approval gate with risk tiers."""
from __future__ import annotations

import asyncio

import pytest

from koda.security.guardrails import (
    DEFAULT_RULES,
    GuardrailAction,
    GuardrailRule,
)
from koda.tools.approval import ApprovalPolicy, ApprovalRequest, threshold_from_config
from koda.tools.registry import RiskLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Execute a coroutine synchronously."""
    return asyncio.run(coro)


def _policy(
    threshold: RiskLevel = RiskLevel.SAFE,
    callback=None,
    rules=DEFAULT_RULES,
    scope=None,
) -> ApprovalPolicy:
    return ApprovalPolicy(
        approvals_path=None,
        auto_approve_threshold=threshold,
        callback=callback,
        rules=rules,
        scope=scope,
    )


def _req(tool: str = "nmap", risk: RiskLevel = RiskLevel.SAFE, args: dict | None = None, engagement: str = "eng") -> ApprovalRequest:
    return ApprovalRequest(tool_name=tool, arguments=args or {}, risk=risk, engagement=engagement)


# ---------------------------------------------------------------------------
# SAFE auto-approves at default threshold
# ---------------------------------------------------------------------------


def test_safe_tool_auto_approved():
    """A SAFE-risk tool is approved without a callback when threshold=SAFE."""
    policy = _policy(threshold=RiskLevel.SAFE)
    decision = _run(policy.decide_full(_req(risk=RiskLevel.SAFE)))
    assert decision.allowed is True
    assert decision.stage == "threshold"


# ---------------------------------------------------------------------------
# SENSITIVE requires explicit approval (threshold=SAFE)
# ---------------------------------------------------------------------------


def test_sensitive_tool_denied_without_callback():
    """SENSITIVE tool is refused when threshold=SAFE and no callback configured."""
    policy = _policy(threshold=RiskLevel.SAFE, callback=None)
    decision = _run(policy.decide_full(_req(risk=RiskLevel.SENSITIVE)))
    assert decision.allowed is False
    assert decision.stage == "callback"


def test_sensitive_tool_approved_via_callback():
    """SENSITIVE tool is approved when the operator callback returns True."""
    policy = _policy(threshold=RiskLevel.SAFE, callback=lambda req, gd: True)
    decision = _run(policy.decide_full(_req(risk=RiskLevel.SENSITIVE)))
    assert decision.allowed is True
    assert decision.stage == "callback"


# ---------------------------------------------------------------------------
# DANGEROUS requires callback unless threshold covers it
# ---------------------------------------------------------------------------


def test_dangerous_denied_no_callback():
    """DANGEROUS tool refused when no callback is registered."""
    policy = _policy(threshold=RiskLevel.SAFE, callback=None)
    decision = _run(policy.decide_full(_req(risk=RiskLevel.DANGEROUS)))
    assert decision.allowed is False


def test_dangerous_approved_with_threshold_all():
    """When threshold=DANGEROUS ('all'), dangerous tools auto-approve."""
    policy = _policy(threshold=RiskLevel.DANGEROUS)
    decision = _run(policy.decide_full(_req(risk=RiskLevel.DANGEROUS)))
    assert decision.allowed is True
    assert decision.stage == "threshold"


# ---------------------------------------------------------------------------
# BLOCKED (guardrail) — never runs regardless of threshold or entries
# ---------------------------------------------------------------------------


def test_guardrail_block_overrides_threshold():
    """A guardrail BLOCK refusal cannot be overridden even with threshold=DANGEROUS."""
    # This rule blocks every invocation of the test tool.
    block_rule = GuardrailRule(
        name="test.always_block",
        pattern=r".*",
        action=GuardrailAction.BLOCK,
        reason="Test hard block.",
        tool="dangerous.tool",
    )
    policy = _policy(threshold=RiskLevel.DANGEROUS, rules=[block_rule])
    decision = _run(policy.decide_full(_req(tool="dangerous.tool", risk=RiskLevel.DANGEROUS, args={"cmd": "run"})))
    assert decision.allowed is False
    assert decision.stage == "guardrail"
    assert "block" in decision.matched_rule.lower()


def test_guardrail_block_overrides_always_entry():
    """A guardrail BLOCK overrides even a sticky 'always' approval entry."""
    block_rule = GuardrailRule(
        name="test.hard_block",
        pattern=r".*",
        action=GuardrailAction.BLOCK,
        reason="Absolute block.",
        tool="scary.tool",
    )
    policy = _policy(rules=[block_rule])
    policy.set("scary.tool", "always")  # operator tries to pre-approve it
    decision = _run(policy.decide_full(_req(tool="scary.tool", risk=RiskLevel.SAFE, args={"x": "anything"})))
    assert decision.allowed is False
    assert decision.stage == "guardrail"


# ---------------------------------------------------------------------------
# Argument-level guardrails — nmap loopback escalation
# ---------------------------------------------------------------------------


def test_nmap_aggressive_flag_escalates_to_dangerous():
    """Aggressive nmap flags escalate the effective risk and require human approval."""
    policy = _policy(threshold=RiskLevel.SENSITIVE, callback=None)
    # -sS is a stealth SYN scan — matches scanner.nmap_aggressive rule.
    decision = _run(policy.decide_full(_req(
        tool="nmap",
        risk=RiskLevel.SENSITIVE,
        args={"command": "nmap -sS 127.0.0.1"},
    )))
    # Escalated to DANGEROUS, threshold=SENSITIVE can't cover DANGEROUS, no callback → refused.
    assert decision.allowed is False


def test_nmap_safe_flags_pass_through(tmp_path):
    """nmap with basic flags and no aggressive patterns respects the threshold."""
    policy = _policy(threshold=RiskLevel.SENSITIVE)
    decision = _run(policy.decide_full(_req(
        tool="nmap",
        risk=RiskLevel.SENSITIVE,
        args={"command": "nmap -p 80,443 192.168.1.1"},
    )))
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Deny list entry
# ---------------------------------------------------------------------------


def test_never_entry_blocks_tool():
    """A tool on the deny list is refused regardless of risk."""
    policy = _policy(threshold=RiskLevel.DANGEROUS)
    policy.set("banned.tool", "never")
    decision = _run(policy.decide_full(_req(tool="banned.tool", risk=RiskLevel.SAFE, args={})))
    assert decision.allowed is False
    assert decision.stage == "entry"


# ---------------------------------------------------------------------------
# Sticky 'always' approval respects escalation guard
# ---------------------------------------------------------------------------


def test_always_entry_approved_for_normal_call():
    """'always' entry approves a tool that hasn't triggered an escalation."""
    policy = _policy(threshold=RiskLevel.SAFE)
    policy.set("approved.tool", "always")
    decision = _run(policy.decide_full(_req(tool="approved.tool", risk=RiskLevel.DANGEROUS, args={})))
    assert decision.allowed is True
    assert decision.stage == "entry"


def test_always_entry_does_not_skip_escalation():
    """'always' entry does NOT bypass a guardrail escalation — still goes to callback."""
    escalate_rule = GuardrailRule(
        name="test.escalate",
        pattern=r"escalate_me",
        action=GuardrailAction.ESCALATE,
        reason="Test escalation.",
        tool="preapproved.tool",
    )
    # No callback → escalated call will be refused.
    policy = _policy(threshold=RiskLevel.SENSITIVE, rules=[escalate_rule], callback=None)
    policy.set("preapproved.tool", "always")
    decision = _run(policy.decide_full(_req(
        tool="preapproved.tool",
        risk=RiskLevel.SENSITIVE,
        args={"cmd": "escalate_me"},
    )))
    assert decision.allowed is False


# ---------------------------------------------------------------------------
# threshold_from_config
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tier,expected",
    [
        ("safe", RiskLevel.SAFE),
        ("medium", RiskLevel.SENSITIVE),
        ("all", RiskLevel.DANGEROUS),
        ("none", RiskLevel.SAFE),
        ("garbage", RiskLevel.DANGEROUS),  # unknown → default "all"
    ],
)
def test_threshold_from_config(tier: str, expected: RiskLevel):
    cfg = {"approvals": {"auto_approve": tier}}
    assert threshold_from_config(cfg) == expected
