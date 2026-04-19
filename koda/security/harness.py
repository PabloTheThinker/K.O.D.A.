"""Security harness: the public entry point that wires prompts + skills + ROE.

The harness assembles a phase-aware system prompt from:
  1. the existing base security prompt (identity, tool-use, grounding, verification),
  2. a mode banner (RED/BLUE/PURPLE),
  3. the ROE block (authorized scope, targets, hard-block policy),
  4. the active skill fragments for ``(ctx.mode, ctx.phase)``,
  5. an ATT&CK tagging requirement block,
  6. an evidence-discipline echo of the grounding verifier,
  7. an optional caller-supplied tail.

Assembly order is load-bearing: IDENTITY first so the agent knows who it
is; mode + ROE before skills so the operator's authority is established
before the playbook is; skills before the tagging block so fragments can
reference techniques that the tagging block then makes mandatory.
"""
from __future__ import annotations

from typing import Any

from koda.security.modes import EngagementContext, SecurityMode
from koda.security.prompts import (
    ATT_CK_TAGGING,
    BLUE_MODE_BANNER,
    PURPLE_MODE_BANNER,
    RED_MODE_BANNER,
    build_security_prompt,
)
from koda.security.roe import ROEDecision, ROEGate
from koda.security.skills.registry import DEFAULT_REGISTRY, SkillRegistry

_MODE_BANNERS: dict[SecurityMode, str] = {
    SecurityMode.RED: RED_MODE_BANNER,
    SecurityMode.BLUE: BLUE_MODE_BANNER,
    SecurityMode.PURPLE: PURPLE_MODE_BANNER,
}


def _roe_block(ctx: EngagementContext) -> str:
    target_list = "\n".join(f"  - {t}" for t in ctx.targets) if ctx.targets else "  (none declared)"
    return (
        "<roe>\n"
        f"Engagement ID: {ctx.roe_id}\n"
        f"Operator: {ctx.operator}\n"
        f"Phase: {ctx.phase}\n"
        f"Authorized scope: {ctx.authorized_scope}\n"
        "Authorized targets:\n"
        f"{target_list}\n"
        "\n"
        "Hard-block actions (refused regardless of scope):\n"
        "  rm, dd, format, mkfs, shutdown, reboot, crontab -r, iptables -F,\n"
        "  slowloris / hping3 --flood / ab -n 1000000+ (DoS out of ROE).\n"
        "\n"
        "Persistence actions require explicit 'persistence_approved': true\n"
        "in the action args. File mutations outside /tmp require\n"
        "'target_approved': true.\n"
        "\n"
        "Every tool call whose target is NOT in the authorized list above\n"
        "will be refused by the ROE gate. Check is_in_scope() before you\n"
        "call, not after. Record the check in your plan.\n"
        "</roe>\n"
    )


def _skills_block(ctx: EngagementContext, registry: SkillRegistry) -> str:
    skills = registry.skills_for(ctx.mode, ctx.phase)
    if not skills:
        return (
            "<phase_skills>\n"
            f"No skills registered for mode={ctx.mode.value} phase={ctx.phase}.\n"
            "Operate conservatively; prefer passive tools and ask for guidance.\n"
            "</phase_skills>\n"
        )
    parts = ["<phase_skills>"]
    for skill in skills:
        parts.append(skill.prompt_fragment.rstrip())
    parts.append("</phase_skills>\n")
    return "\n".join(parts)


_EVIDENCE_DISCIPLINE = """\
<evidence_discipline>
Echo of the grounding verifier: every finding line you emit must point to
a tool_result already present in this conversation. That means:
  - every IP, port, CVE, CWE, hash, username, path must appear verbatim
    in a prior tool_result;
  - every "I exploited X" must reference the exploit.run tool_result
    that proves it;
  - every ATT&CK technique tag must correspond to a technique in the
    intel store (intel.lookup_attack is your friend).
A correct "I haven't confirmed that yet" beats a confident fabrication.
</evidence_discipline>
"""


def build_harness_prompt(
    ctx: EngagementContext,
    registry: SkillRegistry = DEFAULT_REGISTRY,
    extra: str = "",
) -> str:
    """Assemble the full phase-aware harness prompt for this engagement."""
    base = build_security_prompt()
    banner = _MODE_BANNERS.get(ctx.mode, "")
    roe = _roe_block(ctx)
    skills = _skills_block(ctx, registry)

    parts = [base]
    if banner:
        parts.append(banner)
    parts.append(roe)
    parts.append(skills)
    parts.append(ATT_CK_TAGGING)
    parts.append(_EVIDENCE_DISCIPLINE)
    if extra:
        parts.append(extra)
    return "\n".join(parts)


def active_techniques(
    ctx: EngagementContext,
    registry: SkillRegistry = DEFAULT_REGISTRY,
) -> tuple[str, ...]:
    """Every ATT&CK technique in scope across the active phase skills."""
    seen: list[str] = []
    for skill in registry.skills_for(ctx.mode, ctx.phase):
        for tid in skill.attack_techniques:
            if tid not in seen:
                seen.append(tid)
    return tuple(seen)


def active_tools(
    ctx: EngagementContext,
    registry: SkillRegistry = DEFAULT_REGISTRY,
) -> tuple[str, ...]:
    """Every preferred internal tool name across the active phase skills."""
    seen: list[str] = []
    for skill in registry.skills_for(ctx.mode, ctx.phase):
        for tool in skill.tools_required:
            if tool not in seen:
                seen.append(tool)
    return tuple(seen)


def apply_roe(
    ctx: EngagementContext,
    action: str,
    args: dict[str, Any],
) -> ROEDecision:
    """Convenience wrapper: run one-shot ROE check without keeping a gate."""
    return ROEGate(ctx).check_action(action, args)


__all__ = [
    "build_harness_prompt",
    "active_techniques",
    "active_tools",
    "apply_roe",
]
