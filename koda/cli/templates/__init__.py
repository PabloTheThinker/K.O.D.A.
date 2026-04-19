"""Engagement template definitions for ``koda new --template``."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EngagementTemplate:
    """Immutable descriptor for a pre-configured engagement template."""

    name: str
    description: str
    approval_tier: str
    scanners: tuple[str, ...]
    attack_phases: tuple[str, ...]
    report_template: str
    next_steps: tuple[str, ...]


PENTEST = EngagementTemplate(
    name="pentest",
    description="Offensive penetration test — recon through execution, SENSITIVE approval tier.",
    approval_tier="all",          # escalates DANGEROUS at sensitive threshold
    scanners=("semgrep", "trivy", "nuclei", "nmap", "gitleaks", "osv-scanner"),
    attack_phases=("recon", "initial_access", "execution"),
    report_template="pentest-markdown",
    next_steps=(
        "Run `koda use <name>` to activate this engagement.",
        "Add in-scope targets: edit engagement.toml → [scope] targets.",
        "Start a session:  koda",
        "Ask K.O.D.A. to run recon against a scoped target.",
    ),
)

IR = EngagementTemplate(
    name="ir",
    description="Incident response — paranoid on destructive ops, log/forensics scanner set.",
    approval_tier="safe",         # DANGEROUS-blocked; only safe-tier auto-approves
    scanners=("log-analyzer", "port-monitor", "oss-forensics"),
    attack_phases=("persistence", "defense", "exfil"),
    report_template="ir-timeline",
    next_steps=(
        "Run `koda use <name>` to activate this engagement.",
        "Set scope to the affected host(s): edit engagement.toml → [scope] targets.",
        "Start a session:  koda",
        "Ask K.O.D.A. to analyze logs or hunt for persistence indicators.",
    ),
)

AUDIT = EngagementTemplate(
    name="audit",
    description="Compliance/hardening audit — read-only posture, configuration review.",
    approval_tier="safe",         # SAFE-only; no mutations
    scanners=("semgrep", "trivy", "bandit", "1password"),
    attack_phases=("hardening",),
    report_template="audit-findings",
    next_steps=(
        "Run `koda use <name>` to activate this engagement.",
        "Add repos/hosts to audit: edit engagement.toml → [scope] targets.",
        "Start a session:  koda",
        "Ask K.O.D.A. to review configuration or run a compliance scan.",
    ),
)

# Registry: template name → descriptor
REGISTRY: dict[str, EngagementTemplate] = {
    t.name: t for t in (PENTEST, IR, AUDIT)
}


def get(name: str) -> EngagementTemplate | None:
    """Return the template for *name*, or None if unknown."""
    return REGISTRY.get(name)


def names() -> list[str]:
    """Return sorted list of available template names."""
    return sorted(REGISTRY)


__all__ = ["EngagementTemplate", "PENTEST", "IR", "AUDIT", "REGISTRY", "get", "names"]
