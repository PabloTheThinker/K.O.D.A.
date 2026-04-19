"""Skill dataclass — the shape every red/blue/purple skill conforms to.

A Skill is a *read model*: frozen, hashable, safe to share across threads.
The harness consumes it; the registry indexes it; the prompt builder
concatenates its ``prompt_fragment`` into the system prompt for the
active engagement phase.
"""
from __future__ import annotations

from dataclasses import dataclass

from koda.security.modes import SecurityMode


@dataclass(frozen=True)
class Skill:
    """A named operator playbook for a single (mode, phase) slot.

    Fields:
      name              Unique id within the registry (``"red.recon"``).
      phase             EngagementContext.phase value this skill covers.
      mode              SecurityMode this skill belongs to.
      attack_techniques Tuple of MITRE ATT&CK technique IDs in scope.
      relevant_cwe      Tuple of CWE IDs likely to surface in this phase.
      tools_required    Internal Koda tool names the agent should prefer.
      prompt_fragment   Dense operator-voice guidance injected into the
                        system prompt when this skill is active.
      example_plays     Short canonical command sequences the agent can
                        model its first moves on.
    """
    name: str
    phase: str
    mode: SecurityMode
    attack_techniques: tuple[str, ...]
    relevant_cwe: tuple[str, ...]
    tools_required: tuple[str, ...]
    prompt_fragment: str
    example_plays: tuple[str, ...]

    def header(self) -> str:
        """Compact one-line descriptor suitable for banners."""
        return (
            f"[{self.mode.value}:{self.phase}] {self.name} — "
            f"techniques={','.join(self.attack_techniques) or 'none'}"
        )


__all__ = ["Skill"]
