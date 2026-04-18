"""K.O.D.A. agent scaffolding + harness.

`koda new [<name>]` scaffolds a standalone agent (default name: koda).
`koda run <name>` boots that agent's OpenClaw-style harness — filtered
tool registry, per-agent Helix + Drawers memory, SOUL/IDENTITY prompt.
"""
from .harness import AgentRuntime, build_runtime, run_agent
from .scaffold import (
    AGENTS_HOME,
    AgentSpec,
    agent_dir,
    agent_exists,
    list_agents,
    scaffold_agent,
    validate_name,
)

__all__ = [
    "AGENTS_HOME",
    "AgentSpec",
    "AgentRuntime",
    "validate_name",
    "agent_dir",
    "agent_exists",
    "list_agents",
    "scaffold_agent",
    "build_runtime",
    "run_agent",
]
