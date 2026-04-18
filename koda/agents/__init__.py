"""K.O.D.A. agent scaffolding — `koda new <name>` builds a standalone agent."""
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
    "validate_name",
    "agent_dir",
    "agent_exists",
    "list_agents",
    "scaffold_agent",
]
