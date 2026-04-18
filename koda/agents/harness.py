"""Agent harness — load a scaffolded agent and boot its own REPL.

Reads ~/.koda/agents/<name>/config.yaml and wires:
  - provider from config.yaml (provider + model)
  - tool registry filtered to enabled categories
  - approval policy from auto_approve threshold
  - session store at memory/sessions/
  - Helix DSEM at memory/helix.db (created on first write)
  - Drawers at memory/drawers.db (created on first write)
  - system prompt stitched from SOUL.md + IDENTITY.md + TOOLS.md
    (and BOOTSTRAP.md on first run — agent should remove it after)
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..adapters import create_provider
from ..adapters.base import Provider
from ..agent.loop import TurnLoop, TurnOptions
from ..session.store import SessionStore
from ..tools import builtins as _builtins  # noqa: F401  triggers registration
from ..tools.approval import ApprovalPolicy
from ..tools.registry import RiskLevel, Tool, ToolRegistry, global_registry
from .scaffold import AGENTS_HOME, agent_dir, agent_exists, validate_name

_AUTO_APPROVE_MAP = {
    "none": None,  # prompt for everything
    "safe": RiskLevel.SAFE,
    "sensitive": RiskLevel.SENSITIVE,
    "dangerous": RiskLevel.DANGEROUS,
}

# Wizard uses short keys; tools register under these actual categories.
_CATEGORY_MAP = {
    "fs": "fs",
    "scan": "security",
    "net": "network",
    "host": "host",
}


@dataclass
class AgentRuntime:
    name: str
    root: Path
    provider_name: str
    model: str
    provider: Provider
    registry: ToolRegistry
    approvals: ApprovalPolicy
    session: SessionStore
    session_id: str
    system_prompt: str
    has_bootstrap: bool


def _load_config(root: Path) -> dict:
    cfg_path = root / "config.yaml"
    if not cfg_path.exists():
        raise FileNotFoundError(f"config.yaml missing at {cfg_path}")
    with cfg_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"config.yaml at {cfg_path} is not a mapping")
    return data


def _build_filtered_registry(enabled: list[str]) -> ToolRegistry:
    source = global_registry()
    filtered = ToolRegistry()
    allowed = {_CATEGORY_MAP.get(e, e) for e in enabled}
    for name in source.names():
        tool = source.get(name)
        if tool is None:
            continue
        if tool.category in allowed or tool.category == "general":
            filtered.register(
                Tool(
                    name=tool.name,
                    description=tool.description,
                    input_schema=tool.input_schema,
                    handler=tool.handler,
                    risk=tool.risk,
                    category=tool.category,
                )
            )
    return filtered


def _read_if_exists(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return ""


def _build_system_prompt(root: Path, agent_name: str) -> tuple[str, bool]:
    soul = _read_if_exists(root / "SOUL.md")
    identity = _read_if_exists(root / "IDENTITY.md")
    tools_md = _read_if_exists(root / "TOOLS.md")
    bootstrap = _read_if_exists(root / "BOOTSTRAP.md")
    has_bootstrap = bool(bootstrap)

    parts: list[str] = []
    parts.append(f"You are agent `{agent_name}`, a K.O.D.A.-powered harness.")
    if soul:
        parts.append(soul)
    if identity:
        parts.append(identity)
    if tools_md:
        parts.append(tools_md)
    if bootstrap:
        parts.append(
            "FIRST RUN — the following BOOTSTRAP.md exists in your workspace. "
            "Follow it for this conversation, update IDENTITY.md, then delete BOOTSTRAP.md. "
            "Do not reference it again after deletion.\n\n"
            + bootstrap
        )
    return "\n\n---\n\n".join(parts), has_bootstrap


def build_runtime(name: str) -> AgentRuntime:
    validate_name(name)
    if not agent_exists(name):
        raise FileNotFoundError(
            f"Agent {name!r} not found at {agent_dir(name)}. "
            f"Create it with: koda new {name}"
        )
    root = agent_dir(name)
    cfg = _load_config(root)

    agent_cfg = cfg.get("agent") or {}
    tools_cfg = cfg.get("tools") or {}
    memory_cfg = cfg.get("memory") or {}

    provider_name = (agent_cfg.get("provider") or "").strip()
    model = (agent_cfg.get("model") or "").strip()
    if not provider_name:
        raise ValueError("agent.provider missing from config.yaml")

    provider = create_provider(provider_name, {"model": model})

    enabled = list(tools_cfg.get("enabled_categories") or [])
    registry = _build_filtered_registry(enabled)

    auto_approve_key = (tools_cfg.get("auto_approve") or "safe").strip()
    threshold = _AUTO_APPROVE_MAP.get(auto_approve_key, RiskLevel.SAFE)
    approvals_path = root / "approvals.json"
    approvals = ApprovalPolicy(
        approvals_path=approvals_path,
        auto_approve_threshold=threshold,
    )

    sessions_dir = root / (memory_cfg.get("sessions_dir") or "memory/sessions")
    sessions_dir.mkdir(parents=True, exist_ok=True)
    session = SessionStore(sessions_dir / "sessions.db")
    session_id = session.create(title=f"{name}-interactive")

    system_prompt, has_bootstrap = _build_system_prompt(root, name)

    return AgentRuntime(
        name=name,
        root=root,
        provider_name=provider_name,
        model=provider.get_model(),
        provider=provider,
        registry=registry,
        approvals=approvals,
        session=session,
        session_id=session_id,
        system_prompt=system_prompt,
        has_bootstrap=has_bootstrap,
    )


async def _repl_loop(rt: AgentRuntime) -> int:
    loop = TurnLoop(
        provider=rt.provider,
        registry=rt.registry,
        approvals=rt.approvals,
        session=rt.session,
        session_id=rt.session_id,
    )

    print()
    print(f"  agent:    {rt.name}")
    print(f"  root:     {rt.root}")
    print(f"  provider: {rt.provider_name}    model: {rt.model}")
    print(f"  tools:    {', '.join(rt.registry.names()) or '(none enabled)'}")
    print(f"  session:  {rt.session_id}")
    if rt.has_bootstrap:
        print("  note:     BOOTSTRAP.md detected — first-run dialog mode active.")
    print("  type a question, or /exit to quit.")
    print()

    while True:
        try:
            prompt = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not prompt:
            continue
        if prompt in {"/exit", "/quit", "/q"}:
            return 0

        trace = await loop.run(prompt, TurnOptions(extra_system_prompt=rt.system_prompt))
        print()
        if trace.aborted:
            print(f"[aborted: {trace.abort_reason}]")
        else:
            print(trace.final_text)
        print(
            f"\n  iterations={trace.iterations}"
            f"  tool_calls={trace.tool_calls_made}"
            f"  verifier_rejections={trace.verifier_rejections}\n"
        )


def run_agent(name: str) -> int:
    rt = build_runtime(name)
    return asyncio.run(_repl_loop(rt))
