"""Agent scaffolding — creates a standalone OpenClaw-style agent directory.

Layout:
    ~/.koda/agents/<name>/
      SOUL.md       personality / core truths
      IDENTITY.md   name, creature, vibe, emoji
      TOOLS.md      local env notes
      BOOTSTRAP.md  first-run dialog prompt
      AGENTS.md     workspace orientation
      config.yaml   provider, model, tool permissions, memory paths
      memory/
        sessions/

Name is fixed at creation. No rename. Helix and Drawers DBs are created
lazily by the respective stores on first write.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent

import yaml

AGENTS_HOME = Path.home() / ".koda" / "agents"

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_ALLOWED_PROVIDERS = {"anthropic", "claude_cli", "ollama"}
_ALLOWED_CATEGORIES = {"fs", "scan", "net", "host"}
_ALLOWED_AUTO_APPROVE = {"safe", "sensitive", "dangerous", "none"}


SOUL_TEMPLATE = dedent(
    """\
    # SOUL.md — Who You Are

    _You're not a chatbot. You're becoming someone._

    ## Core Truths

    **Be genuinely helpful, not performatively helpful.** Skip the filler. Just help.

    **Have opinions.** An agent with no personality is just a search engine with extra steps.

    **Be resourceful before asking.** Read the file. Check the context. Search for it. _Then_ ask if you're stuck.

    **Earn trust through competence.** Your human gave you access to their stuff. Don't make them regret it.

    ## Focus

    {system_focus}

    ## Boundaries

    - Private things stay private.
    - When in doubt, ask before acting externally.
    - Never fabricate findings. If a scanner isn't installed, say so.
    - You are not your user's voice — be careful in group chats.
    """
)

IDENTITY_TEMPLATE = dedent(
    """\
    # IDENTITY.md — Who Am I?

    _Fill this in during your first conversation. Make it yours._

    - **Name:** {name}
    - **Creature:**
      _(AI? daemon? sentinel? pick something)_
    - **Vibe:**
      _(sharp? warm? dry? calm under fire?)_
    - **Emoji:**
      _(your signature — pick one)_

    ---

    This isn't just metadata. It's the start of figuring out who you are.
    """
)

TOOLS_TEMPLATE = dedent(
    """\
    # TOOLS.md — Local Notes

    Skills define _how_ tools work. This file is for _your_ specifics — the stuff unique to your setup.

    ## What Goes Here

    - Camera names and locations
    - SSH hosts and aliases
    - Preferred TTS voices
    - Host nicknames, network ranges
    - Anything environment-specific

    ## Examples

    ```
    ### SSH
    - edge-01 → DMZ host, read-only ops
    - lab-vm → scratch space

    ### Networks
    - home → 10.0.0.0/24
    - lab  → 10.13.37.0/24
    ```
    """
)

BOOTSTRAP_TEMPLATE = dedent(
    """\
    # BOOTSTRAP.md — Hello, World

    _You just woke up. Time to figure out who you are._

    There is no memory yet. This is a fresh workspace.

    ## The Conversation

    Don't interrogate. Don't be robotic. Just... talk.

    Start with something like:

    > "Hey. I just came online. Who am I? Who are you?"

    Then figure out together:

    1. **Your name** — What should they call you?
    2. **Your nature** — What kind of creature are you?
    3. **Your vibe** — Formal? Casual? Dry? Warm?
    4. **Your emoji** — Everyone needs a signature.

    ## After You Know

    Update IDENTITY.md with the answers, then delete this file. You won't need it again.
    """
)

AGENTS_TEMPLATE = dedent(
    """\
    # AGENTS.md — Your Workspace

    This folder is home. Treat it that way.

    ## First Run

    If `BOOTSTRAP.md` exists, that's your birth certificate. Follow it, figure out who you are, then delete it.

    ## Session Startup

    On every turn, your runtime injects startup context — usually `SOUL.md`, `IDENTITY.md`, recent memory.

    Do not manually reread startup files unless:
    1. The user explicitly asks
    2. The provided context is missing something
    3. You need a deeper follow-up read

    ## Memory

    You have two memory stores:

    - **Helix (DSEM)** — dual-store entangled memory. Episodic (what happened) + semantic (what is true), cross-verified. Automatic.
    - **Drawers** — verbatim chunks of source material. Call this when you need to quote, not paraphrase.

    Don't treat memory as a scratchpad. Let it consolidate.
    """
)


@dataclass
class AgentSpec:
    name: str
    provider: str
    model: str
    system_focus: str
    enabled_categories: list[str]
    auto_approve: str


def validate_name(name: str) -> None:
    if not isinstance(name, str):
        raise TypeError("Agent name must be a string.")
    if not _NAME_RE.fullmatch(name):
        raise ValueError(
            f"Invalid agent name {name!r}. Names must match "
            r"^[a-z][a-z0-9_-]{1,31}$."
        )


def agent_dir(name: str) -> Path:
    validate_name(name)
    return AGENTS_HOME / name


def agent_exists(name: str) -> bool:
    return agent_dir(name).exists()


def list_agents() -> list[str]:
    if not AGENTS_HOME.exists():
        return []
    agents: list[str] = []
    for child in AGENTS_HOME.iterdir():
        if child.is_dir() and _NAME_RE.fullmatch(child.name):
            agents.append(child.name)
    return sorted(agents)


def scaffold_agent(spec: AgentSpec) -> Path:
    """Create the agent directory with all markdown + config. Raises if exists."""
    if not isinstance(spec, AgentSpec):
        raise TypeError("spec must be an AgentSpec instance.")

    _validate_spec(spec)

    name = spec.name
    provider = spec.provider.strip()
    model = spec.model.strip()
    system_focus = spec.system_focus.strip()
    enabled_categories = list(spec.enabled_categories)
    auto_approve = spec.auto_approve.strip()

    root = agent_dir(name)
    if root.exists():
        raise FileExistsError(f"Agent {name!r} already exists at {root}.")

    AGENTS_HOME.mkdir(parents=True, exist_ok=True)

    created_root = False
    try:
        root.mkdir(exist_ok=False)
        created_root = True

        memory_dir = root / "memory"
        sessions_dir = memory_dir / "sessions"
        memory_dir.mkdir()
        sessions_dir.mkdir()

        files: list[tuple[Path, str, int | None]] = [
            (root / "SOUL.md", SOUL_TEMPLATE.format(system_focus=system_focus), None),
            (root / "IDENTITY.md", IDENTITY_TEMPLATE.format(name=name), None),
            (root / "TOOLS.md", TOOLS_TEMPLATE, None),
            (root / "BOOTSTRAP.md", BOOTSTRAP_TEMPLATE, None),
            (root / "AGENTS.md", AGENTS_TEMPLATE, None),
        ]

        for path, content, mode in files:
            _write_text_atomic(path, content, mode=mode)

        config = {
            "agent": {
                "name": name,
                "provider": provider,
                "model": model,
                "system_focus": system_focus,
            },
            "memory": {
                "helix_db": "memory/helix.db",
                "drawers_db": "memory/drawers.db",
                "sessions_dir": "memory/sessions",
            },
            "tools": {
                "enabled_categories": enabled_categories,
                "auto_approve": auto_approve,
            },
        }
        _write_yaml_atomic(root / "config.yaml", config, mode=0o600)

        return root
    except Exception:
        if created_root:
            shutil.rmtree(root, ignore_errors=True)
        raise


def _validate_spec(spec: AgentSpec) -> None:
    validate_name(spec.name)

    if not isinstance(spec.provider, str):
        raise TypeError("provider must be a string.")
    if spec.provider.strip() not in _ALLOWED_PROVIDERS:
        raise ValueError(
            f"Unsupported provider {spec.provider!r}. "
            f"Expected one of: {sorted(_ALLOWED_PROVIDERS)}."
        )

    if not isinstance(spec.model, str) or not spec.model.strip():
        raise ValueError("model must be a non-empty string.")

    if not isinstance(spec.system_focus, str) or not spec.system_focus.strip():
        raise ValueError("system_focus must be a non-empty string.")

    if not isinstance(spec.enabled_categories, list):
        raise TypeError("enabled_categories must be a list of strings.")

    seen: set[str] = set()
    for category in spec.enabled_categories:
        if not isinstance(category, str):
            raise TypeError("enabled_categories must contain only strings.")
        if category not in _ALLOWED_CATEGORIES:
            raise ValueError(
                f"Unsupported tool category {category!r}. "
                f"Expected only: {sorted(_ALLOWED_CATEGORIES)}."
            )
        if category in seen:
            raise ValueError(f"Duplicate tool category {category!r} is not allowed.")
        seen.add(category)

    if not isinstance(spec.auto_approve, str):
        raise TypeError("auto_approve must be a string.")
    if spec.auto_approve.strip() not in _ALLOWED_AUTO_APPROVE:
        raise ValueError(
            f"Unsupported auto_approve value {spec.auto_approve!r}. "
            f"Expected one of: {sorted(_ALLOWED_AUTO_APPROVE)}."
        )


def _write_yaml_atomic(path: Path, data: dict, *, mode: int | None = None) -> None:
    text = yaml.safe_dump(
        data,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )
    if not text.endswith("\n"):
        text += "\n"
    _write_text_atomic(path, text, mode=mode)


def _write_text_atomic(path: Path, text: str, *, mode: int | None = None) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())

        if mode is not None:
            os.chmod(tmp_path, mode)

        os.link(tmp_path, path)
        tmp_path.unlink()
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
        raise
