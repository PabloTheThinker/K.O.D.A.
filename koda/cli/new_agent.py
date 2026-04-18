"""`koda new <name>` — interactive wizard to scaffold an OpenClaw-style agent.

Builds a standalone agent directory under ~/.koda/agents/<name>/ with
SOUL.md, IDENTITY.md, TOOLS.md, BOOTSTRAP.md, AGENTS.md, config.yaml, and
memory/sessions/. Name is fixed at creation — no rename.
"""
from __future__ import annotations

import os
import shutil
import sys

from ..agents import AgentSpec, agent_exists, list_agents, scaffold_agent, validate_name

_CATEGORIES = [
    ("fs", "filesystem — list/read files"),
    ("scan", "security scanners — semgrep, trivy, bandit, gitleaks, SARIF"),
    ("net", "network — port scan, SSL audit, HTTP headers, DNS"),
    ("host", "host health — auth log, file integrity, dep CVE, fail2ban"),
]

_PROVIDERS = [
    ("anthropic", "claude via API (needs ANTHROPIC_API_KEY)"),
    ("claude_cli", "claude CLI on PATH"),
    ("ollama", "local ollama (needs ollama serve running)"),
]

_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-6",
    "claude_cli": "",
    "ollama": "qwen3:14b",
}


def _banner(name: str) -> None:
    print()
    print("  K.O.D.A. — new agent scaffold")
    print(f"  name: {name}  (fixed — cannot be changed later)")
    print()


def _prompt(question: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        raw = input(f"{question}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(130)
    return raw or default


def _choose(question: str, options: list[tuple[str, str]], default_key: str) -> str:
    print(f"\n{question}")
    keys = []
    for key, desc in options:
        marker = "*" if key == default_key else " "
        print(f"  {marker} {key:<12}  {desc}")
        keys.append(key)
    while True:
        raw = _prompt("  choice", default_key)
        if raw in keys:
            return raw
        print(f"  not recognized. pick one of: {', '.join(keys)}")


def _multichoice(question: str, options: list[tuple[str, str]], defaults: list[str]) -> list[str]:
    print(f"\n{question}  (comma-separated; enter for defaults)")
    keys = []
    for key, desc in options:
        marker = "*" if key in defaults else " "
        print(f"  {marker} {key:<8}  {desc}")
        keys.append(key)
    default_str = ",".join(defaults)
    while True:
        raw = _prompt("  enabled", default_str)
        picks = [p.strip() for p in raw.split(",") if p.strip()]
        unknown = [p for p in picks if p not in keys]
        if unknown:
            print(f"  unknown category: {', '.join(unknown)}")
            continue
        if not picks:
            print("  at least one category must be enabled.")
            continue
        seen: set[str] = set()
        deduped: list[str] = []
        for p in picks:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        return deduped


def _default_provider() -> str:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if shutil.which("claude"):
        return "claude_cli"
    return "ollama"


def _run_wizard(name: str) -> int:
    try:
        validate_name(name)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if agent_exists(name):
        print(f"error: agent {name!r} already exists.", file=sys.stderr)
        print(f"       see: koda agents list", file=sys.stderr)
        return 1

    _banner(name)

    provider = _choose("provider", _PROVIDERS, _default_provider())
    default_model = _DEFAULT_MODELS.get(provider, "")
    model = _prompt("model", default_model)
    if not model and provider != "claude_cli":
        print("error: model is required for this provider.", file=sys.stderr)
        return 2
    if not model:
        model = "default"

    print()
    focus = _prompt(
        "what should this agent focus on (one sentence)",
        "general-purpose security operations",
    )

    categories = _multichoice(
        "tool categories",
        _CATEGORIES,
        defaults=["fs", "scan", "net", "host"],
    )

    auto_approve = _choose(
        "auto-approve threshold (tools at or below this risk run without prompting)",
        [
            ("safe", "only SAFE tools auto-approved (recommended)"),
            ("sensitive", "SAFE + SENSITIVE auto-approved"),
            ("dangerous", "everything auto-approved (danger zone)"),
            ("none", "always prompt"),
        ],
        "safe",
    )

    spec = AgentSpec(
        name=name,
        provider=provider,
        model=model,
        system_focus=focus,
        enabled_categories=categories,
        auto_approve=auto_approve,
    )

    try:
        root = scaffold_agent(spec)
    except (ValueError, TypeError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print()
    print(f"  agent scaffolded at: {root}")
    print()
    print("  files:")
    print("    SOUL.md       — personality / core truths")
    print("    IDENTITY.md   — first-run dialog target (fill in during bootstrap)")
    print("    TOOLS.md      — local env notes")
    print("    BOOTSTRAP.md  — delete after first-run conversation")
    print("    AGENTS.md     — workspace orientation")
    print("    config.yaml   — provider, model, tool permissions")
    print("    memory/       — helix + drawers DBs created on first write")
    print()
    print(f"  next: koda run {name}")
    print()
    return 0


def _cmd_agents(argv: list[str]) -> int:
    sub = argv[0] if argv else "list"
    if sub in {"list", "ls"}:
        names = list_agents()
        if not names:
            print("no agents scaffolded yet. create one with: koda new <name>")
            return 0
        for n in names:
            print(n)
        return 0
    print(f"unknown agents subcommand: {sub}", file=sys.stderr)
    print("usage: koda agents list", file=sys.stderr)
    return 2


def cmd_new(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage: koda new <agent-name>")
        print("  scaffolds a standalone agent under ~/.koda/agents/<name>/")
        print("  name rules: ^[a-z][a-z0-9_-]{1,31}$ — fixed at creation, no rename.")
        return 0
    name = argv[0]
    return _run_wizard(name)


def cmd_agents(argv: list[str]) -> int:
    return _cmd_agents(argv)
