"""K.O.D.A. CLI entry — REPL + first-run wizard dispatch."""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path

from ..adapters import create_provider
from ..agent.loop import TurnLoop, TurnOptions
from ..config import CONFIG_PATH, KODA_HOME, config_exists, load_config
from ..session.store import SessionStore
from ..tools import builtins as _builtins  # triggers tool registration
from ..tools.approval import ApprovalPolicy
from ..tools.registry import RiskLevel, global_registry
from .wizard import run_setup_wizard

_ = _builtins

APPROVALS_PATH = KODA_HOME / "approvals.json"
SESSIONS_DB = KODA_HOME / "sessions.db"
SECRETS_ENV = KODA_HOME / "secrets.env"

_BANNER = r"""
  K.O.D.A. — Kinetic Operative Defense Agent
"""


def _load_secrets_env() -> None:
    """Load ~/.koda/secrets.env into os.environ (does NOT override existing vars)."""
    if not SECRETS_ENV.exists():
        return
    try:
        for line in SECRETS_ENV.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except OSError:
        pass


def _pick_provider_from_config(config: dict) -> tuple[str, dict]:
    name = config.get("default_provider") or ""
    providers = config.get("provider") or {}
    if name and name in providers:
        return name, dict(providers[name])
    return _pick_provider_auto()


def _pick_provider_auto() -> tuple[str, dict]:
    explicit = os.environ.get("KODA_PROVIDER", "").lower().strip()
    if explicit:
        return explicit, {"model": os.environ.get("KODA_MODEL", "")}
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", {"model": os.environ.get("KODA_MODEL") or "claude-sonnet-4-6"}
    if shutil.which("claude"):
        return "claude_cli", {"model": os.environ.get("KODA_MODEL", "")}
    return "ollama", {"model": os.environ.get("KODA_MODEL") or "qwen3:14b"}


async def _repl() -> int:
    KODA_HOME.mkdir(parents=True, exist_ok=True)
    _load_secrets_env()

    if not config_exists():
        print("no config found — starting first-run setup.\n")
        run_setup_wizard()
        _load_secrets_env()

    config = load_config()
    provider_name, provider_cfg = _pick_provider_from_config(config)
    provider = create_provider(provider_name, provider_cfg)
    registry = global_registry()
    approvals = ApprovalPolicy(approvals_path=APPROVALS_PATH, auto_approve_threshold=RiskLevel.SAFE)
    session = SessionStore(SESSIONS_DB)
    session_id = session.create(title="interactive")

    loop = TurnLoop(
        provider=provider,
        registry=registry,
        approvals=approvals,
        session=session,
        session_id=session_id,
    )

    print(_BANNER)
    print(f"provider: {provider_name}   model: {provider.get_model()}")
    print(f"tools:    {', '.join(registry.names())}")
    print(f"session:  {session_id}")
    print("type a question, or /exit to quit.\n")

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
        if prompt in {"/setup", "/wizard"}:
            run_setup_wizard()
            continue

        trace = await loop.run(prompt, TurnOptions())
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


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] in {"-h", "--help"}:
        print(_BANNER)
        print("usage: koda               start the REPL (runs setup on first run)")
        print("       koda setup         re-run the setup wizard")
        print("       koda doctor        show config + provider status")
        print("       koda mcp           start MCP server (expose tools to other agents)")
        print("       koda --help        show this message")
        print("env: KODA_PROVIDER (anthropic|claude_cli|ollama), KODA_MODEL, ANTHROPIC_API_KEY, KODA_HOME")
        return 0
    if argv and argv[0] == "setup":
        KODA_HOME.mkdir(parents=True, exist_ok=True)
        run_setup_wizard()
        return 0
    if argv and argv[0] == "doctor":
        return _doctor()
    if argv and argv[0] == "mcp":
        from ..mcp.server import main as mcp_main
        return mcp_main(argv[1:])
    return asyncio.run(_repl())


def _doctor() -> int:
    KODA_HOME.mkdir(parents=True, exist_ok=True)
    _load_secrets_env()
    print(f"KODA_HOME:  {KODA_HOME}")
    print(f"config:     {CONFIG_PATH}  {'(found)' if config_exists() else '(missing — run: koda setup)'}")
    if config_exists():
        cfg = load_config()
        print(f"provider:   {cfg.get('default_provider', '(unset)')}")
        providers = cfg.get("provider") or {}
        for name, pc in providers.items():
            print(f"  - {name}: {pc}")
    print(f"anthropic_key: {'yes' if os.environ.get('ANTHROPIC_API_KEY') else 'no'}")
    print(f"claude CLI:    {shutil.which('claude') or 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
