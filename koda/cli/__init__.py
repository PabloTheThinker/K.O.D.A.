"""K.O.D.A. CLI entry — a small REPL that wires provider + registry + approvals + session + loop."""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path

from ..adapters import create_provider
from ..agent.loop import TurnLoop, TurnOptions
from ..session.store import SessionStore
from ..tools import builtins as _builtins  # triggers tool registration
from ..tools.approval import ApprovalPolicy
from ..tools.registry import RiskLevel, global_registry

_ = _builtins

KODA_HOME = Path(os.environ.get("KODA_HOME", Path.home() / ".koda"))
APPROVALS_PATH = KODA_HOME / "approvals.json"
SESSIONS_DB = KODA_HOME / "sessions.db"

_BANNER = r"""
  K.O.D.A. — Kinetic Operative Defense Agent
"""


def _pick_provider() -> tuple[str, dict]:
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
    provider_name, provider_cfg = _pick_provider()
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
        print("usage: koda              start the REPL")
        print("       koda --help       show this message")
        print("env: KODA_PROVIDER (anthropic|claude_cli|ollama), KODA_MODEL, ANTHROPIC_API_KEY")
        return 0
    return asyncio.run(_repl())


if __name__ == "__main__":
    raise SystemExit(main())
