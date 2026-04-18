"""K.O.D.A. CLI entry.

Profile isolation pattern (ported from Hermes agent):

  1. Stdlib-only module-level code so we can intercept ``--profile/-p``
     BEFORE any koda modules are imported (module constants in config.py
     bind KODA_HOME at import time).
  2. ``_apply_profile_override()`` pre-parses sys.argv, resolves the
     profile to a directory, sets ``os.environ['KODA_HOME']``, and strips
     the flag so argparse/main() never see it.
  3. Sticky default via ``~/.koda/active_profile`` — a plain-text file
     containing the profile name.

Subcommands:
  koda                    start REPL (first run → setup wizard)
  koda setup              (re)run setup wizard
  koda doctor             show config + provider status
  koda mcp                start MCP server
  koda profile <cmd>      list|create|use|delete|show
  koda -p <name> ...      run anything under a named profile
"""
from __future__ import annotations

import os
import sys


def _apply_profile_override() -> None:
    """Pre-parse --profile/-p; set KODA_HOME before any koda imports.

    Falls back to sticky default at ~/.koda/active_profile.
    """
    argv = sys.argv[1:]
    profile_name: str | None = None
    consume = 0
    flag_idx = -1

    for i, arg in enumerate(argv):
        if arg in ("--profile", "-p") and i + 1 < len(argv):
            profile_name = argv[i + 1]
            consume = 2
            flag_idx = i
            break
        if arg.startswith("--profile="):
            profile_name = arg.split("=", 1)[1]
            consume = 1
            flag_idx = i
            break

    # Sticky default: read without importing koda.profiles (can't import
    # yet — would drag config.py transitively). Minimal inline reader.
    if profile_name is None:
        try:
            active = _default_koda_root() / "active_profile"
            if active.exists():
                name = active.read_text(encoding="utf-8").strip()
                if name and name != "default":
                    profile_name = name
        except (OSError, UnicodeDecodeError):
            pass

    if profile_name is None:
        return

    # Resolve — now safe to import koda.profiles (it doesn't import config).
    try:
        from ..profiles import resolve_profile_env
        koda_home = resolve_profile_env(profile_name)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 — must not prevent startup
        print(f"warning: profile override failed ({exc}); using default", file=sys.stderr)
        return

    os.environ["KODA_HOME"] = koda_home

    if consume > 0 and flag_idx >= 0:
        start = flag_idx + 1  # +1 for sys.argv[0]
        sys.argv = sys.argv[:start] + sys.argv[start + consume:]


def _default_koda_root():
    from pathlib import Path
    env = os.environ.get("KODA_DEFAULT_HOME")
    if env:
        return Path(env)
    return Path.home() / ".koda"


_apply_profile_override()


_BANNER = r"""
  K.O.D.A. — Kinetic Operative Defense Agent
"""


def _load_secrets_env() -> None:
    """Load <KODA_HOME>/secrets.env into os.environ (doesn't override)."""
    from ..config import KODA_HOME
    path = KODA_HOME / "secrets.env"
    if not path.exists():
        return
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
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
    import shutil
    explicit = os.environ.get("KODA_PROVIDER", "").lower().strip()
    if explicit:
        return explicit, {"model": os.environ.get("KODA_MODEL", "")}
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", {"model": os.environ.get("KODA_MODEL") or "claude-sonnet-4-6"}
    if shutil.which("claude"):
        return "claude_cli", {"model": os.environ.get("KODA_MODEL", "")}
    return "ollama", {"model": os.environ.get("KODA_MODEL") or "qwen3:14b"}


async def _repl() -> int:
    from ..adapters import create_provider
    from ..agent.loop import TurnLoop, TurnOptions
    from ..audit import AuditLogger
    from ..auth import CredentialBroker
    from ..config import KODA_HOME, config_exists, load_config
    from ..evidence import EvidenceStore
    from ..profiles import read_active_profile, seed_default_soul
    from ..session.store import SessionStore
    from ..tools import builtins as _builtins  # noqa: F401 — registers tools
    from ..tools.approval import ApprovalPolicy
    from ..tools.registry import RiskLevel, global_registry
    from .wizard import run_setup_wizard

    KODA_HOME.mkdir(parents=True, exist_ok=True)
    _load_secrets_env()

    if not config_exists():
        print("no config found — starting first-run setup.\n")
        run_setup_wizard()
        _load_secrets_env()

    seed_default_soul(KODA_HOME)

    config = load_config()
    provider_name, provider_cfg = _pick_provider_from_config(config)
    provider = create_provider(provider_name, provider_cfg)
    registry = global_registry()

    active = read_active_profile()
    profile_label = active or "default"
    engagement = os.environ.get("KODA_ENGAGEMENT", "").strip() or "default"

    audit = AuditLogger(profile=profile_label)
    evidence = EvidenceStore()
    credentials = CredentialBroker(audit=audit)

    approvals = ApprovalPolicy(
        approvals_path=KODA_HOME / "approvals.json",
        auto_approve_threshold=RiskLevel.SAFE,
        audit=audit,
    )
    session = SessionStore(KODA_HOME / "sessions.db")
    session_id = session.create(title="interactive", engagement=engagement)
    audit.emit("session.open", session_id=session_id, engagement=engagement, profile=profile_label)

    loop = TurnLoop(
        provider=provider,
        registry=registry,
        approvals=approvals,
        session=session,
        session_id=session_id,
        engagement=engagement,
        audit=audit,
        evidence=evidence,
        credentials=credentials,
    )

    print(_BANNER)
    print(f"profile:    {profile_label}")
    print(f"engagement: {engagement}")
    print(f"home:       {KODA_HOME}")
    print(f"provider:   {provider_name}   model: {provider.get_model()}")
    print(f"tools:      {', '.join(registry.names())}")
    print(f"session:    {session_id}")
    print("type a question, or /exit to quit.\n")

    while True:
        try:
            prompt = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            audit.emit("session.close", session_id=session_id, engagement=engagement)
            audit.close()
            return 0
        if not prompt:
            continue
        if prompt in {"/exit", "/quit", "/q"}:
            audit.emit("session.close", session_id=session_id, engagement=engagement)
            audit.close()
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


def _cmd_profile(argv: list[str]) -> int:
    from ..profiles import (
        create_profile, delete_profile, list_profiles,
        profile_exists, read_active_profile, use_profile,
    )

    if not argv or argv[0] in {"-h", "--help"}:
        print("usage:")
        print("  koda profile list")
        print("  koda profile create <name> [--clone | --clone-all]")
        print("  koda profile use <name>")
        print("  koda profile delete <name>")
        print("  koda profile show")
        return 0

    sub = argv[0]
    rest = argv[1:]

    if sub in {"list", "ls"}:
        profiles = list_profiles()
        if not profiles:
            print("no profiles found (default profile missing)")
            return 0
        active = read_active_profile()
        width = max(len(p.name) for p in profiles)
        for p in profiles:
            marker = "*" if (p.name == "default" and active is None) or p.name == active else " "
            flags = []
            if p.has_config:
                flags.append("config")
            if p.has_secrets:
                flags.append("secrets")
            if p.has_soul:
                flags.append("soul")
            meta = f"{p.provider}:{p.model}" if p.provider else "(no provider)"
            print(f"  {marker} {p.name:<{width}}  {meta:<28}  [{' '.join(flags) or 'empty'}]")
            print(f"      {p.path}")
        return 0

    if sub == "create":
        if not rest:
            print("usage: koda profile create <name> [--clone | --clone-all]", file=sys.stderr)
            return 2
        name = rest[0]
        clone_config = "--clone" in rest[1:]
        clone_all = "--clone-all" in rest[1:]
        try:
            path = create_profile(name, clone_config=clone_config, clone_all=clone_all)
        except (ValueError, FileExistsError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"created profile {name!r} at {path}")
        print(f"next: koda -p {name}    (or: koda profile use {name})")
        return 0

    if sub == "use":
        if not rest:
            print("usage: koda profile use <name>", file=sys.stderr)
            return 2
        name = rest[0]
        try:
            use_profile(name)
        except (ValueError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if name == "default":
            print("cleared sticky profile — using default")
        else:
            print(f"sticky profile set to {name!r}")
        return 0

    if sub in {"delete", "rm"}:
        if not rest:
            print("usage: koda profile delete <name>", file=sys.stderr)
            return 2
        name = rest[0]
        if not profile_exists(name):
            print(f"error: profile {name!r} not found", file=sys.stderr)
            return 1
        try:
            path = delete_profile(name)
        except (ValueError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"deleted {path}")
        return 0

    if sub == "show":
        from ..config import KODA_HOME
        print(f"KODA_HOME:      {KODA_HOME}")
        print(f"active_profile: {read_active_profile() or 'default'}")
        return 0

    print(f"unknown profile subcommand: {sub}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    import asyncio
    argv = argv if argv is not None else sys.argv[1:]

    if argv and argv[0] in {"-h", "--help"}:
        print(_BANNER)
        print("usage: koda                   start REPL (runs setup on first run)")
        print("       koda setup             (re)run the setup wizard")
        print("       koda doctor            show config + provider status")
        print("       koda mcp               start MCP server (expose tools)")
        print("       koda profile <cmd>     list | create | use | delete | show")
        print("       koda -p <name> ...     use a named profile for this command")
        print()
        print("env: KODA_PROVIDER, KODA_MODEL, ANTHROPIC_API_KEY, KODA_HOME, KODA_DEFAULT_HOME")
        return 0

    if argv and argv[0] == "setup":
        from ..config import KODA_HOME
        from ..profiles import seed_default_soul
        from .wizard import run_setup_wizard
        KODA_HOME.mkdir(parents=True, exist_ok=True)
        run_setup_wizard()
        seed_default_soul(KODA_HOME)
        return 0

    if argv and argv[0] == "doctor":
        return _doctor()

    if argv and argv[0] == "mcp":
        from ..mcp.server import main as mcp_main
        return mcp_main(argv[1:])

    if argv and argv[0] in {"profile", "profiles"}:
        return _cmd_profile(argv[1:])

    return asyncio.run(_repl())


def _doctor() -> int:
    import shutil
    from ..config import CONFIG_PATH, KODA_HOME, config_exists, load_config
    from ..profiles import read_active_profile

    KODA_HOME.mkdir(parents=True, exist_ok=True)
    _load_secrets_env()

    print(f"active:        {read_active_profile() or 'default'}")
    print(f"KODA_HOME:     {KODA_HOME}")
    print(f"config:        {CONFIG_PATH}  {'(found)' if config_exists() else '(missing — run: koda setup)'}")
    print(f"SOUL.md:       {'found' if (KODA_HOME/'SOUL.md').exists() else 'missing'}")
    print(f"secrets.env:   {'found' if (KODA_HOME/'secrets.env').exists() else 'missing'}")
    if config_exists():
        cfg = load_config()
        print(f"provider:      {cfg.get('default_provider', '(unset)')}")
        providers = cfg.get("provider") or {}
        for name, pc in providers.items():
            print(f"  - {name}: {pc}")
    print(f"anthropic_key: {'yes' if os.environ.get('ANTHROPIC_API_KEY') else 'no'}")
    print(f"claude CLI:    {shutil.which('claude') or 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
