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
  koda                        start REPL (first run → setup wizard)
  koda setup                  (re)run setup wizard
  koda doctor                 show config + provider status
  koda mcp                    start MCP server
  koda new --template <t> <n> scaffold a new engagement from a template
  koda use <name>             activate an engagement
  koda profile <cmd>          list|create|use|delete|show
  koda -p <name> ...          run anything under a named profile
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


def _cmd_use(argv: list[str]) -> int:
    """Activate a named engagement (writes active_engagement file)."""
    from ..config import KODA_HOME

    if not argv or argv[0] in {"-h", "--help"}:
        print("usage: koda use <engagement-name>")
        print()
        print("  Writes <name> to KODA_HOME/active_engagement so the next")
        print("  `koda` session picks it up automatically.")
        print()
        print("  koda use default   — reset to the default engagement")
        return 0

    name = argv[0]
    active_file = KODA_HOME / "active_engagement"
    eng_dir = KODA_HOME / "engagements" / name

    if name != "default" and not eng_dir.is_dir():
        print(
            f"error: engagement {name!r} not found at {eng_dir}\n"
            "       create it first with: koda new --template <template> <name>",
            file=sys.stderr,
        )
        return 1

    try:
        KODA_HOME.mkdir(parents=True, exist_ok=True)
        active_file.write_text(name + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"error: could not write active_engagement: {exc}", file=sys.stderr)
        return 1

    print(f"active engagement set to {name!r}")
    if name != "default":
        print(f"  path: {eng_dir}")
    return 0


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


_REPL_HELP = """
commands:
  /help                    this help
  /new, /reset             start a fresh session (clears memory)
  /status                  show session + provider stats
  /model [id]              show or switch model
  /models                  list models advertised by the provider
  /history [n=5]           show last n turns in this session
  /setup, /wizard          (re)run the setup wizard
  /exit, /quit, /q         exit the REPL
""".strip()


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
    from ..tools.approval import ApprovalPolicy, threshold_from_config
    from ..tools.registry import global_registry
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
    engagement = os.environ.get("KODA_ENGAGEMENT", "").strip() or \
        config.get("engagement", {}).get("default", "default")

    audit = AuditLogger(profile=profile_label)
    evidence = EvidenceStore()
    credentials = CredentialBroker(audit=audit)

    threshold = threshold_from_config(config)
    approvals = ApprovalPolicy(
        approvals_path=KODA_HOME / "approvals.json",
        auto_approve_threshold=threshold,
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

    stats = {"turns": 0, "tool_calls": 0}
    approval_tier = config.get("approvals", {}).get("auto_approve", "all")

    print(_BANNER)
    print(f"profile:    {profile_label}")
    print(f"engagement: {engagement}")
    print(f"home:       {KODA_HOME}")
    print(f"provider:   {provider_name}   model: {provider.get_model()}")
    print(f"approvals:  {approval_tier}  (threshold: {threshold.value})")
    print(f"tools:      {', '.join(registry.names())}")
    print(f"session:    {session_id}")
    print("type a question, or /help for commands.\n")

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

        if prompt.startswith("/"):
            cmd, _, arg = prompt.partition(" ")
            cmd = cmd.lower()
            arg = arg.strip()

            if cmd in {"/exit", "/quit", "/q"}:
                audit.emit("session.close", session_id=session_id, engagement=engagement)
                audit.close()
                return 0
            if cmd in {"/setup", "/wizard"}:
                run_setup_wizard()
                continue
            if cmd == "/help":
                print(_REPL_HELP + "\n")
                continue
            if cmd == "/status":
                print(
                    f"  turns: {stats['turns']}  tool_calls: {stats['tool_calls']}\n"
                    f"  session: {session_id}  engagement: {engagement}\n"
                    f"  provider: {provider_name}  model: {provider.get_model()}\n"
                    f"  approvals: {approval_tier} ({threshold.value})\n"
                )
                continue
            if cmd in {"/new", "/reset"}:
                session_id = session.create(title="interactive", engagement=engagement)
                loop.session_id = session_id
                stats["turns"] = 0
                stats["tool_calls"] = 0
                audit.emit("session.open", session_id=session_id, engagement=engagement,
                           profile=profile_label, reason=cmd)
                print(f"  new session: {session_id}\n")
                continue
            if cmd == "/model":
                if not arg:
                    print(f"  current model: {provider.get_model()}\n")
                elif hasattr(provider, "set_model"):
                    try:
                        provider.set_model(arg)  # type: ignore[attr-defined]
                        audit.emit("repl.model_switch", model=arg)
                        print(f"  model now: {arg}\n")
                    except Exception as exc:  # noqa: BLE001
                        print(f"  switch failed: {exc}\n")
                else:
                    print("  provider does not support runtime model switching\n")
                continue
            if cmd == "/models":
                listed = getattr(provider, "list_models", None)
                if not callable(listed):
                    print("  provider does not advertise a model list\n")
                    continue
                try:
                    names = list(listed())
                except Exception as exc:  # noqa: BLE001
                    print(f"  list failed: {exc}\n")
                    continue
                if not names:
                    print("  no models listed\n")
                else:
                    print("  " + "\n  ".join(names[:50]) + "\n")
                continue
            if cmd == "/history":
                try:
                    limit = int(arg) if arg else 5
                except ValueError:
                    limit = 5
                try:
                    msgs = session.messages(session_id)
                except Exception as exc:  # noqa: BLE001
                    print(f"  history error: {exc}\n")
                    continue
                user_msgs = [m for m in msgs if getattr(m, "role", "") == "user"]
                if not user_msgs:
                    print("  no prior turns in this session\n")
                    continue
                for m in user_msgs[-limit:]:
                    body = str(getattr(m, "content", ""))[:120].replace("\n", " ")
                    print(f"  • {body}")
                print()
                continue

            print(f"  unknown command: {cmd}  — /help for list\n")
            continue

        trace = await loop.run(prompt, TurnOptions())
        stats["turns"] += 1
        stats["tool_calls"] += trace.tool_calls_made
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
        create_profile,
        delete_profile,
        list_profiles,
        profile_exists,
        read_active_profile,
        use_profile,
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

    if argv and argv[0] in {"-V", "--version", "version"}:
        from .. import __version__
        print(f"koda {__version__}")
        return 0

    if argv and argv[0] in {"-h", "--help"}:
        from .. import __version__
        print(_BANNER)
        print(f"K.O.D.A. {__version__}")
        print()
        print("usage: koda                        start REPL (runs setup on first run)")
        print("       koda setup                  (re)run the setup wizard")
        print("       koda doctor                 show config + provider status")
        print("       koda mcp                    start MCP server (expose tools)")
        print("       koda telegram               start the Telegram bridge daemon")
        print("       koda intel <cmd>            sync | status | lookup | search threat intel")
        print("       koda report <cmd>           generate | stats security reports")
        print("       koda audit --preset <n>     run a mission preset end-to-end")
        print("       koda audit --list-presets   list all available mission presets")
        print("       koda new --template <t> <n> scaffold an engagement from a template")
        print("       koda new --list-templates   list available templates")
        print("       koda use <name>             activate an engagement")
        print("       koda scan remote <target>   scan a remote host over SSH (ControlMaster)")
        print("       koda schedule add|list|run  scheduled monitoring + diff alerts")
        print("       koda tools [--toolset x]    list registered tools by toolset")
        print("       koda plugins                list user plugins in $KODA_HOME/plugins/")
        print("       koda remote push|pull|list  sync evidence bundles to/from S3/R2/MinIO")
        print("       koda update                 pull + install the latest release")
        print("       koda check                  run repo linter + tests (pre-push hygiene)")
        print("       koda learn <cmd>            promote Helix concepts → skill drafts")
        print("       koda uninstall              remove K.O.D.A. (interactive checklist)")
        print("       koda profile <cmd>          list | create | use | delete | show")
        print("       koda version                print version and exit")
        print("       koda -p <name> ...          use a named profile for this command")
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

    if argv and argv[0] == "telegram":
        _load_secrets_env()
        from ..notify.telegram_daemon import main as telegram_main
        return telegram_main(argv[1:])

    if argv and argv[0] == "intel":
        from .intel import main as intel_main
        return intel_main(argv[1:])

    if argv and argv[0] == "report":
        from .report import main as report_main
        return report_main(argv[1:])

    if argv and argv[0] == "audit":
        from .audit import main as audit_main
        return audit_main(argv[1:])

    if argv and argv[0] == "update":
        return _cmd_update(argv[1:])

    if argv and argv[0] == "check":
        return _cmd_check(argv[1:])

    if argv and argv[0] == "learn":
        from .learn import main as learn_main
        return learn_main(argv[1:])

    if argv and argv[0] == "uninstall":
        return _cmd_uninstall(argv[1:])

    if argv and argv[0] == "new":
        from .new import main as new_main
        return new_main(argv[1:])

    if argv and argv[0] == "use":
        return _cmd_use(argv[1:])

    if argv and argv[0] in {"profile", "profiles"}:
        return _cmd_profile(argv[1:])

    if argv and argv[0] == "remote":
        from .remote import main as remote_main
        return remote_main(argv[1:])

    if argv and argv[0] == "scan":
        from .scan import main as scan_main
        return scan_main(argv[1:])

    if argv and argv[0] == "schedule":
        from .schedule import main as schedule_main
        return schedule_main(argv[1:])

    if argv and argv[0] == "tools":
        return _cmd_tools(argv[1:])

    if argv and argv[0] == "plugins":
        return _cmd_plugins(argv[1:])

    return asyncio.run(_repl())


def _cmd_plugins(argv: list[str]) -> int:
    """List user plugins discovered under ``$KODA_HOME/plugins/``.

    User plugins are plain ``.py`` files (or packages) that self-register tools
    at import time. Drop one in and it shows up at next invocation — no edits
    to the KODA source required.
    """
    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda plugins")
        print()
        print("  Lists .py files and packages found under $KODA_HOME/plugins/")
        print("  and the tools each registered at load time.")
        return 0

    from ..config import KODA_HOME
    from ..tools import builtins as _builtins  # noqa: F401 — triggers registration
    from ..tools.registry import global_registry

    plugin_dir = KODA_HOME / "plugins"
    print(f"plugin dir: {plugin_dir}")
    if not plugin_dir.is_dir():
        print("  (directory does not exist — create it and drop .py files in)")
        return 0

    loaded = list(_builtins._LOADED_PLUGINS)
    if not loaded:
        print("  (no plugins found)")
        return 0

    # Every tool whose handler lives under koda_user_plugins.* came from a
    # plugin — group by plugin stem so we can show who registered what.
    registry = global_registry()
    plugin_tools: dict[str, list[str]] = {stem: [] for stem in loaded}
    for tool_name in registry.names():
        tool = registry.get(tool_name)
        if tool is None:
            continue
        mod_name = getattr(tool.handler, "__module__", "")
        if not mod_name.startswith("koda_user_plugins."):
            continue
        stem = mod_name.split(".", 2)[1]
        plugin_tools.setdefault(stem, []).append(tool_name)

    print(f"{len(loaded)} plugin(s):\n")
    width = max(len(s) for s in loaded)
    for stem in loaded:
        tools = sorted(plugin_tools.get(stem, []))
        shown = ", ".join(tools) if tools else "(no tools registered)"
        print(f"  {stem:<{width}}  {shown}")
    return 0


def _cmd_tools(argv: list[str]) -> int:
    """List registered tools grouped by toolset.

    Tools self-register at import time. This is the introspection surface so
    operators can see what a session has available without starting the REPL.
    """
    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda tools [--toolset NAME[,NAME...]] [--names]")
        print()
        print("  --toolset  restrict output to the given toolset(s)")
        print("  --names    print bare tool names only, one per line")
        return 0

    wanted: set[str] | None = None
    names_only = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--toolset" and i + 1 < len(argv):
            wanted = {x.strip() for x in argv[i + 1].split(",") if x.strip()}
            i += 2
            continue
        if a.startswith("--toolset="):
            wanted = {x.strip() for x in a.split("=", 1)[1].split(",") if x.strip()}
            i += 1
            continue
        if a == "--names":
            names_only = True
            i += 1
            continue
        print(f"unknown flag: {a}", file=sys.stderr)
        return 2

    from ..tools import builtins as _builtins  # noqa: F401 — triggers registration
    from ..tools.registry import global_registry

    groups = global_registry().toolsets()
    if wanted is not None:
        groups = {ts: tools for ts, tools in groups.items() if ts in wanted}
        missing = wanted - set(groups)
        if missing:
            print(f"unknown toolset(s): {', '.join(sorted(missing))}", file=sys.stderr)
            return 1

    if not groups:
        print("no tools registered.")
        return 0

    if names_only:
        for tools in groups.values():
            for name in tools:
                print(name)
        return 0

    total = sum(len(tools) for tools in groups.values())
    print(f"{total} tool(s) across {len(groups)} toolset(s):\n")
    width = max(len(ts) for ts in groups)
    for ts, tools in groups.items():
        print(f"  [{ts:<{width}}]  {', '.join(tools)}")
    return 0


_INSTALLER_URL = "https://koda.vektraindustries.com/install"


def _cmd_update(argv: list[str]) -> int:
    """Update K.O.D.A. in place.

    Fast path: if the install has a ``.source/`` git clone, fetch, show a
    summary (current → latest, commit count, changelog preview), prompt,
    then ``git pull --ff-only`` and reinstall deps only when pyproject.toml
    actually changed between revisions.

    Fallback (``--installer``): re-run the hosted curl | bash installer —
    slower, but covers exotic install layouts.
    """
    import shutil
    import subprocess
    from pathlib import Path

    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda update [--check] [--yes] [--branch NAME] [--dir PATH]")
        print("                   [--installer] [--url URL] [--force]")
        print()
        print("  --check          check for updates, don't apply them")
        print("  --yes, -y        skip the confirmation prompt")
        print("  --branch NAME    git branch to track (default: main)")
        print("  --dir PATH       install directory (default: auto-detected)")
        print("  --installer      bypass git and re-run the hosted installer")
        print("  --url URL        installer URL (default: hosted)")
        print("  --force          proceed even with uncommitted local changes")
        return 0

    branch = "main"
    install_dir: str | None = None
    url = _INSTALLER_URL
    use_installer = False
    check_only = False
    assume_yes = False
    force = False

    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--branch" and i + 1 < len(argv):
            branch = argv[i + 1]; i += 2; continue
        if a == "--dir" and i + 1 < len(argv):
            install_dir = argv[i + 1]; i += 2; continue
        if a == "--url" and i + 1 < len(argv):
            url = argv[i + 1]; i += 2; continue
        if a == "--installer":
            use_installer = True; i += 1; continue
        if a == "--check":
            check_only = True; i += 1; continue
        if a in ("--yes", "-y"):
            assume_yes = True; i += 1; continue
        if a == "--force":
            force = True; i += 1; continue
        print(f"unknown flag: {a}", file=sys.stderr)
        return 2

    if install_dir is None:
        install_dir = _detect_install_dir()

    source_dir = Path(install_dir) / ".source" if install_dir else None
    has_git_source = (
        source_dir is not None
        and (source_dir / ".git").exists()
        and shutil.which("git") is not None
    )

    if has_git_source and not use_installer:
        return _update_via_git(
            source_dir=source_dir,  # type: ignore[arg-type]
            install_dir=Path(install_dir),  # type: ignore[arg-type]
            branch=branch,
            check_only=check_only,
            assume_yes=assume_yes,
            force=force,
        )

    # ── Installer fallback ────────────────────────────────────────
    if check_only:
        print("--check requires a git-based install; run `koda update --installer` instead.",
              file=sys.stderr)
        return 1

    if not shutil.which("curl"):
        print("error: curl not found on PATH", file=sys.stderr)
        return 1
    if not shutil.which("bash"):
        print("error: bash not found on PATH", file=sys.stderr)
        return 1

    print(f"→ updating K.O.D.A. from {url} (branch: {branch})")
    if install_dir:
        print(f"  install dir: {install_dir}")

    bash_args = ["--no-wizard", "--branch", branch]
    if install_dir:
        bash_args += ["--dir", install_dir]

    cmd = f"curl -fsSL {url} | bash -s -- " + " ".join(
        f"'{a}'" if " " in a else a for a in bash_args
    )
    try:
        result = subprocess.run(cmd, shell=True, check=False)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130

    if result.returncode == 0:
        print("\n✓ update complete — restart any running `koda` sessions.")
    else:
        print(f"\n✗ update failed (rc={result.returncode})", file=sys.stderr)
    return result.returncode


def _detect_install_dir() -> str | None:
    """Auto-detect install dir from sys.prefix (the venv root).

    Don't use sys.executable.resolve() — uv symlinks .venv/bin/python to
    system python, which would send us into /usr.
    """
    from pathlib import Path
    candidate = Path(sys.prefix).parent  # .venv -> {install}
    if (candidate / ".source" / ".git").exists():
        return str(candidate)
    return None


def _git(source_dir, *args: str, check: bool = True):
    import subprocess
    return subprocess.run(
        ["git", "-C", str(source_dir), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _update_via_git(
    *,
    source_dir,
    install_dir,
    branch: str,
    check_only: bool,
    assume_yes: bool,
    force: bool,
) -> int:
    """Git-based fast path — fetch, diff, pull, optionally reinstall."""
    import hashlib
    import subprocess

    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    def _hash(p) -> str | None:
        try:
            return hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            return None

    # ── Pre-flight ────────────────────────────────────────────────
    status = _git(source_dir, "status", "--porcelain", check=False)
    if status.returncode != 0:
        print(f"error: git status failed: {status.stderr.strip()}", file=sys.stderr)
        return 1
    dirty = bool(status.stdout.strip())
    if dirty and not force:
        print(f"{YELLOW}⚠ uncommitted changes in {source_dir}{RESET}", file=sys.stderr)
        print("  stash or commit first, or re-run with --force.", file=sys.stderr)
        return 1

    current_sha = _git(source_dir, "rev-parse", "HEAD", check=False).stdout.strip()
    current_version = _read_version(install_dir / ".source" / "koda" / "__init__.py")

    print(f"→ fetching updates ({BOLD}{branch}{RESET})…")
    fetch = _git(source_dir, "fetch", "--quiet", "origin", branch, check=False)
    if fetch.returncode != 0:
        print(f"error: git fetch failed: {fetch.stderr.strip()}", file=sys.stderr)
        return 1

    remote_sha = _git(source_dir, "rev-parse", f"origin/{branch}", check=False).stdout.strip()
    if not remote_sha:
        print(f"error: could not resolve origin/{branch}", file=sys.stderr)
        return 1

    ahead_behind = _git(
        source_dir, "rev-list", "--left-right", "--count",
        f"HEAD...origin/{branch}", check=False,
    ).stdout.strip().split()
    ahead = int(ahead_behind[0]) if len(ahead_behind) == 2 else 0
    behind = int(ahead_behind[1]) if len(ahead_behind) == 2 else 0

    # ── Summary ───────────────────────────────────────────────────
    def short(s: str) -> str:
        return s[:7] if s else "—"
    print()
    print(f"  {DIM}current:{RESET}  {BOLD}v{current_version or '?'}{RESET}  ({short(current_sha)})")

    if behind == 0 and ahead == 0:
        print(f"  {GREEN}✓ already on latest{RESET}")
        return 0

    # Peek at remote version
    remote_init = _git(
        source_dir, "show", f"origin/{branch}:koda/__init__.py", check=False,
    ).stdout
    remote_version = _extract_version(remote_init) or "?"
    print(f"  {DIM}latest:{RESET}   {BOLD}v{remote_version}{RESET}  ({short(remote_sha)})")

    if ahead > 0 and behind == 0:
        print(f"\n  {YELLOW}⚠ your branch is {ahead} commit(s) ahead of origin/{branch}.{RESET}")
        print("    nothing to pull.")
        return 0

    if ahead > 0 and behind > 0 and not force:
        print(f"\n  {YELLOW}⚠ diverged: {ahead} ahead, {behind} behind origin/{branch}.{RESET}",
              file=sys.stderr)
        print("    resolve manually or re-run with --force (rebases onto remote).",
              file=sys.stderr)
        return 1

    # Dep drift check
    pyproject = source_dir / "pyproject.toml"
    old_pyproject_hash = _hash(pyproject)
    remote_pyproject = _git(
        source_dir, "show", f"origin/{branch}:pyproject.toml", check=False,
    )
    deps_changed = (
        remote_pyproject.returncode == 0
        and old_pyproject_hash is not None
        and hashlib.sha256(remote_pyproject.stdout.encode()).hexdigest() != old_pyproject_hash
    )

    # Files changed + commit count
    files_changed = _git(
        source_dir, "diff", "--name-only", f"HEAD..origin/{branch}", check=False,
    ).stdout.strip().splitlines()

    print(f"\n  {BOLD}{behind}{RESET} commit(s) · {BOLD}{len(files_changed)}{RESET} file(s) changed"
          + (f" · {YELLOW}deps changed{RESET}" if deps_changed else ""))

    # Changelog preview (up to 8)
    log = _git(
        source_dir, "log", "--oneline", "--no-decorate",
        f"HEAD..origin/{branch}", "-n", "8", check=False,
    ).stdout.strip()
    if log:
        print(f"\n  {DIM}recent:{RESET}")
        for line in log.splitlines():
            print(f"    {CYAN}{line}{RESET}")
        if behind > 8:
            print(f"    {DIM}… and {behind - 8} more{RESET}")

    if check_only:
        print(f"\n  run {BOLD}koda update{RESET} to apply.")
        return 0

    # ── Confirm ───────────────────────────────────────────────────
    if not assume_yes:
        print()
        try:
            answer = input("  apply update? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\naborted", file=sys.stderr)
            return 130
        if answer and answer not in ("y", "yes"):
            print("aborted.", file=sys.stderr)
            return 0

    # ── Pull ──────────────────────────────────────────────────────
    print("\n→ pulling…")
    pull_args = ["pull", "--ff-only", "origin", branch]
    if force and ahead > 0 and behind > 0:
        pull_args = ["pull", "--rebase", "origin", branch]
    pull = _git(source_dir, *pull_args, check=False)
    if pull.returncode != 0:
        print(f"error: git pull failed:\n{pull.stderr.strip()}", file=sys.stderr)
        return 1

    # ── Reinstall deps only if pyproject.toml changed ─────────────
    if deps_changed:
        print("→ reinstalling dependencies (pyproject.toml changed)…")
        venv_python = install_dir / ".venv" / "bin" / "python"
        if not venv_python.exists():
            print(f"  {YELLOW}warn: {venv_python} not found — skipping reinstall{RESET}",
                  file=sys.stderr)
        else:
            rc = subprocess.call(
                [str(venv_python), "-m", "pip", "install", "--quiet", "-e", str(source_dir)],
            )
            if rc != 0:
                print(f"error: dependency install failed (rc={rc})", file=sys.stderr)
                return rc

    new_version = _read_version(install_dir / ".source" / "koda" / "__init__.py")
    print()
    if new_version and new_version != current_version:
        print(f"{GREEN}✓{RESET} updated: v{current_version} → {BOLD}v{new_version}{RESET}")
    else:
        print(f"{GREEN}✓{RESET} updated ({short(current_sha)} → {short(remote_sha)})")
    print("  restart any running `koda` sessions.")
    return 0


def _extract_version(init_source: str) -> str | None:
    """Pull __version__ string out of a koda/__init__.py blob."""
    import re
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_source)
    return m.group(1) if m else None


def _read_version(init_path) -> str | None:
    try:
        return _extract_version(init_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return None


def _cmd_check(argv: list[str]) -> int:
    """Run repo linter + tests to verify changes before push.

    Detects project type in the current working directory and runs the
    configured tools:

      * Python (``pyproject.toml`` present): ``ruff check .`` then ``pytest``
        if a ``tests/`` directory exists.
      * JS/TS (``package.json`` present): ``npm run lint`` and ``npm test``
        if those scripts are defined.

    Exits non-zero on the first failure so it composes with shell:
    ``koda check && git push``.
    """
    import shutil
    import subprocess
    from pathlib import Path

    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda check [--lint-only] [--tests-only] [--dir PATH]")
        print("                  [--install-hook] [--uninstall-hook]")
        print()
        print("  --lint-only       skip the test suite")
        print("  --tests-only      skip the linter")
        print("  --dir PATH        run against PATH instead of cwd")
        print("  --install-hook    write a .git/hooks/pre-push calling `koda check`")
        print("  --uninstall-hook  remove the pre-push hook")
        return 0

    lint_only = False
    tests_only = False
    install_hook = False
    uninstall_hook = False
    target_dir: Path | None = None

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--lint-only":
            lint_only = True
        elif arg == "--tests-only":
            tests_only = True
        elif arg == "--install-hook":
            install_hook = True
        elif arg == "--uninstall-hook":
            uninstall_hook = True
        elif arg == "--dir" and i + 1 < len(argv):
            target_dir = Path(argv[i + 1]).resolve()
            i += 1
        else:
            print(f"error: unknown flag {arg!r}", file=sys.stderr)
            print("run `koda check --help` for usage", file=sys.stderr)
            return 2
        i += 1

    root = target_dir or Path.cwd()

    if install_hook or uninstall_hook:
        return _check_manage_hook(root, install=install_hook)

    if lint_only and tests_only:
        print("error: --lint-only and --tests-only are mutually exclusive", file=sys.stderr)
        return 2

    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    has_pyproject = (root / "pyproject.toml").exists()
    has_package_json = (root / "package.json").exists()

    if not has_pyproject and not has_package_json:
        print(f"{YELLOW}⚠ no pyproject.toml or package.json in {root}{RESET}", file=sys.stderr)
        print("  nothing to check.", file=sys.stderr)
        return 1

    def run(label: str, cmd: list[str]) -> int:
        print(f"{DIM}→{RESET} {BOLD}{label}{RESET} {DIM}({' '.join(cmd)}){RESET}")
        result = subprocess.run(cmd, cwd=str(root))
        if result.returncode == 0:
            print(f"  {GREEN}✓ passed{RESET}")
        else:
            print(f"  {RED}✗ failed (exit {result.returncode}){RESET}")
        return result.returncode

    # ── Lint ──────────────────────────────────────────────────────
    if not tests_only:
        if has_pyproject:
            if shutil.which("ruff") is None:
                print(f"{YELLOW}⚠ ruff not installed — skipping lint{RESET}", file=sys.stderr)
            else:
                rc = run("ruff", ["ruff", "check", "."])
                if rc != 0:
                    return rc
        if has_package_json and _npm_has_script(root, "lint"):
            rc = run("npm lint", ["npm", "run", "lint"])
            if rc != 0:
                return rc

    # ── Tests ─────────────────────────────────────────────────────
    if not lint_only:
        if has_pyproject and (root / "tests").is_dir():
            if shutil.which("pytest") is None:
                print(f"{YELLOW}⚠ pytest not installed — skipping tests{RESET}", file=sys.stderr)
            else:
                rc = run("pytest", ["pytest", "-q"])
                if rc != 0:
                    return rc
        if has_package_json and _npm_has_script(root, "test"):
            rc = run("npm test", ["npm", "test", "--silent"])
            if rc != 0:
                return rc

    print()
    print(f"{GREEN}✓ check passed{RESET}")
    return 0


def _npm_has_script(root, name: str) -> bool:
    """Return True if ``package.json`` defines a script named ``name``."""
    import json
    try:
        data = json.loads((root / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    scripts = data.get("scripts")
    return isinstance(scripts, dict) and name in scripts


def _check_manage_hook(root, *, install: bool) -> int:
    """Install or remove a ``.git/hooks/pre-push`` that runs ``koda check``."""
    from pathlib import Path

    git_dir = Path(root) / ".git"
    if not git_dir.is_dir():
        print(f"error: {root} is not a git repository", file=sys.stderr)
        return 1

    hook = git_dir / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)

    if install:
        hook.write_text(
            "#!/usr/bin/env bash\n"
            "# Installed by `koda check --install-hook`\n"
            "exec koda check\n"
        )
        hook.chmod(0o755)
        print(f"✓ pre-push hook installed: {hook}")
        return 0

    # uninstall
    if hook.exists():
        # Only remove hooks we likely created, to avoid nuking user hooks.
        try:
            body = hook.read_text(encoding="utf-8")
        except OSError:
            body = ""
        if "koda check --install-hook" in body:
            hook.unlink()
            print(f"✓ pre-push hook removed: {hook}")
            return 0
        print(f"⚠ {hook} exists but was not created by koda — leaving it alone", file=sys.stderr)
        return 1
    print(f"no pre-push hook at {hook}")
    return 0


def _cmd_uninstall(argv: list[str]) -> int:
    """Remove K.O.D.A. with an interactive checklist.

    Categories:
      1. binaries  — install dir (.source/.venv) + ~/.local/bin/koda launcher
      2. config    — config.yaml, secrets.env, SOUL.md, active_profile/engagement
      3. data      — sessions.db, approvals.json, audit/, evidence/, engagements/
      4. profiles  — ~/.koda/profiles/* (non-default profiles)
      5. shell     — PATH export line added to ~/.bashrc or ~/.zshrc
    """
    import shutil
    from pathlib import Path

    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda uninstall [--all] [--yes] [--dry-run]")
        print()
        print("  --all       remove every category without asking")
        print("  --yes       skip the final y/N confirmation")
        print("  --dry-run   print what would be removed, but don't delete")
        return 0

    all_mode = "--all" in argv
    yes_mode = "--yes" in argv
    dry_run = "--dry-run" in argv
    unknown = [a for a in argv if a not in {"--all", "--yes", "--dry-run"}]
    if unknown:
        print(f"unknown flag: {unknown[0]}", file=sys.stderr)
        return 2

    home = Path.home()
    koda_home = Path(os.environ.get("KODA_HOME", home / ".koda")).expanduser()

    # Detect install dir from sys.prefix (venv root). sys.executable.resolve()
    # follows uv's symlink into /usr and loses the venv path.
    install_dir: Path | None = None
    candidate = Path(sys.prefix).parent
    if (candidate / ".source" / ".git").exists() and (candidate / ".venv").exists():
        install_dir = candidate

    launcher = home / ".local" / "bin" / "koda"

    categories: list[dict] = [
        {
            "key": "binaries",
            "label": "Code + venv + launcher",
            "paths": [p for p in (install_dir, launcher) if p],
            "desc": "reinstall required to use koda again",
        },
        {
            "key": "config",
            "label": "Config + secrets + soul",
            "paths": [
                koda_home / "config.yaml",
                koda_home / "secrets.env",
                koda_home / "SOUL.md",
                koda_home / "active_profile",
                koda_home / "active_engagement",
            ],
            "desc": "provider keys, wizard config, engagement pointer",
        },
        {
            "key": "data",
            "label": "Session data + evidence + audit",
            "paths": [
                koda_home / "sessions.db",
                koda_home / "approvals.json",
                koda_home / "audit",
                koda_home / "evidence",
                koda_home / "engagements",
                koda_home / "credentials",
                koda_home / "telegram_inbox",
                koda_home / "telegram_offset",
            ],
            "desc": "irreversible — engagement records go with this",
        },
        {
            "key": "profiles",
            "label": "Non-default profiles",
            "paths": [koda_home / "profiles"],
            "desc": "every saved profile under ~/.koda/profiles/",
        },
        {
            "key": "shell",
            "label": "Shell PATH export",
            "paths": [],  # special — we edit files, not delete them
            "desc": "strips the `# K.O.D.A.` block from ~/.bashrc / ~/.zshrc",
        },
    ]

    # Prune to what actually exists so we don't ask about phantom dirs.
    def _has_content(cat: dict) -> bool:
        if cat["key"] == "shell":
            for rc in (home / ".bashrc", home / ".zshrc", home / ".profile"):
                if rc.exists() and "# K.O.D.A." in _safe_read(rc):
                    return True
            return False
        return any(p.exists() for p in cat["paths"])

    present = [c for c in categories if _has_content(c)]
    if not present:
        print("nothing to uninstall — no K.O.D.A. files found.")
        return 0

    print("\n  K.O.D.A. \u2014 uninstall\n")
    print(f"  install dir:  {install_dir or '(not detected)'}")
    print(f"  KODA_HOME:    {koda_home}")
    print(f"  launcher:     {launcher if launcher.exists() else '(not found)'}")
    if dry_run:
        print("  DRY RUN \u2014 nothing will be removed\n")
    else:
        print()

    selected: list[dict] = []
    if all_mode:
        selected = list(present)
        print("  --all: selecting every category.\n")
    else:
        print("  Select what to remove (y/N per category):\n")
        for cat in present:
            line = f"    [{cat['key']:<9}] {cat['label']} \u2014 {cat['desc']}"
            print(line)
            try:
                ans = input("      remove? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\naborted.")
                return 1
            if ans in {"y", "yes"}:
                selected.append(cat)

    if not selected:
        print("\nnothing selected. exiting.")
        return 0

    print("\n  Will remove:")
    for cat in selected:
        print(f"    \u2022 {cat['label']}")
        if cat["key"] == "shell":
            continue
        for p in cat["paths"]:
            if p.exists():
                print(f"        - {p}")

    if not yes_mode and not dry_run:
        try:
            ans = input("\n  proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\naborted.")
            return 1
        if ans not in {"y", "yes"}:
            print("aborted.")
            return 1

    removed = 0
    for cat in selected:
        if cat["key"] == "shell":
            removed += _strip_shell_path_lines(home, dry_run=dry_run)
            continue
        for p in cat["paths"]:
            if not p.exists():
                continue
            if dry_run:
                print(f"  would remove: {p}")
                removed += 1
                continue
            try:
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p)
                else:
                    p.unlink()
                print(f"  removed: {p}")
                removed += 1
            except OSError as exc:
                print(f"  failed: {p} \u2014 {exc}", file=sys.stderr)

    # If KODA_HOME is now empty, sweep the directory itself.
    if not dry_run and koda_home.exists():
        try:
            remaining = [p for p in koda_home.iterdir()]
            if not remaining:
                koda_home.rmdir()
                print(f"  removed: {koda_home}")
        except OSError:
            pass

    print(f"\n\u2713 uninstall complete \u2014 {removed} item(s) {'listed' if dry_run else 'removed'}.")
    if dry_run:
        print("  (dry-run: nothing was actually deleted)")
    return 0


def _safe_read(path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _strip_shell_path_lines(home, *, dry_run: bool) -> int:
    """Remove the '# K.O.D.A.' block the installer added to shell RC files."""
    touched = 0
    for rc in (home / ".bashrc", home / ".zshrc", home / ".profile"):
        if not rc.exists():
            continue
        content = _safe_read(rc)
        if "# K.O.D.A." not in content:
            continue

        lines = content.splitlines()
        out: list[str] = []
        skip = 0
        for line in lines:
            if skip > 0:
                skip -= 1
                continue
            if line.strip() == "# K.O.D.A.":
                # Skip this line + the next PATH export (installer pairs them).
                skip = 1
                continue
            out.append(line)

        new_content = "\n".join(out)
        if new_content and not new_content.endswith("\n"):
            new_content += "\n"

        if dry_run:
            print(f"  would edit: {rc} (strip `# K.O.D.A.` block)")
        else:
            try:
                rc.write_text(new_content, encoding="utf-8")
                print(f"  edited: {rc} (stripped K.O.D.A. PATH block)")
            except OSError as exc:
                print(f"  failed editing {rc}: {exc}", file=sys.stderr)
                continue
        touched += 1
    return touched


def _doctor() -> int:
    import shutil

    from .. import __version__
    from ..config import CONFIG_PATH, KODA_HOME, config_exists, load_config
    from ..profiles import read_active_profile

    KODA_HOME.mkdir(parents=True, exist_ok=True)
    _load_secrets_env()

    ok, warn, err = "\u2713", "\u2022", "\u2717"

    print(f"K.O.D.A. {__version__}")
    print()
    print("[profile]")
    print(f"  {ok} active         {read_active_profile() or 'default'}")
    print(f"  {ok} KODA_HOME      {KODA_HOME}")
    print()
    print("[config]")
    if config_exists():
        print(f"  {ok} config         {CONFIG_PATH}")
    else:
        print(f"  {err} config         missing  \u2014 run: koda setup")
    soul_mark = ok if (KODA_HOME / "SOUL.md").exists() else warn
    secrets_mark = ok if (KODA_HOME / "secrets.env").exists() else warn
    print(f"  {soul_mark} SOUL.md        {'found' if (KODA_HOME/'SOUL.md').exists() else 'missing'}")
    print(f"  {secrets_mark} secrets.env    {'found' if (KODA_HOME/'secrets.env').exists() else 'missing'}")
    print()

    _doctor_providers(config_exists() and load_config() or {}, ok, warn, err)
    print()
    _doctor_skills(ok, warn, err)
    print()
    _doctor_engagement(KODA_HOME, ok, warn, err)
    print()
    _doctor_tools(ok, warn, shutil)
    return 0


def _doctor_providers(cfg: dict, ok: str, warn: str, err: str) -> None:
    print("[providers]")
    default = cfg.get("default_provider")
    providers = cfg.get("provider") or {}
    if not providers:
        print(f"  {warn} none configured \u2014 run: koda setup")
        return
    for name, pc in providers.items():
        marker = ok if name == default else " "
        model = (pc or {}).get("model", "(no model)")
        tag = " [default]" if name == default else ""
        print(f"  {marker} {name:<14} {model}{tag}")
    if default and default not in providers:
        print(f"  {err} default_provider '{default}' not in provider table")


def _doctor_skills(ok: str, warn: str, err: str) -> None:
    print("[skills]")
    try:
        from ..security.skills.registry import DEFAULT_REGISTRY
        from ..skills.loader import SkillLoader
    except Exception as exc:
        print(f"  {err} loader unavailable: {exc}")
        return

    loader = SkillLoader()
    try:
        registered, errors = loader.register_all()
    except Exception as exc:
        print(f"  {err} skill pack registration crashed: {exc}")
        return

    total = len(DEFAULT_REGISTRY.all_skills())
    builtin = total - registered
    print(f"  {ok} total registered   {total} (builtin: {builtin}, external: {registered})")
    if errors:
        print(f"  {err} load errors        {len(errors)}")
        for path, message in errors[:5]:
            print(f"      - {path}: {message}")
        if len(errors) > 5:
            print(f"      \u2026 and {len(errors) - 5} more")
    else:
        print(f"  {ok} load errors        0")


def _doctor_engagement(koda_home, ok: str, warn: str, err: str) -> None:
    print("[engagement]")
    active_file = koda_home / "active_engagement"
    if not active_file.exists():
        print(f"  {warn} active             none \u2014 run: koda setup")
        return
    try:
        name = active_file.read_text().strip()
    except Exception as exc:
        print(f"  {err} active             unreadable: {exc}")
        return
    if not name:
        print(f"  {warn} active             empty file")
        return
    print(f"  {ok} active             {name}")
    eng_dir = koda_home / "engagements" / name
    if not eng_dir.is_dir():
        print(f"  {warn} directory          missing ({eng_dir})")
        return
    evidence_dir = eng_dir / "evidence"
    audit_log = eng_dir / "audit.jsonl"
    evidence_count = len(list(evidence_dir.glob("*"))) if evidence_dir.is_dir() else 0
    audit_size = audit_log.stat().st_size if audit_log.exists() else 0
    print(f"  {ok} evidence items     {evidence_count}")
    print(f"  {ok} audit log          {audit_size} bytes")


def _doctor_tools(ok: str, warn: str, shutil_mod) -> None:
    print("[environment]")
    keys = [
        ("ANTHROPIC_API_KEY", "anthropic"),
        ("OPENAI_API_KEY", "openai"),
        ("GROQ_API_KEY", "groq"),
        ("GEMINI_API_KEY", "gemini"),
    ]
    for env_var, label in keys:
        mark = ok if os.environ.get(env_var) else warn
        state = "set" if os.environ.get(env_var) else "unset"
        print(f"  {mark} {label:<14} {state}")
    for binary in ("claude", "ollama", "nmap", "semgrep", "trivy"):
        path = shutil_mod.which(binary)
        mark = ok if path else warn
        print(f"  {mark} {binary:<14} {path or 'not found'}")


if __name__ == "__main__":
    raise SystemExit(main())
