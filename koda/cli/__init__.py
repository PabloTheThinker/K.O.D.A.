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
        print("usage: koda                   start REPL (runs setup on first run)")
        print("       koda setup             (re)run the setup wizard")
        print("       koda doctor            show config + provider status")
        print("       koda mcp               start MCP server (expose tools)")
        print("       koda telegram          start the Telegram bridge daemon")
        print("       koda intel <cmd>       sync | status | lookup | search threat intel")
        print("       koda report <cmd>      generate | stats security reports")
        print("       koda update            pull + install the latest release")
        print("       koda uninstall         remove K.O.D.A. (interactive checklist)")
        print("       koda profile <cmd>     list | create | use | delete | show")
        print("       koda version           print version and exit")
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

    if argv and argv[0] == "update":
        return _cmd_update(argv[1:])

    if argv and argv[0] == "uninstall":
        return _cmd_uninstall(argv[1:])

    if argv and argv[0] in {"profile", "profiles"}:
        return _cmd_profile(argv[1:])

    return asyncio.run(_repl())


_INSTALLER_URL = "https://koda.vektraindustries.com/install"


def _cmd_update(argv: list[str]) -> int:
    """Update K.O.D.A. in place by re-running the hosted installer.

    Preserves the existing install directory and venv; the installer does
    `git pull --ff-only` when .source/ is already a clone. Runs with
    --no-wizard so user config stays untouched.
    """
    import shutil
    import subprocess
    from pathlib import Path

    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda update [--branch NAME] [--dir PATH] [--url URL]")
        print()
        print("  --branch NAME   git branch to pull (default: main)")
        print("  --dir PATH      install directory (default: auto-detected)")
        print("  --url URL       installer URL (default: hosted)")
        return 0

    branch = "main"
    install_dir: str | None = None
    url = _INSTALLER_URL

    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--branch" and i + 1 < len(argv):
            branch = argv[i + 1]; i += 2; continue
        if a == "--dir" and i + 1 < len(argv):
            install_dir = argv[i + 1]; i += 2; continue
        if a == "--url" and i + 1 < len(argv):
            url = argv[i + 1]; i += 2; continue
        print(f"unknown flag: {a}", file=sys.stderr)
        return 2

    # Auto-detect install dir from sys.prefix (the venv root). Don't use
    # sys.executable.resolve() — uv symlinks .venv/bin/python to system
    # python, which would send us into /usr.
    if install_dir is None:
        candidate = Path(sys.prefix).parent  # .venv -> {install}
        if (candidate / ".source" / ".git").exists():
            install_dir = str(candidate)

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

    # curl URL | bash -s -- <args...>
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
