"""K.O.D.A. first-run setup wizard.

Honest, minimal onboarding: detect Ollama, detect claude CLI, take an
Anthropic key if the user has one, pick a default provider and model, write
~/.koda/config.yaml, and run a one-shot self-test so the user sees proof of
life before the REPL opens.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..config import CONFIG_PATH, KODA_HOME, save_config
from ..adapters import create_provider
from ..adapters.base import Message, Role

_IS_TTY = sys.stdin.isatty() and sys.stdout.isatty()

GOLD = "\033[38;5;178m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"
CLEAR_LINE = "\033[2K"


def _can_raw() -> bool:
    if not _IS_TTY:
        return False
    try:
        import termios  # noqa: F401
        import tty  # noqa: F401
        return True
    except ImportError:
        return False


def _read_key() -> str:
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            seq = sys.stdin.read(2)
            if seq == "[A":
                return "up"
            if seq == "[B":
                return "down"
            return "esc"
        if ch in ("\r", "\n"):
            return "enter"
        if ch == "\x03":
            raise KeyboardInterrupt
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


_BANNER = f"""
{GOLD}{BOLD}  ██╗  ██╗ ██████╗ ██████╗  █████╗
  ██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗
  █████╔╝ ██║   ██║██║  ██║███████║
  ██╔═██╗ ██║   ██║██║  ██║██╔══██║
  ██║  ██╗╚██████╔╝██████╔╝██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝{RESET}
  {BOLD}Kinetic Operative Defense Agent{RESET}
  {DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
  {DIM}Vektra Industries • Open Source • AI Security{RESET}
"""


def _prompt(label: str, default: str = "", secret: bool = False) -> str:
    if not _IS_TTY:
        return default
    suffix = f" [{default}]" if default and not secret else ""
    display = f"{CYAN}{label}{suffix}{RESET}: "
    if secret:
        try:
            import getpass
            val = getpass.getpass(display)
        except (ImportError, EOFError):
            val = input(display)
    else:
        val = input(display)
    return val.strip() or default


def _confirm(label: str, default: bool = True) -> bool:
    if not _IS_TTY:
        return default
    hint = "Y/n" if default else "y/N"
    val = input(f"{CYAN}{label} [{hint}]{RESET}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def _select(label: str, options: list[str], default: int = 0) -> int:
    if not options:
        return 0
    if _can_raw():
        return _select_raw(label, options, default)
    return _select_fallback(label, options, default)


def _select_raw(label: str, options: list[str], default: int) -> int:
    cursor = default
    n = len(options)

    def _draw() -> None:
        sys.stdout.write(f"\r{BOLD}{label}{RESET}\n")
        for i, opt in enumerate(options):
            if i == cursor:
                sys.stdout.write(f"  {GREEN}› {opt}{RESET}\n")
            else:
                sys.stdout.write(f"  {DIM}  {opt}{RESET}\n")
        sys.stdout.flush()

    def _clear(count: int) -> None:
        for _ in range(count):
            sys.stdout.write("\033[A" + CLEAR_LINE)
        sys.stdout.flush()

    _draw()
    while True:
        key = _read_key()
        if key in ("up", "k"):
            cursor = (cursor - 1) % n
        elif key in ("down", "j"):
            cursor = (cursor + 1) % n
        elif key == "enter":
            _clear(n + 1)
            sys.stdout.write(f"{BOLD}{label}{RESET} {GREEN}{options[cursor]}{RESET}\n")
            sys.stdout.flush()
            return cursor
        elif key == "esc":
            _clear(n + 1)
            sys.stdout.write(f"{BOLD}{label}{RESET} {DIM}{options[default]}{RESET}\n")
            sys.stdout.flush()
            return default
        else:
            continue
        _clear(n + 1)
        _draw()


def _select_fallback(label: str, options: list[str], default: int) -> int:
    print(f"\n{CYAN}{label}{RESET}")
    for i, opt in enumerate(options):
        marker = f"{GOLD}*{RESET}" if i == default else " "
        print(f"  {marker} {i + 1}) {opt}")
    if not _IS_TTY:
        return default
    raw = input(f"  choice [{default + 1}]: ").strip()
    if not raw:
        return default
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(options):
            return idx
    except ValueError:
        pass
    return default


def _detect_ollama(base_url: str = "http://127.0.0.1:11434") -> list[dict[str, Any]]:
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        models = []
        for m in data.get("models", []):
            info: dict[str, Any] = {"name": m["name"]}
            details = m.get("details", {})
            if details.get("parameter_size"):
                info["size"] = details["parameter_size"]
            models.append(info)
        return models
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return []


def _detect_claude_cli() -> str | None:
    return shutil.which("claude")


def _detect_env_anthropic_key() -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    return key or None


def _status_line(ok: bool, name: str, detail: str = "") -> str:
    mark = f"{GREEN}✓{RESET}" if ok else f"{DIM}○{RESET}"
    body = f"{name}"
    if detail:
        body += f" {DIM}— {detail}{RESET}"
    return f"  {mark} {body}"


def _collect_providers() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (detected, offered_cloud). detected is ready-to-use; offered_cloud are ones we can prompt for a key."""
    detected: list[dict[str, Any]] = []

    env_key = _detect_env_anthropic_key()
    if env_key:
        detected.append({
            "id": "anthropic",
            "label": "Anthropic (ANTHROPIC_API_KEY in env)",
            "default_model": "claude-sonnet-4-6",
            "source": "env",
        })

    claude_cli = _detect_claude_cli()
    if claude_cli:
        detected.append({
            "id": "claude_cli",
            "label": f"Claude CLI ({claude_cli})",
            "default_model": "",
            "source": "binary",
        })

    ollama_models = _detect_ollama()
    if ollama_models:
        detected.append({
            "id": "ollama",
            "label": f"Ollama — {len(ollama_models)} model(s)",
            "default_model": ollama_models[0]["name"],
            "models": [m["name"] for m in ollama_models[:15]],
            "source": "local",
        })

    offered_cloud = [
        {"id": "anthropic", "label": "Anthropic (Claude)", "default_model": "claude-sonnet-4-6"},
    ]
    offered_cloud = [c for c in offered_cloud if not any(d["id"] == c["id"] for d in detected)]

    return detected, offered_cloud


def _pick_model(provider: dict[str, Any]) -> str:
    if provider["id"] == "ollama" and provider.get("models"):
        idx = _select("Model", provider["models"], default=0)
        return provider["models"][idx]
    if provider["id"] == "anthropic":
        options = ["claude-sonnet-4-6", "claude-opus-4-7", "claude-haiku-4-5"]
        idx = _select("Model", options, default=0)
        return options[idx]
    if provider["id"] == "claude_cli":
        return _prompt("Model (blank = CLI default)", "")
    return _prompt("Model", provider.get("default_model", ""))


async def _self_test(provider_name: str, provider_cfg: dict[str, Any]) -> tuple[bool, str]:
    try:
        provider = create_provider(provider_name, provider_cfg)
        resp = await provider.complete(
            messages=[Message(role=Role.USER, content="Reply with exactly one word: pong")],
            system="You are K.O.D.A. self-test. Be terse.",
        )
        text = (resp.text or "").strip()
        return True, text[:120] if text else "(empty response)"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def run_setup_wizard(config_path: Path | None = None, noninteractive: bool = False) -> dict[str, Any]:
    """Run the first-run wizard. Writes ~/.koda/config.yaml and returns the config dict."""
    path = config_path or CONFIG_PATH
    print(_BANNER)
    print(f"  Config will be written to: {DIM}{path}{RESET}\n")

    print(f"{GOLD}━━━ Detecting environment{RESET}")
    detected, offered_cloud = _collect_providers()

    if detected:
        for p in detected:
            print(_status_line(True, p["label"]))
    else:
        print(_status_line(False, "no providers auto-detected"))

    if offered_cloud and _IS_TTY and not noninteractive:
        for cloud in offered_cloud:
            if _confirm(f"\nAdd {cloud['label']} by pasting an API key?", default=False):
                key = _prompt(f"{cloud['label']} API key", secret=True)
                if key:
                    os.environ["ANTHROPIC_API_KEY"] = key
                    KODA_HOME.mkdir(parents=True, exist_ok=True)
                    secrets_path = KODA_HOME / "secrets.env"
                    with secrets_path.open("a", encoding="utf-8") as f:
                        f.write(f"ANTHROPIC_API_KEY={key}\n")
                    try:
                        os.chmod(secrets_path, 0o600)
                    except OSError:
                        pass
                    print(f"  {GREEN}✓{RESET} key saved to {secrets_path}")
                    detected.append({
                        "id": cloud["id"],
                        "label": cloud["label"],
                        "default_model": cloud["default_model"],
                        "source": "user",
                    })

    if not detected:
        print(f"\n{RED}No providers available.{RESET} Install Ollama, install the claude CLI, or set ANTHROPIC_API_KEY. Then re-run: {BOLD}koda setup{RESET}")
        sys.exit(1)

    labels = [p["label"] for p in detected]
    idx = _select("Default provider", labels, default=0)
    chosen = detected[idx]

    model = _pick_model(chosen) if _IS_TTY and not noninteractive else chosen.get("default_model", "")

    provider_cfg: dict[str, Any] = {"model": model} if model else {}
    if chosen["id"] == "ollama":
        provider_cfg["base_url"] = "http://127.0.0.1:11434"

    config: dict[str, Any] = {
        "version": 1,
        "default_provider": chosen["id"],
        "provider": {chosen["id"]: provider_cfg},
        "approvals": {
            "auto_approve": "safe",
        },
        "session": {
            "db_path": str(KODA_HOME / "sessions.db"),
        },
    }

    save_config(config, path)
    print(f"\n  {GREEN}✓{RESET} wrote {path}")

    if _IS_TTY and not noninteractive and _confirm("\nRun a self-test against the chosen provider?", default=True):
        print(f"  {DIM}pinging {chosen['id']}...{RESET}")
        ok, detail = asyncio.run(_self_test(chosen["id"], provider_cfg))
        if ok:
            print(f"  {GREEN}✓{RESET} response: {detail}")
        else:
            print(f"  {YELLOW}✗ self-test failed:{RESET} {detail}")
            print(f"  {DIM}the config is written; fix the provider and re-run `koda`.{RESET}")

    print(f"\n{GOLD}━━━ Ready{RESET}")
    print(f"  start the REPL:  {BOLD}koda{RESET}")
    print(f"  re-run wizard:   {BOLD}koda setup{RESET}")
    print(f"  help:            {BOLD}koda --help{RESET}\n")
    return config


__all__ = ["run_setup_wizard"]
