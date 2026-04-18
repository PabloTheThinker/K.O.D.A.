"""K.O.D.A. first-run setup wizard.

Uses the shared wizard primitives (Prompter, per-provider setup). Detects
providers, captures API keys (persisted to ~/.koda/secrets.env, chmod 600),
picks a model, optionally configures quota, writes ~/.koda/config.yaml,
and runs a one-shot self-test.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from ..adapters import create_provider
from ..adapters.base import Message, Role
from ..config import CONFIG_PATH, KODA_HOME, save_config
from ..wizard import (
    Prompter,
    ProviderSetupResult,
    SelectOption,
    WizardCancelled,
    detect_anthropic_env_key,
    detect_claude_cli,
    detect_ollama_models,
    save_secrets,
    setup_anthropic,
    setup_claude_cli,
    setup_ollama,
)

SECRETS_PATH = KODA_HOME / "secrets.env"


def _detect_available(prompter: Prompter) -> list[SelectOption]:
    options: list[SelectOption] = []

    env_key = detect_anthropic_env_key()
    claude = detect_claude_cli()
    ollama = detect_ollama_models()

    prompter.section("Detecting environment")
    prompter.status(bool(env_key), "ANTHROPIC_API_KEY",
                    detail="present" if env_key else "not set")
    prompter.status(bool(claude), "Claude CLI",
                    detail=claude or "not found")
    prompter.status(bool(ollama), "Ollama",
                    detail=f"{len(ollama)} model(s)" if ollama else "not reachable")

    options.append(SelectOption(
        value="anthropic",
        label="Anthropic (Claude)",
        hint="API — needs ANTHROPIC_API_KEY" + (" (detected)" if env_key else ""),
    ))
    options.append(SelectOption(
        value="claude_cli",
        label="Claude CLI",
        hint="local subprocess" + (f" ({claude})" if claude else " — not installed"),
    ))
    options.append(SelectOption(
        value="ollama",
        label="Ollama",
        hint="local models" + (f" — {len(ollama)} available" if ollama else " — not running"),
    ))
    return options


def _run_provider_setup(prompter: Prompter, provider_id: str) -> ProviderSetupResult:
    if provider_id == "anthropic":
        return setup_anthropic(prompter, existing_key=detect_anthropic_env_key())
    if provider_id == "claude_cli":
        return setup_claude_cli(prompter)
    if provider_id == "ollama":
        return setup_ollama(prompter)
    raise ValueError(f"unknown provider: {provider_id}")


async def _self_test(result: ProviderSetupResult) -> tuple[bool, str]:
    try:
        provider = create_provider(result.provider_id, result.merged_config())
        messages = [
            Message(role=Role.SYSTEM, content="You are K.O.D.A. self-test. Be terse."),
            Message(role=Role.USER, content="Reply with exactly one word: pong"),
        ]
        resp = await provider.chat(messages)
        text = (resp.text or "").strip()
        return True, text[:120] if text else "(empty response)"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def run_setup_wizard(
    config_path: Path | None = None,
    noninteractive: bool = False,
) -> dict[str, Any]:
    path = config_path or CONFIG_PATH
    prompter = Prompter(tty=None if not noninteractive else False)

    prompter.intro(
        "K.O.D.A. — Kinetic Operative Defense Agent",
        f"First-run setup. Writes config to {path}",
    )

    try:
        options = _detect_available(prompter)
        choice = prompter.select(
            "Default provider",
            options,
            initial=0,
        )
        result = _run_provider_setup(prompter, choice)
    except WizardCancelled as exc:
        prompter.outro(f"cancelled: {exc}")
        return {}

    KODA_HOME.mkdir(parents=True, exist_ok=True)
    if result.secrets:
        save_secrets(result.secrets, SECRETS_PATH)
        for key in result.secrets:
            os.environ.setdefault(key, result.secrets[key])
        prompter.status(True, f"saved secrets to {SECRETS_PATH}")

    config: dict[str, Any] = {
        "version": 1,
        "default_provider": result.provider_id,
        "provider": {result.provider_id: result.merged_config()},
        "approvals": {"auto_approve": "safe"},
        "session": {"db_path": str(KODA_HOME / "sessions.db")},
    }
    save_config(config, path)
    prompter.status(True, f"wrote {path}")

    if prompter.confirm("Run a self-test against the chosen provider?", default=True):
        with prompter.progress(f"pinging {result.provider_id}") as p:
            ok, detail = asyncio.run(_self_test(result))
            p.stop(detail if ok else f"failed: {detail}")
        if not ok:
            prompter.note(
                "Config is written. Fix the provider and re-run `koda`.",
                title="Self-test failed",
            )

    prompter.outro("ready — start with: koda")
    return config


__all__ = ["run_setup_wizard"]
