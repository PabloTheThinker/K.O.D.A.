"""K.O.D.A. first-run setup wizard.

Uses the shared wizard primitives (Prompter, per-provider setup). Detects
providers, captures API keys (persisted to ~/.koda/secrets.env, chmod 600),
picks a model, optionally configures quota, writes ~/.koda/config.yaml,
and runs a one-shot self-test.

Koda is a harness — it mounts on any engine. The wizard reflects that:
local-first (Ollama, Claude CLI), then the Anthropic / OpenAI /
Google / xAI / Groq / Together / OpenRouter / DeepSeek / Mistral tier.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

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
    detect_deepseek_env_key,
    detect_gemini_env_key,
    detect_groq_env_key,
    detect_mistral_env_key,
    detect_ollama_models,
    detect_openai_env_key,
    detect_openrouter_env_key,
    detect_together_env_key,
    detect_xai_env_key,
    save_secrets,
    setup_anthropic,
    setup_claude_cli,
    setup_gemini,
    setup_ollama,
    setup_openai_compat,
)

SECRETS_PATH = KODA_HOME / "secrets.env"


@dataclass(frozen=True)
class _ProviderOption:
    value: str
    label: str
    base_hint: str
    detector: Callable[[], Any] | None  # returns truthy if reachable/configured
    detail_fn: Callable[[Any], str] | None = None


# Order matters — what the wizard shows first is what most users should try.
# Local-first (no key needed), then cloud tiers.
_PROVIDER_OPTIONS: tuple[_ProviderOption, ...] = (
    _ProviderOption(
        value="ollama", label="Ollama",
        base_hint="local models, no API key",
        detector=detect_ollama_models,
        detail_fn=lambda v: f"{len(v)} model(s) available" if v else "not reachable",
    ),
    _ProviderOption(
        value="claude_cli", label="Claude CLI",
        base_hint="local subprocess — reuses your `claude` auth",
        detector=detect_claude_cli,
        detail_fn=lambda v: v or "not installed",
    ),
    _ProviderOption(
        value="anthropic", label="Anthropic (Claude)",
        base_hint="API — ANTHROPIC_API_KEY",
        detector=detect_anthropic_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
    _ProviderOption(
        value="openai", label="OpenAI",
        base_hint="API — OPENAI_API_KEY",
        detector=detect_openai_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
    _ProviderOption(
        value="gemini", label="Google Gemini",
        base_hint="API — GEMINI_API_KEY",
        detector=detect_gemini_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
    _ProviderOption(
        value="groq", label="Groq",
        base_hint="API — GROQ_API_KEY, fastest inference",
        detector=detect_groq_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
    _ProviderOption(
        value="together", label="Together AI",
        base_hint="API — TOGETHER_API_KEY",
        detector=detect_together_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
    _ProviderOption(
        value="openrouter", label="OpenRouter",
        base_hint="API — OPENROUTER_API_KEY, many models",
        detector=detect_openrouter_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
    _ProviderOption(
        value="deepseek", label="DeepSeek",
        base_hint="API — DEEPSEEK_API_KEY",
        detector=detect_deepseek_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
    _ProviderOption(
        value="xai", label="xAI (Grok)",
        base_hint="API — XAI_API_KEY",
        detector=detect_xai_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
    _ProviderOption(
        value="mistral", label="Mistral",
        base_hint="API — MISTRAL_API_KEY",
        detector=detect_mistral_env_key,
        detail_fn=lambda v: "key detected" if v else "no key",
    ),
)


def _detect_available(prompter: Prompter) -> list[SelectOption]:
    prompter.section("Detecting environment")

    options: list[SelectOption] = []
    for opt in _PROVIDER_OPTIONS:
        probe = opt.detector() if opt.detector else None
        present = bool(probe)
        detail = opt.detail_fn(probe) if opt.detail_fn else ""
        prompter.status(present, opt.label, detail=detail or opt.base_hint)
        hint = opt.base_hint + (f" — {detail}" if present and detail else "")
        options.append(SelectOption(value=opt.value, label=opt.label, hint=hint))
    return options


def _run_provider_setup(prompter: Prompter, provider_id: str) -> ProviderSetupResult:
    if provider_id == "anthropic":
        return setup_anthropic(prompter, existing_key=detect_anthropic_env_key())
    if provider_id == "claude_cli":
        return setup_claude_cli(prompter)
    if provider_id == "ollama":
        return setup_ollama(prompter)
    if provider_id == "gemini":
        return setup_gemini(prompter, existing_key=detect_gemini_env_key())
    if provider_id in {"openai", "groq", "together", "openrouter", "deepseek", "xai", "mistral"}:
        return setup_openai_compat(prompter, provider_id)
    raise ValueError(f"unknown provider: {provider_id}")


async def _self_test(result: ProviderSetupResult) -> tuple[bool, str]:
    try:
        provider = create_provider(result.provider_id, result.merged_config())
        messages = [
            Message(role=Role.SYSTEM, content="You are K.O.D.A. self-test. Be terse."),
            Message(role=Role.USER, content="Reply with exactly one word: pong"),
        ]
        resp = await provider.chat(messages)
        if resp.stop_reason == "error":
            return False, resp.text[:200]
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
