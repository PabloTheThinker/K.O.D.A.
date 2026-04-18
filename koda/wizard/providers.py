"""Per-provider wizard setup — API key capture, model picker, quota config.

Each setup_*() function returns a ProviderSetupResult that the caller uses
to populate config.yaml and persist any secrets to ~/.koda/secrets.env.
Modeled on OpenClaw's provider-wizard flow: detect → configure auth →
pick model → (optional) configure quota → return result.
"""
from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .prompter import Prompter, SelectOption, WizardCancelled


@dataclass
class QuotaSpec:
    daily_usd: float | None = None
    monthly_usd: float | None = None
    max_tokens_per_turn: int | None = None

    def is_empty(self) -> bool:
        return (
            self.daily_usd is None
            and self.monthly_usd is None
            and self.max_tokens_per_turn is None
        )

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.daily_usd is not None:
            out["daily_usd"] = self.daily_usd
        if self.monthly_usd is not None:
            out["monthly_usd"] = self.monthly_usd
        if self.max_tokens_per_turn is not None:
            out["max_tokens_per_turn"] = self.max_tokens_per_turn
        return out


@dataclass
class ProviderSetupResult:
    provider_id: str
    provider_label: str
    model: str
    config: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    quota: QuotaSpec = field(default_factory=QuotaSpec)

    def merged_config(self) -> dict[str, Any]:
        """Return the config.yaml shape for provider.<id> = {...}."""
        payload = {"model": self.model, **self.config}
        if not self.quota.is_empty():
            payload["quota"] = self.quota.as_dict()
        return payload


# --- Detection helpers ---

def detect_anthropic_env_key() -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    return key or None


def detect_claude_cli() -> str | None:
    return shutil.which("claude")


def detect_ollama_models(base_url: str = "http://127.0.0.1:11434") -> list[dict[str, Any]]:
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return []
    out: list[dict[str, Any]] = []
    for m in data.get("models", []):
        info: dict[str, Any] = {"name": m["name"]}
        details = m.get("details", {})
        if details.get("parameter_size"):
            info["size"] = details["parameter_size"]
        out.append(info)
    return out


# --- Shared helpers ---

def _validate_api_key(prefix: str, min_len: int = 20):
    def _check(value: str) -> str | None:
        if len(value) < min_len:
            return f"key looks too short ({len(value)} chars)."
        if prefix and not value.startswith(prefix):
            return f"expected key to start with {prefix!r}."
        return None
    return _check


def _validate_positive_float(allow_empty: bool = True):
    def _check(value: str) -> str | None:
        if not value and allow_empty:
            return None
        try:
            n = float(value)
        except ValueError:
            return "enter a number (e.g. 2.50) or leave blank."
        if n < 0:
            return "must be non-negative."
        return None
    return _check


def _validate_positive_int(allow_empty: bool = True):
    def _check(value: str) -> str | None:
        if not value and allow_empty:
            return None
        try:
            n = int(value)
        except ValueError:
            return "enter a whole number or leave blank."
        if n <= 0:
            return "must be a positive integer."
        return None
    return _check


def _maybe_float(raw: str) -> float | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _maybe_int(raw: str) -> int | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _configure_quota(prompter: Prompter, *, scope_label: str) -> QuotaSpec:
    """Prompt for optional daily / monthly / per-turn caps."""
    spec = QuotaSpec()
    if not prompter.confirm(
        f"Configure usage quotas for {scope_label}?",
        default=False,
    ):
        return spec

    prompter.note(
        "Leave any field blank to skip it.\n"
        "Caps are advisory — the runtime logs a warning when exceeded and\n"
        "refuses the next call.",
        title="Quota",
    )

    daily = prompter.text(
        "Daily USD cap",
        placeholder="blank = no cap",
        validate=_validate_positive_float(allow_empty=True),
    )
    spec.daily_usd = _maybe_float(daily)

    monthly = prompter.text(
        "Monthly USD cap",
        placeholder="blank = no cap",
        validate=_validate_positive_float(allow_empty=True),
    )
    spec.monthly_usd = _maybe_float(monthly)

    per_turn = prompter.text(
        "Max output tokens per turn",
        placeholder="blank = model default",
        validate=_validate_positive_int(allow_empty=True),
    )
    spec.max_tokens_per_turn = _maybe_int(per_turn)

    return spec


# --- Provider setup functions ---

_ANTHROPIC_MODELS = [
    SelectOption(
        value="claude-sonnet-4-6",
        label="claude-sonnet-4-6",
        hint="balanced — default for most work",
    ),
    SelectOption(
        value="claude-opus-4-7",
        label="claude-opus-4-7",
        hint="most capable — slower, more expensive",
    ),
    SelectOption(
        value="claude-haiku-4-5",
        label="claude-haiku-4-5",
        hint="fast + cheap — good for quick tasks",
    ),
]


def setup_anthropic(prompter: Prompter, *, existing_key: str | None = None) -> ProviderSetupResult:
    prompter.section("Anthropic (Claude)")

    key = existing_key or ""
    if key:
        prompter.status(True, "API key detected from environment")
    else:
        prompter.note(
            "Paste your Anthropic API key. It will be saved to\n"
            "~/.koda/secrets.env with 0600 permissions. Keys are never\n"
            "written to config.yaml or git.",
            title="API key",
        )
        key = prompter.password(
            "Anthropic API key",
            validate=_validate_api_key("sk-ant-"),
        )

    model = prompter.select(
        "Default model",
        _ANTHROPIC_MODELS,
        initial=0,
    )

    quota = _configure_quota(prompter, scope_label="Anthropic")

    return ProviderSetupResult(
        provider_id="anthropic",
        provider_label="Anthropic (Claude)",
        model=model,
        config={},
        secrets={"ANTHROPIC_API_KEY": key} if key and not existing_key else {},
        quota=quota,
    )


def setup_claude_cli(prompter: Prompter) -> ProviderSetupResult:
    prompter.section("Claude CLI")

    binary = detect_claude_cli()
    if binary:
        prompter.status(True, "claude binary on PATH", detail=binary)
    else:
        prompter.status(False, "claude binary not found")
        prompter.note(
            "The Claude CLI provides inference via a subprocess. Install it\n"
            "from https://docs.claude.com/en/docs/claude-code/cli then re-run.",
            title="Setup required",
        )

    model = prompter.text(
        "Default model (blank uses the CLI default)",
        default="",
        placeholder="e.g. claude-sonnet-4-6 or leave blank",
    )

    quota = _configure_quota(prompter, scope_label="Claude CLI")

    return ProviderSetupResult(
        provider_id="claude_cli",
        provider_label="Claude CLI",
        model=model or "",
        config={},
        secrets={},
        quota=quota,
    )


def setup_ollama(
    prompter: Prompter,
    *,
    base_url: str = "http://127.0.0.1:11434",
) -> ProviderSetupResult:
    prompter.section("Ollama (local)")

    models = detect_ollama_models(base_url)
    if not models:
        prompter.status(False, "Ollama not reachable", detail=base_url)
        prompter.note(
            "Ollama isn't responding. Start it with `ollama serve` and pull a\n"
            "model (e.g. `ollama pull qwen3:14b`) then re-run this wizard.",
            title="Setup required",
        )
        model = prompter.text(
            "Model name",
            default="qwen3:14b",
            placeholder="qwen3:14b",
        )
        host = prompter.text(
            "Ollama base URL",
            default=base_url,
        )
        quota = _configure_quota(prompter, scope_label="Ollama")
        return ProviderSetupResult(
            provider_id="ollama",
            provider_label="Ollama (local)",
            model=model,
            config={"base_url": host},
            secrets={},
            quota=quota,
        )

    prompter.status(True, f"{len(models)} model(s) available")

    options = [
        SelectOption(
            value=m["name"],
            label=m["name"],
            hint=m.get("size", ""),
        )
        for m in models
    ]
    model = prompter.select("Default model", options, initial=0)

    host = prompter.text(
        "Ollama base URL",
        default=base_url,
    )

    quota = _configure_quota(prompter, scope_label="Ollama")

    return ProviderSetupResult(
        provider_id="ollama",
        provider_label="Ollama (local)",
        model=model,
        config={"base_url": host},
        secrets={},
        quota=quota,
    )


__all__ = [
    "QuotaSpec",
    "ProviderSetupResult",
    "detect_anthropic_env_key",
    "detect_claude_cli",
    "detect_ollama_models",
    "setup_anthropic",
    "setup_claude_cli",
    "setup_ollama",
    "WizardCancelled",
]
