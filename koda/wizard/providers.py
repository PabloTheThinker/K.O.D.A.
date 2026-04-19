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

def _first_env(*names: str) -> str | None:
    for n in names:
        val = os.environ.get(n, "").strip()
        if val:
            return val
    return None


def detect_anthropic_env_key() -> str | None:
    return _first_env("ANTHROPIC_API_KEY")


def detect_openai_env_key() -> str | None:
    return _first_env("OPENAI_API_KEY")


def detect_groq_env_key() -> str | None:
    return _first_env("GROQ_API_KEY")


def detect_together_env_key() -> str | None:
    return _first_env("TOGETHER_API_KEY")


def detect_openrouter_env_key() -> str | None:
    return _first_env("OPENROUTER_API_KEY")


def detect_deepseek_env_key() -> str | None:
    return _first_env("DEEPSEEK_API_KEY")


def detect_xai_env_key() -> str | None:
    return _first_env("XAI_API_KEY", "GROK_API_KEY")


def detect_mistral_env_key() -> str | None:
    return _first_env("MISTRAL_API_KEY")


def detect_azure_openai_env_key() -> str | None:
    return _first_env("AZURE_OPENAI_API_KEY")


def detect_gemini_env_key() -> str | None:
    from pathlib import Path
    key = _first_env("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY")
    if key:
        return key
    fallback = Path.home() / ".config" / "gcloud" / "api-key.txt"
    if fallback.is_file():
        try:
            return fallback.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return None


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


# ---------------------------------------------------------------------------
# OpenAI-compatible provider setup (OpenAI, Groq, Together, OpenRouter,
# DeepSeek, xAI/Grok, Mistral, Fireworks, Cerebras, Perplexity, vLLM)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _OpenAICompatSpec:
    provider_id: str
    label: str
    env_key: str
    key_hint_prefix: str          # e.g. "sk-", "gsk_", "tgp_", "sk-or-"
    min_key_len: int
    default_models: tuple[tuple[str, str], ...]  # (model_id, hint)
    detector: Any = None          # callable → Optional[str]


_OPENAI_SPECS: dict[str, _OpenAICompatSpec] = {
    "openai": _OpenAICompatSpec(
        provider_id="openai",
        label="OpenAI",
        env_key="OPENAI_API_KEY",
        key_hint_prefix="sk-",
        min_key_len=30,
        default_models=(
            ("gpt-4o", "flagship multimodal"),
            ("gpt-4o-mini", "fast, cheap"),
            ("o1-mini", "reasoning-tuned"),
            ("gpt-4-turbo", "legacy flagship"),
        ),
        detector=detect_openai_env_key,
    ),
    "groq": _OpenAICompatSpec(
        provider_id="groq",
        label="Groq",
        env_key="GROQ_API_KEY",
        key_hint_prefix="gsk_",
        min_key_len=20,
        default_models=(
            ("llama-3.3-70b-versatile", "Meta Llama 3.3 70B"),
            ("llama-3.1-8b-instant", "Meta Llama 3.1 8B — fast"),
            ("mixtral-8x7b-32768", "Mixtral 32k ctx"),
            ("qwen-2.5-32b", "Qwen 2.5 32B"),
        ),
        detector=detect_groq_env_key,
    ),
    "together": _OpenAICompatSpec(
        provider_id="together",
        label="Together AI",
        env_key="TOGETHER_API_KEY",
        key_hint_prefix="",
        min_key_len=30,
        default_models=(
            ("meta-llama/Llama-3.3-70B-Instruct-Turbo", "Llama 3.3 70B"),
            ("deepseek-ai/DeepSeek-V3", "DeepSeek V3"),
            ("Qwen/Qwen2.5-Coder-32B-Instruct", "Qwen 2.5 Coder 32B"),
        ),
        detector=detect_together_env_key,
    ),
    "openrouter": _OpenAICompatSpec(
        provider_id="openrouter",
        label="OpenRouter",
        env_key="OPENROUTER_API_KEY",
        key_hint_prefix="sk-or-",
        min_key_len=30,
        default_models=(
            ("anthropic/claude-sonnet-4", "Claude Sonnet 4 via OpenRouter"),
            ("openai/gpt-4o", "GPT-4o via OpenRouter"),
            ("google/gemini-2.5-flash", "Gemini 2.5 Flash"),
            ("meta-llama/llama-3.3-70b-instruct", "Llama 3.3 70B"),
        ),
        detector=detect_openrouter_env_key,
    ),
    "deepseek": _OpenAICompatSpec(
        provider_id="deepseek",
        label="DeepSeek",
        env_key="DEEPSEEK_API_KEY",
        key_hint_prefix="sk-",
        min_key_len=30,
        default_models=(
            ("deepseek-chat", "general chat (V3)"),
            ("deepseek-reasoner", "reasoning (R1)"),
        ),
        detector=detect_deepseek_env_key,
    ),
    "xai": _OpenAICompatSpec(
        provider_id="xai",
        label="xAI (Grok)",
        env_key="XAI_API_KEY",
        key_hint_prefix="xai-",
        min_key_len=30,
        default_models=(
            ("grok-2-latest", "Grok 2"),
            ("grok-2-mini", "Grok 2 Mini"),
        ),
        detector=detect_xai_env_key,
    ),
    "mistral": _OpenAICompatSpec(
        provider_id="mistral",
        label="Mistral",
        env_key="MISTRAL_API_KEY",
        key_hint_prefix="",
        min_key_len=20,
        default_models=(
            ("mistral-large-latest", "Mistral Large"),
            ("mistral-small-latest", "Mistral Small"),
            ("codestral-latest", "Codestral — code-specialized"),
        ),
        detector=detect_mistral_env_key,
    ),
}


def setup_openai_compat(
    prompter: Prompter,
    provider_id: str,
    *,
    existing_key: str | None = None,
) -> ProviderSetupResult:
    """Unified wizard for OpenAI-compatible providers.

    Dispatches on provider_id into the spec table; same flow for all:
    detect key → capture key → pick model → configure quota.
    """
    spec = _OPENAI_SPECS.get(provider_id)
    if spec is None:
        raise ValueError(f"unknown OpenAI-compatible provider: {provider_id}")

    prompter.section(spec.label)
    key = existing_key or (spec.detector() if spec.detector else None) or ""
    if key:
        prompter.status(True, f"API key detected from {spec.env_key}")
    else:
        prompter.note(
            f"Paste your {spec.label} API key. It's stored at "
            f"~/.koda/secrets.env (0600) and never written to config.yaml.",
            title="API key",
        )
        key = prompter.password(
            f"{spec.label} API key",
            validate=_validate_api_key(spec.key_hint_prefix, min_len=spec.min_key_len),
        )

    options = [SelectOption(value=m[0], label=m[0], hint=m[1]) for m in spec.default_models]
    options.append(SelectOption(value="__custom__", label="custom model id…", hint="type your own"))
    picked = prompter.select("Default model", options, initial=0)
    if picked == "__custom__":
        picked = prompter.text(
            "Model id",
            placeholder=spec.default_models[0][0] if spec.default_models else "",
        )

    quota = _configure_quota(prompter, scope_label=spec.label)

    secrets: dict[str, str] = {}
    if key and key != existing_key:
        secrets[spec.env_key] = key

    return ProviderSetupResult(
        provider_id=spec.provider_id,
        provider_label=spec.label,
        model=picked,
        config={"provider_name": spec.provider_id},
        secrets=secrets,
        quota=quota,
    )


# ---------------------------------------------------------------------------
# Gemini setup
# ---------------------------------------------------------------------------

_GEMINI_MODELS = [
    SelectOption(value="gemini-2.5-flash", label="gemini-2.5-flash", hint="fast, 1M context"),
    SelectOption(value="gemini-2.5-pro", label="gemini-2.5-pro", hint="most capable"),
    SelectOption(value="gemini-2.0-flash", label="gemini-2.0-flash", hint="prior-gen fast"),
    SelectOption(value="gemini-2.0-flash-exp-image-generation", label="2.0 flash image-gen", hint="native image output"),
]


def setup_gemini(prompter: Prompter, *, existing_key: str | None = None) -> ProviderSetupResult:
    prompter.section("Google Gemini")

    key = existing_key or detect_gemini_env_key() or ""
    if key:
        prompter.status(True, "Gemini API key detected")
    else:
        prompter.note(
            "Paste your Gemini API key (from aistudio.google.com/app/apikey).\n"
            "Stored at ~/.koda/secrets.env (0600).",
            title="API key",
        )
        key = prompter.password(
            "Gemini API key",
            validate=_validate_api_key("AI", min_len=30),
        )

    model = prompter.select("Default model", _GEMINI_MODELS, initial=0)
    quota = _configure_quota(prompter, scope_label="Gemini")

    secrets = {"GEMINI_API_KEY": key} if key and key != existing_key else {}

    return ProviderSetupResult(
        provider_id="gemini",
        provider_label="Google Gemini",
        model=model,
        config={},
        secrets=secrets,
        quota=quota,
    )


# ---------------------------------------------------------------------------
# Azure OpenAI setup
# ---------------------------------------------------------------------------

_AZURE_DEPLOYMENT_MODELS = (
    ("gpt-4o", "GPT-4o"),
    ("gpt-4.1", "GPT-4.1"),
    ("gpt-4o-mini", "GPT-4o mini — fast, cheap"),
    ("gpt-4-turbo", "GPT-4 Turbo"),
)

_DEFAULT_AZURE_API_VERSION = "2024-08-01-preview"


def setup_azure_openai(
    prompter: Prompter,
    *,
    existing_key: str | None = None,
) -> ProviderSetupResult:
    """Wizard flow for Azure OpenAI deployments.

    Prompts for endpoint, deployment name, api-version, and api-key.
    """
    prompter.section("Azure OpenAI")
    prompter.note(
        "Azure OpenAI requires a resource endpoint, deployment name,\n"
        "api-version, and an api-key (not a Bearer token).\n"
        "Keys are stored at ~/.koda/secrets.env (0600).",
        title="Azure OpenAI",
    )

    def _validate_url(value: str) -> str | None:
        if not value.startswith("https://"):
            return "endpoint must start with https://"
        return None

    endpoint = prompter.text(
        "Azure resource endpoint",
        placeholder="https://my-resource.openai.azure.com",
        validate=_validate_url,
    )

    deployment = prompter.text(
        "Deployment name",
        placeholder="gpt-4o",
    )

    api_version = prompter.text(
        "API version",
        default=_DEFAULT_AZURE_API_VERSION,
        placeholder=_DEFAULT_AZURE_API_VERSION,
    )

    key = existing_key or detect_azure_openai_env_key() or ""
    if key:
        prompter.status(True, "API key detected from AZURE_OPENAI_API_KEY")
    else:
        key = prompter.password(
            "Azure OpenAI api-key",
            validate=_validate_api_key("", min_len=20),
        )

    quota = _configure_quota(prompter, scope_label="Azure OpenAI")
    secrets: dict[str, str] = {}
    if key and key != existing_key:
        secrets["AZURE_OPENAI_API_KEY"] = key

    return ProviderSetupResult(
        provider_id="azure_openai",
        provider_label="Azure OpenAI",
        model=deployment,
        config={
            "endpoint": endpoint,
            "deployment": deployment,
            "api_version": api_version or _DEFAULT_AZURE_API_VERSION,
        },
        secrets=secrets,
        quota=quota,
    )


# ---------------------------------------------------------------------------
# llama.cpp server setup
# ---------------------------------------------------------------------------


def setup_llamacpp(prompter: Prompter) -> ProviderSetupResult:
    """Wizard flow for a local llama.cpp server (``./server`` binary).

    Prompts for host, port, optional bearer token, and an optional
    cosmetic model label.
    """
    prompter.section("llama.cpp server (local)")
    prompter.note(
        "Point K.O.D.A. at a running llama.cpp server started with:\n"
        "  ./server -m <model.gguf> --port 8080\n"
        "The server exposes /v1/chat/completions in OpenAI-compatible mode.\n"
        "Tool-call support depends on your build and loaded model.",
        title="llama.cpp",
    )

    host = prompter.text(
        "Server host",
        default="127.0.0.1",
        placeholder="127.0.0.1",
    )

    def _validate_port(value: str) -> str | None:
        try:
            n = int(value)
        except ValueError:
            return "enter a port number."
        if not 1 <= n <= 65535:
            return "port must be 1-65535."
        return None

    port_raw = prompter.text(
        "Server port",
        default="8080",
        placeholder="8080",
        validate=_validate_port,
    )
    port = int(port_raw or "8080")

    api_key = prompter.password(
        "Bearer token (blank if none)",
        validate=lambda v: None,  # optional
    )

    model_label = prompter.text(
        "Model label (cosmetic — blank to skip)",
        default="",
        placeholder="e.g. llama-3.1-8b-q4",
    )

    quota = _configure_quota(prompter, scope_label="llama.cpp")

    cfg: dict[str, Any] = {"host": host, "port": port}
    if model_label:
        cfg["model"] = model_label

    secrets: dict[str, str] = {}
    if api_key:
        secrets["LLAMACPP_API_KEY"] = api_key
        cfg["api_key"] = api_key

    return ProviderSetupResult(
        provider_id="llamacpp",
        provider_label="llama.cpp (local)",
        model=model_label or "",
        config=cfg,
        secrets=secrets,
        quota=quota,
    )


__all__ = [
    "QuotaSpec",
    "ProviderSetupResult",
    "detect_anthropic_env_key",
    "detect_azure_openai_env_key",
    "detect_openai_env_key",
    "detect_groq_env_key",
    "detect_together_env_key",
    "detect_openrouter_env_key",
    "detect_deepseek_env_key",
    "detect_xai_env_key",
    "detect_mistral_env_key",
    "detect_gemini_env_key",
    "detect_claude_cli",
    "detect_ollama_models",
    "setup_anthropic",
    "setup_azure_openai",
    "setup_claude_cli",
    "setup_llamacpp",
    "setup_ollama",
    "setup_openai_compat",
    "setup_gemini",
    "WizardCancelled",
]
