"""K.O.D.A. shared wizard primitives — used by `koda setup` and `koda new`.

Modeled on OpenClaw's WizardPrompter API: intro/outro/note/select/
multiselect/text/password/confirm/progress. Concrete implementation uses
raw termios for arrow-key navigation with a plain fallback for non-TTY.
"""
from .prompter import Prompter, SelectOption, WizardCancelled
from .providers import (
    ProviderSetupResult,
    QuotaSpec,
    detect_anthropic_env_key,
    detect_claude_cli,
    detect_ollama_models,
    setup_anthropic,
    setup_claude_cli,
    setup_ollama,
)
from .secrets import save_secrets

__all__ = [
    "Prompter", "SelectOption", "WizardCancelled",
    "ProviderSetupResult", "QuotaSpec",
    "setup_anthropic", "setup_claude_cli", "setup_ollama",
    "detect_anthropic_env_key", "detect_claude_cli", "detect_ollama_models",
    "save_secrets",
]
