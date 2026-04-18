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
    detect_deepseek_env_key,
    detect_gemini_env_key,
    detect_groq_env_key,
    detect_mistral_env_key,
    detect_ollama_models,
    detect_openai_env_key,
    detect_openrouter_env_key,
    detect_together_env_key,
    detect_xai_env_key,
    setup_anthropic,
    setup_claude_cli,
    setup_gemini,
    setup_ollama,
    setup_openai_compat,
)
from .secrets import save_secrets

__all__ = [
    "Prompter", "SelectOption", "WizardCancelled",
    "ProviderSetupResult", "QuotaSpec",
    "setup_anthropic", "setup_claude_cli", "setup_ollama",
    "setup_openai_compat", "setup_gemini",
    "detect_anthropic_env_key", "detect_claude_cli", "detect_ollama_models",
    "detect_openai_env_key", "detect_groq_env_key", "detect_together_env_key",
    "detect_openrouter_env_key", "detect_deepseek_env_key", "detect_xai_env_key",
    "detect_mistral_env_key", "detect_gemini_env_key",
    "save_secrets",
]
