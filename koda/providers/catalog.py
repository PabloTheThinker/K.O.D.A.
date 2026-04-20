"""Provider catalog — declarative list of supported backends.

Each entry describes a provider in enough detail that the wizard menu,
OpenAI-compat routing, and create_provider dispatch can all be derived
from this one table. Adding a new OpenAI-compatible cloud provider is a
single catalog append — no changes to adapters, wizard, or CLI.

Fields
------
id            lowercase provider id used in config.yaml and create_provider
label         human-readable label shown in the setup wizard
hint          one-line hint shown under the label in the wizard menu
tier          "local" | "cloud" — drives wizard ordering (local first)
transport     "direct"        — a dedicated Provider class in koda.adapters
              "openai_compat" — served by OpenAICompatProvider
              "bespoke"       — direct adapter with its own setup flow
env_keys      env vars probed for an API key (first non-empty wins).
              Empty tuple = no env-based detection (credential chain /
              interactive-only auth).
base_url      default HTTPS endpoint for transport="openai_compat".
              Unused for direct/bespoke transports.
base_url_env  env var users can set to override the default endpoint.
              Adopted from Hermes overlays — lets operators point at an
              in-cluster proxy without touching config.yaml.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderEntry:
    id: str
    label: str
    hint: str
    tier: str  # "local" | "cloud"
    transport: str  # "direct" | "openai_compat" | "bespoke"
    env_keys: tuple[str, ...] = ()
    base_url: str = ""
    base_url_env: str = ""


# Ordering matters: the wizard renders entries in this order, with local
# tier (no key needed) surfaced first so privacy-first operators don't
# have to scroll past cloud options.
PROVIDER_CATALOG: tuple[ProviderEntry, ...] = (
    # --- Local (no API key) ---
    ProviderEntry(
        id="ollama",
        label="Ollama",
        hint="local models, no API key",
        tier="local",
        transport="bespoke",
    ),
    ProviderEntry(
        id="llamacpp",
        label="llama.cpp (local)",
        hint="local server — no API key needed",
        tier="local",
        transport="bespoke",
    ),
    # --- Cloud: first-class (direct adapter) ---
    ProviderEntry(
        id="anthropic",
        label="Anthropic (Claude)",
        hint="API — ANTHROPIC_API_KEY",
        tier="cloud",
        transport="direct",
        env_keys=("ANTHROPIC_API_KEY",),
    ),
    ProviderEntry(
        id="gemini",
        label="Google Gemini",
        hint="API — GEMINI_API_KEY",
        tier="cloud",
        transport="direct",
        env_keys=("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY"),
    ),
    ProviderEntry(
        id="azure_openai",
        label="Azure OpenAI",
        hint="Azure deployment — AZURE_OPENAI_API_KEY",
        tier="cloud",
        transport="bespoke",
        env_keys=("AZURE_OPENAI_API_KEY",),
    ),
    ProviderEntry(
        id="vertex_ai",
        label="Google Vertex AI",
        hint="enterprise Gemini — ADC or explicit token",
        tier="cloud",
        transport="bespoke",
    ),
    ProviderEntry(
        id="bedrock",
        label="AWS Bedrock",
        hint="AWS credential chain — no API key stored",
        tier="cloud",
        transport="bespoke",
    ),
    # --- Cloud: OpenAI-compat ---
    ProviderEntry(
        id="openai",
        label="OpenAI",
        hint="API — OPENAI_API_KEY",
        tier="cloud",
        transport="openai_compat",
        env_keys=("OPENAI_API_KEY",),
        base_url="https://api.openai.com/v1",
        base_url_env="OPENAI_BASE_URL",
    ),
    ProviderEntry(
        id="groq",
        label="Groq",
        hint="API — GROQ_API_KEY, fastest inference",
        tier="cloud",
        transport="openai_compat",
        env_keys=("GROQ_API_KEY",),
        base_url="https://api.groq.com/openai/v1",
        base_url_env="GROQ_BASE_URL",
    ),
    ProviderEntry(
        id="cerebras",
        label="Cerebras",
        hint="API — CEREBRAS_API_KEY, wafer-scale inference",
        tier="cloud",
        transport="openai_compat",
        env_keys=("CEREBRAS_API_KEY",),
        base_url="https://api.cerebras.ai/v1",
        base_url_env="CEREBRAS_BASE_URL",
    ),
    ProviderEntry(
        id="fireworks",
        label="Fireworks",
        hint="API — FIREWORKS_API_KEY, open-weight models",
        tier="cloud",
        transport="openai_compat",
        env_keys=("FIREWORKS_API_KEY",),
        base_url="https://api.fireworks.ai/inference/v1",
        base_url_env="FIREWORKS_BASE_URL",
    ),
    ProviderEntry(
        id="together",
        label="Together AI",
        hint="API — TOGETHER_API_KEY",
        tier="cloud",
        transport="openai_compat",
        env_keys=("TOGETHER_API_KEY",),
        base_url="https://api.together.xyz/v1",
        base_url_env="TOGETHER_BASE_URL",
    ),
    ProviderEntry(
        id="openrouter",
        label="OpenRouter",
        hint="API — OPENROUTER_API_KEY, many models",
        tier="cloud",
        transport="openai_compat",
        env_keys=("OPENROUTER_API_KEY",),
        base_url="https://openrouter.ai/api/v1",
        base_url_env="OPENROUTER_BASE_URL",
    ),
    ProviderEntry(
        id="deepseek",
        label="DeepSeek",
        hint="API — DEEPSEEK_API_KEY",
        tier="cloud",
        transport="openai_compat",
        env_keys=("DEEPSEEK_API_KEY",),
        base_url="https://api.deepseek.com/v1",
        base_url_env="DEEPSEEK_BASE_URL",
    ),
    ProviderEntry(
        id="xai",
        label="xAI (Grok)",
        hint="API — XAI_API_KEY",
        tier="cloud",
        transport="openai_compat",
        env_keys=("XAI_API_KEY", "GROK_API_KEY"),
        base_url="https://api.x.ai/v1",
        base_url_env="XAI_BASE_URL",
    ),
    ProviderEntry(
        id="mistral",
        label="Mistral",
        hint="API — MISTRAL_API_KEY",
        tier="cloud",
        transport="openai_compat",
        env_keys=("MISTRAL_API_KEY",),
        base_url="https://api.mistral.ai/v1",
        base_url_env="MISTRAL_BASE_URL",
    ),
    ProviderEntry(
        id="perplexity",
        label="Perplexity",
        hint="API — PERPLEXITY_API_KEY, search-grounded",
        tier="cloud",
        transport="openai_compat",
        env_keys=("PERPLEXITY_API_KEY",),
        base_url="https://api.perplexity.ai",
        base_url_env="PERPLEXITY_BASE_URL",
    ),
    ProviderEntry(
        id="huggingface",
        label="Hugging Face",
        hint="API — HF_TOKEN, inference router",
        tier="cloud",
        transport="openai_compat",
        env_keys=("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_API_KEY"),
        base_url="https://router.huggingface.co/v1",
        base_url_env="HF_BASE_URL",
    ),
    ProviderEntry(
        id="nvidia",
        label="NVIDIA NIM",
        hint="API — NVIDIA_API_KEY, enterprise inference",
        tier="cloud",
        transport="openai_compat",
        env_keys=("NVIDIA_API_KEY", "NIM_API_KEY"),
        base_url="https://integrate.api.nvidia.com/v1",
        base_url_env="NVIDIA_BASE_URL",
    ),
    ProviderEntry(
        id="zai",
        label="Z.AI / GLM",
        hint="API — GLM_API_KEY or ZAI_API_KEY",
        tier="cloud",
        transport="openai_compat",
        env_keys=("GLM_API_KEY", "ZAI_API_KEY", "Z_AI_API_KEY"),
        base_url="https://api.z.ai/api/paas/v4",
        base_url_env="GLM_BASE_URL",
    ),
    ProviderEntry(
        id="moonshot",
        label="Moonshot (Kimi)",
        hint="API — MOONSHOT_API_KEY",
        tier="cloud",
        transport="openai_compat",
        env_keys=("MOONSHOT_API_KEY", "KIMI_API_KEY"),
        base_url="https://api.moonshot.cn/v1",
        base_url_env="MOONSHOT_BASE_URL",
    ),
    ProviderEntry(
        id="ollama_cloud",
        label="Ollama Cloud",
        hint="API — OLLAMA_CLOUD_API_KEY, managed Ollama",
        tier="cloud",
        transport="openai_compat",
        env_keys=("OLLAMA_CLOUD_API_KEY",),
        base_url="https://ollama.com/v1",
        base_url_env="OLLAMA_CLOUD_BASE_URL",
    ),
)


def by_id(provider_id: str) -> ProviderEntry | None:
    key = (provider_id or "").lower().strip()
    for entry in PROVIDER_CATALOG:
        if entry.id == key:
            return entry
    return None


def openai_compat_ids() -> tuple[str, ...]:
    return tuple(e.id for e in PROVIDER_CATALOG if e.transport == "openai_compat")


def local_first_ids() -> tuple[str, ...]:
    return tuple(
        e.id for e in sorted(PROVIDER_CATALOG, key=lambda x: (x.tier != "local",))
    )
