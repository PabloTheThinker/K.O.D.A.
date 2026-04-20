# Providers

K.O.D.A. is model-agnostic. 22 providers — 2 local, 20 cloud — are
supported behind a single declarative catalog
([`koda/providers/catalog.py`](https://github.com/PabloTheThinker/K.O.D.A./blob/main/koda/providers/catalog.py)).
Swap backends with `koda setup`; no code changes, no re-install.

## How the catalog works

The catalog is the source of truth. One entry per backend, shared by:

- the first-run setup wizard (menu ordering, hints, env-var probes)
- `create_provider()` dispatch in `koda/adapters/__init__.py`
- the OpenAI-compat router (`base_url` + `base_url_env` resolution)

Three transports cover every backend:

- **direct** — a dedicated `Provider` subclass in `koda.adapters`
  (Anthropic, Gemini, Ollama, llama.cpp, Azure OpenAI, Vertex AI,
  Bedrock).
- **openai_compat** — served by the shared `OpenAICompatProvider` over
  the cloud vendor's OpenAI-compatible endpoint.
- **bespoke** — direct adapter with a custom setup flow (credential
  chain, interactive auth, or a deployment-specific handshake).

Adding a new OpenAI-compatible cloud provider is a single catalog
append — no wizard, adapter, or dispatch changes required.

## The 22 providers

### Local (no API key)

| Provider     | Transport | Default model                     | Notes                         |
| ------------ | --------- | --------------------------------- | ----------------------------- |
| Ollama       | bespoke   | `qwen2.5-coder:14b`               | Air-gap ready. Recommended.   |
| llama.cpp    | bespoke   | operator-selected                 | Local server, OpenAI-ish API. |

### Cloud — direct adapter

| Provider        | Transport | Env var(s)                                      | Recommended |
| --------------- | --------- | ----------------------------------------------- | ----------- |
| Anthropic       | direct    | `ANTHROPIC_API_KEY`                             | ✅          |
| Google Gemini   | direct    | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_GENAI_API_KEY` | ✅ |
| Azure OpenAI    | bespoke   | `AZURE_OPENAI_API_KEY`                          |             |
| Vertex AI       | bespoke   | ADC / explicit token                            |             |
| AWS Bedrock     | bespoke   | AWS credential chain                            |             |

### Cloud — OpenAI-compat

| Provider           | Env var(s)                                              | Base URL                                      | Recommended |
| ------------------ | ------------------------------------------------------- | --------------------------------------------- | ----------- |
| OpenAI             | `OPENAI_API_KEY`                                        | `https://api.openai.com/v1`                   | ✅          |
| Groq               | `GROQ_API_KEY`                                          | `https://api.groq.com/openai/v1`              | ✅          |
| Cerebras           | `CEREBRAS_API_KEY`                                      | `https://api.cerebras.ai/v1`                  |             |
| Fireworks          | `FIREWORKS_API_KEY`                                     | `https://api.fireworks.ai/inference/v1`       |             |
| Together AI        | `TOGETHER_API_KEY`                                      | `https://api.together.xyz/v1`                 |             |
| OpenRouter         | `OPENROUTER_API_KEY`                                    | `https://openrouter.ai/api/v1`                | ✅          |
| DeepSeek           | `DEEPSEEK_API_KEY`                                      | `https://api.deepseek.com/v1`                 |             |
| xAI (Grok)         | `XAI_API_KEY`, `GROK_API_KEY`                           | `https://api.x.ai/v1`                         |             |
| Mistral            | `MISTRAL_API_KEY`                                       | `https://api.mistral.ai/v1`                   |             |
| Perplexity         | `PERPLEXITY_API_KEY`                                    | `https://api.perplexity.ai`                   |             |
| Hugging Face       | `HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN`, `HUGGINGFACE_API_KEY` | `https://router.huggingface.co/v1`        |             |
| NVIDIA NIM         | `NVIDIA_API_KEY`, `NIM_API_KEY`                         | `https://integrate.api.nvidia.com/v1`         |             |
| Z.AI / GLM         | `GLM_API_KEY`, `ZAI_API_KEY`, `Z_AI_API_KEY`            | `https://api.z.ai/api/paas/v4`                |             |
| Moonshot (Kimi)    | `MOONSHOT_API_KEY`, `KIMI_API_KEY`                      | `https://api.moonshot.cn/v1`                  |             |
| Ollama Cloud       | `OLLAMA_API_KEY` (alias: `OLLAMA_CLOUD_API_KEY`)        | `https://ollama.com/v1`                       |             |

Every OpenAI-compat base URL can be overridden with the provider's
`*_BASE_URL` env var (e.g. `OPENAI_BASE_URL`, `HF_BASE_URL`) — useful
for in-cluster proxies, enterprise gateways, or local mocks.

## Picking a provider

- **Privacy / air-gap required** → Ollama. Everything else needs egress.
- **Fastest inference on hosted models** → Groq or Cerebras.
- **One key, many models** → OpenRouter.
- **Enterprise compliance required** → Azure OpenAI, Vertex AI, or
  Bedrock (all use their platform's IAM rather than a raw API key).
- **Already in the Anthropic / Google / OpenAI ecosystem** → the
  matching direct adapter. Direct adapters track vendor-specific
  features (prompt caching, extended thinking) that generic OpenAI-compat
  routes miss.

## Tool-use support

K.O.D.A. is a tool-using agent. Adapters that do not support tool
calling are flagged with `supports_tools=False` in the catalog. The
first-run wizard runs a real tool-calling round trip against your
chosen model before writing config, and warns if the model can't
handle tools.

If a cloud provider *claims* OpenAI-compat but silently drops tool
calls, the probe catches it. Report it as a provider bug against that
cloud vendor — the catalog entry stays accurate.

## Adding a provider

For OpenAI-compat vendors, a single catalog append is enough:

```python
# koda/providers/catalog.py
ProviderEntry(
    id="new_vendor",
    label="New Vendor",
    hint="API — NEW_VENDOR_API_KEY",
    tier="cloud",
    transport="openai_compat",
    env_keys=("NEW_VENDOR_API_KEY",),
    base_url="https://api.new-vendor.example/v1",
    base_url_env="NEW_VENDOR_BASE_URL",
),
```

For vendors that need a direct adapter, follow
[`AGENTS.md`](https://github.com/PabloTheThinker/K.O.D.A./blob/main/AGENTS.md)
§ *How to add a provider*:

1. Add an adapter in `koda/adapters/<name>.py` implementing `Provider.chat()`
   with tool-call support.
2. Register it in `create_provider()`.
3. Add the wizard verification entry — a real chat roundtrip is required
   before config writes.
4. Add the catalog entry (`transport="direct"` or `"bespoke"`).
5. Update the README provider table and this page.
6. Add a `[Unreleased]` entry to `CHANGELOG.md`.

## Cost tracking

Turn-level USD cost is recorded on every `turn.complete` /
`turn.aborted` audit event. Pricing comes from
[`koda/providers/pricing.py`](https://github.com/PabloTheThinker/K.O.D.A./blob/main/koda/providers/pricing.py)
via longest-prefix match on the model id. Local and unpriced models are
counted in tokens only (USD = 0).

Rollups:

```bash
koda cost                                  # by model, full log
koda cost --by engagement --since 2026-04-01
koda cost --by session --engagement acme-q2
```

## Air-gap notes

- Ollama and llama.cpp are the only transports that run with zero
  egress. Everything else is BYO key plus an outbound HTTPS connection
  to the vendor's API.
- Direct adapters never reach out at import time — the provider is
  only contacted when `chat()` is first called. Safe to install on a
  disconnected box and add keys later.
- The offline threat-intel cache (CISA KEV / EPSS / CWE / NVD /
  ExploitDB / MITRE ATT&CK / CAPEC) is independent of the provider
  choice. Sync once, scan forever.
