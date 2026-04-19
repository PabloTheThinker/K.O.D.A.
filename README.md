<p align="center">
  <h1 align="center">K.O.D.A.</h1>
  <p align="center"><strong>Kinetic Operative Defense Agent</strong></p>
  <p align="center">Open-source AI security agent harness — grounded tool-use, honest scanning, model-agnostic.</p>
</p>

<p align="center">
  <a href="https://github.com/PabloTheThinker/K.O.D.A./blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://ollama.ai"><img src="https://img.shields.io/badge/Ollama-Air--Gap_Ready-black?style=for-the-badge" alt="Ollama"></a>
  <a href="https://vektraindustries.com"><img src="https://img.shields.io/badge/Vektra-Industries-8b5cf6?style=for-the-badge" alt="Vektra Industries"></a>
</p>

<p align="center">
  <a href="#install">Install</a> &nbsp;|&nbsp;
  <a href="#quick-start">Quick Start</a> &nbsp;|&nbsp;
  <a href="https://github.com/PabloTheThinker/K.O.D.A./issues">Issues</a> &nbsp;|&nbsp;
  <a href="https://vektraindustries.com">Website</a>
</p>

---

K.O.D.A. is a harness for running a security-focused AI agent against code, hosts, and infrastructure. It ships a tool-first execution model, a grounding verifier that rejects fabricated claims (no invented CVEs, no invented file paths), and a semantic layer that turns action-intent prompts into real tool calls before the model can improvise.

Run it on a SOC workstation, an air-gapped analyst laptop, or anywhere Python runs.

```
Ask → Route → Tool-call → Ground → Respond
```

## Why another agent

Most agent frameworks are general-purpose. Security work isn't. When a user asks *"is my project safe?"* a general-purpose agent will often write a confident-looking report from thin air — fake CVEs, fake file paths, fake line numbers. K.O.D.A. treats every security claim as ungrounded until a tool has produced evidence for it.

## What's inside

- **Grounding verifier** — assistant text is checked against the tool transcript before it's allowed out.
- **Approval gate** — risk-tiered per-tool decisions, scoped to the active engagement.
- **Append-only audit log** — JSONL with `fsync` on security-relevant events, size-rotated.
- **Tamper-evident evidence store** — SHA-256 content addressing + merkle chain per engagement, portable `tar.gz` bundles that reverify with stdlib only.
- **Credential broker** — per-engagement vault with placeholder detection, cooldown on failure, and automatic redaction across transcripts, evidence, and audit.
- **Local threat intel** — offline SQLite cache of CISA KEV, EPSS, CWE, NVD CVE. No network at query time.
- **Findings correlation** — content-fingerprint dedup + KEV/EPSS/CVSS enrichment + severity upgrade on KEV hit.
- **Scanner wrappers** — Semgrep, Trivy, Bandit, Gitleaks, Nuclei, OSV-Scanner, Nmap, Grype, plus a generic SARIF 2.1.0 reader.

## Install

```bash
curl -fsSL https://koda.vektraindustries.com/install | bash
```

Handles everything: Python 3.11+ via `uv`, venv, dependencies, PATH, and the setup wizard.

**Or manually:**

```bash
git clone https://github.com/PabloTheThinker/K.O.D.A..git && cd K.O.D.A.
python3 -m venv .venv && source .venv/bin/activate
pip install .
koda setup
```

## Quick Start

```bash
koda setup                  # Configure providers + verify credentials live
koda doctor                 # Verify config + provider status
koda                        # Start the interactive REPL
koda telegram               # Run the Telegram operator bridge
koda update                 # Pull + install the latest release
koda uninstall              # Interactive removal checklist (--dry-run supported)
```

## Providers

Eleven providers — local-first, BYO model. The wizard pings each candidate with a real chat roundtrip **before** writing config, so you know credentials work before the first engagement.

| Provider       | Detect                                  | Key env                |
|----------------|-----------------------------------------|------------------------|
| Ollama         | `http://127.0.0.1:11434` reachable      | (none — local)         |
| Claude CLI     | `claude` binary on `PATH`               | (none — CLI auth)      |
| Anthropic      | `ANTHROPIC_API_KEY`                     | `ANTHROPIC_API_KEY`    |
| OpenAI         | `OPENAI_API_KEY`                        | `OPENAI_API_KEY`       |
| Google Gemini  | `GEMINI_API_KEY` / `GOOGLE_API_KEY`     | `GEMINI_API_KEY`       |
| Groq           | `GROQ_API_KEY`                          | `GROQ_API_KEY`         |
| Together AI    | `TOGETHER_API_KEY`                      | `TOGETHER_API_KEY`     |
| OpenRouter     | `OPENROUTER_API_KEY`                    | `OPENROUTER_API_KEY`   |
| DeepSeek       | `DEEPSEEK_API_KEY`                      | `DEEPSEEK_API_KEY`     |
| xAI (Grok)     | `XAI_API_KEY` / `GROK_API_KEY`          | `XAI_API_KEY`          |
| Mistral        | `MISTRAL_API_KEY`                       | `MISTRAL_API_KEY`      |

On verification failure: retry with new creds, skip (save anyway), or abort.

## Engagements

Every session is scoped to an engagement — a named boundary for a pentest, IR case, or audit. Sessions, credentials, evidence, and audit rows carry the engagement label. Set it via `KODA_ENGAGEMENT=acme-q2` before starting the REPL, or leave it default for personal use.

## Remote Operations

K.O.D.A. ships a **Telegram bridge** for running engagements from a phone. Configure via `koda setup` (Stage 8), then `koda telegram` runs a daemon that relays messages, approvals, and alerts to your chat. Slash commands (`/help`, `/status`, `/new`, `/model`, `/history`) work from both the REPL and Telegram with parity.

An MCP server is also available: `koda mcp` exposes the scanner and evidence tools to any MCP-compatible client.

## Security

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](./SECURITY.md) for the disclosure channel and response SLA.

## Status

Beta. The harness, provider adapters (11), grounding verifier, approval gate, credential broker, evidence store, threat-intel cache, scanner wrappers (8), Telegram bridge, and MCP server are live and have end-to-end smoke coverage (`scripts/smoke.sh`). CI runs lint + install smoke on every push. API surface is stabilizing; expect small breaking changes before 1.0.

## License

MIT. See [LICENSE](./LICENSE).

Architectural credit: this codebase is an independent reimplementation inspired by the open-source harness patterns of [Nous Research's Hermes](https://github.com/NousResearch/hermes-agent) (MIT) and [OpenClaw](https://www.npmjs.com/package/openclaw). No code was copied; the patterns were analyzed and rewritten from scratch for the security domain.
