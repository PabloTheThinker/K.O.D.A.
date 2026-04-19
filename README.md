<p align="center">
  <h1 align="center">K.O.D.A.</h1>
  <p align="center"><strong>Kinetic Operative Defense Agent</strong></p>
  <p align="center">An open-source AI security agent harness — grounded tool-use, honest scanning, model-agnostic.</p>
</p>

<p align="center">
  <a href="https://github.com/PabloTheThinker/K.O.D.A./actions/workflows/ci.yml"><img src="https://github.com/PabloTheThinker/K.O.D.A./actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/PabloTheThinker/K.O.D.A./releases"><img src="https://img.shields.io/github/v/release/PabloTheThinker/K.O.D.A.?include_prereleases&sort=semver" alt="Release"></a>
  <a href="https://github.com/PabloTheThinker/K.O.D.A./blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://ollama.ai"><img src="https://img.shields.io/badge/Ollama-Air--Gap_Ready-black" alt="Ollama"></a>
  <a href="https://vektraindustries.com"><img src="https://img.shields.io/badge/Vektra-Industries-8b5cf6" alt="Vektra Industries"></a>
</p>

<p align="center">
  <a href="#why-koda">Why K.O.D.A.</a> &nbsp;·&nbsp;
  <a href="#install">Install</a> &nbsp;·&nbsp;
  <a href="#quick-start">Quickstart</a> &nbsp;·&nbsp;
  <a href="#security-model">Security</a> &nbsp;·&nbsp;
  <a href="#architecture">Architecture</a> &nbsp;·&nbsp;
  <a href="#status--roadmap">Roadmap</a> &nbsp;·&nbsp;
  <a href="https://github.com/PabloTheThinker/K.O.D.A./issues">Issues</a>
</p>

---

## Why K.O.D.A.

Most agent frameworks are general-purpose. Security work isn't.

- **Grounded tool-use.** Assistant text is verified against the tool transcript before it reaches you. No invented CVEs, no invented file paths, no invented line numbers.
- **Air-gap ready.** Runs on a SOC workstation, an offline analyst laptop, or anything with Python. Local-first via Ollama; BYO key for hosted models. Zero telemetry. Zero phone-home.
- **Evidence-first.** Every tool call produces a hash-addressed artifact in a merkle chain. The chain reverifies offline with Python stdlib. Bundles are portable and auditor-friendly.
- **Narrow.** K.O.D.A. is a security agent. It wraps scanners, not browsers. Keeping scope tight keeps the trust boundary reviewable.

```
Ask → Route → Tool-call → Ground → Respond
```

## Install

```bash
curl -fsSL https://koda.vektraindustries.com/install | bash
```

Handles everything: Python 3.11+ via `uv`, venv, dependencies, PATH, and the
first-run setup wizard.

**Or manually:**

```bash
git clone https://github.com/PabloTheThinker/K.O.D.A..git && cd K.O.D.A.
python3 -m venv .venv && source .venv/bin/activate
pip install .
koda setup
```

## Quick Start

```bash
koda setup                  # configure providers + verify credentials live
koda doctor                 # verify config + provider status
koda                        # start the interactive REPL
koda telegram               # run the Telegram operator bridge
koda mcp                    # expose tools over MCP (stdio + SSE)
koda update                 # pull + install the latest release
koda version                # print version and exit
koda uninstall              # interactive removal checklist (--dry-run supported)
```

## Security Model

K.O.D.A. is a security tool, so the trust boundary is the product. Five pieces
enforce it:

- **Grounding verifier.** Assistant text is checked against the tool transcript
  before it's released. Ungrounded claims (CVEs, file paths, line numbers not
  produced by a tool call) are rejected.
- **Approval gate.** Every tool has a risk tier — SAFE / SENSITIVE / DANGEROUS
  / BLOCKED — with argument-level guardrails. BLOCKED never runs. Thresholds
  are set per-engagement at wizard time.
- **Credential broker.** Per-engagement credential vault with placeholder
  detection, cooldown on failure, and automatic redaction across transcripts,
  evidence, and audit rows.
- **Tamper-evident evidence.** SHA-256 content addressing, merkle chain per
  engagement, portable `tar.gz` bundles that reverify with Python stdlib only —
  years later, offline, on any machine.
- **Append-only audit.** JSONL with `fsync` on security-relevant events,
  size-rotated. Engagement-scoped.

Found a vulnerability? See [SECURITY.md](./SECURITY.md) — **do not open a
public issue.**

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                          Operator                            │
│                 (REPL · Telegram · MCP)                      │
└──────────┬───────────────────────────────────┬───────────────┘
           │                                   │
           ▼                                   ▼
┌───────────────────────┐           ┌──────────────────────────┐
│    Provider adapter   │           │    Approval gate         │
│  (11 backends, BYO)   │◀─────────▶│  SAFE|SENSITIVE|DANGER   │
└──────────┬────────────┘           └────────────┬─────────────┘
           │                                     │
           ▼                                     ▼
┌───────────────────────┐           ┌──────────────────────────┐
│   Grounding verifier  │◀─────────▶│     Tool registry        │
│  reject fabrications  │           │  scanners · fs · net     │
└──────────┬────────────┘           └────────────┬─────────────┘
           │                                     │
           ▼                                     ▼
┌──────────────────────────────────────────────────────────────┐
│   Evidence store (SHA-256 + merkle chain, tar.gz bundles)    │
│   Audit log (append-only JSONL, fsync)                       │
│   Credential broker (per-engagement, redaction)              │
│   Local threat intel (KEV / EPSS / CWE / NVD, offline)       │
└──────────────────────────────────────────────────────────────┘
```

Core flow: the operator prompts, the provider routes, the approval gate
guards, the tool runs, the grounding verifier checks the output, evidence and
audit capture the transcript. Scanners plug in through a uniform Finding
contract.

## Providers

Eleven providers — local-first, BYO model. The wizard pings each candidate
with a real chat roundtrip **before** writing config, so you know credentials
work before the first engagement.

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

## Scanners

Eight scanner wrappers plus a generic SARIF 2.1.0 reader. Findings flow
through a uniform contract: content-fingerprint dedup, KEV/EPSS/CVSS
enrichment, severity upgrade on KEV hit.

| Tool          | Role                                       |
|---------------|--------------------------------------------|
| Semgrep       | Source-code static analysis                |
| Bandit        | Python security linter                     |
| Gitleaks      | Secret detection in git history            |
| Trivy         | Container / filesystem / dependency scan   |
| OSV-Scanner   | OSS vulnerability enumeration              |
| Grype         | SBOM / image vulnerability scan            |
| Nuclei        | Template-driven network / web probes       |
| Nmap          | Network reconnaissance                     |
| SARIF reader  | Ingest any SARIF 2.1.0 output              |

## Engagements

Every session is scoped to an engagement — a named boundary for a pentest,
IR case, or audit. Sessions, credentials, evidence, and audit rows all carry
the engagement label. Set it via `KODA_ENGAGEMENT=acme-q2` before starting
the REPL, or leave it at `default` for personal use.

## Remote Operations

K.O.D.A. ships a **Telegram bridge** for running engagements from a phone.
Configure via `koda setup` (Stage 8), or manually by writing
`~/.koda/secrets.env`:

```
KODA_TELEGRAM_BOT_TOKEN=<BotFather token>
KODA_TELEGRAM_CHAT_ID=<your Telegram user id>
```

Then `koda telegram` runs a daemon that relays messages, approvals, and
alerts to your chat. Only the configured `CHAT_ID` is served — all other
chats are audit-logged and dropped. Inline-keyboard approvals, inbound
photos/documents (25 MB cap), fragment buffering, and slash commands
(`/help`, `/new`, `/reset`, `/status`, `/model`, `/models`, `/history`,
`/stop`) work from both the REPL and Telegram with parity. Stdlib-only —
no third-party dependencies.

An **MCP server** is also available: `koda mcp` exposes the scanner and
evidence tools to any MCP-compatible client (stdio + SSE transports).

## Security Harness

K.O.D.A. ships with a phase-aware security harness that turns any
connected model into a disciplined operator — red, blue, or purple.

```
koda intel sync --all              # offline corpus: KEV, EPSS, CWE, NVD,
                                   #   ExploitDB, MITRE ATT&CK, CAPEC
koda intel lookup CVE-2021-44228   # full chain: CVE → KEV → EPSS → CWE
                                   #   → linked exploits → ATT&CK
koda report generate \             # exec, technical, Markdown, SARIF 2.1
  --findings findings.jsonl --out ./reports
```

Red mode exposes 8 phase skills (recon → enumeration → initial access →
execution → persistence → privesc → lateral → exfil). Blue mode exposes
6 (defense, hunt, triage, IR, forensics, hardening). Each phase injects
its own ATT&CK-tagged skill fragment into the system prompt so the
model reasons in TTPs, not in ad-hoc prose. A Rules-of-Engagement gate
enforces scope (CIDR/hostname), blocks destructive actions, and logs
every decision to `<KODA_HOME>/engagements/<roe_id>/roe.jsonl`. Sigma
rules, CIS audits, and NIST 800-61 IR playbooks are bundled. Stdlib-only.

## Status & Roadmap

Beta. The harness, 11 provider adapters, grounding verifier, approval gate,
credential broker, evidence store, threat-intel cache, 8 scanner wrappers,
Telegram bridge, and MCP server are live and have end-to-end smoke coverage
(`scripts/smoke.sh`). CI runs lint + install matrix on every push. API
surface is stabilizing; expect small breaking changes before 1.0.

See [ROADMAP.md](./ROADMAP.md) for what's next.

## Migrating From

K.O.D.A. draws architectural inspiration from two projects — here's how the
concepts map if you're already using them:

- **[Hermes Agent](https://github.com/NousResearch/hermes-agent)** — K.O.D.A.'s
  profile isolation and REPL slash-command grammar are Hermes-style. If you
  have a Hermes `~/.hermes` layout, `koda -p <name>` will feel familiar.
  Session import is not yet supported — it's on the roadmap.
- **[OpenClaw](https://www.npmjs.com/package/openclaw)** — OpenClaw's installer
  UX and onboarding flow are the model for `install.sh` and `koda setup`.
  If you've used OpenClaw skills, the risk-tier approval model maps directly
  onto OpenClaw's approval prompts.

A full migration guide will land in `docs/migrating.md` once the hosted docs
site is up.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Short version: run
`ruff check . && scripts/smoke.sh`, update `CHANGELOG.md` under
`[Unreleased]`, open a PR. Agent-readable project instructions live in
[AGENTS.md](./AGENTS.md).

Security issues go to [SECURITY.md](./SECURITY.md), **not** public issues.

## License

MIT — see [LICENSE](./LICENSE).

Architectural credit: K.O.D.A. is an independent reimplementation inspired by
the open-source harness patterns of
[Nous Research's Hermes](https://github.com/NousResearch/hermes-agent) (MIT)
and [OpenClaw](https://www.npmjs.com/package/openclaw). No code was copied;
the patterns were analyzed and rewritten from scratch for the security domain.

Built by [Vektra Industries](https://vektraindustries.com).
