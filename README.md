<p align="center">
  <img src="assets/koda-hero.png" alt="K.O.D.A." width="720">
</p>

<p align="center"><strong>Kinetic Operative Defense Agent</strong></p>
<p align="center"><em>Open-source security specialist — grounded tool-use, honest scanning, model-agnostic, air-gap ready.</em></p>

<p align="center">
  <a href="https://github.com/PabloTheThinker/K.O.D.A./actions/workflows/ci.yml"><img src="https://github.com/PabloTheThinker/K.O.D.A./actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/PabloTheThinker/K.O.D.A./releases"><img src="https://img.shields.io/github/v/release/PabloTheThinker/K.O.D.A.?include_prereleases&sort=semver&style=for-the-badge" alt="Release"></a>
  <a href="https://github.com/PabloTheThinker/K.O.D.A./blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white&style=for-the-badge" alt="Python 3.11+"></a>
  <a href="https://ollama.ai"><img src="https://img.shields.io/badge/Ollama-Air--Gap_Ready-black?style=for-the-badge" alt="Ollama"></a>
  <a href="https://vektraindustries.com"><img src="https://img.shields.io/badge/Built%20by-Vektra%20Industries-8b5cf6?style=for-the-badge" alt="Vektra Industries"></a>
</p>

<p align="center">
  <a href="#why-koda">Why</a> &nbsp;·&nbsp;
  <a href="#install">Install</a> &nbsp;·&nbsp;
  <a href="#quickstart">Quickstart</a> &nbsp;·&nbsp;
  <a href="#skills">Skills</a> &nbsp;·&nbsp;
  <a href="#nlu-router">NLU</a> &nbsp;·&nbsp;
  <a href="#security-model">Security</a> &nbsp;·&nbsp;
  <a href="#architecture">Architecture</a> &nbsp;·&nbsp;
  <a href="#providers">Providers</a> &nbsp;·&nbsp;
  <a href="#scanners">Scanners</a> &nbsp;·&nbsp;
  <a href="#status--roadmap">Roadmap</a> &nbsp;·&nbsp;
  <a href="https://github.com/PabloTheThinker/K.O.D.A./issues">Issues</a>
</p>

---

**K.O.D.A.** is an open-source AI security specialist built by [Vektra Industries](https://vektraindustries.com). It wraps your scanners, your intel, and your LLM of choice inside a harness that enforces Rules of Engagement, grounds every claim in tool evidence, signs every artifact, and behaves like an operator — not a chatbot with regex. It runs on a SOC workstation, an offline analyst laptop, or a $5 VPS. Local-first via [Ollama](https://ollama.ai); BYO key for hosted models. Zero telemetry. Zero phone-home.

If you want a security agent that can be trusted with a real engagement — authorized scope, reviewable decisions, auditor-grade evidence — this is it.

<table>
<tr><td><b>Grounded tool-use</b></td><td>Every CVE, file path, line number, and CVSS score in assistant output must appear verbatim in a prior tool result. Fabrications are rejected before they reach the operator.</td></tr>
<tr><td><b>Rules-of-Engagement gate</b></td><td>Scope (CIDR/hostname) is declared up front. Destructive actions require explicit authorization. Every approval decision is logged to an append-only JSONL with fsync on security-relevant events.</td></tr>
<tr><td><b>Evidence-first</b></td><td>SHA-256 content-addressed artifacts, per-engagement merkle chain, portable <code>tar.gz</code> bundles that reverify offline with Python stdlib only — years later, on any machine.</td></tr>
<tr><td><b>External skill packs</b></td><td>Drop a <code>SKILL.md</code> directory into <code>skills/</code> and it auto-registers. Frontmatter drives mode/phase/ATT&CK mapping; markdown body becomes the operator playbook. Ships with <code>sherlock</code>, <code>oss-forensics</code>, <code>1password</code>; community packs compose.</td></tr>
<tr><td><b>Rule-based NLU router</b></td><td>Pure-Python intent classifier (recon / exploit / IR / audit / lookup / admin / chat) runs before every LLM call. Extracts targets (domains, IPv4, usernames, CVEs, paths), infers risk tier, ranks matching skills, emits a <code>turn.route</code> audit event. No LLM calls in the hot path.</td></tr>
<tr><td><b>Red / Blue / Purple harness</b></td><td>Phase-aware operator voice — 8 red phases (recon → exfil), 6 blue phases (defense, hunt, triage, IR, forensics, hardening). Every finding carries an ATT&CK technique ID. Sigma rules, CIS audits, and NIST 800-61 IR playbooks ship with the harness.</td></tr>
<tr><td><b>Model-agnostic</b></td><td>22 providers (2 local + 20 cloud) behind one declarative catalog. Ollama, llama.cpp, Anthropic, OpenAI, Gemini, Azure, Vertex, Bedrock, Groq, Cerebras, Fireworks, Together, OpenRouter, DeepSeek, xAI, Mistral, Perplexity, Hugging Face, NVIDIA NIM, Z.AI/GLM, Moonshot, Ollama Cloud. Switch with <code>koda setup</code> — no code changes.</td></tr>
<tr><td><b>Remote operations</b></td><td>Telegram bridge with inline-keyboard approvals, fragment buffering, and slash-command parity with the REPL. MCP server (stdio + SSE) exposes scanners and evidence tools to any MCP-compatible client.</td></tr>
<tr><td><b>Air-gap ready</b></td><td>Ollama local models, offline threat-intel cache (KEV, EPSS, CWE, NVD, ExploitDB, MITRE ATT&CK, CAPEC), stdlib-only verification. No outbound calls after initial corpus sync.</td></tr>
</table>

---

## Why K.O.D.A.

Most agent frameworks are general-purpose. Security work isn't.

The question a SOC lead, pentester, or IR consultant needs answered before handing an agent real access is always the same: *can I trust its output to a client report?* K.O.D.A. is engineered around that question. A grounding verifier rejects ungrounded claims. An approval gate fences every risky call. A credential broker redacts secrets across transcripts, evidence, and audit logs. A per-engagement merkle chain makes tampering detectable in a way that survives offline review.

The agent is narrow on purpose. It wraps scanners, not browsers. It reasons in MITRE ATT&CK IDs, not ad-hoc prose. It ships with rules of engagement, not a kitchen sink. Keeping scope tight keeps the trust boundary reviewable.

```
Ask → Route (NLU) → Approve → Tool-call → Ground → Evidence + Audit → Respond
```

## Install

```bash
curl -fsSL https://koda.vektraindustries.com/install | bash
```

The installer handles Python 3.11+ via [uv](https://github.com/astral-sh/uv), venv, dependencies, PATH, and launches the first-run setup wizard.

> **Linux and macOS supported.** Windows users should run under [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install). Tested on Ubuntu 22.04+, Debian 12+, Kali, macOS 13+.

**Manual install:**

```bash
git clone https://github.com/PabloTheThinker/K.O.D.A..git && cd K.O.D.A.
python3 -m venv .venv && source .venv/bin/activate
pip install .
koda setup
```

## Quickstart

```bash
koda setup                  # configure providers + verify credentials live
koda doctor                 # verify config + provider status
koda                        # start the interactive REPL
koda telegram               # run the Telegram operator bridge
koda mcp                    # expose tools over MCP (stdio + SSE)
koda intel sync --all       # pull offline threat-intel corpus
koda update                 # pull + install the latest release
koda version                # print version and exit
koda uninstall              # interactive removal checklist (--dry-run supported)
```

### Three ways to run it

**Pick an outcome.** Translate a security goal into a scanner composition:

```bash
koda audit --preset server-hardening localhost
koda audit --preset web-app https://staging.example.com
koda audit --list-presets          # web-app, pci-readiness, post-breach, sbom-scan…
```

See [`docs/audit-presets.md`](docs/audit-presets.md).

**Scan a client server over SSH.** ControlMaster-multiplexed OpenSSH, static binaries auto-uploaded, full audit trail, no permanent remote footprint:

```bash
koda scan remote user@server.example.com /srv/app --scanner trivy --scanner gitleaks
```

See [`docs/remote-scanning.md`](docs/remote-scanning.md).

**Keep watch on a fleet.** Schedule recurring scans via system cron or systemd-user timers; fingerprint-based diff alerts only on new findings:

```bash
koda schedule add nightly-prod --cron "0 3 * * *" --preset server-hardening \
    --target prod.example.com --alert telegram
```

See [`docs/continuous-monitoring.md`](docs/continuous-monitoring.md).

## Skills

Skill packs are the extensibility seam. A skill is a directory with a single `SKILL.md` file:

```
skills/
  sherlock/
    SKILL.md        # YAML frontmatter + markdown playbook
```

The frontmatter drives mode, phase, MITRE ATT&CK mapping, and prerequisites. The markdown body is injected into the system prompt as an operator playbook when the phase is active:

```yaml
---
name: sherlock
description: OSINT username search across 400+ social networks.
version: 1.0.0
mode: red
phase: recon
attack_techniques: [T1589, T1593]
tools_required: [shell.exec]
prerequisites:
  commands: [sherlock]
---

# Sherlock OSINT Username Search
...
```

Packs auto-register from three locations at boot:

1. `./skills` (project-local)
2. `~/.koda/skills` (per-user)
3. `$KODA_SKILLS_PATH` (colon-separated, OS-path style)

Malformed packs don't raise — they surface as `(path, message)` errors the loader reports back. To load manually:

```python
from koda.skills import load_default_packs
count, errors = load_default_packs()
```

**Built-in packs (v0.3.0):**

| Pack | Mode | Phase | ATT&CK | Purpose |
|------|------|-------|--------|---------|
| `sherlock` | red | recon | T1589, T1593 | OSINT username search across 400+ social networks |
| `oss-forensics` | blue | ir | T1195.002, T1588.001 | Supply-chain investigation of GitHub repositories |
| `1password` | blue | hardening | T1552.001 | 1Password CLI integration for secret handling |

Community packs compose the same way — drop the directory in `skills/` and it's live.

## NLU Router

Before every LLM call, a pure-Python rule-based router classifies the user's request:

- **Intent** — recon, exploit, IR, audit, lookup, admin, chat, or ambiguous
- **Targets** — domains, IPv4 addresses, usernames, CVE IDs, file paths
- **Risk tier** — SAFE, SENSITIVE, or DANGEROUS (EXPLOIT → DANGEROUS; active recon → SENSITIVE; passive recon → SAFE)
- **Matched skills** — registry-backed ranking of packs whose mode/phase fits the intent
- **Clarify question** — one sharp question when scope or intent is unclear

The decision is injected into the system prompt as an `<nlu>` hint block and emitted as a `turn.route` audit event. The model still makes the call — the router is a pre-LLM signal layer, not a gate.

```python
from koda.nlu import IntentRouter
router = IntentRouter()
decision = router.route("find accounts for username johndoe123")
# decision.intent == Intent.RECON
# decision.risk == RiskTier.SAFE
# decision.matched_skills[:3] == ('red.recon', 'red.enumeration', 'sherlock')
```

Zero network calls. All regex compiled at module load. Deterministic.

## Security Model

K.O.D.A. is a security tool, so the trust boundary *is* the product. Five components enforce it:

- **Grounding verifier.** Assistant text is checked against the tool transcript before release. Ungrounded CVEs, file paths, and line numbers are rejected.
- **Approval gate.** Every tool carries a risk tier — SAFE / SENSITIVE / DANGEROUS / BLOCKED — with argument-level guardrails. BLOCKED never runs. Thresholds are set per-engagement at wizard time.
- **Credential broker.** Per-engagement vault with placeholder detection, cooldown on failure, and automatic redaction across transcripts, evidence, and audit rows.
- **Tamper-evident evidence.** SHA-256 content addressing, per-engagement merkle chain, portable `tar.gz` bundles that reverify with Python stdlib only.
- **Append-only audit.** JSONL with `fsync` on security-relevant events, size-rotated, engagement-scoped.

Found a vulnerability? See [SECURITY.md](./SECURITY.md) — **do not open a public issue.**

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                          Operator                            │
│                 (REPL · Telegram · MCP)                      │
└──────────┬───────────────────────────────────┬───────────────┘
           │                                   │
           ▼                                   ▼
┌───────────────────────┐           ┌──────────────────────────┐
│    NLU router         │           │    Approval gate         │
│  intent · risk · scope│           │  SAFE|SENSITIVE|DANGER   │
└──────────┬────────────┘           └────────────┬─────────────┘
           │                                     │
           ▼                                     │
┌───────────────────────┐                        │
│   Provider adapter    │                        │
│  (11 backends, BYO)   │                        │
└──────────┬────────────┘                        │
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
│   Skill registry (built-in + SKILL.md packs)                 │
└──────────────────────────────────────────────────────────────┘
```

Flow: the operator prompts, the NLU router classifies intent and risk, the provider routes through the matched skill, the approval gate guards, the tool runs, the grounding verifier checks the output, evidence and audit capture the transcript. Scanners plug in through a uniform `Finding` contract.

## Providers

22 providers — 2 local, 20 cloud — behind one declarative catalog (`koda/providers/catalog.py`). The wizard surfaces recommended providers first and pings each candidate with a real chat roundtrip **before** writing config, so you know credentials work before the first engagement. After verification it runs a tool-use probe and warns if the model ignores function-calling.

| Provider        | Tier   | Detect                                          | Key env                                  |
|-----------------|--------|-------------------------------------------------|------------------------------------------|
| Ollama          | local  | `http://127.0.0.1:11434` reachable              | (none — local)                           |
| llama.cpp       | local  | local server reachable                          | (none — local)                           |
| Anthropic       | cloud  | `ANTHROPIC_API_KEY`                             | `ANTHROPIC_API_KEY`                      |
| Google Gemini   | cloud  | `GEMINI_API_KEY` / `GOOGLE_API_KEY`             | `GEMINI_API_KEY`                         |
| Azure OpenAI    | cloud  | `AZURE_OPENAI_API_KEY`                          | `AZURE_OPENAI_API_KEY`                   |
| Google Vertex AI| cloud  | ADC / explicit token                            | (ADC)                                    |
| AWS Bedrock     | cloud  | AWS credential chain                            | (AWS creds)                              |
| OpenAI          | cloud  | `OPENAI_API_KEY`                                | `OPENAI_API_KEY`                         |
| Groq            | cloud  | `GROQ_API_KEY`                                  | `GROQ_API_KEY`                           |
| Cerebras        | cloud  | `CEREBRAS_API_KEY`                              | `CEREBRAS_API_KEY`                       |
| Fireworks       | cloud  | `FIREWORKS_API_KEY`                             | `FIREWORKS_API_KEY`                      |
| Together AI     | cloud  | `TOGETHER_API_KEY`                              | `TOGETHER_API_KEY`                       |
| OpenRouter      | cloud  | `OPENROUTER_API_KEY`                            | `OPENROUTER_API_KEY`                     |
| DeepSeek        | cloud  | `DEEPSEEK_API_KEY`                              | `DEEPSEEK_API_KEY`                       |
| xAI (Grok)      | cloud  | `XAI_API_KEY` / `GROK_API_KEY`                  | `XAI_API_KEY`                            |
| Mistral         | cloud  | `MISTRAL_API_KEY`                               | `MISTRAL_API_KEY`                        |
| Perplexity      | cloud  | `PERPLEXITY_API_KEY`                            | `PERPLEXITY_API_KEY`                     |
| Hugging Face    | cloud  | `HF_TOKEN` / `HUGGING_FACE_HUB_TOKEN`           | `HF_TOKEN`                               |
| NVIDIA NIM      | cloud  | `NVIDIA_API_KEY` / `NIM_API_KEY`                | `NVIDIA_API_KEY`                         |
| Z.AI / GLM      | cloud  | `GLM_API_KEY` / `ZAI_API_KEY`                   | `GLM_API_KEY`                            |
| Moonshot (Kimi) | cloud  | `MOONSHOT_API_KEY` / `KIMI_API_KEY`             | `MOONSHOT_API_KEY`                       |
| Ollama Cloud    | cloud  | `OLLAMA_API_KEY`                                | `OLLAMA_API_KEY`                         |

On verification failure: retry with new creds, skip (save anyway), or abort.

## Scanners

Eight scanner wrappers plus a generic SARIF 2.1.0 reader. Findings flow through a uniform contract: content-fingerprint dedup, KEV/EPSS/CVSS enrichment, severity upgrade on KEV hit.

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

## Security Harness

K.O.D.A. ships with a phase-aware security harness that turns any connected model into a disciplined operator — red, blue, or purple.

```bash
koda intel sync --all              # offline corpus: KEV, EPSS, CWE, NVD,
                                   #   ExploitDB, MITRE ATT&CK, CAPEC
koda intel lookup CVE-2021-44228   # full chain: CVE → KEV → EPSS → CWE
                                   #   → linked exploits → ATT&CK
koda report generate \             # exec, technical, Markdown, SARIF 2.1
  --findings findings.jsonl --out ./reports
```

Red mode exposes 8 phase skills (recon → enumeration → initial access → execution → persistence → privesc → lateral → exfil). Blue mode exposes 6 (defense, hunt, triage, IR, forensics, hardening). Each phase injects its own ATT&CK-tagged skill fragment into the system prompt so the model reasons in TTPs, not in ad-hoc prose. A Rules-of-Engagement gate enforces scope (CIDR/hostname), blocks destructive actions, and logs every decision to `<KODA_HOME>/engagements/<roe_id>/roe.jsonl`. Sigma rules, CIS audits, and NIST 800-61 IR playbooks are bundled. Stdlib-only.

**Operator persona.** Koda speaks as a professional red-turned-blue operator: calm, precise, ROE-first, evidence-over-opinion, jargon-matching. It infers the narrowest reasonable scope from vague asks, drops ceremony under incident pressure, and refuses action outside declared scope. The persona block loads into every system prompt.

## Engagements

Every session is scoped to an engagement — a named boundary for a pentest, IR case, or audit. Sessions, credentials, evidence, and audit rows all carry the engagement label. Set it via `KODA_ENGAGEMENT=acme-q2` before starting the REPL, or leave it at `default` for personal use.

## Remote Operations

K.O.D.A. ships a **Telegram bridge** for running engagements from a phone. Configure via `koda setup` (Stage 8), or manually by writing `~/.koda/secrets.env`:

```
KODA_TELEGRAM_BOT_TOKEN=<BotFather token>
KODA_TELEGRAM_CHAT_ID=<your Telegram user id>
```

`koda telegram` runs a daemon that relays messages, approvals, and alerts to your chat. Only the configured `CHAT_ID` is served — all other chats are audit-logged and dropped. Inline-keyboard approvals, inbound photos/documents (25 MB cap), fragment buffering, and slash commands (`/help`, `/new`, `/reset`, `/status`, `/model`, `/models`, `/history`, `/stop`) work from both the REPL and Telegram with parity. Stdlib-only — no third-party dependencies.

An **MCP server** is also available: `koda mcp` exposes the scanner and evidence tools to any MCP-compatible client (stdio + SSE transports).

## Status & Roadmap

Beta. The harness, 11 provider adapters, grounding verifier, approval gate, credential broker, evidence store, threat-intel cache, 8 scanner wrappers, external skill pack loader, NLU router, Telegram bridge, and MCP server are live with smoke coverage (`scripts/smoke.sh`) and a focused unit suite (`tests/`). CI runs lint + install matrix on every push. API surface is stabilizing; expect small breaking changes before 1.0.

See [ROADMAP.md](./ROADMAP.md) for what's next.

## Migrating From

K.O.D.A. draws architectural inspiration from two projects — here's how the concepts map if you're already using them:

- **[Hermes Agent](https://github.com/NousResearch/hermes-agent)** — K.O.D.A.'s profile isolation, REPL slash-command grammar, and `SKILL.md` pack format are Hermes-style. If you have Hermes skill packs, they typically load with minor frontmatter additions (`mode`, `phase`, `attack_techniques`).
- **[OpenClaw](https://www.npmjs.com/package/openclaw)** — OpenClaw's installer UX and onboarding flow are the model for `install.sh` and `koda setup`. If you've used OpenClaw skills, the risk-tier approval model maps directly onto OpenClaw's approval prompts.

A full migration guide will land in `docs/migrating.md` once the hosted docs site is up.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Short version: run `ruff check . && pytest tests/ && scripts/smoke.sh`, update `CHANGELOG.md` under `[Unreleased]`, open a PR. Agent-readable project instructions live in [AGENTS.md](./AGENTS.md).

Security issues go to [SECURITY.md](./SECURITY.md), **not** public issues.

## License

MIT — see [LICENSE](./LICENSE).

Architectural credit: K.O.D.A. is an independent reimplementation inspired by the open-source harness patterns of [Nous Research's Hermes](https://github.com/NousResearch/hermes-agent) (MIT) and [OpenClaw](https://www.npmjs.com/package/openclaw). No code was copied; the patterns were analyzed and rewritten from scratch for the security domain.

Built by [Vektra Industries](https://vektraindustries.com).
