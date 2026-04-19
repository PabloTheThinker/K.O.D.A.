# Changelog

All notable changes to K.O.D.A. are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — 2026-04-19

Legacy-port turn: pre-filter, compressor, reflection, and agent-loop wiring.

### Added
- **Guardian pre-filter** (`koda/security/guardian.py`) — cheap regex
  detector that runs before the LLM call and tool dispatch. Catches
  prompt injection, destructive shell commands, and sensitive-data writes
  in `strict` / `balanced` / `permissive` modes. Append-only incident log
  with bounded tail, JSON save/load state. Ported from
  `koda-agent/koda/cognition/guardian.py` — stripped of the cognitive-
  module base; acts the same on turn 1 as on turn 1000.
- **Context compressor** (`koda/session/compressor.py`) — keeps the
  system prompt, the first exchange, and the last N messages at full
  fidelity; replaces the middle with a security-aware summary
  (user requests, tool counts, errors, refused approvals, ATT&CK IDs,
  CVE IDs). No LLM calls in the hot path by default; optional
  LLM-backed summarization with graceful fallback.
- **Reflection engine** (`koda/agent/reflection.py`) — bounded journal
  of per-turn outcomes with pattern extraction (`recent_hint()`,
  `get_patterns()`) suitable for post-engagement retrospectives and
  light system-prompt nudges.
- **TurnLoop wiring** — `TurnLoop(..., guardian=, reflection=,
  compressor=)` are all optional. Guardian scans user input and every
  tool call before the approval gate; blocks emit `guardian.block`
  audit events and surface as refusal messages. Reflection records
  every terminal turn. Compressor emits `session.compressed` events
  when the transcript grows past 80% of budget.
- **Two more built-in skill packs** ported from `koda-cli-legacy`:
  `log-analyzer` (blue/hunt, T1078/T1110/T1098 — journalctl auth triage)
  and `port-monitor` (blue/hunt, T1571/T1021/T1090 — listener drift
  detection).
- Test suites: `test_guardian.py` (13 tests), `test_compressor.py` (6),
  `test_reflection.py` (6) — 38 total passing.

## [0.3.0] — 2026-04-19

Framework turn: external skill packs, rule-based NLU, operator persona.

### Added
- **External skill pack loader** (`koda/skills/`) — drop `SKILL.md` directories
  into `./skills`, `~/.koda/skills`, or `$KODA_SKILLS_PATH` to register security
  playbooks with `koda.security.skills.registry.DEFAULT_REGISTRY`. YAML
  frontmatter drives mode/phase/attack_techniques; markdown body becomes the
  operator-voice prompt fragment. Errors surface as `(path, message)` pairs —
  never raise.
- **Built-in skill packs** ported from Hermes' `optional-skills/security/`:
  `sherlock` (OSINT username search, red/recon, T1589/T1593),
  `oss-forensics` (GitHub supply-chain IR, blue/ir, T1195.002/T1588.001),
  `1password` (CLI secrets, blue/hardening, T1552.001).
- **Rule-based NLU router** (`koda/nlu/`) — pure-Python intent classifier
  (recon / exploit / ir / audit / lookup / admin / chat / ambiguous), target
  extraction (domains, IPv4, usernames, CVEs, paths), risk-tier inference,
  and registry-backed skill ranking. No LLM calls in the hot path.
- **Agent loop integration** — `TurnLoop(router=...)` classifies every user
  turn before the LLM call, emits a `turn.route` audit event, and injects
  an `<nlu>` hint block into the system prompt with intent, risk, targets,
  matched skills, and an optional clarify question.
- **Persona block** in the security prompt — Koda now has a distinct operator
  voice (calm, precise, ROE-first, evidence-over-opinion, jargon-matching).
- Test suite at `tests/test_skills_loader.py` and `tests/test_nlu_router.py`
  (13 tests covering frontmatter parsing, loader error paths, intent
  classification, risk inference, and clarify routing).

### Added (previous Unreleased)
- `koda --version` / `koda version` — print version and exit.

### Changed
- README restructured: "Why K.O.D.A.", elevated Security Model, Architecture
  section with flow diagram, Status & Roadmap, Migrating From sections.

### Fixed
- `koda/__init__.py` version now matches `pyproject.toml` (was 0.1.0, now 0.2.0).

## [0.2.0] — 2026-04-18

First public-ready beta. Full security agent surface end-to-end.

### Added
- **Pre-save credential verification** in the setup wizard — every provider is
  pinged with a real chat roundtrip before config is written. Retry / skip /
  abort loop on failure.
- **Telegram bridge** (`koda telegram`) — full bi-directional operator surface
  with inline-keyboard approvals, inbound media, fragment buffering, and slash
  commands (`/help`, `/status`, `/new`, `/model`, `/history`) at parity with
  the REPL.
- **MCP server** (`koda mcp`) — exposes scanner + evidence tools to any
  MCP-compatible client over stdio and SSE.
- **Append-only audit log** (JSONL) with `fsync` on security-relevant events
  and size-based rotation.
- **Tamper-evident evidence store** — SHA-256 content addressing + merkle chain
  per engagement, portable `tar.gz` bundles that reverify with Python stdlib
  only.
- **Credential broker** — per-engagement vault with placeholder detection,
  cooldown on failure, and automatic redaction across transcripts, evidence,
  and audit rows.
- **Local threat intel cache** — offline SQLite of CISA KEV, EPSS, CWE, and
  NVD CVE. Zero network at query time.
- **Findings correlation** — content-fingerprint dedup, KEV/EPSS/CVSS
  enrichment, severity upgrade on KEV hit.
- **Scanner wrappers (8)** — Semgrep, Trivy, Bandit, Gitleaks, Nuclei,
  OSV-Scanner, Nmap, Grype. Generic SARIF 2.1.0 reader for anything else.
- **11 provider adapters** — Ollama, Claude CLI, Anthropic, OpenAI, Google
  Gemini, Groq, Together AI, OpenRouter, DeepSeek, xAI (Grok), Mistral.
- **Multi-stage setup wizard** — risk acknowledgement, engagement naming,
  approval thresholds, scanner probe, Telegram setup.
- **Engagement-scoped isolation** — sessions, credentials, evidence, and audit
  rows are all tagged with the active engagement; swapping engagements swaps
  the entire context.
- **Profile isolation** — `koda -p <name>` runs under a named `KODA_HOME`;
  sticky default via `~/.koda/active_profile`.
- **Approval gate** — per-tool risk tiers (SAFE / SENSITIVE / DANGEROUS /
  BLOCKED) with argument-level guardrails. Defaults auto-approve up to
  DANGEROUS; BLOCKED never runs.
- **Helix DSEM memory** — dual-store entangled memory with cross-store
  verification and conflict tracking.
- **Installer** — hosted one-liner with update and uninstall flows.
- **CI** — GitHub Actions running ruff, Python 3.11/3.12/3.13 install+import
  matrix, and `install.sh` smoke on every push.
- **Distribution hardening** — SECURITY.md, .github/ISSUE_TEMPLATE/ structured
  forms, .github/workflows/ci.yml.

### Changed
- Install-directory detection now uses `sys.prefix` instead of
  `sys.executable.resolve()` — `uv`-managed venvs symlink `.venv/bin/python`
  to the system Python, which was causing auto-detect to point into `/usr`.

### Security
- Credential redaction is enforced across transcripts, evidence, and audit —
  secrets never leak into captured artifacts.
- Default approval threshold blocks anything marked DANGEROUS without explicit
  consent at wizard time.

## [0.1.0] — 2026-03-01

Initial scaffold. Private development; no public release.

### Added
- Harness skeleton, tool registry, approval gate.
- Three initial provider adapters (Ollama, Claude CLI, Anthropic).
- Session store, turn loop, CLI entry, first-run setup wizard.

[Unreleased]: https://github.com/PabloTheThinker/K.O.D.A./compare/v0.4.0...HEAD
[0.4.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.4.0
[0.3.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.3.0
[0.2.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.2.0
[0.1.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.1.0
