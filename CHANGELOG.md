# Changelog

All notable changes to K.O.D.A. are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (Scheduled Monitoring)
- **Continuous monitoring** (`koda schedule add|list|remove|run|history|diff`) — registers
  periodic security scans via the OS scheduler (systemd user timer on Ubuntu, crontab fallback
  on macOS / headless). No long-running daemon; the OS fires `koda schedule _tick <id>` at the
  configured cron expression.
- **Diff-based alerts** — each tick computes fingerprint-based new / resolved / persistent
  categories and fires alerts only when new findings appear (configurable via
  `--alert-on findings|change|empty`). CRITICAL and HIGH surface first in every alert.
- **Alert channels**: `file:<path>` (default, always works), `telegram` (lazy — skips
  gracefully when bridge not configured), `email:<addr>` (requires `KODA_HOME/smtp.toml`),
  `webhook:<url>` (POST JSON, 5s timeout, one retry, audit on both attempts). Credentials
  are redacted from all alert payloads.
- **Run artifacts** — each run writes `KODA_HOME/schedules/<id>/runs/<run_id>/findings.jsonl`
  and `meta.toml` (timings, exit code, severity breakdown). `latest` symlink tracks the most
  recent run for fast diff computation.
- **Schema-versioned schedule records** — `KODA_HOME/schedules/<id>.toml` carries
  `schema_version = 1`; newer readers refuse to load schedules they can't understand.
- **`koda schedule diff`** — explicit before/after diff with `--from` / `--to` run IDs.
- **`koda schedule history`** — list past runs with finding counts.
- **Orphan marker detection** — `koda schedule list` warns when crontab or systemd entries
  exist without a matching `.toml` file.
- **Tests**: `tests/test_schedule.py` — 65 tests covering models, diff engine, all alert
  channels, crontab install/remove/list, systemd install/remove, tick happy path, scanner
  failure recovery, alert-on policy, and CLI integration.
- **Docs**: `docs/continuous-monitoring.md` — quick start, alert channels table, diff
  semantics, run history, OS integration details.

### Added
- **Remote SSH scanning** (`koda scan remote <ssh-target>`) — run any scanner
  against a remote box over standard OpenSSH without installing anything
  permanently. Uses ControlMaster multiplexing (one handshake, N commands).
  Static Go binaries (trivy, gitleaks, nuclei, osv-scanner, grype) are
  uploaded to a `/tmp/koda-<uuid>/bin/` scratchpad and deleted on exit.
  Non-shippable scanners (semgrep, bandit, nmap, falco, checkov, kics) are
  used as-is if pre-installed, or skipped with a clear warning.
  `--sudo` probes passwordless sudo first; falls back to a single interactive
  prompt whose password is piped via stdin and never written to disk or logged.
  Five audit events: `scan.remote.connect`, `scan.remote.upload`,
  `scan.remote.run`, `scan.remote.pull`, `scan.remote.cleanup`.
  `--preset <name>` lazily imports `koda.missions.get(name)` — works today
  with `--scanner` alone while the missions agent ships.
  New package `koda/remote/` (`ssh.py`, `probe.py`, `provision.py`,
  `executor.py`) + `koda/cli/scan.py`. +40 unit tests (no real SSH hit).
  Docs: `docs/remote-scanning.md`.
- **Hardened MCP server** — `koda mcp` over SSE now requires an
  `Authorization: Bearer` token on every request (auto-generated on
  first run, persisted to `mcp.toml` with 0600 perms). Optional mTLS via
  `--tls-cert/--tls-key/--client-ca` flags. Stdio transport unchanged.
  `--no-auth` refuses any non-loopback bind. Every auth attempt is
  audit-logged (`mcp.auth.ok` / `mcp.auth.denied`).
- **Remote evidence bundle sync** (`koda remote push|pull|list`) for
  S3-compatible object storage (AWS S3, Cloudflare R2, MinIO). Uploads
  a bundle plus a plain-text `.sha256` sidecar so pulls on a fresh
  machine can verify integrity with stdlib-only tooling. boto3 stays
  optional/lazy. Credentials never appear in captured output. Every
  push/pull/list is audit-logged.
- **Dependency-Track scanner wrapper** — queries a running DT server
  (`KODA_DTRACK_URL` + `KODA_DTRACK_API_KEY`) via REST API, maps findings
  into `UnifiedFinding`, filters suppressed entries, preserves CVSS v3
  over v2 and CWE extraction.
- **Two more provider adapters**: Google Vertex AI (enterprise Gemini
  with ADC or explicit token; default `gemini-1.5-pro-002`) and AWS
  Bedrock (Converse API; default `anthropic.claude-3-5-sonnet-20241022-v2:0`
  in `us-east-1`). Both use lazy imports so optional deps
  (`google-auth`, `boto3`) stay optional.
- **Release workflow now publishes CycloneDX SBOMs** (`sbom.cdx.json` +
  `.xml`) alongside each wheel on the GitHub Release. `SOURCE_DATE_EPOCH`
  pinned to the tag commit timestamp for reproducible builds.
- **Compatibility documentation** (`docs/compatibility.md`) — public API
  surface, deprecation policy, supported Python versions, artifact
  compatibility guarantees.

### Added (v0.6 Wave 2 — Mission Presets)
- **Mission presets** (`koda audit --preset <name>`) — five outcome-oriented
  preset compositions that translate a security goal into a scanner set,
  approval tier, and report style. Presets: `server-hardening`, `web-app`,
  `pci-readiness`, `post-breach`, `sbom-scan`. New module `koda.missions`
  exports a frozen `MissionPreset` dataclass with `PRESET_SCHEMA_VERSION = 1`.
- **`koda audit` subcommand** with `--list-presets`, `--explain <preset>`,
  `--preset <name> [target]`, `--dry-run`, `--engagement`, `--no-report`,
  `--skip-scanner`, and `--url` flags. Exits 0 on pass (no HIGH/CRITICAL),
  1 on fail, 2 on usage error.
- Approval-tier enforcement: presets declare `safe`/`sensitive`/`dangerous`;
  the CLI refuses to run if the active config's threshold is below the preset's
  required tier.
- Dependency-Track special dispatch in `sbom-scan`: reads
  `KODA_DTRACK_URL`/`KODA_DTRACK_API_KEY`/`KODA_DTRACK_PROJECT_UUID` from
  the environment; skips gracefully when absent.
- `docs/audit-presets.md` — preset reference page; added to mkdocs nav after
  "Skill packs".
- Tests: +59 in `tests/test_missions.py` and `tests/test_cli_audit.py`.

### Changed
- **Scanner registry exposes `replay_run_cmd` context manager** — a
  `ContextVar`-backed injection point that makes any scanner runner
  parse a supplied `(stdout, stderr, exit_code)` tuple instead of
  spawning a subprocess. Replaces a `unittest.mock.patch` call that
  previously lived in production code at `koda/remote/executor.py` —
  test infrastructure no longer imported at runtime.

### Added (v0.6 Wave 1)
- **Engagement templates** (`koda new --template pentest|ir|audit`) with
  per-template defaults for approval tier, scanners, ATT&CK phases, and
  report style. Writes `engagement.toml` under
  `KODA_HOME/engagements/<name>/`. Sibling command `koda use <name>` sets
  the active engagement.
- **Report-by-engagement wrapper** — `koda report engagement <name>`
  auto-fills `ReportContext` metadata from `engagement.toml` and reads
  `findings.jsonl` from the engagement directory. Delegates to the same
  generate/write_bundle path as `koda report generate`.
- **Three new scanner wrappers**: Checkov (IaC), KICS (IaC), Falco
  (runtime). KICS uses the additive severity-bitmask exit scheme;
  Falco surfaces findings via stdout JSONL (no findings exit code).
- **Two new provider adapters**: Azure OpenAI (default api-version
  `2024-08-01-preview`) and llama.cpp (local `./server`-compatible
  HTTP). Wired into the setup wizard and registry aliases.
- Tests: +47 for scanners, +35 for engagement templates/CLI, +32 for
  new adapters. **295 total passing**, ruff clean.

## [0.5.0] — 2026-04-19

Distribution + hardening turn: PyPI, trust-path tests, scanner exit-code
policy, expanded `doctor`, docs site.

### Added
- **PyPI distribution** as `koda-security` (the bare `koda` name is held
  by an unrelated project on PyPI). Import name and CLI command are
  unchanged. Release workflow (`.github/workflows/release.yml`) builds
  wheel + sdist, runs `twine check`, publishes via OIDC Trusted
  Publishing on `v*` tags (no API tokens stored), and auto-creates a
  GitHub Release with notes extracted from this changelog.
- **Docs site** (`mkdocs` + Material theme). Pages: index, install,
  security model, skill packs. Deploys to GitHub Pages on push to
  `main` via `.github/workflows/docs.yml`.
- **Trust-path unit tests** (65): `auth.broker` (credential storage,
  placeholder rejection, cooldown, redaction, engagement isolation),
  `evidence.store` + `evidence.bundle` (SHA-256 addressing, merkle chain
  verify, tamper detection, bundle roundtrip), `security.verifier`
  (grounded vs ungrounded claims, CVE/CWE/CVSS recognition),
  `tools.approval` (risk-tier enforcement, guardrail BLOCK overrides,
  the escalation-overrides-allowlist invariant).
- **Scanner exit-code classifier** (`koda/security/scanners/exit_codes.py`)
  with `ExitStatus` enum (`SUCCESS | FINDINGS | CANCELED | ERROR`) and
  per-scanner policy covering semgrep, gitleaks, bandit, osv-scanner,
  grype, trivy, nuclei, and nmap. Non-zero exits that signal findings
  (semgrep `1`, gitleaks `1`, bandit `1`, osv `1`) now surface as
  `FINDINGS`, not errors. SIGINT (`130`) is classified as `CANCELED`.
  +67 unit tests.
- **Expanded `koda doctor`** — version string, provider table (with
  default marker), skill pack registry state and load errors, active
  engagement details (evidence count + audit log size), env/binary
  checks. Status-glyph output stays skimmable.
- `PYPI_SETUP.md` — first-time maintainer checklist for PyPI + Trusted
  Publishing + GitHub Pages + first tagged release.

### Fixed
- Two pre-existing silent-swallow paths in scanner wrappers where exit
  code 2+ would fall through to the parse path and either emit zero
  findings or raise a JSON error that was swallowed. Now surfaces a
  clear `ExitStatus.ERROR` with the raw stderr message.

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

[Unreleased]: https://github.com/PabloTheThinker/K.O.D.A./compare/v0.5.0...HEAD
[0.5.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.5.0
[0.4.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.4.0
[0.3.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.3.0
[0.2.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.2.0
[0.1.0]: https://github.com/PabloTheThinker/K.O.D.A./releases/tag/v0.1.0
