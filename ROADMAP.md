# K.O.D.A. Roadmap

What's next, roughly ordered by urgency and dependency. Dates are targets,
not promises — plans change when reality pushes back.

**Current release:** [v0.5.0](./CHANGELOG.md#050--2026-04-19) (2026-04-19)
**Unreleased on main:** v0.6 + v0.7 + v1.0 hardening (see
[CHANGELOG](./CHANGELOG.md#unreleased)).

## Legend

- `[x]` — shipped
- `[ ]` — planned / not started
- `[~]` — in progress
- **help wanted** — a good place for contributors to jump in

---

## Shipped

### v0.5.0 — Distribution + Hardening (2026-04-19)

- [x] **PyPI release** as `koda-security` (import name and CLI unchanged).
      OIDC Trusted Publishing — no secrets stored. `pipx install
      koda-security` works.
- [x] **Hosted docs** (mkdocs + Material theme; GitHub Pages).
- [x] **Trust-path test coverage** on `auth.broker`, `evidence.store`,
      `security.verifier`, `tools.approval`.
- [x] **Scanner exit-code classifier** with per-scanner policy
      (SUCCESS / FINDINGS / CANCELED / ERROR).
- [x] **Expanded `koda doctor`** — version, provider health, skill pack
      state, engagement details.

### v0.4.0 — Legacy-port turn (2026-04-19)

- [x] **Guardian pre-filter** — regex detector for prompt injection,
      destructive shell, sensitive-data writes.
- [x] **Context compressor** — security-aware transcript summarization.
- [x] **Reflection engine** — per-turn outcome journal.
- [x] **TurnLoop integration** — all three wired as optional dependencies.
- [x] Skill packs: `log-analyzer`, `port-monitor`.

### v0.3.0 — Framework turn (2026-04-19)

- [x] External skill-pack loader (`SKILL.md` frontmatter).
- [x] Built-in skill packs: `sherlock`, `oss-forensics`, `1password`.
- [x] Rule-based NLU router (intent, risk, target extraction).
- [x] Operator persona in the security prompt.

### v0.2.0 — Public beta (2026-04-18)

- [x] Pre-save credential verification.
- [x] Telegram bridge (inline approvals, REPL parity).
- [x] MCP server (stdio + SSE).
- [x] Append-only audit log with `fsync` + rotation.
- [x] Tamper-evident evidence store (SHA-256 + merkle chain).
- [x] Credential broker with redaction across transcripts/evidence/audit.
- [x] Local threat intel cache (offline KEV/EPSS/CWE/CVE SQLite).
- [x] 8 scanner wrappers (Semgrep, Trivy, Bandit, Gitleaks, Nuclei,
      OSV-Scanner, Nmap, Grype) + generic SARIF reader.
- [x] 11 provider adapters.
- [x] Engagement + profile isolation, approval gate.

---

## Unreleased on main — heading toward v0.6 / v0.7 / v1.0

### v0.6 — Capability Expansion

- [x] **Three new scanner wrappers**: Checkov (IaC), KICS (IaC),
      Falco (runtime).
- [x] **Dependency-Track scanner wrapper** — REST integration with the
      DT server; CVSS v3-preferred mapping, suppressed-finding filter.
- [x] **Four new provider adapters**: Azure OpenAI, llama.cpp (local
      server), Google Vertex AI (ADC + explicit token), AWS Bedrock
      (Converse API).
- [x] **Engagement templates** — `koda new --template pentest|ir|audit`
      with per-template approval tiers, scanner sets, ATT&CK phases.
      Sibling command `koda use <name>` sets the active engagement.
- [x] **Report generation** — `koda report engagement <name>` auto-fills
      metadata from `engagement.toml` and renders the evidence chain to
      executive / technical / markdown / SARIF.
- [x] **Mission presets** — `koda audit --preset <name>` translates a
      security outcome into a scanner composition, runs it end-to-end,
      and exits 0/1 based on HIGH/CRITICAL findings. Five presets ship:
      `server-hardening`, `web-app`, `pci-readiness`, `post-breach`,
      `sbom-scan`. Approval-tier enforcement, `--dry-run`, `--skip-scanner`,
      per-scanner arg overrides, Dependency-Track optional integration.
      `PRESET_SCHEMA_VERSION = 1`. Docs: `docs/audit-presets.md`.

### v0.7 — Multi-Operator

- [x] **Scheduled monitoring** — `koda schedule add|list|remove|run|history|diff`
      registers cron/systemd user timer entries (no daemon). Diff-based alerts:
      new / resolved / persistent by fingerprint. Channels: file, telegram, email,
      webhook. `--alert-on findings|change|empty`. Run artifacts (findings.jsonl +
      meta.toml) persisted per tick. Schema-versioned schedule records.
      Docs: `docs/continuous-monitoring.md`.
- [x] **Remote SSH scanning** — `koda scan remote <ssh-target>` runs any
      scanner against a remote box over ControlMaster-multiplexed OpenSSH.
      Static Go binaries auto-uploaded; Python-package scanners require
      pre-installation. `--sudo` with passwordless probe + one-time prompt.
      Full audit trail. No paramiko; no permanent remote footprint.
- [x] **Remote bundles** — `koda remote push|pull|list` for
      S3-compatible storage (AWS S3, R2, MinIO) with `.sha256` sidecar
      integrity verification.
- [x] **Hardened MCP** — `Authorization: Bearer` on the SSE transport
      (auto-generated + persisted), optional mTLS via client-CA flag,
      every auth attempt audit-logged. Stdio unchanged. `--no-auth`
      refuses any non-loopback bind.
### Shipped as part of the v0.6 / v0.7 cycle
- [x] **SBOM per release** — CycloneDX `.json` + `.xml` attached to every
      GitHub Release.
- [x] **Reproducible builds** — `SOURCE_DATE_EPOCH` pinned to tag commit
      timestamp; rebuilds produce byte-identical wheel/sdist.
- [x] **Formal compatibility statement** — [docs/compatibility.md](https://pablothethinker.github.io/K.O.D.A./compatibility/)
      documents public API surface, deprecation policy, Python support
      matrix, artifact compatibility.

## Later (Shelved)

Tracked but not currently scheduled — revisit when there is a user base
large enough to justify the lift:

- **v1.0 / SemVer freeze** with third-party security audit of the trust
  boundaries (grounding verifier, approval gate, credential broker,
  evidence chain, Guardian pre-filter) and Sigstore/cosign-signed
  release artifacts.
- **Team mode.** Multi-operator engagements with per-operator audit
  trails and handoff.

## Exploratory

- Distributed grounding: cross-check claims against multiple LLMs before
  emitting them.
- Live threat-intel feeds (optional, opt-in) alongside the offline cache.
- GUI dashboard for evidence + findings triage — probably a separate
  repo.
- Native mobile operator app (Telegram bridge covers this today).

---

## Non-Goals

Things we've deliberately decided NOT to do:

- **General-purpose agent framework.** K.O.D.A. stays narrow. Other
  projects do the general case well.
- **Cloud-hosted service.** K.O.D.A. runs on your box. No managed tier.
- **Telemetry / analytics.** Zero phone-home, ever.
- **Swapping the grounding verifier for "prompt engineering."** The
  verifier is the product.

---

Contributions welcome on anything marked **help wanted**, or anything on
this list — open an issue to discuss scope before a large PR. See
[CONTRIBUTING.md](./CONTRIBUTING.md) for the dev setup.
