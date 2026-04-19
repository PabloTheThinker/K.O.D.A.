# K.O.D.A. Roadmap

What's next, roughly ordered by urgency and dependency. Dates are targets,
not promises — plans change when reality pushes back.

**Current release:** [v0.4.0](./CHANGELOG.md#040--2026-04-19) (2026-04-19)

## Legend

- `[x]` — shipped
- `[ ]` — planned / not started
- `[~]` — in progress
- **help wanted** — a good place for contributors to jump in

---

## Shipped

### v0.4.0 — Legacy-port turn (2026-04-19)

- [x] **Guardian pre-filter** — cheap regex detector for prompt injection,
      destructive shell commands, and sensitive-data writes. Runs before
      LLM call and tool dispatch.
- [x] **Context compressor** — keeps system prompt + first exchange + last
      N messages at full fidelity; security-aware middle summary (ATT&CK
      IDs, CVE IDs, tool counts, refused approvals).
- [x] **Reflection engine** — bounded journal of per-turn outcomes with
      pattern extraction for post-engagement retrospectives.
- [x] **TurnLoop integration** — all three wired as optional dependencies.
- [x] Two new skill packs: `log-analyzer` (blue/hunt, T1078/T1110/T1098)
      and `port-monitor` (blue/hunt, T1571/T1021/T1090).

### v0.3.0 — Framework turn (2026-04-19)

- [x] **External skill pack loader** — drop `SKILL.md` into `skills/`,
      `~/.koda/skills`, or `$KODA_SKILLS_PATH`.
- [x] **Built-in skill packs** — `sherlock`, `oss-forensics`, `1password`.
- [x] **Rule-based NLU router** — intent classifier, target extraction,
      risk tier, registry-backed skill ranking.
- [x] **Operator persona** in the security prompt.

### v0.2.0 — Public beta (2026-04-18)

- [x] Pre-save credential verification in setup wizard.
- [x] Telegram bridge (inline approvals, inbound media, REPL parity).
- [x] MCP server (stdio + SSE).
- [x] Append-only audit log with `fsync` + rotation.
- [x] Tamper-evident evidence store (SHA-256 + merkle chain).
- [x] Credential broker with redaction across transcripts/evidence/audit.
- [x] Local threat intel cache (offline KEV/EPSS/CWE/CVE SQLite).
- [x] 8 scanner wrappers (Semgrep, Trivy, Bandit, Gitleaks, Nuclei,
      OSV-Scanner, Nmap, Grype) + generic SARIF reader.
- [x] 11 provider adapters (Ollama, Claude CLI, Anthropic, OpenAI, Gemini,
      Groq, Together, OpenRouter, DeepSeek, xAI, Mistral).
- [x] Engagement + profile isolation.
- [x] Approval gate with per-tool risk tiers.
- [x] Installer one-liner, GitHub Actions CI.

---

## Next up — v0.5 (Distribution + Hardening)

The goal: make K.O.D.A. trivially installable, and make the trust-critical
paths covered by tests instead of hope.

- [ ] **PyPI release.** Publish `koda` as a wheel so `pipx install koda`
      and `uv tool install koda` work without a git clone. **help wanted**
- [ ] **Hosted docs.** Move long-form content out of the README into a
      docs site (mkdocs or similar). README becomes the router.
      **help wanted**
- [ ] **Trust-path test coverage.** Unit tests on `auth.broker`,
      `evidence.store`, `security.grounding`, and `tools.approval`. Smoke
      covers end-to-end; unit tests cover the trust boundary.
- [ ] **Scanner exit-code hygiene.** Normalize non-zero exits from
      Semgrep, Trivy, Nuclei so "tool found things" and "tool failed"
      don't look identical.
- [ ] **`koda doctor` parity.** Surface version, provider health, skill
      pack load errors, engagement state.

## v0.6 — Capability Expansion

- [ ] **Additional scanners.** Checkov, KICS, Dependency-Track adapter,
      Falco (runtime). **help wanted** — scanner wrappers are a great
      first PR.
- [ ] **Additional providers.** Azure OpenAI, AWS Bedrock, Vertex AI,
      local llama.cpp server. **help wanted**
- [ ] **Engagement templates.** `koda new --template pentest` scaffolds
      a pentest-oriented config (scanner set, approval thresholds, report
      template); `--template ir` for incident response.
- [ ] **Report generation.** `koda report <engagement>` emits a
      client-ready Markdown/HTML report from the evidence chain.

## v0.7 — Multi-Operator

- [ ] **Team mode.** Multi-operator engagements with per-operator audit
      trails and handoff.
- [ ] **Remote bundles.** Upload evidence bundles to S3 / R2 / MinIO
      with server-side hash verification.
- [ ] **Hardened MCP.** OAuth / mTLS on the MCP server for multi-client
      deployments.

## v1.0 — Production-Ready

API stable. SemVer commitments kick in — no breaking changes in 1.x
without a deprecation cycle.

- [ ] **Third-party security audit.** External review of the trust
      boundaries: grounding verifier, approval gate, credential broker,
      evidence chain, Guardian pre-filter.
- [ ] **Reproducible builds.** Signed wheels; SBOM per release.
- [ ] **Formal compatibility statement** for MCP, SARIF 2.1.0, and the
      evidence bundle format.

## Post-1.0 (Exploratory)

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
