# K.O.D.A. Roadmap

Scope: what's next, roughly ordered by urgency and dependency. Dates are
targets, not promises. Plans change when reality pushes back.

## 0.2.x — Stabilization (Now)

Beta. Public but API pre-stable. Small breakages are acceptable if they buy
a cleaner 1.0.

- [ ] **PyPI release.** Publish `koda` as a wheel so `uv tool install koda`
      and `pipx install koda` work without a git clone.
- [ ] **Hosted docs.** Move long-form content out of the README into a docs
      site (mkdocs or similar). README becomes the router.
- [ ] **Unit tests.** `scripts/smoke.sh` covers end-to-end; we need
      `pytest` coverage on the trust-critical paths: `auth.broker`,
      `evidence.store`, `security.grounding`, `tools.approval`.
- [ ] **`koda --version` surface parity.** Version string already prints;
      also expose it in `koda doctor` and in the REPL banner.
- [ ] **Scanner exit-code hygiene.** Normalize non-zero exits from Semgrep,
      Trivy, Nuclei so "tool found things" and "tool failed" don't look
      identical.

## 0.3 — Capability Expansion

- [ ] **Additional scanners.** Checkov, KICS, Dependency-Track adapter,
      Falco (runtime).
- [ ] **Additional providers.** Azure OpenAI, AWS Bedrock, Vertex AI, local
      llama.cpp server. All go through the same verification flow.
- [ ] **Engagement templates.** `koda new --template pentest` scaffolds a
      pentest-oriented config (scanner set, approval thresholds, report
      template) vs. `--template ir` for incident response.
- [ ] **Report generation.** `koda report <engagement>` emits a client-ready
      Markdown/HTML report from the evidence chain.

## 0.4 — Multi-Operator

- [ ] **Team mode.** Multi-operator engagements with per-operator audit
      trails and handoff.
- [ ] **Remote bundles.** Upload evidence bundles to S3/R2/MinIO with
      server-side hash verification.
- [ ] **Hardened MCP.** OAuth / mTLS on the MCP server for multi-client
      deployments.

## 1.0 — Production-Ready

API stable. SemVer commitments kick in here. No breaking changes in 1.x
without a deprecation cycle.

- [ ] **Security audit.** Third-party review of the trust boundaries:
      grounding verifier, approval gate, credential broker, evidence chain.
- [ ] **Reproducible builds.** Ship signed wheels; SBOM per release.
- [ ] **Interop.** Formal compatibility statement for MCP, SARIF 2.1.0, and
      the evidence bundle format.

## Post-1.0 (Exploratory)

- Distributed grounding: cross-check claims against multiple LLMs before
  emitting them.
- Live threat-intel feeds (optional, opt-in) alongside the offline cache.
- GUI dashboard for evidence + findings triage — probably a separate repo.
- Native mobile operator app — Telegram bridge covers this today; a
  purpose-built client would be nicer.

## Non-Goals

Things we've deliberately decided NOT to do:

- **General-purpose agent framework.** OpenClaw and Hermes already do this
  well. K.O.D.A. stays narrow.
- **Cloud-hosted service.** K.O.D.A. runs on your box. No managed tier.
- **Telemetry / analytics.** Zero phone-home, ever.
- **Swapping the grounding verifier for "prompt engineering."** The verifier
  is the product.

---

Contributions welcome on anything on this list — open an issue to discuss
scope before a large PR.
