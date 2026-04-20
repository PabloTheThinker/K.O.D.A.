# K.O.D.A. Vision

K.O.D.A. is an AI security specialist that can be trusted with a real
engagement.

It runs on your workstation, under your rules of engagement, against
targets you are authorized to touch. Local-first via Ollama; BYO key for
hosted models. Zero telemetry. Zero phone-home.

This document explains the current state and direction of the project.
Iteration is fast — pre-1.0 releases may land breaking changes, tracked
in [`CHANGELOG.md`](CHANGELOG.md).

- Project overview and developer docs: [`README.md`](README.md)
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Incident response: [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md)
- Roadmap: [`ROADMAP.md`](ROADMAP.md)

## Why K.O.D.A. exists

Most agent frameworks are general-purpose. Security work isn't.

The question a SOC lead, pentester, or IR consultant needs answered
before handing an agent real access is always the same: *can I trust its
output to a client report?* K.O.D.A. is engineered around that question.

- A grounding verifier rejects claims (CVE, file path, line number, CVSS)
  that didn't come out of a tool call.
- An approval gate fences every risky action behind a tier the operator
  controls.
- A credential broker redacts secrets across transcripts, evidence, and
  audit logs.
- A per-engagement merkle chain makes tampering detectable offline,
  years later, using Python stdlib only.

The agent is narrow on purpose. It wraps scanners, not browsers. It
reasons in MITRE ATT&CK IDs, not ad-hoc prose. It ships with rules of
engagement, not a kitchen sink. Keeping scope tight keeps the trust
boundary reviewable.

## Product principles

1. **Security claims need evidence.** If the model says it, a tool must
   have produced it. The verifier is non-optional.
2. **Local-first, air-gap ready.** Ollama plus an offline threat-intel
   cache means K.O.D.A. runs on an analyst laptop with no egress. Cloud
   providers are bring-your-own-key, never defaults that leak data.
3. **Evidence outlives the agent.** Bundles verify offline with stdlib
   only. A report you write today must hold up in an audit five years
   from now on a fresh machine.
4. **Operators are in command.** The approval gate, rules of engagement,
   and scope boundaries exist so the operator always has the last word
   on consequential actions.
5. **Slim dependencies.** Every runtime dep is a supply-chain surface.
   We vendor or skip before we add.
6. **Model-agnostic.** 22 providers behind one declarative catalog. No
   provider is load-bearing; swap backends without touching code.

## Current focus

Pre-1.0 priorities, roughly in order:

- **Security and safe defaults** — the approval gate, grounding verifier,
  and credential redaction stay conservative.
- **First-run UX** — install → setup wizard → first engagement in under
  five minutes on a cold machine.
- **Scanner breadth** — more wrappers that produce `UnifiedFinding`
  rows: file-system, network, cloud config, container, SCA, SAST.
- **Reproducible builds + SBOMs** — every release publishes wheels with
  deterministic hashes and an SBOM suitable for SLSA attestation.
- **Air-gap story** — offline model bundles, offline intel sync, stdlib
  verification — all testable without network.

## Out of scope (on purpose)

- General-purpose chat or coding agent. Use something else.
- Plug-and-play exploit framework. K.O.D.A. reasons about findings; it
  doesn't ship payloads.
- Managed SaaS. The project is a harness you run yourself.

## Contribution rules

- One PR = one issue / topic. Don't bundle unrelated changes.
- PRs over ~5,000 changed lines are reviewed only in exceptional cases.
- Do not open batches of tiny PRs at once — each carries review cost.
- Closely related small fixes grouped into one focused PR are welcome.
- For anything touching the approval gate, grounding verifier, credential
  broker, or audit chain, open an issue for discussion before you code.
