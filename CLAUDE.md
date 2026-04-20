# CLAUDE.md

This file is read by Claude Code (and any compatible coding agent) when
working in the K.O.D.A. repository. The authoritative project instructions
live in [`AGENTS.md`](AGENTS.md) — treat it as the source of truth.

## Quick orientation

- **What this repo is:** a security-focused agent harness. Grounding
  verifier, approval gate, evidence store, credential broker. Not a
  general-purpose agent framework.
- **Repo map, hard rules, and PR checklist:** see [`AGENTS.md`](AGENTS.md).
- **Security policy and reporting:** [`SECURITY.md`](SECURITY.md).
- **Incident response playbook:** [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md).
- **Product direction:** [`VISION.md`](VISION.md).
- **Contribution guide:** [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Before you touch code

1. Read [`AGENTS.md`](AGENTS.md) end-to-end — repo map, hard rules, how to
   add a scanner or provider, and the PR checklist.
2. Read any scoped `AGENTS.md` in the subtree you are about to edit
   (currently only the root — subtree-scoped instructions will land here
   as the surface grows).
3. Run `ruff check .` and `scripts/smoke.sh` before opening a PR. CI runs
   the same checks across a Python 3.11 / 3.12 / 3.13 install matrix.

## Non-negotiables (mirrored from AGENTS.md)

- Security claims need evidence. The grounding verifier is the last line
  of defense — don't route around it.
- Credentials go through `auth.broker` and are redacted everywhere they
  surface.
- Engagement scope is load-bearing; cross-engagement leaks are P0.
- The approval gate defaults (SAFE / SENSITIVE / DANGEROUS / BLOCKED) are
  conservative by design.
- No telemetry, no phone-home, no runtime dependencies without discussion.

## Reference

- File refs in PRs / reviews: use repo-root paths only, e.g.
  `koda/providers/catalog.py:48`. No absolute paths, no `~/`.
- Never commit secrets. `detect-secrets` / `gitleaks` run in CI.
- Update `CHANGELOG.md` under `[Unreleased]` as part of the change — our
  release notes are assembled from it.
