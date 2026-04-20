# K.O.D.A. Incident Response Plan

This document describes how the K.O.D.A. project responds to a
vulnerability report or security incident in the harness itself. It is
the operational companion to [`SECURITY.md`](SECURITY.md) (policy and
reporting channels).

> K.O.D.A. is maintained by a solo developer. The phrase "incident
> owner" below means the maintainer today. A dedicated security rotation
> will exist once the project's contributor count justifies it.

## 1. Detection and triage

Signals we watch:

- GitHub private vulnerability reports on this repository.
- Direct disclosures via X DM ([@pablothethinker](https://x.com/pablothethinker))
  or the encrypted channel negotiated in the first reply.
- Automated signals: Dependabot, CodeQL, secret scanning, `gitleaks` +
  `detect-secrets` in CI.
- Upstream advisories for any runtime dependency (we keep the list
  intentionally small — see `pyproject.toml`).

Initial triage, within the SLA in [`SECURITY.md`](SECURITY.md):

1. Confirm the affected component, version range, and trust boundary
   impact. K.O.D.A.'s trust boundaries are: approval gate, grounding
   verifier, credential broker, evidence store, audit log, scanner
   wrappers, provider adapters, installer, Telegram bridge, MCP server.
2. Classify against the in-scope / out-of-scope lists in
   [`SECURITY.md`](SECURITY.md). Issues in upstream scanners or LLM
   provider APIs are redirected to those projects.
3. The incident owner acknowledges the reporter (privately when the
   report is sensitive) and begins the response.

## 2. Assessment

Severity guide (aligned with our release cadence):

- **Critical** — supply-chain compromise, repo/release tampering,
  unauthenticated bypass of the approval gate or grounding verifier,
  credential exfiltration, or any issue enabling code execution against
  an operator's workstation from an untrusted target.
- **High** — authenticated bypass of a trust-boundary control,
  cross-engagement data leak (evidence, credentials, transcript), or
  exposure of K.O.D.A.-managed secrets on disk or in logs.
- **Medium** — practical security weakness constrained by operator
  misuse, local-only reach, or non-default configuration.
- **Low** — defense-in-depth findings, hardening gaps, or narrowly
  scoped DoS without a demonstrated trust-boundary bypass.

## 3. Response

1. Acknowledge the reporter. For sensitive reports, stay private until
   a fix is ready.
2. Reproduce on the latest released version and on `main`. Build a
   minimum-viable reproducer before writing the patch.
3. Implement the fix plus regression coverage. Tests that would have
   caught the issue are required, not optional.
4. For critical / high: prepare a patched release and a GitHub Security
   Advisory as quickly as practical; request a CVE when appropriate.
5. For medium / low: patch in the normal release flow and document
   mitigation guidance in release notes.
6. Credential exposure incidents additionally require rotation guidance
   — if a bug could have leaked an operator's API key, we say so
   explicitly in the advisory so operators know to rotate.

## 4. Communication

Channels:

- GitHub Security Advisories on the K.O.D.A. repository.
- Release notes / `CHANGELOG.md` entry for the fixed version.
- Direct follow-up with the reporter on status and resolution.
- A pinned notice on `koda.vektraindustries.com` for critical issues
  that require operator action before upgrading.

Disclosure policy:

- Critical and high incidents receive coordinated disclosure with CVE
  issuance when appropriate.
- Low-risk hardening work may ship in release notes without an
  advisory, depending on exposure.
- Reporter credit is included in the advisory by default; anonymous
  credit is honored on request.

## 5. Recovery and follow-up

After the fix ships:

1. Verify remediation in CI and in a clean install from the published
   wheel. Evidence-bundle verification and scanner smoke paths are
   re-run against the patched build.
2. Short post-incident review: timeline, root cause, detection gap,
   prevention plan. Kept private when reporter confidentiality applies;
   summarized publicly otherwise.
3. File follow-up hardening tasks (tests, docs, code) and track them to
   completion in the issue tracker.

## 6. Operator-side response

If you are running K.O.D.A. and receive an advisory:

1. Read the advisory end-to-end — it will state whether rotation of API
   keys, re-export of evidence bundles, or re-sync of the intel cache
   is needed.
2. Upgrade with `pipx upgrade koda-security` (or your install method).
   Verify `koda --version` and `koda doctor`.
3. If credential exposure is possible, rotate the affected keys with
   the upstream provider before re-running any engagement.
4. If evidence integrity could be affected, re-verify open engagements
   with `koda bundle verify` on a patched install.

Report anything unexpected via the channels in
[`SECURITY.md`](SECURITY.md).
