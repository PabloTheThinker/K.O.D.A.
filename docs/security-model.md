# Security Model

K.O.D.A. executes real security tooling against real targets. The harness
exists so a mistake by the operator — or the LLM — doesn't turn into a
shipped incident.

## Trust boundaries

Four places where the harness refuses to trust the LLM:

1. **Approval gate** (`koda/tools/approval.py`). Every tool call is tiered
   SAFE / SENSITIVE / DANGEROUS. `BLOCKED` decisions come from the
   guardrails layer and cannot be overridden from within a session.
2. **Grounding verifier** (`koda/security/verifier.py`). Claims in
   LLM output (CVE IDs, CWE references, package names) are checked
   against the evidence chain before being written to a report.
3. **Credential broker** (`koda/auth/broker.py`). Secrets are stored
   per engagement, redacted across transcripts/evidence/audit, and
   rate-limited on failure.
4. **Guardian pre-filter** (`koda/security/guardian.py`). Cheap regex
   detector that runs *before* the LLM call and tool dispatch. Catches
   prompt injection, destructive shell commands, and sensitive-data
   writes.

## Evidence chain

Every artifact written during an engagement is SHA-256 addressed and
linked into a merkle chain. Export produces a tamper-evident `.tar.gz`
that reverifies with Python stdlib only — no K.O.D.A. install required
for a third party to check your work.

## Audit log

Append-only JSONL, `fsync`-on-security-event, size-based rotation.
Covers:

- Tool approvals + denials
- Credential access + cooldowns
- Guardian blocks
- Compression events
- Turn termination (success / error)
- Engagement state changes

## Operator responsibility

The harness cannot prevent misuse — only make misuse legible. You are
responsible for:

- Running K.O.D.A. only against systems you own or are authorized to test.
- Keeping API keys and credentials out of shared configs.
- Reviewing the approval tier before running in a high-risk engagement.
- Auditing the evidence and audit logs for your own compliance needs.

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/PabloTheThinker/K.O.D.A./blob/main/SECURITY.md).
Until a dedicated disclosure email exists, the primary channel is a DM
to [@pablothethinker on X](https://x.com/pablothethinker) or a
[GitHub private advisory](https://github.com/PabloTheThinker/K.O.D.A./security/advisories/new).
