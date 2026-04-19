# AGENTS.md — Project Instructions for Code Agents

This file is read by AI coding agents (Claude Code, Codex, Cursor, etc.)
working in the K.O.D.A. repo. It exists so a fresh agent can get productive
without reverse-engineering the whole tree.

## What K.O.D.A. is

A security-focused agent harness. It wraps an LLM with a grounding verifier,
an approval gate, an evidence store, and a credential broker so the model
can actually run scanners and make claims that hold up in a report.

**Not** a general-purpose agent framework. Changes that broaden the scope
are usually out of scope — open an issue first.

## Repo map

```
koda/
  adapters/       Provider adapters (11): anthropic, claude_cli, ollama, …
  agent/          Turn loop, agent state
  audit/          Append-only JSONL audit log
  auth/           Credential broker + redaction
  cli/            CLI entry, REPL, setup wizard, doctor, update, uninstall
  evidence/       Content-addressed store + merkle chain + bundle export
  intel/          Local CISA KEV / EPSS / CWE / NVD cache
  mcp/            MCP server (stdio + SSE)
  memory/helix/   Dual-store entangled memory (alpha + beta + conflicts)
  notify/         Telegram bridge daemon
  security/       Grounding verifier, scanner registry
  session/        Engagement-scoped SQLite session store (FTS5)
  tools/          Tool registry, approval gate, builtins, scanner wrappers
  config.py       Paths, KODA_HOME resolution
  profiles.py     Named profile isolation
scripts/
  smoke.sh        End-to-end smoke test (runs in CI)
.github/
  workflows/ci.yml     Lint + install matrix + install.sh smoke
  ISSUE_TEMPLATE/      Structured bug/feature forms
install.sh        Hosted one-liner installer
```

## Hard rules

1. **Security claims need evidence.** Never have the model emit a CVE, a file
   path, or a line number that didn't come out of a tool call. The grounding
   verifier is the last line of defense — don't route around it.
2. **Don't log secrets.** Credentials must go through `auth.broker` and be
   redacted everywhere they surface (transcript, evidence, audit). If you
   add a new output surface, wire redaction in.
3. **Engagement scope is load-bearing.** Sessions, credentials, evidence,
   audit rows — everything is tagged with the active engagement. A bug that
   leaks across engagements is a P0.
4. **Approval gate defaults stay conservative.** Tools default SAFE /
   SENSITIVE / DANGEROUS / BLOCKED. BLOCKED never runs. Don't add code paths
   that bypass the gate.
5. **No runtime dependencies without discussion.** Slim deps is a feature;
   air-gapped analysts install from a wheel cache.

## How to add a scanner

1. Add a wrapper in `koda/tools/scanners/<name>.py` that produces a list of
   `Finding` objects.
2. Register it in `koda/tools/scanners/__init__.py`.
3. Update the wizard's scanner probe (`koda/cli/wizard.py`) if the detector
   needs to find the binary on PATH.
4. Update the README scanner list.
5. Update `CHANGELOG.md` under `[Unreleased]`.

## How to add a provider

1. Add an adapter in `koda/adapters/<name>.py` implementing the `Provider`
   base class with `chat()` supporting tool calls.
2. Register it in `koda/adapters/__init__.py`'s `create_provider()`.
3. Add the verification entry in `koda/cli/wizard.py` — a real chat roundtrip
   is required before config writes.
4. Update the README providers table.
5. Update `CHANGELOG.md` under `[Unreleased]`.

## Before you open a PR

```bash
ruff check .
scripts/smoke.sh
```

Both must be green. CI runs the same checks plus a Python 3.11/3.12/3.13
install matrix.

## What NOT to do

- Don't restructure directories without discussion — tools, docs, and agents
  all have paths memorized.
- Don't add telemetry, analytics, or phone-home calls. K.O.D.A. runs on
  air-gapped analyst laptops; network egress is a feature, not a default.
- Don't weaken the approval gate "for testing." Use `--auto-approve` at the
  call site or a per-engagement config override.
- Don't disable ruff rules globally without a reason in the PR description.
- Don't skip writing to `CHANGELOG.md` — release notes are assembled from it.
