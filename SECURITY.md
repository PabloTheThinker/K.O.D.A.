# Security Policy

K.O.D.A. is a security-focused tool. We take vulnerabilities in the harness itself seriously.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security reports.**

Email: **security@vektraindustries.com**

Include:
- A description of the issue and its impact
- Steps to reproduce (minimum viable reproducer preferred)
- Affected versions / commit SHAs if known
- Any proof-of-concept code, logs, or evidence bundles
- Your name / handle for credit (optional)

You can encrypt sensitive details with our PGP key on request.

## Response SLA

- **Acknowledgement** within 72 hours
- **Triage + severity assessment** within 7 days
- **Fix or mitigation plan** within 30 days for high-severity issues

We will keep you informed during the process and credit you in the advisory once a fix is public, unless you prefer to remain anonymous.

## In Scope

Vulnerabilities in:
- The K.O.D.A. harness (approval gate, grounding verifier, credential broker, evidence store, audit log)
- Scanner wrappers and their sandboxing
- Provider adapters (credential handling, prompt injection defenses)
- The installer (`install.sh`) and update/uninstall commands
- Telegram bridge authentication and scoping
- MCP server exposure

## Out of Scope

- Vulnerabilities in upstream scanners themselves (report to the scanner's upstream project)
- Vulnerabilities in LLM providers' APIs (report to Anthropic / OpenAI / etc.)
- Issues in user-supplied engagements, tools, or configuration
- Social engineering of K.O.D.A. operators
- Running K.O.D.A. against systems you do not own or are not authorized to test (this is a policy violation, not a K.O.D.A. vulnerability)

## Disclosure

We follow coordinated disclosure. Once a fix is released, we publish an advisory describing the issue, affected versions, remediation, and credit.

Historic advisories live in GitHub Security Advisories on this repository.

## Operator Responsibility

K.O.D.A. executes real security tooling against real targets. You are responsible for:
- Only running it against systems you own or are authorized to test
- Keeping API keys and credentials out of shared configs
- Reviewing the approval tier before running in a high-risk engagement
- Auditing the evidence and audit logs for your own compliance requirements

A harness cannot prevent misuse — it can only make misuse legible.
