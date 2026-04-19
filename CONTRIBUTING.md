# Contributing to K.O.D.A.

Thanks for helping. K.O.D.A. is a security agent harness — the quality of
patches directly affects what people ship against real targets, so the bar is
high on verification and low on ceremony.

## Before you start

- **Security issues go to [SECURITY.md](./SECURITY.md), not issues or PRs.**
- Check open issues and discussions first. Small bug fixes can just be PRs;
  large changes (new scanners, new providers, new core subsystems) should
  start as an issue.
- If you're unsure whether something fits, open a `feature_request` issue and
  ask — we'd rather have the conversation up front than watch a big PR rot.

## Development setup

```bash
git clone https://github.com/PabloTheThinker/K.O.D.A..git
cd K.O.D.A.
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
koda setup    # configure a provider so the REPL can actually run
```

Python 3.11+ is required. The CI matrix covers 3.11, 3.12, and 3.13.

## Running the checks

```bash
ruff check .           # lint
scripts/smoke.sh       # end-to-end smoke: imports, engagement isolation,
                       # evidence chain, SARIF parity, CLI compile
```

Both run in CI on every push. Fix the smoke before asking for review.

## Scope of changes

K.O.D.A. is opinionated about what belongs in core:

- **New scanner wrappers** — welcome, as long as the tool produces structured
  output we can normalize into findings. See `koda/tools/scanners/` for the
  contract.
- **New provider adapters** — welcome. Provider adapters live in
  `koda/adapters/`; follow the existing `Provider` base class and implement
  `chat()` with tool calls.
- **New core primitives** (memory layers, new stores, new verifiers) — open
  an issue first. These touch the trust boundary.
- **Features for non-security use cases** — likely a no. K.O.D.A. is
  deliberately narrow. Agent frameworks for general coding already exist.

## Style

- `ruff` is authoritative. Config is in `pyproject.toml`. Don't disable rules
  without a reason in the PR description.
- Docstrings on public functions and classes. Terse is fine; what-it-does
  beats why-it-does-it.
- No new runtime dependencies without a discussion. Slim deps is a feature.
- Tests or a smoke-script addition for anything that touches the security
  model (audit, evidence, credentials, approvals, grounding).

## Commit messages

Imperative present tense, one line, ~60 chars:

```
Add grype scanner wrapper
Fix evidence bundle reverify on empty engagement
```

If there's context worth preserving, put it in the body. Link the issue
number.

## PR checklist

Before requesting review:

- [ ] `ruff check .` clean
- [ ] `scripts/smoke.sh` green
- [ ] No new files at repo root unless genuinely project-wide
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] README updated if you added or changed user-facing commands

## Releases

Maintainers cut releases. The flow is:

1. Update `koda/__init__.py` and `pyproject.toml` to the new version.
2. Move `[Unreleased]` notes under a new `[vX.Y.Z]` heading in `CHANGELOG.md`.
3. Tag: `git tag -s vX.Y.Z -m "K.O.D.A. vX.Y.Z"`
4. GitHub Release with the changelog body.

## License

By contributing, you agree your work is released under the MIT License that
governs the rest of the project.
