# Contributing to K.O.D.A.

Thanks for being here. K.O.D.A. is a security agent harness — patches land
on a tool people point at real targets, so the bar is high on verification
and low on ceremony. Short PRs with tests get merged fastest.

> **Note from the maintainer:** this is my first open-source project at
> this scale. If a process feels awkward or missing, open a discussion —
> improving how we collaborate is as welcome as improving the code.

## Ways to help (pick what fits)

Not everything needs to be code. All of these move the project forward:

- **Try it and report back.** Run `koda setup`, point it at a scanner, file
  an issue if anything breaks or surprises you. Sharp-edge reports are gold.
- **Write a skill pack.** Drop a `SKILL.md` into `skills/` — operator
  playbooks for a specific technique (red/blue/hunt). See
  [`skills/sherlock/SKILL.md`](./skills/sherlock/SKILL.md) for the format.
- **Add a scanner wrapper or provider adapter.** See "Scope of changes."
- **Fix docs.** README unclear? A command in the quickstart broken on your
  machine? Those PRs are always welcome.
- **Triage issues.** Reproducing a bug report and adding a minimal repro is
  a genuinely helpful contribution.
- **Ask a question.** Open a Discussion. "How would I…" threads help shape
  the roadmap.

## Before you start

- **Security issues go to [SECURITY.md](./SECURITY.md), not issues or PRs.**
- For small bug fixes, a PR is fine — no pre-discussion needed.
- For larger changes (new scanners, new providers, new core subsystems),
  open a `feature_request` issue first so we can align on scope. Nothing
  worse than a big PR that needs to be rewritten.
- If you're unsure whether an idea fits, just ask in Discussions.

## Development setup

```bash
git clone https://github.com/PabloTheThinker/K.O.D.A..git
cd K.O.D.A.
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
koda setup    # configure a provider so the REPL can actually run
```

Python 3.11+ is required. CI covers 3.11, 3.12, and 3.13.

If you don't have API budget, point `koda setup` at a local Ollama server
(`ollama pull qwen3:14b`) — every feature works against a local model.

## Running the checks

```bash
ruff check .                              # lint
python3 -m pytest tests/                  # unit tests
scripts/smoke.sh                          # end-to-end smoke
```

All three run in CI on every push. Fix them locally before asking for
review.

### If pytest complains about `PYTHONHASHSEED`

Some shells export a stale or invalid `PYTHONHASHSEED`. If pytest refuses
to start, clear it for the command:

```bash
env -u PYTHONHASHSEED python3 -m pytest tests/
```

## Scope of changes

K.O.D.A. is opinionated about what belongs in core:

- **New scanner wrappers** — welcome, as long as the tool produces
  structured output (JSON / SARIF) we can normalize into findings. See
  `koda/tools/scanners/` for the contract. Include a small recorded
  fixture in `tests/` so CI doesn't need the binary installed.
- **New provider adapters** — welcome. They live in `koda/adapters/`;
  follow the existing `Provider` base class and implement `chat()` with
  tool calls. Include a mock-backed unit test.
- **New skill packs** — drop into `skills/<name>/SKILL.md` with YAML
  frontmatter (`mode`, `phase`, `attack_techniques`). Body is the
  operator-voice prompt fragment. No code required.
- **New core primitives** (memory layers, new verifiers, new trust
  boundaries) — open an issue first. These touch the security model and
  need design discussion before code.
- **Features for non-security use cases** — probably a no. K.O.D.A. is
  deliberately narrow. General agent frameworks already exist.

## Style

- `ruff` is authoritative. Config is in `pyproject.toml`. Don't disable
  rules without a note in the PR description.
- Docstrings on public functions and classes. Terse is fine.
- **No new runtime dependencies** without a discussion. Slim deps is a
  feature — users install K.O.D.A. on pentest laptops and air-gapped
  workstations.
- Tests for anything touching the security model (audit log, evidence
  chain, credential broker, approval gate, grounding verifier, Guardian).

## Commit messages

Imperative present tense, one line, roughly 60 characters:

```
Add grype scanner wrapper
Fix evidence bundle reverify on empty engagement
Port Guardian pre-filter from legacy harness
```

If there's context worth preserving, put it in the commit body. Link the
issue number (`Fixes #42`) if it closes one.

## PR checklist

Before requesting review:

- [ ] `ruff check .` clean
- [ ] `python3 -m pytest tests/` green
- [ ] `scripts/smoke.sh` green
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] README updated if you added or changed a user-facing command
- [ ] No new files at repo root unless genuinely project-wide

Small docs-only PRs can skip the tests — just call it out in the PR
description.

## Releases

Maintainers cut releases. The flow:

1. Bump version in `koda/__init__.py` and `pyproject.toml`
   (SemVer: patch for fixes, minor for features, major for breaking changes).
2. Move `[Unreleased]` notes under a new `[vX.Y.Z]` heading in
   `CHANGELOG.md` with the release date.
3. Commit: `chore: release vX.Y.Z`
4. Tag: `git tag -s vX.Y.Z -m "K.O.D.A. vX.Y.Z"`
5. Push: `git push origin main --tags`
6. GitHub Release with the changelog body.

## License

By contributing, you agree your work is released under the MIT License
that governs the rest of the project.
