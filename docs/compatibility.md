# Compatibility

This page tells you what K.O.D.A. promises to keep working, what it
reserves the right to change, and how to read version numbers.

## Semantic versioning

K.O.D.A. follows [Semantic Versioning 2.0.0](https://semver.org/).

Given a version `MAJOR.MINOR.PATCH`:

- **MAJOR** — breaking changes. You may need to edit config, scripts, or
  integrations before upgrading.
- **MINOR** — additive changes. New scanners, new providers, new
  commands. Old behavior preserved.
- **PATCH** — bug fixes and security fixes only. No behavioral change
  unless the previous behavior was a bug.

Pre-1.0 exception: while the project is in beta (`0.x.y`), the MINOR
component may contain breaking changes. Each MINOR release documents any
break explicitly in [CHANGELOG](https://github.com/PabloTheThinker/K.O.D.A./blob/main/CHANGELOG.md).
Starting at `1.0.0`, MAJOR is the only channel that can break.

## Supported Python versions

K.O.D.A. supports the three most recent stable CPython releases. As of
v0.5.0:

- **Python 3.11** — supported
- **Python 3.12** — supported
- **Python 3.13** — supported

When a new CPython stable lands, we add it within one MINOR release and
drop the oldest in the MAJOR release after that. CI runs on all
currently-supported versions on every push.

## What is a public API

These surfaces are **stable** within a MAJOR:

- The `koda` CLI commands and their documented flags
- The shape of `UnifiedFinding` in JSONL output and SARIF reports
- The evidence bundle format (directory layout, merkle chain,
  `tar.gz` structure)
- The audit-log JSONL schema (event names, required fields)
- The skill-pack directory contract (`SKILL.md` frontmatter fields,
  resolution order)
- Environment variables documented in `docs/install.md` and the
  `koda doctor` output

These surfaces are **internal** — they may change in any MINOR:

- Python modules and classes under `koda.*` (the package is not yet a
  library API; it's a CLI's implementation)
- The internal shape of session state, turn loop, compressor, reflection
- Scanner wrapper internals (registry function names, parse helpers)
- Provider adapter internals beyond the `BaseAdapter` contract

If you depend on something internal and would like it promoted, open a
[discussion](https://github.com/PabloTheThinker/K.O.D.A./discussions) —
we're happy to consider it.

## Deprecation policy

When a public surface needs to change:

1. The new way lands in a MINOR. Both the new and old paths work.
2. The old path emits a deprecation warning (`stderr`, tagged
   `[koda: deprecated]`) and is documented in the changelog.
3. The old path is removed no sooner than the next MAJOR, with at least
   one MINOR release of overlap.

Example: if a flag is deprecated in 0.7.0, it will continue to work
through the rest of the 0.x series and will only be removed in 1.0.0.

## Artifact compatibility

Evidence bundles and audit logs written by any 0.x.y release can be
read and reverified by any later 0.x.y release. We consider this a hard
promise — engagement artifacts must survive tool upgrades.

## Reproducible builds

Releases on PyPI are built with `SOURCE_DATE_EPOCH` pinned to the tag's
commit timestamp. Rebuilding at the same commit produces byte-identical
wheel + sdist artifacts. Each GitHub Release includes a CycloneDX SBOM
(`sbom.cdx.json` and `sbom.cdx.xml`) describing every dependency baked
into the published artifacts.

## Questions

Not sure whether something you depend on is stable? Ask in
[discussions](https://github.com/PabloTheThinker/K.O.D.A./discussions)
before building on it.
