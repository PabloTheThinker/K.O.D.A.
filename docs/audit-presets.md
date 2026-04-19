# Audit Presets

## What's a preset?

A mission preset translates a security *outcome* into a scanner composition.
Instead of choosing individual tools, you pick a goal — and K.O.D.A. selects, runs, and reports on the right combination for you.

## Quick Start

```bash
pipx install koda-security
koda audit --preset server-hardening localhost
```

List all presets and explain one:

```bash
koda audit --list-presets
koda audit --explain pci-readiness
```

Run with options:

```bash
# Dry run — shows the plan without executing anything
koda audit --preset web-app --dry-run /path/to/repo

# Skip a scanner you don't have installed
koda audit --preset server-hardening --skip-scanner grype localhost

# Run a web-app audit with a live nuclei scan against staging
koda audit --preset web-app --url https://staging.example.com /path/to/repo

# Re-use an existing engagement instead of creating a throwaway
koda audit --preset pci-readiness --engagement q2-pci-2026 /path/to/src
```

## Available Presets

| Name | Audience | Tier | Frameworks |
|---|---|---|---|
| `server-hardening` | Small-business IT / solo sysadmin | sensitive | CIS-Ubuntu, CIS-Linux |
| `web-app` | Developer building or shipping a web app | sensitive | OWASP-Top-10 |
| `pci-readiness` | E-commerce / payment-handling SMB | sensitive | PCI-DSS-4.0 |
| `post-breach` | Owner / IR consultant investigating a compromise | **safe** | — |
| `sbom-scan` | OSS maintainer / dev shipping a library | **safe** | SLSA, CycloneDX |

### `server-hardening`

Checks a Linux server for credential leaks, unpatched packages, and open
ports. Scanners: `gitleaks`, `grype`, `trivy`, `osv-scanner`, `nmap`.

Success criteria: no CRITICAL/HIGH findings, all packages patched, no open
ports beyond SSH and documented services.

### `web-app`

SAST + secret scan + dependency audit + optional live HTTP template scan.
Scanners: `semgrep`, `gitleaks`, `osv-scanner`, `trivy`, `nuclei` (requires
`--url`).

Pass `--url <staging-url>` to activate nuclei against a live target.

### `pci-readiness`

Pre-assessment sweep for businesses preparing for PCI-DSS 4.0 review.
Scanners: `semgrep`, `gitleaks`, `trivy`, `osv-scanner`, `nmap`.

Not a substitute for a QSA or ASV scan — it's a readiness check.

### `post-breach`

Forensic-safe triage for active or suspected compromises. **Never runs
anything that could disturb a forensic image.** Scanners: `log-analyzer`,
`oss-forensics`, `gitleaks`, `trivy` (rootfs mode).

Approval tier is `safe` — it will run even under the most restrictive config.

### `sbom-scan`

Supply-chain health check: cross-checks every dependency against three
independent vuln databases. Scanners: `osv-scanner`, `grype`, `trivy` (sbom
mode), `dependency_track` (optional — requires `KODA_DTRACK_URL`).

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No HIGH or CRITICAL findings — audit passed |
| `1` | HIGH or CRITICAL findings found — remediation required |
| `2` | Usage error (bad flag, missing required argument) |

CI integration example:

```yaml
- run: koda audit --preset web-app --no-report .
```

## Writing Your Own Preset

Add a `MissionPreset` entry to `koda/missions/__init__.py`. The minimal
skeleton:

```python
from koda.missions import MissionPreset, PRESET_SCHEMA_VERSION

MY_PRESET = MissionPreset(
    name="my-preset",
    title="My Custom Audit",
    summary="One sentence about what this does.",
    description="## My Custom Audit\n\nLonger markdown description.",
    audience="who this is for",
    scanners=("semgrep", "trivy"),
    scanner_args={},
    approval_tier="sensitive",    # "safe" | "sensitive" | "dangerous"
    attack_phases=("initial_access",),
    compliance_frameworks=("CIS",),
    report_style="technical",     # "executive" | "technical" | "audit" | "ir-timeline"
    success_criteria="- No CRITICAL/HIGH findings.",
    next_steps="- Patch everything flagged.",
    requires_target=True,
    default_target_type="path",   # "host" | "url" | "path" | "local"
)
```

Then register it in `_REGISTRY` at the bottom of the same file.

## Compliance Frameworks

The `compliance_frameworks` tuple is **pure metadata** today. K.O.D.A. uses
it for display in `--list-presets` and `--explain` output, and future report
sections will gate compliance-specific content behind these tags.

Current values in use:

| Tag | Standard |
|---|---|
| `CIS-Ubuntu` | CIS Ubuntu Linux Benchmark |
| `CIS-Linux` | CIS Linux Generic Benchmark |
| `OWASP-Top-10` | OWASP Top 10 (2021) |
| `PCI-DSS-4.0` | PCI-DSS version 4.0 |
| `SLSA` | Supply-chain Levels for Software Artifacts |
| `CycloneDX` | CycloneDX SBOM standard |

Future work: map framework tags to specific report sections, rule-set filters,
and pass/fail thresholds per control.
