"""Mission presets for ``koda audit --preset <name>``.

A mission preset translates a security *outcome* into a scanner composition,
approval tier, and report style.  The operator picks a goal — "harden this
server", "check my web app", "investigate a suspected breach" — and K.O.D.A.
selects and runs the appropriate toolchain.

Schema versioning
-----------------
``PRESET_SCHEMA_VERSION`` is exported from this module and stamped into every
preset.  Increment when any field is added, removed, or changes semantics.
Consumers can check the version to forward-compat their own tooling without
parsing all preset fields.

Usage
-----
>>> from koda.missions import get_preset, list_presets, PRESET_SCHEMA_VERSION
>>> preset = get_preset("server-hardening")
>>> preset.scanners
('gitleaks', 'grype', 'trivy', 'osv-scanner', 'nmap')
"""
from __future__ import annotations

from dataclasses import dataclass

#: Increment this when the MissionPreset schema changes.
#: v1 — initial release (2026-04-19).
PRESET_SCHEMA_VERSION: int = 1


@dataclass(frozen=True)
class MissionPreset:
    """Immutable descriptor for a security mission preset.

    Fields
    ------
    name
        URL-safe slug used on the CLI (e.g. ``"server-hardening"``).
    title
        Human-readable title displayed in ``--list-presets`` output.
    summary
        One- or two-sentence pitch for the listing table.
    description
        Markdown body shown by ``koda audit --explain <preset>``.
    audience
        Plain-English description of who this preset is for.
    scanners
        Ordered tuple of scanner names resolved through
        :class:`koda.security.scanners.registry.ScannerRegistry`.
    scanner_args
        Per-scanner argument overrides forwarded as ``**kwargs`` to each
        runner.  Keys are scanner names; values are passed through
        ``registry.run(name, target, **scanner_args[name])``.
    approval_tier
        One of ``"safe"`` / ``"sensitive"`` / ``"dangerous"``.  The CLI
        enforces this against the current config threshold before running.
    attack_phases
        ATT&CK phases this preset focuses on (pure metadata for display
        and future filtering).
    compliance_frameworks
        Standards this preset addresses (CIS, PCI-DSS, etc.).  Pure
        metadata today — future work will gate report sections behind these.
    report_style
        One of ``"executive"`` / ``"technical"`` / ``"audit"`` /
        ``"ir-timeline"``.  Passed to the report generator as the primary
        format.  ``"audit"`` maps to the ``"markdown"`` writer with
        audit-specific framing; ``"ir-timeline"`` maps to ``"technical"``
        with IR-specific headers.
    success_criteria
        Markdown snippet describing what a passing audit looks like.
        Shown at the end of a clean run and in ``--explain`` output.
    next_steps
        Markdown snippet advising what to do when findings are surfaced.
    requires_target
        If ``True``, a positional *target* argument is required on the
        CLI.  If ``False`` the preset can run without one (e.g. local-only
        checks).
    default_target_type
        One of ``"host"`` / ``"url"`` / ``"path"`` / ``"local"``.
        Informs arg-parser help text and scanner dispatch logic.
    schema_version
        Set automatically to :data:`PRESET_SCHEMA_VERSION`.  Do not pass
        this — it is injected by the module-level preset constructors.
    """

    name: str
    title: str
    summary: str
    description: str
    audience: str
    scanners: tuple[str, ...]
    scanner_args: dict
    approval_tier: str
    attack_phases: tuple[str, ...]
    compliance_frameworks: tuple[str, ...]
    report_style: str
    success_criteria: str
    next_steps: str
    requires_target: bool
    default_target_type: str
    schema_version: int = PRESET_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Preset definitions
# ---------------------------------------------------------------------------

SERVER_HARDENING = MissionPreset(
    name="server-hardening",
    title="Server Hardening Audit",
    summary=(
        "Checks an Ubuntu/Linux server for credential leaks, unpatched packages, "
        "and open ports against CIS benchmarks."
    ),
    description="""\
## Server Hardening Audit

**Audience:** Small-business IT / solo sysadmin

Run this against a freshly provisioned server before it goes live, or
periodically against production to catch drift.  The preset scans system
config directories for stray credentials, checks all installed packages for
known CVEs via three independent databases, and maps the network surface with
Nmap.

### What gets checked

| Scanner | What it does |
|---|---|
| `gitleaks` | Secret patterns in `/etc`, `/root`, and the target path |
| `grype` | CVE matches via the Anchore vuln DB (dpkg / RPM / pip) |
| `trivy` | Filesystem mode — OS packages + language deps |
| `osv-scanner` | Google OSV database cross-check |
| `nmap` | Open TCP/UDP ports on the host |

### Compliance

Aligns with **CIS Ubuntu Linux** and **CIS Linux** benchmarks.  Not a
substitute for a full CIS-CAT scan, but flags the most commonly failed
controls (unpatched packages, world-readable secrets, open management ports).
""",
    audience="small-business IT / solo sysadmin",
    scanners=("gitleaks", "grype", "trivy", "osv-scanner", "nmap"),
    scanner_args={
        "nmap": {"extra_args": ["-sV", "--open"]},
        "trivy": {"scan_type": "fs"},
    },
    approval_tier="sensitive",
    attack_phases=("initial_access", "privilege_escalation", "defense_evasion"),
    compliance_frameworks=("CIS-Ubuntu", "CIS-Linux"),
    report_style="audit",
    success_criteria="""\
- No CRITICAL or HIGH findings from any scanner.
- All installed OS packages are at their latest patched version.
- No open ports beyond SSH (22) and explicitly documented services.
- No secret patterns found in `/etc`, `/root`, or config directories.
""",
    next_steps="""\
- For each CRITICAL/HIGH finding, check the scanner's fix suggestion and
  apply the recommended package update or configuration change.
- Close or firewall any unexpected open ports identified by Nmap.
- Rotate any credentials surfaced by Gitleaks immediately.
- Re-run this preset after remediation to verify the finding count drops
  to zero.
""",
    requires_target=True,
    default_target_type="host",
)

WEB_APP = MissionPreset(
    name="web-app",
    title="Web Application Security Review",
    summary=(
        "SAST + secret scan + dependency audit + live template scan for "
        "developers shipping a web app."
    ),
    description="""\
## Web Application Security Review

**Audience:** Developer building or shipping a web app

Point this at your repo (and optionally a staging URL) before a production
push.  The preset combines static analysis, dependency auditing, and live
HTTP probing to catch the most common OWASP Top 10 issues without requiring
a dedicated pen-tester.

### What gets checked

| Scanner | What it does |
|---|---|
| `semgrep` | SAST rules for injection, XSS, SSRF, auth bypass, and more |
| `gitleaks` | Hardcoded secrets and API keys in the repo history |
| `osv-scanner` | Dependency CVEs (npm, pip, go.mod, Cargo.toml, etc.) |
| `trivy` | Container image CVEs (if a Dockerfile is present) |
| `nuclei` | Live HTTP template scan against the staging URL |

### Compliance

Targets **OWASP Top 10** (2021).  Use the technical report to map findings
to A01–A10 before a compliance review or bug-bounty submission.

### Notes

- `nuclei` only runs when `--url` is passed; it is skipped for code-only scans.
- Trivy runs in image mode if a container image tag is detected; otherwise it
  falls back to filesystem mode.
""",
    audience="developer building or shipping a web app",
    scanners=("semgrep", "gitleaks", "osv-scanner", "trivy", "nuclei"),
    scanner_args={
        "semgrep": {"config": "auto"},
        "trivy": {"scan_type": "fs"},
    },
    approval_tier="sensitive",
    attack_phases=("initial_access", "execution", "exfiltration"),
    compliance_frameworks=("OWASP-Top-10",),
    report_style="technical",
    success_criteria="""\
- No CRITICAL or HIGH findings from Semgrep.
- Zero secrets or API keys found by Gitleaks.
- All direct and transitive dependencies are free of known CVEs.
- No Nuclei templates fire on the staging URL (or `--url` target).
""",
    next_steps="""\
- Triage Semgrep findings by rule ID — `p/security-audit` rules at HIGH
  should be fixed before merge; MEDIUM rules may be accepted-risk with a
  comment.
- Rotate any secrets surfaced by Gitleaks and remove them from git history
  using `git filter-repo`.
- Update vulnerable dependencies to the fixed versions shown in the report.
- If Nuclei fired on the staging URL, reproduce manually before treating
  as confirmed.
""",
    requires_target=True,
    default_target_type="path",
)

PCI_READINESS = MissionPreset(
    name="pci-readiness",
    title="PCI-DSS 4.0 Readiness Assessment",
    summary=(
        "Pre-assessment scanner sweep for e-commerce and payment-handling "
        "businesses preparing for PCI-DSS 4.0 review."
    ),
    description="""\
## PCI-DSS 4.0 Readiness Assessment

**Audience:** E-commerce / payment-handling small business preparing for a
PCI-DSS assessment

This is a *readiness* scan, not a Qualified Security Assessor (QSA) audit.
Run it on your Cardholder Data Environment (CDE) before the official
assessment to surface low-hanging-fruit issues that an assessor will flag
anyway.

### What gets checked

| Scanner | What it does |
|---|---|
| `semgrep` | SAST with PCI-relevant rulesets (insecure crypto, hardcoded PANs) |
| `gitleaks` | Secrets and credential patterns near card-data code paths |
| `trivy` | CVE sweep of OS packages and container images |
| `osv-scanner` | Dependency vulnerability cross-check |
| `nmap` | Network surface of the CDE boundary |

### Compliance

Aligns with **PCI-DSS 4.0** requirements, particularly:

- **Req 6.3.2**: Maintain an inventory of bespoke and custom software.
- **Req 6.4**: Protect web-facing apps against known attacks.
- **Req 12.3.2**: Targeted risk analysis for hardware and software tech.

This preset does *not* replace a QSA, ASV scan, or penetration test required
by PCI-DSS.
""",
    audience="e-commerce / payment-handling SMB preparing for PCI-DSS assessment",
    scanners=("semgrep", "gitleaks", "trivy", "osv-scanner", "nmap"),
    scanner_args={
        "semgrep": {"config": "auto"},
        "trivy": {"scan_type": "fs"},
        "nmap": {"extra_args": ["-sV", "--open", "-p", "1-65535"]},
    },
    approval_tier="sensitive",
    attack_phases=("initial_access", "collection", "exfiltration"),
    compliance_frameworks=("PCI-DSS-4.0",),
    report_style="audit",
    success_criteria="""\
- No CRITICAL findings in any scanner output.
- No secret or credential patterns found adjacent to card-data handling code.
- All network services on the CDE boundary are inventoried and justified.
- No public-facing services running software with known CVEs.
""",
    next_steps="""\
- Document every finding in your risk register with remediation owner and
  target date — assessors will ask for this.
- Rotate any credentials surfaced by Gitleaks before the assessment.
- For each open port flagged by Nmap, verify it is documented in your
  network diagram and has a business justification.
- Engage an Approved Scanning Vendor (ASV) for the official external scan
  required by PCI-DSS Req 11.3.
""",
    requires_target=True,
    default_target_type="path",
)

POST_BREACH = MissionPreset(
    name="post-breach",
    title="Post-Breach Triage",
    summary=(
        "Forensic-safe snapshot scan for owners and consultants investigating "
        "an active or suspected compromise. Never touches a forensic image."
    ),
    description="""\
## Post-Breach Triage

**Audience:** Owner or IR consultant investigating an active or suspected
compromise

This preset is explicitly **forensic-safe**: it never runs anything that
could disturb a forensic image, trigger an IDS, or alert the attacker.
Every scanner here is read-only and non-intrusive.

### What gets checked

| Scanner | What it does |
|---|---|
| `log-analyzer` | Auth failures, lateral movement, privilege abuse in system logs |
| `oss-forensics` | Supply-chain indicators — tampered packages, unusual sideloads |
| `gitleaks` | Secrets added in recent commits (attacker persistence pattern) |
| `trivy` | Rootfs CVE sweep — identifies what an attacker could exploit |

### ATT&CK coverage

Focuses on post-exploitation: **persistence**, **defense evasion**, and
**exfiltration** techniques.  Look for T1053 (scheduled task), T1098
(account manipulation), T1048 (exfil over alternative protocol).

### Evidence discipline

Do not modify the affected system while this scan is running.  Preserve all
output to the evidence bundle before any remediation.

> **Legal note**: Contact counsel *before* engaging law enforcement.  IR
> evidence collected incorrectly can be inadmissible.
""",
    audience="owner / IR consultant investigating an active or suspected compromise",
    scanners=("log-analyzer", "oss-forensics", "gitleaks", "trivy"),
    scanner_args={
        "gitleaks": {"extra_args": ["--no-git"]},
        "trivy": {"scan_type": "rootfs"},
    },
    approval_tier="safe",
    attack_phases=("persistence", "defense_evasion", "exfiltration"),
    compliance_frameworks=(),
    report_style="ir-timeline",
    success_criteria="""\
- No unrecognized persistence mechanisms found.
- No new secrets committed in recent git history.
- Log analysis shows no evidence of lateral movement or privilege escalation.
""",
    next_steps="""\
- **Preserve the evidence bundle before doing anything else.**
  `koda remote push` can upload it to secure storage.
- Contact counsel before engaging law enforcement — chain of custody matters.
- Rotate *every* credential surfaced in the scan output, starting with
  the ones with the highest privilege.
- If rootfs CVEs were found, treat the host as compromised and rebuild
  from a known-good image rather than patching in place.
- Engage a professional IR firm if the scope of the compromise is unclear.
""",
    requires_target=True,
    default_target_type="path",
)

SBOM_SCAN = MissionPreset(
    name="sbom-scan",
    title="SBOM & Supply-Chain Health",
    summary=(
        "Continuous supply-chain health check for OSS maintainers and developers "
        "shipping libraries. Exports SBOM in CycloneDX and SPDX."
    ),
    description="""\
## SBOM & Supply-Chain Health

**Audience:** OSS maintainer or developer shipping a library who wants
continuous supply-chain health monitoring

Generate a Software Bill of Materials and cross-check every dependency against
three independent vulnerability databases.  Integrates with Dependency-Track
if `KODA_DTRACK_URL` is set in the environment.

### What gets checked

| Scanner | What it does |
|---|---|
| `osv-scanner` | Google OSV — broad language coverage, GHSA + NVD |
| `grype` | Anchore Grype — SBOM generation + CVE matching |
| `trivy` | Trivy SBOM mode — CycloneDX + SPDX export |
| `dependency_track` | Dependency-Track server query (if `KODA_DTRACK_URL` set) |

### Compliance

Aligns with:

- **SLSA** (Supply-chain Levels for Software Artifacts) — provenance metadata
- **CycloneDX** — machine-readable SBOM export
- **SPDX** — alternative SBOM format for toolchain interop

### Dependency-Track integration

If `KODA_DTRACK_URL` and `KODA_DTRACK_API_KEY` are set, findings from the
running DT server are merged into the report.  The preset passes
`--project-uuid` from `scanner_args` if configured; otherwise the CLI will
prompt or skip DT.

### Notes on dispatch

`dependency_track` requires `project_uuid`, `base_url`, and `api_key` as
keyword arguments — it cannot be dispatched via the generic `target` path.
The audit CLI special-cases this scanner: it reads `KODA_DTRACK_URL`,
`KODA_DTRACK_API_KEY`, and `KODA_DTRACK_PROJECT_UUID` from the environment and
passes them as kwargs.  If any are absent, the scanner is silently skipped
(not an error).
""",
    audience="OSS maintainer / developer shipping a library",
    scanners=("osv-scanner", "grype", "trivy", "dependency_track"),
    scanner_args={
        "trivy": {"scan_type": "fs"},
        # dependency_track is dispatched specially by the audit CLI — see description.
        # Base URL and API key are read from environment variables.
        "dependency_track": {},
    },
    approval_tier="safe",
    attack_phases=("initial_access",),
    compliance_frameworks=("SLSA", "CycloneDX"),
    report_style="technical",
    success_criteria="""\
- Zero KEV-matching CVEs in the dependency tree (CISA Known Exploited Vulns).
- SBOM exports cleanly in both CycloneDX and SPDX formats.
- No packages with CRITICAL severity findings across all three scanners.
""",
    next_steps="""\
- For KEV-matching findings, treat as P0 — these have known active exploits.
  Update or replace the affected dependency immediately.
- For CRITICAL CVEs not in KEV, schedule remediation within your SLA.
- Pin the generated SBOM to the release artifact in your release workflow
  (`trivy sbom` output can feed directly into GitHub Releases).
- If using Dependency-Track, configure periodic polling (`koda schedule`)
  to catch new CVEs against the same SBOM without re-running a full scan.
""",
    requires_target=True,
    default_target_type="path",
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, MissionPreset] = {
    p.name: p
    for p in (
        SERVER_HARDENING,
        WEB_APP,
        PCI_READINESS,
        POST_BREACH,
        SBOM_SCAN,
    )
}


def get_preset(name: str) -> MissionPreset | None:
    """Return the preset for *name*, or ``None`` if unknown."""
    return _REGISTRY.get(name)


def list_presets() -> list[MissionPreset]:
    """Return all presets in insertion order."""
    return list(_REGISTRY.values())


def preset_names() -> list[str]:
    """Return sorted list of preset names."""
    return sorted(_REGISTRY)


__all__ = [
    "PRESET_SCHEMA_VERSION",
    "MissionPreset",
    "SERVER_HARDENING",
    "WEB_APP",
    "PCI_READINESS",
    "POST_BREACH",
    "SBOM_SCAN",
    "get_preset",
    "list_presets",
    "preset_names",
]
