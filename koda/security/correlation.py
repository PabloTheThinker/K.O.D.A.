"""Findings correlation — dedupe + enrich raw scanner output.

Scanners disagree about severity, miss CVE/CWE mappings, and double-
report the same issue across parallel runs. Correlation collapses
duplicates (content fingerprint) and layers threat-intel signal
(KEV, EPSS, CWE) onto each finding so triage sees "this one matters
because it's actively exploited" instead of a flat severity column.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..intel import EnrichmentBundle, NullThreatIntel, ThreatIntel
from .findings import FindingStore, Severity, UnifiedFinding


@dataclass
class CorrelationReport:
    total_in: int = 0
    unique: int = 0
    duplicates_merged: int = 0
    enriched_with_kev: int = 0
    enriched_with_epss: int = 0
    upgraded_by_kev: int = 0
    findings: list[UnifiedFinding] = field(default_factory=list)


def correlate(
    findings: Iterable[UnifiedFinding],
    *,
    intel: ThreatIntel | NullThreatIntel | None = None,
    store: FindingStore | None = None,
) -> CorrelationReport:
    """Dedupe + enrich. Idempotent; re-running over the same batch is a no-op
    for dedup and refreshes enrichment from the current intel snapshot."""
    intel = intel or NullThreatIntel()
    store = store or FindingStore()
    report = CorrelationReport()

    batch = list(findings)
    report.total_in = len(batch)

    # Collect CVE IDs up front — one intel query per unique CVE beats one
    # per finding when a single CVE shows up in dozens of results.
    cves = {cve.strip().upper() for f in batch for cve in f.cve if cve}
    bundles: dict[str, EnrichmentBundle] = intel.enrich(cves) if cves else {}

    for finding in batch:
        _apply_enrichment(finding, bundles, report)
        is_new, _ = store.add(finding)
        if not is_new:
            report.duplicates_merged += 1

    report.findings = store.query()
    report.unique = len(report.findings)
    return report


def _apply_enrichment(
    finding: UnifiedFinding,
    bundles: dict[str, EnrichmentBundle],
    report: CorrelationReport,
) -> None:
    if not finding.cve:
        return

    best_exploitability = 0.0
    for cve in finding.cve:
        bundle = bundles.get(cve.strip().upper())
        if bundle is None:
            continue
        if bundle.kev is not None and not finding.cisa_kev:
            finding.cisa_kev = True
            report.enriched_with_kev += 1
            if finding.severity.numeric < Severity.HIGH.numeric:
                finding.severity = Severity.HIGH
                report.upgraded_by_kev += 1
        if bundle.epss is not None and finding.epss_score == 0.0:
            finding.epss_score = bundle.epss.score
            report.enriched_with_epss += 1
        if bundle.cve is not None and finding.cvss_score == 0.0:
            finding.cvss_score = bundle.cve.cvss_v3_score
            if not finding.nvd_url:
                finding.nvd_url = f"https://nvd.nist.gov/vuln/detail/{bundle.cve.cve_id}"
        best_exploitability = max(best_exploitability, bundle.exploitability_score())

    if best_exploitability > 0 and "exploitability" not in finding.raw:
        finding.raw = {**finding.raw, "exploitability": best_exploitability}


__all__ = ["CorrelationReport", "correlate"]
