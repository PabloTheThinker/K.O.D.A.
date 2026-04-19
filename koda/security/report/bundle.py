"""ReportBundle — the fully-built input to every writer.

A bundle is the ``ReportContext`` plus the findings, the computed
ATT&CK matrix, and a set of precomputed statistics. Writers never recompute
these — they just read the bundle. Keeps every output format in lockstep.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from ..findings import Severity, UnifiedFinding
from .attack_matrix import AttackCell, build_matrix, coverage_summary
from .context import ReportContext


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
)


@dataclass(frozen=True)
class ReportBundle:
    """Immutable read-model assembled once, consumed by each writer."""

    ctx: ReportContext
    findings: tuple[UnifiedFinding, ...]
    attack_cells: tuple[AttackCell, ...]
    stats: dict[str, Any]
    severity_counts: dict[str, int]
    top_cves: tuple[tuple[str, int], ...]


def _severity_counts(findings: list[UnifiedFinding]) -> dict[str, int]:
    counts = {s.value: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def _top_cves(findings: list[UnifiedFinding], limit: int = 10) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for f in findings:
        for cve in f.cve or []:
            cid = (cve or "").strip().upper()
            if cid:
                counter[cid] += 1
    return counter.most_common(limit)


def _unique_flat(findings: list[UnifiedFinding], attr: str) -> set[str]:
    out: set[str] = set()
    for f in findings:
        for v in getattr(f, attr, []) or []:
            v = (v or "").strip()
            if v:
                out.add(v.upper())
    return out


def build_bundle(
    ctx: ReportContext,
    findings: list[UnifiedFinding],
    intel: Any,
) -> ReportBundle:
    """Assemble the bundle once; writers read it top-to-bottom."""
    cells = build_matrix(findings, intel)
    sev_counts = _severity_counts(findings)
    top_cves = _top_cves(findings)

    unique_cves = _unique_flat(findings, "cve")
    unique_cwes = _unique_flat(findings, "cwe")
    unique_techniques = {c.technique_id for c in cells}
    unique_tactics = {c.tactic_id for c in cells}

    kev_count = sum(1 for f in findings if f.cisa_kev)
    high_cvss = sum(1 for f in findings if (f.cvss_score or 0.0) >= 9.0)
    high_epss = sum(1 for f in findings if (f.epss_score or 0.0) >= 0.9)

    coverage = coverage_summary(cells)

    stats: dict[str, Any] = {
        "total_findings": len(findings),
        "severity_counts": sev_counts,
        "kev_count": kev_count,
        "cvss_ge_9": high_cvss,
        "epss_ge_0_9": high_epss,
        "unique_cves": len(unique_cves),
        "unique_cwes": len(unique_cwes),
        "unique_techniques": len(unique_techniques),
        "unique_tactics": len(unique_tactics),
        "coverage": coverage,
        "top_cves": top_cves,
    }

    return ReportBundle(
        ctx=ctx,
        findings=tuple(findings),
        attack_cells=tuple(cells),
        stats=stats,
        severity_counts=sev_counts,
        top_cves=tuple(top_cves),
    )
