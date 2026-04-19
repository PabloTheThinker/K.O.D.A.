"""Format writers: executive prose, technical text, Markdown, SARIF.

Every writer takes a ``ReportBundle`` and returns a string. No side
effects — the caller decides where bytes land.

Design notes:

  - Executive is plain prose for a CISO/VP. No tool names, no CVE lists,
    no paths. If it can't be said without jargon, it's probably wrong for
    this writer.
  - Technical is monospace-friendly ASCII with `===` / `---` dividers.
    It's the operator's hand-off document.
  - Markdown mirrors the technical content but uses tables, fenced code,
    and clickable MITRE / NVD links. No emojis.
  - SARIF emits canonical 2.1.0. One result per finding, with ATT&CK
    technique IDs on ``properties.tags``, CVSS on ``security-severity``,
    and KEV on a boolean property.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from ..findings import Severity, UnifiedFinding
from .attack_matrix import matrix_by_tactic
from .bundle import ReportBundle

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
)

_SARIF_LEVEL: dict[str, str] = {
    Severity.CRITICAL.value: "error",
    Severity.HIGH.value: "error",
    Severity.MEDIUM.value: "warning",
    Severity.LOW.value: "note",
    Severity.INFO.value: "none",
    Severity.UNKNOWN.value: "none",
}


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------


def _exploit_score(f: UnifiedFinding) -> float:
    """Heuristic used only to rank top-risk findings in the executive summary."""
    score = 0.0
    if f.cisa_kev:
        score += 50.0
    score += float(f.cvss_score or 0.0) * 2.5
    score += float(f.epss_score or 0.0) * 25.0
    score += f.severity.numeric * 3.0
    return score


def _plainspoken_severity(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "severe",
        Severity.MEDIUM: "notable",
        Severity.LOW: "minor",
        Severity.INFO: "informational",
        Severity.UNKNOWN: "undetermined",
    }[sev]


def executive_summary(bundle: ReportBundle) -> str:
    """One-page prose report for leadership. Plain language, no paths."""
    ctx = bundle.ctx
    stats = bundle.stats
    sev = bundle.severity_counts

    total = stats["total_findings"]
    crit = sev.get(Severity.CRITICAL.value, 0)
    high = sev.get(Severity.HIGH.value, 0)
    kev = stats["kev_count"]
    exploitable_today = stats["cvss_ge_9"] + stats["epss_ge_0_9"]

    # Rank top risks
    ranked = sorted(bundle.findings, key=_exploit_score, reverse=True)
    top3 = ranked[:3]

    paras: list[str] = []

    paras.append(
        f"Engagement {ctx.engagement_name} ({ctx.engagement_id}) ran from "
        f"{ctx.started_at or 'unspecified'} to {ctx.ended_at or 'unspecified'}, "
        f"operated by {ctx.operator or 'the security team'} against "
        f"{ctx.scope or 'the agreed scope'}. This memo summarizes the risk "
        f"posture for decision-makers; technical detail lives in the "
        f"accompanying report."
    )

    headline = (
        f"Top line: {total} findings total, {crit} critical and {high} severe. "
        f"{kev} match CISA's Known Exploited Vulnerabilities catalog, meaning "
        f"adversaries are demonstrably using them in the wild right now. An "
        f"additional set of {exploitable_today} issues carry scoring that "
        f"predicts exploitation in the near term."
    )
    paras.append(headline)

    if top3:
        lines: list[str] = ["The three highest-risk items to understand:"]
        for i, f in enumerate(top3, 1):
            descriptor = _plainspoken_severity(f.severity)
            kev_flag = " (actively exploited in the wild)" if f.cisa_kev else ""
            title = f.title or f.rule_id or "unnamed finding"
            lines.append(
                f"  {i}. {title} — {descriptor} risk{kev_flag}. "
                f"{(f.description or '').strip().splitlines()[0][:220] if f.description else ''}"
            )
        paras.append("\n".join(lines))

    if crit + high == 0 and kev == 0:
        posture = (
            "Overall posture: defensible. No critical or severe issues surfaced, "
            "and nothing maps to actively-exploited vulnerabilities. Keep the "
            "remediation hygiene that got you here — routine patching, dependency "
            "updates, and recurring scans."
        )
    elif kev > 0 or crit > 0:
        posture = (
            "Overall posture: requires attention this week. Critical or "
            "actively-exploited findings create a meaningful window of risk — "
            "treat them as incident-adjacent work, not backlog. The remaining "
            "severe and notable items should feed the normal remediation queue "
            "with firm due-dates."
        )
    else:
        posture = (
            "Overall posture: manageable. No critical or actively-exploited "
            "issues, but several severe items warrant near-term remediation. "
            "Normal sprint cadence is appropriate if owners and due-dates are "
            "assigned this week."
        )
    paras.append(posture)

    actions: list[str] = ["Immediate next actions:"]
    if kev > 0:
        actions.append(
            f"  - Patch or mitigate every CISA-KEV match ({kev}) within 7 days; "
            f"these have known exploitation campaigns."
        )
    if crit > 0:
        actions.append(
            f"  - Assign owners to all {crit} critical findings with a 14-day "
            f"remediation SLA."
        )
    if high > 0:
        actions.append(
            f"  - Feed the {high} severe findings into the standard backlog with "
            f"30-day SLAs and monthly review."
        )
    if stats["unique_techniques"] > 0:
        actions.append(
            f"  - Brief detection engineering on the {stats['unique_techniques']} "
            f"distinct ATT&CK techniques represented across the findings so "
            f"monitoring can be aligned."
        )
    actions.append(
        "  - Schedule a re-test once remediations land; do not close issues on "
        "the strength of a developer's assertion alone."
    )
    paras.append("\n".join(actions))

    paras.append(
        "Questions, re-test requests, or scoping changes should route through "
        f"the engagement lead ({ctx.operator or 'security team'}). This memo "
        "was produced by K.O.D.A. from the validated finding set."
    )

    return "\n\n".join(paras) + "\n"


# ---------------------------------------------------------------------------
# Technical report (plain text)
# ---------------------------------------------------------------------------


def _h1(title: str) -> str:
    bar = "=" * max(len(title), 60)
    return f"{bar}\n{title}\n{bar}"


def _h2(title: str) -> str:
    bar = "-" * max(len(title), 40)
    return f"{title}\n{bar}"


def _truncate(text: str, limit: int = 800) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "\u2026"


def _findings_by_severity(findings: tuple[UnifiedFinding, ...]) -> dict[Severity, list[UnifiedFinding]]:
    grouped: dict[Severity, list[UnifiedFinding]] = defaultdict(list)
    for f in findings:
        grouped[f.severity].append(f)
    return grouped


def _format_location(f: UnifiedFinding) -> str:
    if f.file_path and f.start_line:
        return f"{f.file_path}:{f.start_line}"
    if f.file_path:
        return f.file_path
    return "(no source location)"


def technical_report(bundle: ReportBundle) -> str:
    ctx = bundle.ctx
    stats = bundle.stats
    out: list[str] = []

    out.append(_h1(f"K.O.D.A. TECHNICAL REPORT: {ctx.engagement_name}"))
    out.append("")
    out.extend(ctx.header_lines())
    out.append("")

    # Stats
    out.append(_h2("Summary Stats"))
    out.append(f"total findings         : {stats['total_findings']}")
    for sev in _SEVERITY_ORDER:
        n = bundle.severity_counts.get(sev.value, 0)
        if n:
            out.append(f"  {sev.value:<13}      : {n}")
    out.append(f"CISA-KEV matches       : {stats['kev_count']}")
    out.append(f"CVSS >= 9.0            : {stats['cvss_ge_9']}")
    out.append(f"EPSS >= 0.9            : {stats['epss_ge_0_9']}")
    out.append(f"unique CVEs            : {stats['unique_cves']}")
    out.append(f"unique CWEs            : {stats['unique_cwes']}")
    out.append(f"ATT&CK techniques hit  : {stats['unique_techniques']}")
    out.append(f"ATT&CK tactics hit     : {stats['unique_tactics']}")
    out.append("")

    # ATT&CK coverage
    out.append(_h2("ATT&CK Coverage Matrix"))
    cells = list(bundle.attack_cells)
    if not cells:
        out.append("(no ATT&CK techniques mapped)")
    else:
        by_tactic = matrix_by_tactic(cells)
        for tactic_id in sorted(by_tactic.keys()):
            group = by_tactic[tactic_id]
            tactic_name = group[0].tactic_name
            out.append(f"[{tactic_id}] {tactic_name}")
            for c in group:
                out.append(
                    f"    {c.technique_id:<10}  {c.technique_name:<48}  "
                    f"findings={c.finding_count:<3}  max={c.max_severity}"
                )
    out.append("")

    # Full findings grouped by severity
    out.append(_h2("Findings (by severity)"))
    grouped = _findings_by_severity(bundle.findings)
    for sev in _SEVERITY_ORDER:
        bucket = grouped.get(sev) or []
        if not bucket:
            continue
        out.append("")
        out.append(f">> {sev.value.upper()} ({len(bucket)})")
        out.append("")
        for f in bucket:
            out.append(f"id        : {f.id}")
            out.append(f"title     : {f.title or '(untitled)'}")
            out.append(f"scanner   : {f.scanner}  rule: {f.rule_id}")
            out.append(f"location  : {_format_location(f)}")
            if f.cve:
                out.append(f"CVE       : {', '.join(f.cve)}")
            if f.cwe:
                out.append(f"CWE       : {', '.join(f.cwe)}")
            if f.mitre_attack:
                out.append(f"ATT&CK    : {', '.join(f.mitre_attack)}")
            out.append(
                f"CVSS={f.cvss_score:.1f}  EPSS={f.epss_score:.3f}  "
                f"KEV={'yes' if f.cisa_kev else 'no'}  "
                f"validated={'yes' if f.validated else 'no'}"
            )
            if f.description:
                out.append("description:")
                out.append(f"  {_truncate(f.description, 800)}")
            if f.fix_suggestion:
                out.append("fix:")
                out.append(f"  {_truncate(f.fix_suggestion, 600)}")
            out.append("")

    # Per-CVE appendix
    all_cves = sorted({c.upper() for f in bundle.findings for c in (f.cve or []) if c})
    if all_cves:
        out.append(_h2("Appendix A — Per-CVE Enrichment"))
        for cve_id in all_cves:
            out.append(f"{cve_id}")
            try:
                enr = bundle.stats.get("_intel")
            except Exception:
                enr = None
            # Intel lookups happen at write time so stats stays serializable.
            out.extend(_cve_enrichment_lines(cve_id, bundle))
            out.append("")

    out.append(_h2("Footer"))
    out.append(f"roe_id    : {ctx.roe_id or '(none)'}")
    out.append(f"generated : {ctx.ended_at or ''}")
    out.append("")

    return "\n".join(out) + "\n"


def _cve_enrichment_lines(cve_id: str, bundle: ReportBundle) -> list[str]:
    """Pull enrichment via the intel object stashed on the bundle at build time.

    We don't want to hold the intel handle inside the frozen bundle, so we
    store it on a private attribute — writers read it if present, fall
    back to ``(no intel)`` lines otherwise.
    """
    intel = getattr(bundle, "_intel", None) or bundle.stats.get("_intel")
    if intel is None:
        return ["  (no intel handle provided; enrichment skipped)"]
    lookup = getattr(intel, "lookup_cve", None)
    if not callable(lookup):
        return ["  (intel handle does not support lookup_cve)"]
    try:
        enr = lookup(cve_id)
    except Exception as exc:  # noqa: BLE001
        return [f"  (intel lookup failed: {exc})"]

    lines: list[str] = []
    if enr.kev is not None:
        kev = enr.kev
        lines.append(
            f"  KEV=yes  vendor={kev.vendor or '?'}  product={kev.product or '?'}"
            f"  due={kev.due_date or '?'}  ransomware={'yes' if kev.known_ransomware else 'no'}"
        )
    else:
        lines.append("  KEV=no")
    if enr.epss is not None:
        lines.append(f"  EPSS score={enr.epss.score:.4f}  percentile={enr.epss.percentile:.4f}")
    if enr.cve is not None:
        lines.append(
            f"  CVSSv3={enr.cve.cvss_v3_score:.1f}  vector={enr.cve.cvss_v3_vector or '-'}"
        )
        if enr.cve.description:
            lines.append(f"  description: {_truncate(enr.cve.description, 400)}")
    if not lines:
        lines.append("  (no enrichment data available)")
    return lines


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _md_cve_link(cve_id: str) -> str:
    return f"[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})"


def _md_attack_link(tid: str) -> str:
    slug = tid.replace(".", "/")
    return f"[{tid}](https://attack.mitre.org/techniques/{slug})"


def _md_cwe_link(cwe_id: str) -> str:
    num = cwe_id.split("-", 1)[-1]
    return f"[{cwe_id}](https://cwe.mitre.org/data/definitions/{num}.html)"


def markdown_report(bundle: ReportBundle) -> str:
    ctx = bundle.ctx
    stats = bundle.stats
    out: list[str] = []

    out.append(f"# Engagement: {ctx.engagement_name}")
    out.append("")
    out.append(f"**ID:** `{ctx.engagement_id}`  ")
    out.append(f"**Client:** {ctx.client or '_(internal)_'}  ")
    out.append(f"**Operator:** {ctx.operator}  ")
    out.append(f"**Mode:** `{ctx.mode}`  ")
    out.append(f"**Window:** {ctx.window() or '_(unspecified)_'}  ")
    out.append(f"**Scope:** {ctx.scope}  ")
    if ctx.targets:
        out.append(f"**Targets:** {', '.join(f'`{t}`' for t in ctx.targets)}  ")
    if ctx.roe_id:
        out.append(f"**RoE:** `{ctx.roe_id}`  ")
    out.append("")

    # Stats table
    out.append("## Summary")
    out.append("")
    out.append("| Metric | Value |")
    out.append("|---|---:|")
    out.append(f"| Total findings | {stats['total_findings']} |")
    for sev in _SEVERITY_ORDER:
        n = bundle.severity_counts.get(sev.value, 0)
        if n:
            out.append(f"| {sev.value.capitalize()} | {n} |")
    out.append(f"| CISA-KEV matches | {stats['kev_count']} |")
    out.append(f"| CVSS >= 9.0 | {stats['cvss_ge_9']} |")
    out.append(f"| EPSS >= 0.9 | {stats['epss_ge_0_9']} |")
    out.append(f"| Unique CVEs | {stats['unique_cves']} |")
    out.append(f"| Unique CWEs | {stats['unique_cwes']} |")
    out.append(f"| ATT&CK techniques hit | {stats['unique_techniques']} |")
    out.append(f"| ATT&CK tactics hit | {stats['unique_tactics']} |")
    out.append("")

    # Top CVEs
    if bundle.top_cves:
        out.append("### Top CVEs")
        out.append("")
        out.append("| CVE | Occurrences |")
        out.append("|---|---:|")
        for cid, n in bundle.top_cves:
            out.append(f"| {_md_cve_link(cid)} | {n} |")
        out.append("")

    # ATT&CK matrix
    out.append("## ATT&CK Coverage")
    out.append("")
    if not bundle.attack_cells:
        out.append("_No ATT&CK techniques mapped._")
    else:
        out.append("| Tactic | Technique | Findings | Max severity |")
        out.append("|---|---|---:|---|")
        for cell in sorted(bundle.attack_cells, key=lambda c: (c.tactic_id, c.technique_id)):
            out.append(
                f"| {cell.tactic_id} {cell.tactic_name} | "
                f"{_md_attack_link(cell.technique_id)} {cell.technique_name} | "
                f"{cell.finding_count} | {cell.max_severity} |"
            )
    out.append("")

    # Findings by severity
    out.append("## Findings")
    out.append("")
    grouped = _findings_by_severity(bundle.findings)
    for sev in _SEVERITY_ORDER:
        bucket = grouped.get(sev) or []
        if not bucket:
            continue
        out.append(f"### {sev.value.capitalize()} ({len(bucket)})")
        out.append("")
        for f in bucket:
            out.append(f"#### {f.title or f.rule_id or f.id}")
            out.append("")
            out.append(f"- **ID:** `{f.id}`")
            out.append(f"- **Scanner:** `{f.scanner}`  **Rule:** `{f.rule_id}`")
            out.append(f"- **Location:** `{_format_location(f)}`")
            if f.cve:
                out.append(f"- **CVE:** {', '.join(_md_cve_link(c) for c in f.cve)}")
            if f.cwe:
                out.append(f"- **CWE:** {', '.join(_md_cwe_link(c) for c in f.cwe)}")
            if f.mitre_attack:
                out.append(f"- **ATT&CK:** {', '.join(_md_attack_link(t) for t in f.mitre_attack)}")
            out.append(
                f"- **CVSS:** {f.cvss_score:.1f}  **EPSS:** {f.epss_score:.3f}  "
                f"**KEV:** {'yes' if f.cisa_kev else 'no'}  "
                f"**Validated:** {'yes' if f.validated else 'no'}"
            )
            if f.description:
                out.append("")
                out.append(_truncate(f.description, 800))
            if f.snippet:
                out.append("")
                out.append("```")
                out.append(f.snippet[:600])
                out.append("```")
            if f.fix_suggestion:
                out.append("")
                out.append(f"**Fix:** {_truncate(f.fix_suggestion, 600)}")
            out.append("")

    # Appendix
    all_cves = sorted({c.upper() for f in bundle.findings for c in (f.cve or []) if c})
    if all_cves:
        out.append("## Appendix A — Per-CVE Enrichment")
        out.append("")
        for cve_id in all_cves:
            out.append(f"### {_md_cve_link(cve_id)}")
            out.append("")
            for line in _cve_enrichment_lines(cve_id, bundle):
                out.append(f"- {line.strip()}")
            out.append("")

    out.append("---")
    out.append(f"_RoE `{ctx.roe_id or '(none)'}` — generated {ctx.ended_at or ''}_")
    out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def _sarif_location(f: UnifiedFinding) -> dict[str, Any]:
    loc: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": f.file_path or "unknown",
            },
        }
    }
    region: dict[str, Any] = {}
    if f.start_line:
        region["startLine"] = int(f.start_line)
    if f.end_line and f.end_line != f.start_line:
        region["endLine"] = int(f.end_line)
    if f.start_col:
        region["startColumn"] = int(f.start_col)
    if f.end_col:
        region["endColumn"] = int(f.end_col)
    if f.snippet:
        region["snippet"] = {"text": f.snippet[:600]}
    if region:
        loc["physicalLocation"]["region"] = region
    return loc


def _sarif_result(f: UnifiedFinding) -> dict[str, Any]:
    level = _SARIF_LEVEL.get(f.severity.value, "warning")
    tags: list[str] = list(f.mitre_attack or [])
    for cwe in f.cwe or []:
        if cwe and cwe not in tags:
            tags.append(cwe)

    props: dict[str, Any] = {
        "severity": f.severity.value,
        "cisa-kev": bool(f.cisa_kev),
        "cvss_score": float(f.cvss_score or 0.0),
        "epss_score": float(f.epss_score or 0.0),
        "cve": list(f.cve or []),
        "cwe": list(f.cwe or []),
        "mitre_attack": list(f.mitre_attack or []),
    }
    if f.cvss_score:
        # GitHub's SARIF viewer uses this key for numeric severity.
        props["security-severity"] = f"{float(f.cvss_score):.1f}"
    if tags:
        props["tags"] = tags

    result: dict[str, Any] = {
        "ruleId": f.rule_id or f.id,
        "level": level,
        "message": {"text": f.title or f.description or f.rule_id or f.id},
        "locations": [_sarif_location(f)],
        "properties": props,
    }
    if f.id:
        result["fingerprints"] = {"koda.id": f.id}
    if f.fix_suggestion:
        result["fixes"] = [
            {"description": {"text": f.fix_suggestion[:600]}},
        ]
    return result


def _sarif_rules(findings: tuple[UnifiedFinding, ...]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        rid = f.rule_id or f.id
        if not rid or rid in seen:
            continue
        seen[rid] = {
            "id": rid,
            "name": (f.title or rid)[:100],
            "shortDescription": {"text": (f.title or rid)[:200]},
            "fullDescription": {"text": (f.description or f.title or rid)[:1000]},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity.value, "warning")},
            "properties": {
                "tags": list({*(f.mitre_attack or []), *(f.cwe or [])}),
            },
        }
    return list(seen.values())


def sarif_report(bundle: ReportBundle) -> str:
    """Emit canonical SARIF 2.1.0 as a JSON string."""
    ctx = bundle.ctx
    rules = _sarif_rules(bundle.findings)
    results = [_sarif_result(f) for f in bundle.findings]

    invocation: dict[str, Any] = {
        "executionSuccessful": True,
    }
    if ctx.started_at:
        invocation["startTimeUtc"] = ctx.started_at
    if ctx.ended_at:
        invocation["endTimeUtc"] = ctx.ended_at

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "koda",
                "informationUri": "https://koda.vektraindustries.com/",
                "rules": rules,
            }
        },
        "invocations": [invocation],
        "results": results,
        "properties": {
            "engagement_id": ctx.engagement_id,
            "engagement_name": ctx.engagement_name,
            "operator": ctx.operator,
            "mode": ctx.mode,
            "scope": ctx.scope,
            "roe_id": ctx.roe_id,
            "targets": list(ctx.targets),
        },
    }

    log: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(log, indent=2, ensure_ascii=False)
