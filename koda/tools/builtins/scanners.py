"""Real scanner wrappers — semgrep, trivy, bandit, gitleaks, nuclei, osv-scanner, nmap, grype.

Each scanner is a binary that K.O.D.A. shells out to. Output is parsed into
UnifiedFinding and deduped into a shared FindingStore. The tools here do NOT
invent data — if a scanner is not installed, the tool reports that plainly and
returns. If a scan returns zero findings, that is the reported result; we do
not fabricate.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ...security.findings import FindingStore, Severity
from ...security.scanners.registry import ScannerRegistry
from ..registry import RiskLevel, Tool, ToolResult, register


_finding_store: FindingStore | None = None


def _store() -> FindingStore:
    global _finding_store
    if _finding_store is None:
        _finding_store = FindingStore()
    return _finding_store


def _render_finding(f: Any, indent: str = "  ") -> list[str]:
    lines = [f"{indent}[{f.severity.value.upper():8s}] {f.title}"]
    if f.file_path:
        loc = f"{indent}         {f.file_path}"
        if f.start_line:
            loc += f":{f.start_line}"
        lines.append(loc)
    if f.cve:
        lines.append(f"{indent}         CVE: {', '.join(f.cve[:3])}")
    return lines


def _scan_run(scanner: str, target: str) -> ToolResult:
    reg = ScannerRegistry()
    installed = reg.installed()
    if scanner not in installed or not installed.get(scanner):
        avail = [k for k, v in installed.items() if v]
        return ToolResult(
            content=f"Scanner '{scanner}' not installed. Available: {', '.join(avail) or '(none)'}",
            is_error=True,
        )

    t = Path(target).expanduser()
    if not t.exists():
        return ToolResult(content=f"Target does not exist: {t}", is_error=True)

    result = reg.run(scanner, str(t))
    if not result.success:
        return ToolResult(content=result.error or f"{scanner} failed", is_error=True)

    store = _store()
    for f in result.findings:
        store.add(f)

    lines = [
        f"scanner: {scanner}",
        f"target:  {t}",
        f"elapsed: {result.elapsed:.1f}s",
        f"findings: {len(result.findings)}",
        "",
    ]
    if result.findings:
        lines.append("Top findings (real matches, not inferences):")
        for f in result.findings[:20]:
            lines.extend(_render_finding(f))
        if len(result.findings) > 20:
            lines.append(f"  ... and {len(result.findings) - 20} more (use security.findings to query)")
    else:
        lines.append(f"No findings reported by {scanner}. This does NOT mean the target is safe;")
        lines.append("other scanners and tools may still find issues.")

    return ToolResult(
        content="\n".join(lines),
        metadata={"scanner": scanner, "findings": len(result.findings), "elapsed": result.elapsed},
    )


def _scan_available() -> ToolResult:
    reg = ScannerRegistry()
    installed = reg.installed()
    avail = [k for k, v in installed.items() if v]
    missing = [k for k, v in installed.items() if not v]

    lines = []
    if avail:
        lines.append(f"installed: {', '.join(avail)}")
    if missing:
        lines.append(f"not installed: {', '.join(missing)}")
    lines.append(f"{len(avail)} of {len(installed)} scanners available")
    return ToolResult(content="\n".join(lines), metadata={"available": avail, "missing": missing})


def _scan_all(target: str) -> ToolResult:
    reg = ScannerRegistry()
    t = Path(target).expanduser()
    if not t.exists():
        return ToolResult(content=f"Target does not exist: {t}", is_error=True)

    results = reg.run_all(str(t))
    store = _store()
    total = 0
    lines = [f"target: {t}", ""]
    for r in results:
        status = "ok" if r.success else "fail"
        lines.append(f"  [{status:4s}] {r.scanner}: {len(r.findings)} findings ({r.elapsed:.1f}s)")
        if r.error:
            lines.append(f"           error: {r.error}")
        for f in r.findings:
            store.add(f)
        total += len(r.findings)

    lines.append(f"\ntotal: {total} findings from {len(results)} scanner(s)")

    top = store.query()[:10]
    if top:
        lines.append("\nTop findings across all scanners:")
        for f in top:
            lines.extend(_render_finding(f))

    return ToolResult(
        content="\n".join(lines),
        metadata={"total_findings": total, "scanners_ran": len(results)},
    )


def _security_findings(severity: str = "", scanner: str = "", limit: int = 50) -> ToolResult:
    store = _store()
    sev = Severity(severity.lower()) if severity else None
    results = store.query(severity=sev, scanner=scanner or None)
    results = results[: max(1, min(limit, 500))]

    lines = [f"stored findings: {len(store._findings)}  (showing {len(results)})"]
    if not results:
        lines.append("no findings match the filter.")
        return ToolResult(content="\n".join(lines))

    for f in results:
        lines.extend(_render_finding(f))
    return ToolResult(
        content="\n".join(lines),
        metadata={"returned": len(results), "stats": store.stats()},
    )


register(Tool(
    name="scan.available",
    description=(
        "List which security scanners (semgrep, trivy, bandit, gitleaks, nuclei, osv-scanner, "
        "nmap, grype) are installed on this host. Call this FIRST before claiming a scanner is available."
    ),
    input_schema={"type": "object", "properties": {}, "required": []},
    handler=_scan_available,
    risk=RiskLevel.SAFE,
    category="security",
))


register(Tool(
    name="scan.run",
    description=(
        "Run a single named security scanner against a target directory/file. Scanners: "
        "semgrep (SAST), trivy (dependencies+containers), bandit (Python SAST), gitleaks "
        "(secrets), nuclei (web), osv-scanner (SCA), nmap (network), grype (vuln). Parses "
        "output into a unified finding format. Use scan.available first if unsure what is installed."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "scanner": {"type": "string", "description": "Scanner name (semgrep, trivy, bandit, gitleaks, nuclei, osv-scanner, nmap, grype)."},
            "target": {"type": "string", "description": "Target path — directory or file."},
        },
        "required": ["scanner", "target"],
    },
    handler=_scan_run,
    risk=RiskLevel.SAFE,
    category="security",
))


register(Tool(
    name="scan.all",
    description=(
        "Run every installed scanner against the target in sequence. Returns a per-scanner "
        "breakdown plus top findings across all scanners."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target path — directory or file."},
        },
        "required": ["target"],
    },
    handler=_scan_all,
    risk=RiskLevel.SAFE,
    category="security",
))


register(Tool(
    name="security.findings",
    description=(
        "Query findings already stored from previous scans. Filter by severity (critical, "
        "high, medium, low, info) or scanner name. Does NOT run new scans — only reads."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "severity": {"type": "string", "description": "Optional — filter by severity."},
            "scanner": {"type": "string", "description": "Optional — filter by scanner name."},
            "limit": {"type": "integer", "description": "Max findings to return (default 50, max 500)."},
        },
        "required": [],
    },
    handler=_security_findings,
    risk=RiskLevel.SAFE,
    category="security",
))
