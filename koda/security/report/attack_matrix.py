"""Build an ATT&CK tactic/technique matrix from a finding set.

For each ``UnifiedFinding.mitre_attack`` entry we enrich via
``intel.lookup_attack_technique`` to recover the technique's tactic and
display name. If a finding has no mitre_attack list but carries CWEs, we
best-effort derive candidate techniques by walking CWE -> CAPEC via
``intel.attack_for_cwe`` and keeping CAPECs whose name matches a known
technique name. This is a fallback only; when it derives nothing we
simply skip that finding.

The result is a list of ``AttackCell``s, one per (technique) group. Helper
functions pivot that list by tactic and summarize coverage.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..findings import Severity, UnifiedFinding


# Minimal static fallback so reports still render when intel DB is empty.
# Keys are ATT&CK Enterprise technique IDs; values are (name, tactic_id,
# tactic_name). Extend as needed — we don't try to ship the full corpus.
_TECHNIQUE_FALLBACK: dict[str, tuple[str, str, str]] = {
    "T1190": ("Exploit Public-Facing Application", "TA0001", "Initial Access"),
    "T1195": ("Supply Chain Compromise", "TA0001", "Initial Access"),
    "T1078": ("Valid Accounts", "TA0001", "Initial Access"),
    "T1566": ("Phishing", "TA0001", "Initial Access"),
    "T1059": ("Command and Scripting Interpreter", "TA0002", "Execution"),
    "T1203": ("Exploitation for Client Execution", "TA0002", "Execution"),
    "T1068": ("Exploitation for Privilege Escalation", "TA0004", "Privilege Escalation"),
    "T1110": ("Brute Force", "TA0006", "Credential Access"),
    "T1555": ("Credentials from Password Stores", "TA0006", "Credential Access"),
    "T1552": ("Unsecured Credentials", "TA0006", "Credential Access"),
    "T1003": ("OS Credential Dumping", "TA0006", "Credential Access"),
    "T1046": ("Network Service Discovery", "TA0007", "Discovery"),
    "T1021": ("Remote Services", "TA0008", "Lateral Movement"),
    "T1005": ("Data from Local System", "TA0009", "Collection"),
    "T1041": ("Exfiltration Over C2 Channel", "TA0010", "Exfiltration"),
    "T1071": ("Application Layer Protocol", "TA0011", "Command and Control"),
    "T1499": ("Endpoint Denial of Service", "TA0040", "Impact"),
    "T1486": ("Data Encrypted for Impact", "TA0040", "Impact"),
}

_TACTIC_NAME_FALLBACK: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


@dataclass(frozen=True)
class AttackCell:
    """One technique's slot in the coverage matrix."""

    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    finding_count: int
    max_severity: str
    finding_ids: tuple[str, ...]


def _enrich_technique(intel: Any, technique_id: str) -> tuple[str, str, str] | None:
    """Return (name, tactic_id, tactic_name) for a technique, or None.

    Prefers the intel DB; falls back to the static map. We never raise
    here — enrichment is best-effort context.
    """
    tid = (technique_id or "").strip().upper()
    if not tid:
        return None

    name = ""
    tactic_id = ""
    tactic_name = ""

    lookup = getattr(intel, "lookup_attack_technique", None)
    if callable(lookup):
        try:
            info = lookup(tid)
        except Exception:
            info = None
        if info is not None:
            name = getattr(info, "name", "") or ""
            tactic_id = getattr(info, "tactic", "") or ""
    else:
        # Module-level helper form: feeds.lookup_attack_technique(intel, tid)
        try:
            from ...intel.feeds import lookup_attack_technique as _m_lookup

            info = _m_lookup(intel, tid)
            if info is not None:
                name = getattr(info, "name", "") or ""
                tactic_id = getattr(info, "tactic", "") or ""
        except Exception:
            pass

    if not name or not tactic_id:
        fallback = _TECHNIQUE_FALLBACK.get(tid)
        if fallback is not None:
            fb_name, fb_tactic_id, fb_tactic_name = fallback
            name = name or fb_name
            tactic_id = tactic_id or fb_tactic_id
            tactic_name = tactic_name or fb_tactic_name

    if tactic_id and not tactic_name:
        tactic_name = _TACTIC_NAME_FALLBACK.get(tactic_id, tactic_id)

    if not name and not tactic_id:
        return None

    return name or tid, tactic_id or "TA0000", tactic_name or "Unknown"


def _derive_from_cwe(intel: Any, cwes: list[str]) -> list[str]:
    """Best-effort: walk CWE -> CAPEC -> technique names. Returns technique IDs."""
    attack_for_cwe = None
    try:
        from ...intel.feeds import attack_for_cwe as _m_attack_for_cwe
        attack_for_cwe = _m_attack_for_cwe
    except Exception:
        return []

    # Reverse index the fallback map by lowercased name to spot candidate IDs.
    name_to_tid = {name.lower(): tid for tid, (name, _, _) in _TECHNIQUE_FALLBACK.items()}
    derived: list[str] = []
    for cwe in cwes:
        try:
            capecs = attack_for_cwe(intel, cwe)
        except Exception:
            continue
        for cap in capecs:
            nm = (getattr(cap, "name", "") or "").lower()
            for known_name, tid in name_to_tid.items():
                if known_name and known_name in nm:
                    if tid not in derived:
                        derived.append(tid)
                    break
    return derived


def build_matrix(
    findings: list[UnifiedFinding],
    intel: Any,
) -> list[AttackCell]:
    """Aggregate findings into AttackCells, one per technique."""
    # technique_id -> {tactic_id, tactic_name, technique_name, fids, max_sev}
    buckets: dict[str, dict[str, Any]] = {}

    for finding in findings:
        techniques = [t for t in (finding.mitre_attack or []) if t]
        if not techniques and finding.cwe:
            techniques = _derive_from_cwe(intel, list(finding.cwe))
        if not techniques:
            continue

        seen: set[str] = set()
        for raw_tid in techniques:
            tid = raw_tid.strip().upper()
            if not tid or tid in seen:
                continue
            seen.add(tid)
            info = _enrich_technique(intel, tid)
            if info is None:
                continue
            tname, tactic_id, tactic_name = info
            bucket = buckets.setdefault(
                tid,
                {
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_name,
                    "technique_name": tname,
                    "finding_ids": [],
                    "max_sev_num": 0,
                    "max_sev_str": Severity.UNKNOWN.value,
                },
            )
            if finding.id not in bucket["finding_ids"]:
                bucket["finding_ids"].append(finding.id)
            sev_num = finding.severity.numeric
            if sev_num > bucket["max_sev_num"]:
                bucket["max_sev_num"] = sev_num
                bucket["max_sev_str"] = finding.severity.value

    cells = [
        AttackCell(
            tactic_id=b["tactic_id"],
            tactic_name=b["tactic_name"],
            technique_id=tid,
            technique_name=b["technique_name"],
            finding_count=len(b["finding_ids"]),
            max_severity=b["max_sev_str"],
            finding_ids=tuple(b["finding_ids"]),
        )
        for tid, b in buckets.items()
    ]
    cells.sort(key=lambda c: (c.tactic_id, c.technique_id))
    return cells


def matrix_by_tactic(cells: list[AttackCell]) -> dict[str, list[AttackCell]]:
    """Pivot AttackCells into {tactic_id: [cells]} for grid rendering."""
    out: dict[str, list[AttackCell]] = {}
    for cell in cells:
        out.setdefault(cell.tactic_id, []).append(cell)
    for tactic_id in out:
        out[tactic_id].sort(key=lambda c: c.technique_id)
    return out


def coverage_summary(cells: list[AttackCell]) -> dict[str, int]:
    """Headline coverage stats."""
    tactics = {c.tactic_id for c in cells}
    techniques = {c.technique_id for c in cells}
    return {
        "techniques_hit": len(techniques),
        "tactics_hit": len(tactics),
    }
