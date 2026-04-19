"""Sigma rule synthesis.

Turns a defender finding / alert into a draft Sigma rule YAML. Stdlib-only:
no ``yaml`` dependency. The serializer emits a strict, narrow subset of
YAML sufficient for Sigma rule consumers.

Scope:
  - titles, ids, status, description, references, tags, logsource,
    detection (selection + condition), falsepositives, level.
  - indicators → a single ``selection`` block with ``key: value`` or
    ``key: [a, b]`` entries. Condition defaults to ``selection``.

Output is deterministic (dict keys serialized in insertion order).
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any


# ATT&CK technique id → coarse tactic name. Only the majors — the
# serializer falls back to just the technique tag when the tactic is
# unknown.
_TACTIC_BY_TECHNIQUE: dict[str, str] = {
    # Reconnaissance
    "T1595": "reconnaissance",
    "T1589": "reconnaissance",
    "T1590": "reconnaissance",
    "T1591": "reconnaissance",
    "T1592": "reconnaissance",
    "T1593": "reconnaissance",
    "T1594": "reconnaissance",
    "T1596": "reconnaissance",
    "T1597": "reconnaissance",
    "T1598": "reconnaissance",
    # Initial access
    "T1190": "initial_access",
    "T1133": "initial_access",
    "T1078": "initial_access",
    "T1566": "initial_access",
    # Execution
    "T1059": "execution",
    # Persistence
    "T1053": "persistence",
    "T1136": "persistence",
    "T1547": "persistence",
    "T1505": "persistence",
    # Privilege escalation
    "T1068": "privilege_escalation",
    "T1548": "privilege_escalation",
    "T1134": "privilege_escalation",
    # Credential access
    "T1003": "credential_access",
    # Discovery
    "T1046": "discovery",
    "T1135": "discovery",
    "T1018": "discovery",
    "T1069": "discovery",
    "T1087": "discovery",
    # Lateral movement
    "T1021": "lateral_movement",
    "T1570": "lateral_movement",
    "T1563": "lateral_movement",
    # Command and control
    "T1071": "command_and_control",
    # Exfiltration
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1567": "exfiltration",
    # Impact
    "T1486": "impact",
    # Defense evasion
    "T1055": "defense_evasion",
}


@dataclass(frozen=True)
class SigmaRuleDraft:
    """A Sigma rule draft. Field names match Sigma YAML keys."""
    title: str
    id: str
    status: str = "experimental"
    description: str = ""
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    falsepositives: tuple[str, ...] = ()
    level: str = "medium"


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

_PRODUCT_DEFAULT_SERVICE: dict[str, str] = {
    "windows": "sysmon",
    "linux": "auditd",
    "macos": "unified_log",
    "apache": "access",
    "nginx": "access",
}


def _tactic_tag_for(technique: str) -> str | None:
    base = technique.split(".", 1)[0].upper()
    tactic = _TACTIC_BY_TECHNIQUE.get(base)
    if tactic is None:
        return None
    return f"attack.{tactic}"


def draft_from_finding(
    *,
    title: str,
    attack_techniques: list[str],
    product: str,
    service: str = "",
    indicators: dict[str, Any] | None = None,
    references: list[str] | None = None,
    level: str = "medium",
) -> SigmaRuleDraft:
    """Build a SigmaRuleDraft from a finding.

    - ``title`` becomes the rule title.
    - ``attack_techniques`` are turned into ``attack.tXXXX`` tags plus a
      ``attack.<tactic>`` tag where the tactic is known.
    - ``product`` / ``service`` populate ``logsource``. If ``service`` is
      empty, a sensible default is picked from the product.
    - ``indicators`` becomes a ``selection`` block. Lists become YAML
      lists; scalars become scalar values.
    - ``references`` is passed through.
    - ``level`` must be one of informational/low/medium/high/critical;
      callers pass it verbatim (no validation beyond non-empty).
    """
    rid = str(uuid.uuid4())
    svc = service or _PRODUCT_DEFAULT_SERVICE.get(product.lower(), "")
    logsource: dict[str, str] = {"product": product.lower()}
    if svc:
        logsource["service"] = svc

    tags: list[str] = []
    for t in attack_techniques:
        low = t.strip().lower()
        if not low:
            continue
        tech_tag = f"attack.{low}"
        if tech_tag not in tags:
            tags.append(tech_tag)
        tactic = _tactic_tag_for(t)
        if tactic is not None and tactic not in tags:
            tags.append(tactic)

    detection: dict[str, Any] = {}
    if indicators:
        detection["selection"] = dict(indicators)
    detection["condition"] = "selection" if indicators else "selection"

    desc_bits: list[str] = []
    if attack_techniques:
        desc_bits.append(
            "Detects activity mapping to MITRE ATT&CK "
            + ", ".join(attack_techniques)
        )
    desc_bits.append(f"Drafted from finding: {title}")

    return SigmaRuleDraft(
        title=title,
        id=rid,
        status="experimental",
        description=". ".join(desc_bits) + ".",
        references=tuple(references or ()),
        tags=tuple(tags),
        logsource=logsource,
        detection=detection,
        falsepositives=("Legitimate administrative activity.",),
        level=level,
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

_NEEDS_QUOTING = re.compile(r"[:#\[\]\{\},&*!|>'\"%@`]")


def _scalar(value: Any) -> str:
    """Serialize a scalar value to a YAML token."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    s = str(value)
    if s == "":
        return "''"
    # Quote when the string contains YAML-significant characters, looks
    # like a number, or starts with whitespace / hyphen.
    needs = False
    if _NEEDS_QUOTING.search(s):
        needs = True
    elif s[0] in " -?" or s[-1] == " ":
        needs = True
    elif s.lower() in ("true", "false", "null", "yes", "no", "on", "off"):
        needs = True
    else:
        try:
            float(s)
            needs = True
        except ValueError:
            pass
    if needs:
        # Single-quote escape: double any internal single quotes.
        inner = s.replace("'", "''")
        return f"'{inner}'"
    return s


def _emit_list(items: tuple[Any, ...] | list[Any], indent: int) -> list[str]:
    pad = " " * indent
    return [f"{pad}- {_scalar(i)}" for i in items]


def _emit_mapping(
    mapping: dict[str, Any],
    indent: int,
) -> list[str]:
    pad = " " * indent
    out: list[str] = []
    for k, v in mapping.items():
        key = _scalar(k)
        if isinstance(v, dict):
            if not v:
                out.append(f"{pad}{key}: {{}}")
                continue
            out.append(f"{pad}{key}:")
            out.extend(_emit_mapping(v, indent + 4))
        elif isinstance(v, (list, tuple)):
            if not v:
                out.append(f"{pad}{key}: []")
                continue
            out.append(f"{pad}{key}:")
            out.extend(_emit_list(v, indent + 4))
        else:
            out.append(f"{pad}{key}: {_scalar(v)}")
    return out


def serialize(draft: SigmaRuleDraft) -> str:
    """Serialize a SigmaRuleDraft to Sigma-compatible YAML."""
    lines: list[str] = []
    lines.append(f"title: {_scalar(draft.title)}")
    lines.append(f"id: {_scalar(draft.id)}")
    lines.append(f"status: {_scalar(draft.status)}")
    if draft.description:
        lines.append(f"description: {_scalar(draft.description)}")
    if draft.references:
        lines.append("references:")
        lines.extend(_emit_list(draft.references, 4))
    if draft.tags:
        lines.append("tags:")
        lines.extend(_emit_list(draft.tags, 4))
    if draft.logsource:
        lines.append("logsource:")
        lines.extend(_emit_mapping(draft.logsource, 4))
    if draft.detection:
        lines.append("detection:")
        lines.extend(_emit_mapping(draft.detection, 4))
    if draft.falsepositives:
        lines.append("falsepositives:")
        lines.extend(_emit_list(draft.falsepositives, 4))
    lines.append(f"level: {_scalar(draft.level)}")
    return "\n".join(lines) + "\n"


__all__ = ["SigmaRuleDraft", "draft_from_finding", "serialize"]
