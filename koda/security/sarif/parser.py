"""SARIF 2.1.0 parser — reads Static Analysis Results Interchange Format.

Parses SARIF files from any compliant scanner (Semgrep, Trivy, CodeQL,
Checkov, etc.) into typed Python dataclasses. Provides normalization
into K.O.D.A.'s UnifiedFinding format.

Reference: OASIS SARIF v2.1.0
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..findings import Severity, UnifiedFinding


@dataclass
class SarifLocation:
    """A physical location in source code."""
    file_path: str = ""
    uri_base_id: str = ""
    start_line: int = 0
    start_col: int = 0
    end_line: int = 0
    end_col: int = 0
    snippet: str = ""
    context_snippet: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SarifLocation:
        phys = d.get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        region = phys.get("region", {})
        context = phys.get("contextRegion", {})

        return cls(
            file_path=artifact.get("uri", ""),
            uri_base_id=artifact.get("uriBaseId", ""),
            start_line=region.get("startLine", 0),
            start_col=region.get("startColumn", 0),
            end_line=region.get("endLine", region.get("startLine", 0)),
            end_col=region.get("endColumn", 0),
            snippet=_extract_text(region.get("snippet", {})),
            context_snippet=_extract_text(context.get("snippet", {})),
        )


@dataclass
class SarifFix:
    """A proposed fix for a finding."""
    description: str = ""
    changes: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SarifFix:
        desc = _extract_message(d.get("description", {}))
        changes = d.get("artifactChanges", [])
        return cls(description=desc, changes=changes)

    def to_diff(self) -> str:
        """Convert artifact changes to a unified diff-like string."""
        lines = []
        for change in self.changes:
            artifact = change.get("artifactLocation", {}).get("uri", "unknown")
            lines.append(f"--- a/{artifact}")
            lines.append(f"+++ b/{artifact}")
            for repl in change.get("replacements", []):
                deleted = repl.get("deletedRegion", {})
                inserted = _extract_text(repl.get("insertedContent", {}))
                line = deleted.get("startLine", 0)
                lines.append(f"@@ -{line} +{line} @@")
                if inserted:
                    lines.append(f"+{inserted}")
        return "\n".join(lines)


@dataclass
class SarifRule:
    """A rule / reporting descriptor."""
    id: str = ""
    name: str = ""
    short_description: str = ""
    full_description: str = ""
    help_uri: str = ""
    default_level: str = "warning"
    tags: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SarifRule:
        tags = []
        cwe = []
        # Extract CWE from relationships or properties
        for rel in d.get("relationships", []):
            target = rel.get("target", {})
            tid = target.get("id", "")
            if tid.startswith("CWE-"):
                cwe.append(tid)
        props = d.get("properties", {})
        tags = props.get("tags", [])
        # Some scanners put CWE in tags
        for t in tags:
            if t.startswith("CWE-") and t not in cwe:
                cwe.append(t)

        default_cfg = d.get("defaultConfiguration", {})

        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            short_description=_extract_message(d.get("shortDescription", {})),
            full_description=_extract_message(d.get("fullDescription", {})),
            help_uri=d.get("helpUri", ""),
            default_level=default_cfg.get("level", "warning"),
            tags=tags,
            cwe=cwe,
        )


@dataclass
class SarifResult:
    """A single finding/result from a SARIF run."""
    rule_id: str = ""
    rule_index: int = -1
    level: str = "warning"        # note, warning, error
    kind: str = "fail"            # pass, open, review, fail, etc.
    message: str = ""
    locations: list[SarifLocation] = field(default_factory=list)
    fixes: list[SarifFix] = field(default_factory=list)
    fingerprints: dict[str, str] = field(default_factory=dict)
    partial_fingerprints: dict[str, str] = field(default_factory=dict)
    properties: dict[str, Any] = field(default_factory=dict)

    # Populated during normalization from the run's rule definitions
    _rule: Optional[SarifRule] = field(default=None, repr=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SarifResult:
        locations = [SarifLocation.from_dict(loc) for loc in d.get("locations", [])]
        fixes = [SarifFix.from_dict(f) for f in d.get("fixes", [])]

        return cls(
            rule_id=d.get("ruleId", ""),
            rule_index=d.get("ruleIndex", -1),
            level=d.get("level", "warning"),
            kind=d.get("kind", "fail"),
            message=_extract_message(d.get("message", {})),
            locations=locations,
            fixes=fixes,
            fingerprints=d.get("fingerprints", {}),
            partial_fingerprints=d.get("partialFingerprints", {}),
            properties=d.get("properties", {}),
        )

    def normalize(self, scanner: str = "unknown") -> UnifiedFinding:
        """Convert to a UnifiedFinding."""
        loc = self.locations[0] if self.locations else SarifLocation()

        # Map SARIF level to severity. Per SARIF 2.1.0 §3.27.10, the result's
        # level (if explicitly set) overrides the rule's defaultConfiguration;
        # only fall back to the rule default when the result omits level.
        severity_map = {
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "note": Severity.LOW,
            "none": Severity.INFO,
        }
        result_level = (self.level or "").lower()
        if result_level in severity_map:
            severity = severity_map[result_level]
        elif self._rule and self._rule.default_level in severity_map:
            severity = severity_map[self._rule.default_level]
        else:
            severity = Severity.MEDIUM

        # Scanner-specific severity hints on the result properties win last —
        # they carry CVSS/EPSS-derived grades the generic level can't express.
        props_severity = self.properties.get("severity") or self.properties.get("impact")
        if props_severity:
            parsed = Severity.from_str(str(props_severity))
            if parsed != Severity.UNKNOWN:
                severity = parsed

        # Extract CWE from rule
        cwe = []
        if self._rule:
            cwe = list(self._rule.cwe)

        # Build title from rule name or message
        title = ""
        if self._rule and self._rule.name:
            title = self._rule.name
        elif self._rule and self._rule.short_description:
            title = self._rule.short_description
        else:
            title = self.message[:120] if self.message else self.rule_id

        # Build fix suggestion
        fix_suggestion = ""
        fix_diff = ""
        if self.fixes:
            fix_suggestion = self.fixes[0].description
            fix_diff = self.fixes[0].to_diff()

        finding_id = UnifiedFinding.make_id(scanner, self.rule_id, loc.file_path, loc.start_line)

        return UnifiedFinding(
            id=finding_id,
            scanner=scanner,
            rule_id=self.rule_id,
            severity=severity,
            title=title,
            description=self.message,
            file_path=loc.file_path,
            start_line=loc.start_line,
            end_line=loc.end_line,
            start_col=loc.start_col,
            end_col=loc.end_col,
            snippet=loc.snippet,
            cwe=cwe,
            fix_suggestion=fix_suggestion,
            fix_diff=fix_diff,
            raw={"sarif_level": self.level, "sarif_kind": self.kind},
        )


@dataclass
class SarifRun:
    """A single analysis run within a SARIF log."""
    tool_name: str = ""
    tool_version: str = ""
    tool_uri: str = ""
    results: list[SarifResult] = field(default_factory=list)
    rules: list[SarifRule] = field(default_factory=list)
    invocation_success: bool = True
    artifacts: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SarifRun:
        # Parse tool info
        tool = d.get("tool", {})
        driver = tool.get("driver", {})
        tool_name = driver.get("name", "")
        tool_version = driver.get("version", driver.get("semanticVersion", ""))
        tool_uri = driver.get("informationUri", "")

        # Parse rules
        rules_data = driver.get("rules", [])
        rules = [SarifRule.from_dict(r) for r in rules_data]
        rule_map = {r.id: r for r in rules}
        # Also index by position for ruleIndex lookups
        rule_list = rules

        # Parse results and attach rule references
        results = []
        for rd in d.get("results", []):
            result = SarifResult.from_dict(rd)
            # Resolve rule reference
            if result.rule_id and result.rule_id in rule_map:
                result._rule = rule_map[result.rule_id]
            elif 0 <= result.rule_index < len(rule_list):
                result._rule = rule_list[result.rule_index]
                if not result.rule_id:
                    result.rule_id = result._rule.id
            results.append(result)

        # Invocation status
        invocation_success = True
        for inv in d.get("invocations", []):
            if not inv.get("executionSuccessful", True):
                invocation_success = False

        return cls(
            tool_name=tool_name,
            tool_version=tool_version,
            tool_uri=tool_uri,
            results=results,
            rules=rules,
            invocation_success=invocation_success,
            artifacts=d.get("artifacts", []),
        )

    def to_findings(self) -> list[UnifiedFinding]:
        """Convert all results to UnifiedFindings."""
        scanner = self.tool_name.lower().replace(" ", "-")
        return [r.normalize(scanner=scanner) for r in self.results]


@dataclass
class SarifLog:
    """Top-level SARIF 2.1.0 log file."""
    version: str = "2.1.0"
    runs: list[SarifRun] = field(default_factory=list)
    schema_uri: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SarifLog:
        version = d.get("version", "2.1.0")
        schema_uri = d.get("$schema", "")
        runs = [SarifRun.from_dict(r) for r in d.get("runs", [])]
        return cls(version=version, runs=runs, schema_uri=schema_uri)

    @classmethod
    def from_file(cls, path: Path | str) -> SarifLog:
        """Parse a SARIF file from disk."""
        path = Path(path)
        data = json.loads(path.read_text())
        return cls.from_dict(data)

    @classmethod
    def from_str(cls, text: str) -> SarifLog:
        """Parse SARIF from a JSON string."""
        return cls.from_dict(json.loads(text))

    def all_findings(self) -> list[UnifiedFinding]:
        """Get all findings across all runs."""
        findings = []
        for run in self.runs:
            findings.extend(run.to_findings())
        return findings

    def stats(self) -> dict[str, Any]:
        findings = self.all_findings()
        by_severity = {}
        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        return {
            "runs": len(self.runs),
            "total_findings": len(findings),
            "by_severity": by_severity,
            "tools": [r.tool_name for r in self.runs],
        }


def _extract_message(msg: dict[str, Any] | str) -> str:
    """Extract text from a SARIF message object or plain string."""
    if isinstance(msg, str):
        return msg
    return msg.get("text", msg.get("markdown", ""))


def _extract_text(content: dict[str, Any] | str) -> str:
    """Extract text from an artifactContent object."""
    if isinstance(content, str):
        return content
    return content.get("text", "")
