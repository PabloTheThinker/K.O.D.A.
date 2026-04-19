"""Unified finding model — normalizes output from any scanner into one format.

Every scanner (Semgrep, Trivy, Nuclei, Bandit, etc.) produces different
output. This module provides a single UnifiedFinding dataclass that all
scanner results map into, enabling consistent triage, dedup, and reporting.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: str) -> Severity:
        """Parse severity from various scanner formats."""
        v = value.strip().upper()
        mapping = {
            "CRITICAL": cls.CRITICAL, "CRIT": cls.CRITICAL,
            "HIGH": cls.HIGH, "ERROR": cls.HIGH,
            "MEDIUM": cls.MEDIUM, "MED": cls.MEDIUM, "WARNING": cls.MEDIUM,
            "LOW": cls.LOW, "NOTE": cls.LOW,
            "INFO": cls.INFO, "INFORMATIONAL": cls.INFO, "NONE": cls.INFO,
        }
        return mapping.get(v, cls.UNKNOWN)

    @property
    def numeric(self) -> int:
        """Numeric severity for sorting (higher = more severe)."""
        return {
            Severity.CRITICAL: 5, Severity.HIGH: 4,
            Severity.MEDIUM: 3, Severity.LOW: 2,
            Severity.INFO: 1, Severity.UNKNOWN: 0,
        }[self]


class FindingStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    IN_PROGRESS = "in_progress"


@dataclass
class UnifiedFinding:
    """A single security finding, normalized from any scanner."""

    # Identity
    id: str                          # Deterministic hash-based ID
    scanner: str                     # Source scanner (semgrep, trivy, etc.)
    rule_id: str = ""                # Scanner-specific rule ID

    # Classification
    severity: Severity = Severity.UNKNOWN
    confidence: float = 0.0          # 0.0-1.0
    title: str = ""
    description: str = ""
    category: str = ""               # e.g., "injection", "xss", "secret-leak"

    # Location
    file_path: str = ""
    start_line: int = 0
    end_line: int = 0
    start_col: int = 0
    end_col: int = 0
    snippet: str = ""

    # Vulnerability identifiers
    cve: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)

    # Enrichment (populated by enrichment module)
    cisa_kev: bool = False           # In CISA Known Exploited Vulns catalog
    cvss_score: float = 0.0
    epss_score: float = 0.0          # Exploit Prediction Scoring System
    nvd_url: str = ""

    # Remediation
    fix_suggestion: str = ""
    fix_diff: str = ""               # Proposed patch (unified diff)

    # Metadata
    status: FindingStatus = FindingStatus.NEW
    validated: bool = False           # Confirmed by validation agent
    validation_notes: str = ""
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    raw: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def make_id(scanner: str, rule_id: str, file_path: str, start_line: int) -> str:
        """Deterministic finding ID from key attributes."""
        key = f"{scanner}:{rule_id}:{file_path}:{start_line}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def fingerprint(self) -> str:
        """Content-based fingerprint for dedup across scans."""
        key = f"{self.rule_id}:{self.file_path}:{self.snippet[:200]}"
        return hashlib.sha256(key.encode()).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "snippet": self.snippet,
            "cve": self.cve,
            "cwe": self.cwe,
            "mitre_attack": self.mitre_attack,
            "cisa_kev": self.cisa_kev,
            "cvss_score": self.cvss_score,
            "fix_suggestion": self.fix_suggestion,
            "status": self.status.value,
            "validated": self.validated,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }
        if self.fix_diff:
            d["fix_diff"] = self.fix_diff
        if self.validation_notes:
            d["validation_notes"] = self.validation_notes
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> UnifiedFinding:
        d = d.copy()
        d["severity"] = Severity(d.get("severity", "unknown"))
        d["status"] = FindingStatus(d.get("status", "new"))
        for k in ("first_seen", "last_seen"):
            if isinstance(d.get(k), str):
                d[k] = datetime.fromisoformat(d[k])
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in d.items() if k in known})


class FindingStore:
    """Persistent store for findings with dedup and query."""

    def __init__(self, store_path: Path | None = None):
        self._findings: dict[str, UnifiedFinding] = {}
        self._fingerprints: dict[str, str] = {}  # fingerprint -> finding_id
        self.store_path = store_path
        if store_path and store_path.exists():
            self._load()

    def add(self, finding: UnifiedFinding) -> tuple[bool, str]:
        """Add finding. Returns (is_new, finding_id). Deduplicates by fingerprint."""
        fp = finding.fingerprint()
        if fp in self._fingerprints:
            existing_id = self._fingerprints[fp]
            existing = self._findings[existing_id]
            existing.last_seen = datetime.now(UTC)
            # Upgrade severity if new scan found higher
            if finding.severity.numeric > existing.severity.numeric:
                existing.severity = finding.severity
            return False, existing_id

        self._findings[finding.id] = finding
        self._fingerprints[fp] = finding.id
        return True, finding.id

    def get(self, finding_id: str) -> UnifiedFinding | None:
        return self._findings.get(finding_id)

    def query(
        self,
        severity: Severity | None = None,
        scanner: str | None = None,
        status: FindingStatus | None = None,
        file_path: str | None = None,
        validated_only: bool = False,
    ) -> list[UnifiedFinding]:
        """Query findings with filters."""
        results = list(self._findings.values())
        if severity:
            results = [f for f in results if f.severity == severity]
        if scanner:
            results = [f for f in results if f.scanner == scanner]
        if status:
            results = [f for f in results if f.status == status]
        if file_path:
            results = [f for f in results if file_path in f.file_path]
        if validated_only:
            results = [f for f in results if f.validated]
        return sorted(results, key=lambda f: f.severity.numeric, reverse=True)

    def stats(self) -> dict[str, Any]:
        """Summary statistics."""
        findings = list(self._findings.values())
        by_severity = {}
        for s in Severity:
            count = len([f for f in findings if f.severity == s])
            if count:
                by_severity[s.value] = count
        by_scanner = {}
        for f in findings:
            by_scanner[f.scanner] = by_scanner.get(f.scanner, 0) + 1
        return {
            "total": len(findings),
            "by_severity": by_severity,
            "by_scanner": by_scanner,
            "confirmed": len([f for f in findings if f.validated]),
            "fixed": len([f for f in findings if f.status == FindingStatus.FIXED]),
        }

    def save(self) -> None:
        if not self.store_path:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        data = [f.to_dict() for f in self._findings.values()]
        tmp = self.store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.rename(self.store_path)

    def _load(self) -> None:
        try:
            data = json.loads(self.store_path.read_text())
            for d in data:
                finding = UnifiedFinding.from_dict(d)
                self._findings[finding.id] = finding
                self._fingerprints[finding.fingerprint()] = finding.id
        except Exception:
            pass
