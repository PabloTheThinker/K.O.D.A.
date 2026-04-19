"""Diff engine for scheduled scan runs.

Finding identity is the ``UnifiedFinding.fingerprint()`` — a content hash
over ``rule_id``, ``file_path``, and the first 200 bytes of ``snippet``.
Two findings with the same fingerprint are the same issue regardless of when
they were observed.

DiffResult categories:
    new        — fingerprint in current run but not in previous
    resolved   — fingerprint in previous run but not in current
    persistent — fingerprint in both runs

Severity ordering is respected when building alert payloads: CRITICAL and
HIGH findings bubble to the top so the first line of any Telegram/email
message names the most dangerous issue.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..security.findings import UnifiedFinding


@dataclass
class DiffResult:
    """Result of comparing two scan runs."""

    new: list[UnifiedFinding] = field(default_factory=list)
    resolved: list[UnifiedFinding] = field(default_factory=list)
    persistent: list[UnifiedFinding] = field(default_factory=list)

    @property
    def has_new(self) -> bool:
        return bool(self.new)

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.resolved)

    @property
    def is_empty(self) -> bool:
        return not (self.new or self.resolved or self.persistent)

    def summary(self) -> str:
        parts = []
        if self.new:
            parts.append(f"{len(self.new)} new")
        if self.resolved:
            parts.append(f"{len(self.resolved)} resolved")
        if self.persistent:
            parts.append(f"{len(self.persistent)} persistent")
        if not parts:
            return "no findings"
        return ", ".join(parts)


def _load_findings_jsonl(path: Path) -> list[UnifiedFinding]:
    """Load UnifiedFinding list from a JSONL file.  Returns empty list on error."""
    from ..security.findings import UnifiedFinding as UF
    findings: list[UnifiedFinding] = []
    if not path.exists():
        return findings
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                findings.append(UF.from_dict(d))
            except Exception:
                continue
    except OSError:
        pass
    return findings


def _sort_by_severity(findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
    """Sort findings by severity descending (CRITICAL first)."""
    return sorted(findings, key=lambda f: f.severity.numeric, reverse=True)


def diff_runs(
    prev_findings: list[UnifiedFinding] | None,
    curr_findings: list[UnifiedFinding],
) -> DiffResult:
    """Compute diff between *prev_findings* and *curr_findings*.

    If *prev_findings* is ``None`` (first run), every finding is "new".
    """
    if prev_findings is None:
        return DiffResult(
            new=_sort_by_severity(curr_findings),
            resolved=[],
            persistent=[],
        )

    prev_fps: set[str] = {f.fingerprint() for f in prev_findings}
    curr_fps: set[str] = {f.fingerprint() for f in curr_findings}

    new = _sort_by_severity([f for f in curr_findings if f.fingerprint() not in prev_fps])
    resolved = _sort_by_severity([f for f in prev_findings if f.fingerprint() not in curr_fps])
    persistent = _sort_by_severity([f for f in curr_findings if f.fingerprint() in prev_fps])

    return DiffResult(new=new, resolved=resolved, persistent=persistent)


def diff_run_dirs(prev_run_dir: Path | None, curr_run_dir: Path) -> DiffResult:
    """Compute diff by loading ``findings.jsonl`` from run directories."""
    curr_findings = _load_findings_jsonl(curr_run_dir / "findings.jsonl")
    if prev_run_dir is None:
        return diff_runs(None, curr_findings)
    prev_findings = _load_findings_jsonl(prev_run_dir / "findings.jsonl")
    return diff_runs(prev_findings, curr_findings)


__all__ = ["DiffResult", "diff_runs", "diff_run_dirs"]
