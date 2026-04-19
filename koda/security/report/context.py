"""Engagement context passed into report generation.

Frozen dataclass — captures the who/what/when/where of an engagement so
every generated artifact (executive, technical, Markdown, SARIF) shares
one source of metadata. Fields are all plain strings/tuples so the
context round-trips through JSON and audit logs without surprise.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReportContext:
    """Metadata block for a single engagement's report bundle."""

    engagement_id: str
    engagement_name: str
    scope: str
    operator: str
    started_at: str
    ended_at: str
    mode: str
    targets: tuple[str, ...]
    client: str = ""
    roe_id: str = ""

    def window(self) -> str:
        """Human-readable engagement window. Empty string if either end is unset."""
        if not self.started_at or not self.ended_at:
            return self.started_at or self.ended_at or ""
        return f"{self.started_at} -> {self.ended_at}"

    def header_lines(self) -> list[str]:
        """One-line-per-field header block used by the plain-text writers."""
        lines = [
            f"engagement_id : {self.engagement_id}",
            f"engagement    : {self.engagement_name}",
            f"client        : {self.client or '(internal)'}",
            f"operator      : {self.operator}",
            f"mode          : {self.mode}",
            f"window        : {self.window()}",
            f"scope         : {self.scope}",
        ]
        if self.targets:
            lines.append(f"targets       : {', '.join(self.targets)}")
        if self.roe_id:
            lines.append(f"roe_id        : {self.roe_id}")
        return lines
