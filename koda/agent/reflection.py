"""Post-engagement reflection — behavioral pattern extraction for Koda.

Hermes-style reflection is LLM-initiated and unpredictable. Koda's is
deterministic: every agent turn appends one record to a bounded journal,
and ``get_patterns()`` folds the journal into a small dict operators can
inspect at the end of an engagement.

The journal is intentionally flat and JSON-safe so it can drop straight
into the engagement evidence store alongside the audit log.

Ported from koda-agent/koda/cognition/reflection.py — stripped of the
``CognitiveModule`` base class and ``StepContext``/``StepResult`` schema
imports, which were tied to the trait-adaptive harness Koda no longer
runs. The remaining surface is a self-contained dataclass.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class ReflectionEngine:
    """Bounded journal of agent turns, with pattern extraction helpers."""

    max_entries: int = 200
    journal: list[dict] = field(default_factory=list)

    def record(
        self,
        *,
        success: bool,
        tools: Iterable[str] | None = None,
        error: str | None = None,
        correction: str | None = None,
        input_len: int = 0,
        output_len: int = 0,
        iteration: int = 0,
        engagement: str | None = None,
    ) -> None:
        """Append a single turn's outcome to the journal."""
        entry = {
            "time": datetime.now(UTC).isoformat(timespec="seconds"),
            "success": bool(success),
            "tools": list(tools or []),
            "error": error,
            "correction": correction,
            "input_len": int(input_len),
            "output_len": int(output_len),
            "iteration": int(iteration),
            "engagement": engagement,
        }
        self.journal.append(entry)
        if len(self.journal) > self.max_entries:
            self.journal = self.journal[-self.max_entries :]

    def recent_hint(self, window: int = 10) -> str:
        """A short system-prompt hint based on the last ``window`` turns.

        Returns an empty string if there isn't enough data or no pattern
        is worth mentioning. The string is suitable for prepending to the
        system prompt of the next turn.
        """
        if len(self.journal) < 5:
            return ""
        recent = self.journal[-window:]
        if not recent:
            return ""

        success_rate = sum(1 for e in recent if e.get("success")) / len(recent)

        tool_freq: dict[str, int] = {}
        for e in recent:
            for t in e.get("tools", []):
                tool_freq[t] = tool_freq.get(t, 0) + 1
        top_tools = sorted(tool_freq.items(), key=lambda x: -x[1])[:3]

        parts: list[str] = []
        if success_rate < 0.5:
            parts.append("Recent pattern: low success rate. Consider simplifying approach.")
        elif success_rate > 0.9:
            parts.append("Recent pattern: high success rate. Current approach is working.")
        if top_tools:
            tools_str = ", ".join(f"{t}({c})" for t, c in top_tools)
            parts.append(f"Most-used tools recently: {tools_str}")
        return "\n".join(parts)

    def get_patterns(self) -> dict:
        """Aggregate the full journal into a retrospective report."""
        total = len(self.journal)
        if not total:
            return {"entries": 0}

        successes = sum(1 for e in self.journal if e.get("success"))
        corrections = sum(1 for e in self.journal if e.get("correction"))
        errors = sum(1 for e in self.journal if e.get("error"))

        tool_freq: dict[str, int] = {}
        for e in self.journal:
            for t in e.get("tools", []):
                tool_freq[t] = tool_freq.get(t, 0) + 1

        error_types: dict[str, int] = {}
        for e in self.journal:
            err = e.get("error")
            if err:
                key = str(err)[:50]
                error_types[key] = error_types.get(key, 0) + 1

        return {
            "entries": total,
            "success_rate": round(successes / total, 3),
            "correction_rate": round(corrections / total, 3),
            "error_rate": round(errors / total, 3),
            "top_tools": sorted(tool_freq.items(), key=lambda x: -x[1])[:5],
            "top_errors": sorted(error_types.items(), key=lambda x: -x[1])[:3],
        }

    def save_state(self, path: Path) -> None:
        data = {"journal": self.journal[-self.max_entries :]}
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load_state(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        self.journal = list(data.get("journal", []))


__all__ = ["ReflectionEngine"]
