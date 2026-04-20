"""Generate a Markdown digest of what the learning layer produced.

A report summarizes activity across the three buckets on disk:

  * ``_pending/<name>/``         — drafts awaiting review
  * ``_learned/<name>/``         — approved skills (directly under the root)
  * ``_rejected/<name>-<ts>.md`` — reviewer-rejected drafts, archived

The ``--since`` filter uses filesystem mtimes (we don't persist an authored-at
timestamp in ``.source.json``). ``generate_report`` returns a ``Report``
dataclass; ``render_markdown`` formats it; ``write_report`` drops it under
``_learned/_reports/LEARNED-YYYY-MM-DD.md``.

The report is designed for humans on any KODA install — no Mocha-/Pablo-
specific framing, no external notifier baked in. Users who want a ping can
cat the file into whatever channel they run.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from koda.learning.store import LearnedSkillStore, default_store

REPORTS_DIRNAME = "_reports"


@dataclass
class ReportItem:
    """One skill in the report — pending, approved, or rejected."""

    name: str
    bucket: str  # "pending" | "approved" | "rejected"
    mtime: datetime
    concept_id: str = ""
    title: str = ""
    confidence: float | None = None
    evidence_count: int | None = None
    trigger: str = ""
    synthesizer: str = ""


@dataclass
class Report:
    generated_at: datetime
    since: datetime | None
    pending: list[ReportItem] = field(default_factory=list)
    approved: list[ReportItem] = field(default_factory=list)
    rejected: list[ReportItem] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.pending) + len(self.approved) + len(self.rejected)

    def is_empty(self) -> bool:
        return self.total == 0

    def render_markdown(self) -> str:
        lines: list[str] = []
        stamp = self.generated_at.strftime("%Y-%m-%d")
        lines.append(f"# KODA learning digest — {stamp}")
        lines.append("")
        if self.since is not None:
            lines.append(f"_Since {self.since.isoformat()}._")
        else:
            lines.append("_Lifetime snapshot._")
        lines.append("")
        lines.append(
            f"**Drafted (pending):** {len(self.pending)}  ·  "
            f"**Approved:** {len(self.approved)}  ·  "
            f"**Rejected:** {len(self.rejected)}"
        )
        lines.append("")

        if self.is_empty():
            lines.append("_No new learning activity in this window._")
            lines.append("")
            return "\n".join(lines)

        if self.pending:
            lines.append("## Pending review")
            lines.append("")
            for item in self.pending:
                lines.extend(_render_item(item, command_hint=True))
            lines.append("")

        if self.approved:
            lines.append("## Approved")
            lines.append("")
            for item in self.approved:
                lines.extend(_render_item(item, command_hint=False))
            lines.append("")

        if self.rejected:
            lines.append("## Rejected")
            lines.append("")
            for item in self.rejected:
                lines.extend(_render_item(item, command_hint=False))
            lines.append("")

        return "\n".join(lines)


def generate_report(
    *,
    since: datetime | None = None,
    store: LearnedSkillStore | None = None,
) -> Report:
    """Scan the store and build a :class:`Report` filtered by ``since``."""
    store = store or default_store()
    now = datetime.now(UTC)

    pending = [_item_from_pending(p) for p in store.list_pending()]
    approved = [_item_from_approved(p) for p in store.list_approved()]
    rejected = _collect_rejected(store)

    if since is not None:
        pending = [i for i in pending if i.mtime >= since]
        approved = [i for i in approved if i.mtime >= since]
        rejected = [i for i in rejected if i.mtime >= since]

    pending.sort(key=lambda i: i.mtime, reverse=True)
    approved.sort(key=lambda i: i.mtime, reverse=True)
    rejected.sort(key=lambda i: i.mtime, reverse=True)

    return Report(
        generated_at=now,
        since=since,
        pending=pending,
        approved=approved,
        rejected=rejected,
    )


def write_report(
    report: Report,
    *,
    reports_dir: Path | None = None,
    store: LearnedSkillStore | None = None,
) -> Path:
    """Write ``report`` to ``<reports_dir>/LEARNED-YYYY-MM-DD.md``."""
    if reports_dir is None:
        store = store or default_store()
        reports_dir = store.root / REPORTS_DIRNAME
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.strftime("%Y-%m-%d")
    dest = reports_dir / f"LEARNED-{stamp}.md"
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(report.render_markdown(), encoding="utf-8")
    tmp.replace(dest)
    return dest


# ── Helpers ───────────────────────────────────────────────────────────

def _item_from_pending(pending) -> ReportItem:
    source = pending.source or {}
    skill_file = pending.path / "SKILL.md"
    mtime = _mtime(skill_file) or _mtime(pending.path)
    return ReportItem(
        name=pending.name,
        bucket="pending",
        mtime=mtime,
        concept_id=str(source.get("concept_id", "")),
        title=str(source.get("title", "")),
        confidence=_maybe_float(source.get("confidence")),
        evidence_count=_maybe_int(source.get("evidence_count")),
        trigger=str(source.get("trigger", "")),
        synthesizer=str(source.get("synthesizer", "")),
    )


def _item_from_approved(path: Path) -> ReportItem:
    source = _load_source_json(path / ".source.json")
    mtime = _mtime(path / "SKILL.md") or _mtime(path)
    return ReportItem(
        name=path.name,
        bucket="approved",
        mtime=mtime,
        concept_id=str(source.get("concept_id", "")),
        title=str(source.get("title", "")),
        confidence=_maybe_float(source.get("confidence")),
        evidence_count=_maybe_int(source.get("evidence_count")),
        trigger=str(source.get("trigger", "")),
        synthesizer=str(source.get("synthesizer", "")),
    )


def _collect_rejected(store: LearnedSkillStore) -> list[ReportItem]:
    if not store.rejected_dir.is_dir():
        return []
    items: list[ReportItem] = []
    for entry in sorted(store.rejected_dir.iterdir()):
        if not entry.is_file() or entry.suffix != ".md":
            continue
        # Filename format: "<name>-<YYYYmmddTHHMMSS>.md"
        stem = entry.stem
        name, _sep, _ts = stem.rpartition("-")
        items.append(ReportItem(
            name=name or stem,
            bucket="rejected",
            mtime=_mtime(entry) or datetime.now(UTC),
        ))
    return items


def _render_item(item: ReportItem, *, command_hint: bool) -> list[str]:
    bits: list[str] = [f"- **{item.name}**"]
    meta: list[str] = []
    if item.title and item.title != item.name:
        meta.append(item.title)
    if item.concept_id:
        meta.append(f"concept `{item.concept_id[:10]}`")
    if item.confidence is not None:
        meta.append(f"conf {item.confidence:.2f}")
    if item.evidence_count is not None:
        meta.append(f"ep {item.evidence_count}")
    if item.trigger:
        meta.append(f"trigger {item.trigger}")
    if item.synthesizer:
        meta.append(f"via {item.synthesizer}")
    if meta:
        bits.append("  ·  " + " · ".join(meta))
    out = ["".join(bits)]
    if command_hint:
        out.append(f"  - review: `koda learn approve {item.name}` / `koda learn reject {item.name}`")
    return out


def _mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except (OSError, ValueError):
        return None


def _load_source_json(path: Path) -> dict:
    import json
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _maybe_float(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _maybe_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
