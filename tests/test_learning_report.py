"""Tests for ``koda.learning.report`` — LEARNED-<date>.md digest builder."""
from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from koda.learning.report import (
    REPORTS_DIRNAME,
    generate_report,
    write_report,
)
from koda.learning.store import LearnedSkillStore


def _make_store(tmp_path: Path) -> LearnedSkillStore:
    return LearnedSkillStore(tmp_path / "_learned")


def _drop_pending(store: LearnedSkillStore, name: str, **source: object) -> None:
    store.save_pending(
        name=name,
        skill_md=f"---\nname: {name}\n---\n## Body\ncontent\n",
        source={"concept_id": f"c-{name}", **source},
    )


def _drop_approved(store: LearnedSkillStore, name: str, **source: object) -> None:
    dest = store.root / name
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "SKILL.md").write_text(f"# {name}\n", encoding="utf-8")
    (dest / ".source.json").write_text(
        json.dumps({"concept_id": f"c-{name}", **source}), encoding="utf-8",
    )


def _drop_rejected(store: LearnedSkillStore, name: str, stamp: str) -> None:
    store.rejected_dir.mkdir(parents=True, exist_ok=True)
    (store.rejected_dir / f"{name}-{stamp}.md").write_text(f"# {name}\n", encoding="utf-8")


def test_empty_store_produces_empty_report(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    report = generate_report(store=store)
    assert report.is_empty()
    md = report.render_markdown()
    assert "KODA learning digest" in md
    assert "No new learning activity" in md


def test_report_collects_all_buckets(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    _drop_pending(store, "alpha", confidence=0.91, evidence_count=7,
                  trigger="live-hook", synthesizer="template")
    _drop_approved(store, "beta", confidence=0.88, evidence_count=6)
    _drop_rejected(store, "gamma", "20260420T120000")

    report = generate_report(store=store)
    assert {i.name for i in report.pending} == {"alpha"}
    assert {i.name for i in report.approved} == {"beta"}
    assert {i.name for i in report.rejected} == {"gamma"}

    md = report.render_markdown()
    assert "alpha" in md
    assert "beta" in md
    assert "gamma" in md
    # Pending surfaces the review command hint.
    assert "koda learn approve alpha" in md
    # Confidence + evidence count render for pending / approved.
    assert "conf 0.91" in md
    assert "ep 7" in md


def test_since_filters_out_older_items(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    _drop_pending(store, "old", confidence=0.8)
    # Backdate the pending dir so it falls outside the window.
    target = store.pending_path("old") / "SKILL.md"
    old_ts = time.time() - 7 * 86400
    os.utime(target, (old_ts, old_ts))
    os.utime(store.pending_path("old"), (old_ts, old_ts))

    _drop_pending(store, "fresh", confidence=0.9)

    since = datetime.now(UTC) - timedelta(days=1)
    report = generate_report(since=since, store=store)
    names = {i.name for i in report.pending}
    assert "fresh" in names
    assert "old" not in names


def test_write_report_creates_file(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    _drop_pending(store, "foo", confidence=0.75)

    report = generate_report(store=store)
    dest = write_report(report, store=store)

    assert dest.exists()
    assert dest.parent.name == REPORTS_DIRNAME
    stamp = report.generated_at.strftime("%Y-%m-%d")
    assert dest.name == f"LEARNED-{stamp}.md"
    assert "foo" in dest.read_text(encoding="utf-8")


def test_rejected_name_parses_out_timestamp(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    _drop_rejected(store, "ugly-name", "20260420T030000")
    report = generate_report(store=store)
    assert [i.name for i in report.rejected] == ["ugly-name"]


def test_ordering_is_newest_first(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    _drop_pending(store, "first", confidence=0.8)
    older = time.time() - 3600
    os.utime(store.pending_path("first") / "SKILL.md", (older, older))
    _drop_pending(store, "second", confidence=0.8)

    report = generate_report(store=store)
    assert [i.name for i in report.pending] == ["second", "first"]


def test_report_writes_to_explicit_dir(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    _drop_pending(store, "x", confidence=0.8)
    report = generate_report(store=store)
    dest_dir = tmp_path / "custom-reports"
    dest = write_report(report, reports_dir=dest_dir)
    assert dest.parent == dest_dir
    assert dest.exists()


@pytest.mark.parametrize("bucket", ["pending", "approved"])
def test_metadata_missing_fields_do_not_crash(bucket: str, tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    if bucket == "pending":
        _drop_pending(store, "sparse")
    else:
        _drop_approved(store, "sparse")
    report = generate_report(store=store)
    md = report.render_markdown()
    assert "sparse" in md
