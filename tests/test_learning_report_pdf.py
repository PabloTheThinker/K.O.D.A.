"""Tests for :mod:`koda.learning.report_pdf`.

reportlab is an optional extra, so every test that exercises a real render
skips cleanly when it isn't installed.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from koda.learning.report import Report, ReportItem
from koda.learning.report_pdf import PDFUnavailable, render_pdf

reportlab = pytest.importorskip("reportlab", reason="reportlab not installed")


def _item(name: str, bucket: str, **extra) -> ReportItem:
    return ReportItem(
        name=name,
        bucket=bucket,
        mtime=datetime(2026, 4, 20, tzinfo=UTC),
        **extra,
    )


def _report(**overrides) -> Report:
    base = dict(
        generated_at=datetime(2026, 4, 20, tzinfo=UTC),
        since=datetime(2026, 4, 19, tzinfo=UTC),
        pending=[],
        approved=[],
        rejected=[],
    )
    base.update(overrides)
    return Report(**base)


def test_render_pdf_returns_pdf_bytes() -> None:
    data = render_pdf(_report())
    assert isinstance(data, bytes)
    assert data.startswith(b"%PDF-")


def test_render_pdf_empty_report_is_valid() -> None:
    data = render_pdf(_report())
    # Even an empty window should produce a one-page readable PDF.
    assert data.startswith(b"%PDF-")
    assert len(data) > 500


def test_render_pdf_with_items() -> None:
    report = _report(
        pending=[_item("alpha", "pending", confidence=0.82, evidence_count=7, concept_id="abc1234567xyz")],
        approved=[_item("beta", "approved", title="Beta skill")],
        rejected=[_item("gamma", "rejected")],
    )
    data = render_pdf(report)
    assert data.startswith(b"%PDF-")


def test_render_pdf_escapes_xml_special_chars() -> None:
    report = _report(
        pending=[_item("weird<&>name", "pending", title="x&y <z>")],
    )
    data = render_pdf(report)
    # Shouldn't blow up — reportlab would raise on unescaped angle brackets.
    assert data.startswith(b"%PDF-")


def test_render_pdf_lifetime_snapshot() -> None:
    report = _report(since=None)
    data = render_pdf(report)
    assert data.startswith(b"%PDF-")


def test_pdf_unavailable_is_raised_when_reportlab_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force the import to fail and confirm we surface :class:`PDFUnavailable`."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("reportlab not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(PDFUnavailable) as excinfo:
        render_pdf(_report())
    assert "reportlab" in str(excinfo.value).lower()
