"""PDF rendering for learning digests.

Uses ``reportlab`` (optional extra — ``pip install koda-security[pdf]``).
If reportlab isn't installed we raise :class:`PDFUnavailable` so the CLI
can print a clean install hint instead of crashing with ImportError.

Rendered directly from the structured :class:`~koda.learning.report.Report`
dataclass, not from the Markdown blob — keeps layout control and avoids a
markdown-parser dependency.
"""
from __future__ import annotations

from io import BytesIO

from koda.learning.report import Report, ReportItem


class PDFUnavailable(RuntimeError):
    """reportlab isn't installed — raise with an actionable message."""


def render_pdf(report: Report) -> bytes:
    """Render ``report`` to a PDF byte-string, letter-sized."""
    try:
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
        )
    except ImportError as exc:
        raise PDFUnavailable(
            "reportlab is not installed — run `pip install koda-security[pdf]`"
        ) from exc

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="KODA learning digest",
        author="K.O.D.A.",
    )

    base = getSampleStyleSheet()
    h1 = ParagraphStyle(
        "KodaH1", parent=base["Heading1"], alignment=TA_LEFT,
        textColor="#111111", spaceAfter=6,
    )
    h2 = ParagraphStyle(
        "KodaH2", parent=base["Heading2"], alignment=TA_LEFT,
        textColor="#2a2a2a", spaceBefore=14, spaceAfter=4,
    )
    body = ParagraphStyle(
        "KodaBody", parent=base["BodyText"], leading=14, spaceAfter=4,
    )
    muted = ParagraphStyle(
        "KodaMuted", parent=body, textColor="#666666", fontSize=9,
        spaceAfter=10,
    )
    meta = ParagraphStyle(
        "KodaMeta", parent=base["BodyText"], leftIndent=18, leading=12,
        fontSize=9, textColor="#555555", spaceAfter=6,
    )

    flow: list = []
    stamp = report.generated_at.strftime("%Y-%m-%d")
    flow.append(Paragraph(f"KODA learning digest — {stamp}", h1))
    window = (
        f"Since {report.since.isoformat()}" if report.since is not None
        else "Lifetime snapshot"
    )
    flow.append(Paragraph(window, muted))
    flow.append(Paragraph(
        f"<b>Drafted (pending):</b> {len(report.pending)} &nbsp;·&nbsp; "
        f"<b>Approved:</b> {len(report.approved)} &nbsp;·&nbsp; "
        f"<b>Rejected:</b> {len(report.rejected)}",
        body,
    ))
    flow.append(Spacer(1, 8))

    if report.is_empty():
        flow.append(Paragraph(
            "<i>No new learning activity in this window.</i>", body,
        ))
        doc.build(flow)
        return buf.getvalue()

    if report.pending:
        flow.append(Paragraph("Pending review", h2))
        for item in report.pending:
            _append_item(flow, item, body, meta, include_cmd_hint=True)

    if report.approved:
        flow.append(Paragraph("Approved", h2))
        for item in report.approved:
            _append_item(flow, item, body, meta, include_cmd_hint=False)

    if report.rejected:
        flow.append(Paragraph("Rejected", h2))
        for item in report.rejected:
            _append_item(flow, item, body, meta, include_cmd_hint=False)

    # Prevent orphaned headers if the content ran long — a tasteful page
    # break only when we're flirting with the end of the page.
    if len(flow) > 60:
        flow.insert(60, PageBreak())

    doc.build(flow)
    return buf.getvalue()


def _append_item(
    flow: list, item: ReportItem, body, meta, *, include_cmd_hint: bool,
) -> None:
    from reportlab.platypus import Paragraph

    flow.append(Paragraph(f"<b>{_escape(item.name)}</b>", body))
    bits: list[str] = []
    if item.title and item.title != item.name:
        bits.append(_escape(item.title))
    if item.concept_id:
        bits.append(f"concept <font face='Courier'>{_escape(item.concept_id[:10])}</font>")
    if item.confidence is not None:
        bits.append(f"conf {item.confidence:.2f}")
    if item.evidence_count is not None:
        bits.append(f"ep {item.evidence_count}")
    if item.trigger:
        bits.append(f"trigger {_escape(item.trigger)}")
    if item.synthesizer:
        bits.append(f"via {_escape(item.synthesizer)}")
    if bits:
        flow.append(Paragraph(" · ".join(bits), meta))
    if include_cmd_hint:
        flow.append(Paragraph(
            f"<font face='Courier'>koda learn approve {_escape(item.name)}</font> "
            f"/ <font face='Courier'>koda learn reject {_escape(item.name)}</font>",
            meta,
        ))


def _escape(text: str) -> str:
    """Minimal XML escape for reportlab's inline markup."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
