"""Learning-layer tools exposed via MCP.

Lets an MCP-aware model (Claude Code, Cursor, any tool-using agent running
KODA) drive the learning pipeline natively — generate a digest, check the
pending queue, schedule a daily report. The scheduler touches crontab, so it
carries SENSITIVE risk; everything read-only is SAFE.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from koda.learning import default_store
from koda.learning.report import generate_report
from koda.learning.report_delivery import (
    DeliveryError,
    create_delivery,
    default_delivery_name,
    default_format_name,
)
from koda.learning.schedule import (
    get_report_schedule,
    install_report_schedule,
    remove_report_schedule,
)

from ..registry import RiskLevel, Tool, ToolResult, register

_DELIVERY_CHOICES = ["file", "stdout", "telegram", "webhook"]
_FORMAT_CHOICES = ["md", "pdf"]


def _parse_since(raw: str | None) -> datetime | None:
    if raw is None or raw == "":
        return datetime.now(UTC) - timedelta(hours=24)
    raw = raw.strip().lower()
    if raw in {"all", "none", "lifetime", "0"}:
        return None
    units = {"m": 60, "h": 3600, "d": 86400}
    if raw[-1:] in units and raw[:-1].isdigit():
        seconds = int(raw[:-1]) * units[raw[-1]]
        return datetime.now(UTC) - timedelta(seconds=seconds)
    try:
        ts = datetime.fromisoformat(raw.replace("z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts
    except ValueError:
        return datetime.now(UTC) - timedelta(hours=24)


def _parse_time_to_cron(text: str) -> str | None:
    """Delegate to the CLI parser so tool + CLI share one time grammar."""
    from koda.cli.learn import _parse_time_to_cron as _parser
    return _parser(text)


def _learn_report(
    since: str = "24h",
    format: str = "md",
    deliver: str | None = None,
) -> ToolResult:
    fmt = (format or default_format_name()).lower()
    if fmt not in _FORMAT_CHOICES:
        return ToolResult(
            content=f"unknown format {fmt!r}; expected one of {_FORMAT_CHOICES}",
            is_error=True,
        )
    deliver_name = (deliver or default_delivery_name()).lower()
    if deliver_name not in _DELIVERY_CHOICES:
        return ToolResult(
            content=f"unknown delivery {deliver_name!r}; expected one of {_DELIVERY_CHOICES}",
            is_error=True,
        )

    start = _parse_since(since)
    report = generate_report(since=start)

    if fmt == "md":
        payload = report.render_markdown().encode("utf-8")
        filename = f"LEARNED-{report.generated_at.strftime('%Y-%m-%d')}.md"
    else:
        try:
            from koda.learning.report_pdf import PDFUnavailable, render_pdf
        except ImportError as exc:
            return ToolResult(content=f"pdf unavailable: {exc}", is_error=True)
        try:
            payload = render_pdf(report)
        except PDFUnavailable as exc:
            return ToolResult(content=str(exc), is_error=True)
        filename = f"LEARNED-{report.generated_at.strftime('%Y-%m-%d')}.pdf"

    try:
        result = create_delivery(deliver_name).send(
            report=report, payload=payload, filename=filename, fmt=fmt,
        )
    except DeliveryError as exc:
        return ToolResult(content=str(exc), is_error=True)

    window = "lifetime" if start is None else f"since {start.isoformat()}"
    summary = (
        f"digest delivered via {result.backend} ({window}, {fmt}): "
        f"pending={len(report.pending)} approved={len(report.approved)} "
        f"rejected={len(report.rejected)} -> {result.detail}"
    )
    return ToolResult(
        content=summary,
        metadata={
            "backend": result.backend,
            "detail": result.detail,
            "format": fmt,
            "pending": len(report.pending),
            "approved": len(report.approved),
            "rejected": len(report.rejected),
        },
    )


def _learn_status() -> ToolResult:
    store = default_store()
    pending = store.list_pending()
    approved = store.list_approved()
    schedule = get_report_schedule()
    lines = [
        f"pending  : {len(pending)}",
        f"approved : {len(approved)}",
    ]
    if schedule is None:
        lines.append("schedule : (none)")
    else:
        lines.append(f"schedule : {schedule.cron_expr}  {schedule.command}")
    return ToolResult(
        content="\n".join(lines),
        metadata={
            "pending": len(pending),
            "approved": len(approved),
            "scheduled": schedule is not None,
        },
    )


def _learn_list() -> ToolResult:
    store = default_store()
    pending = store.list_pending()
    approved = store.list_approved()

    lines: list[str] = [f"pending ({len(pending)}):"]
    for p in pending:
        source = p.source or {}
        cid = str(source.get("concept_id", "?"))[:10]
        ev = source.get("evidence_count", "?")
        conf = source.get("confidence")
        conf_s = f"{conf:.2f}" if isinstance(conf, (int, float)) else "?"
        lines.append(f"  - {p.name}  (concept {cid} conf={conf_s} ep={ev})")
    if not pending:
        lines.append("  (none — run the learn pipeline to draft more)")

    lines.append(f"approved ({len(approved)}):")
    for path in approved:
        lines.append(f"  - {path.name}")
    if not approved:
        lines.append("  (none yet)")
    return ToolResult(content="\n".join(lines))


def _learn_schedule_digest(
    time: str,
    since: str = "24h",
    format: str = "md",
    deliver: str | None = None,
) -> ToolResult:
    action = time.strip().lower()
    if action in {"off", "remove", "none"}:
        removed = remove_report_schedule()
        msg = "removed daily digest schedule" if removed else "nothing to remove"
        return ToolResult(content=msg, metadata={"removed": removed})
    if action == "status":
        entry = get_report_schedule()
        if entry is None:
            return ToolResult(
                content="no digest schedule installed",
                metadata={"scheduled": False},
            )
        return ToolResult(
            content=f"{entry.cron_expr}  {entry.command}",
            metadata={"scheduled": True, "cron": entry.cron_expr},
        )

    cron_expr = _parse_time_to_cron(time)
    if cron_expr is None:
        return ToolResult(
            content=(
                f"could not parse {time!r} as a time. "
                "Try 8am, 2:30pm, 14:00, or a 5-field cron expression, "
                "or one of: off|remove|status."
            ),
            is_error=True,
        )

    fmt = (format or "md").lower()
    if fmt not in _FORMAT_CHOICES:
        return ToolResult(
            content=f"unknown format {fmt!r}; expected one of {_FORMAT_CHOICES}",
            is_error=True,
        )
    deliver_name = deliver.lower() if deliver else None
    if deliver_name is not None and deliver_name not in _DELIVERY_CHOICES:
        return ToolResult(
            content=f"unknown delivery {deliver_name!r}; expected one of {_DELIVERY_CHOICES}",
            is_error=True,
        )

    try:
        entry = install_report_schedule(
            cron_expr=cron_expr, since=since, fmt=fmt, deliver=deliver_name,
        )
    except Exception as exc:
        return ToolResult(
            content=f"could not install cron entry: {exc}", is_error=True,
        )
    return ToolResult(
        content=f"scheduled {entry.cron_expr}  {entry.command}",
        metadata={"cron": entry.cron_expr, "command": entry.command},
    )


register(Tool(
    name="learn.report",
    description=(
        "Generate a KODA learning digest of pending/approved/rejected skill "
        "drafts. Renders markdown (default) or PDF and delivers it via the "
        "configured backend — file (default), stdout, telegram, or webhook. "
        "PDF requires the `koda-security[pdf]` extra. Telegram/webhook read "
        "credentials from the environment (KODA_TELEGRAM_BOT_TOKEN / "
        "KODA_TELEGRAM_CHAT_ID / KODA_REPORT_WEBHOOK_URL)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "since": {
                "type": "string",
                "default": "24h",
                "description": "Lookback window: 30m, 24h, 7d, or 'all' for lifetime.",
            },
            "format": {
                "type": "string",
                "enum": _FORMAT_CHOICES,
                "default": "md",
                "description": "Output format — md or pdf.",
            },
            "deliver": {
                "type": "string",
                "enum": _DELIVERY_CHOICES,
                "description": (
                    "Delivery backend. Defaults to KODA_REPORT_DELIVER or 'file'."
                ),
            },
        },
    },
    handler=_learn_report,
    risk=RiskLevel.SAFE,
    category="learn",
))


register(Tool(
    name="learn.status",
    description=(
        "Show the KODA learning pipeline state: pending drafts, approved "
        "skills, and whether a daily digest schedule is installed."
    ),
    input_schema={"type": "object", "properties": {}},
    handler=_learn_status,
    risk=RiskLevel.SAFE,
    category="learn",
))


register(Tool(
    name="learn.list",
    description=(
        "List pending and approved learning skills with confidence and "
        "evidence metadata. Useful before calling approve/reject via the CLI."
    ),
    input_schema={"type": "object", "properties": {}},
    handler=_learn_list,
    risk=RiskLevel.SAFE,
    category="learn",
))


register(Tool(
    name="learn.schedule_digest",
    description=(
        "Install, remove, or inspect the daily learning-digest cron entry. "
        "Pass a natural time (8am, 2:30pm, 14:00) or a raw 5-field cron "
        "expression; 'off' or 'remove' clears the entry; 'status' shows the "
        "current state. `format` and `deliver` are baked into the cron line "
        "so the scheduled run uses the same settings. Touches the user's "
        "crontab — SENSITIVE."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "time": {
                "type": "string",
                "description": (
                    "Time to run daily (8am, 2:30pm, 14:00, or a cron expression), "
                    "or one of: off | remove | status."
                ),
            },
            "since": {
                "type": "string",
                "default": "24h",
                "description": "Lookback window baked into the cron line.",
            },
            "format": {
                "type": "string",
                "enum": _FORMAT_CHOICES,
                "default": "md",
                "description": "Output format for the scheduled report.",
            },
            "deliver": {
                "type": "string",
                "enum": _DELIVERY_CHOICES,
                "description": "Delivery backend for the scheduled report.",
            },
        },
        "required": ["time"],
    },
    handler=_learn_schedule_digest,
    risk=RiskLevel.SENSITIVE,
    category="learn",
))
