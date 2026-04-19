"""Alert channel dispatch for scheduled scan diffs.

Each alert channel is a callable ``(diff, schedule, run_dir) -> None``.
Built-in channels:

  file:<path>      — append JSONL line; always works; default if nothing else
  telegram         — lazy import of the Telegram bridge; skip if not configured
  email:<address>  — lazy smtplib; requires KODA_HOME/smtp.toml
  webhook:<url>    — POST JSON; 5s timeout; one retry; audit regardless

Credentials in finding descriptions are redacted before sending.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..schedule.differ import DiffResult
    from ..schedule.models import Schedule


# ---------------------------------------------------------------------------
# Credential redaction helper
# ---------------------------------------------------------------------------

def _redact(text: str) -> str:
    """Redact potential credentials from *text* using simple heuristics.

    The broker's redactor is the gold standard, but we cannot guarantee it is
    initialised inside a cron tick.  This function is a best-effort fallback
    that strips API-key-shaped tokens.
    """
    import re
    # Remove common key-shaped substrings: 20+ chars of alphanum/+/ /= preceded
    # by an assignment-like pattern.
    text = re.sub(
        r"(?i)(token|key|secret|password|api[_\-]?key|bearer)\s*[:=]\s*\S+",
        r"\1=<REDACTED>",
        text,
    )
    # Try to use the real broker redactor if available.
    try:
        # Use the module-level redact function if exported.
        from ..auth import broker as broker_mod
        from ..auth.broker import CredentialBroker  # noqa: F401 — checked via broker_mod
        if hasattr(broker_mod, "redact"):
            text = broker_mod.redact(text)  # type: ignore[attr-defined]
    except Exception:
        pass
    return text


# ---------------------------------------------------------------------------
# Finding summary helpers
# ---------------------------------------------------------------------------

def _finding_line(f: Any) -> str:
    sev = getattr(f.severity, "value", str(f.severity)).upper()
    title = _redact(f.title or f.rule_id or f.id)
    loc = f.file_path or ""
    if loc:
        return f"[{sev}] {title} — {loc}"
    return f"[{sev}] {title}"


def _build_alert_text(diff: DiffResult, schedule: Schedule) -> str:
    """Build a human-readable alert message (Telegram / email body)."""
    lines = [
        f"K.O.D.A. schedule alert: {schedule.name}",
        f"Target: {schedule.target}",
        f"Summary: {diff.summary()}",
        "",
    ]
    if diff.new:
        lines.append(f"NEW findings ({len(diff.new)}):")
        for f in diff.new[:10]:
            lines.append(f"  • {_finding_line(f)}")
        if len(diff.new) > 10:
            lines.append(f"  … and {len(diff.new) - 10} more")
    if diff.resolved:
        lines.append(f"RESOLVED findings ({len(diff.resolved)}):")
        for f in diff.resolved[:5]:
            lines.append(f"  ✓ {_finding_line(f)}")
        if len(diff.resolved) > 5:
            lines.append(f"  … and {len(diff.resolved) - 5} more")
    return "\n".join(lines)


def _build_alert_payload(
    diff: DiffResult,
    schedule: Schedule,
    ran_at: str,
) -> dict[str, Any]:
    """Build the JSON payload for file and webhook alerts."""
    def finding_to_dict(f: Any) -> dict[str, Any]:
        return {
            "fingerprint": f.fingerprint(),
            "id": f.id,
            "title": _redact(f.title or f.rule_id or ""),
            "severity": getattr(f.severity, "value", str(f.severity)),
            "file_path": f.file_path,
            "scanner": f.scanner,
        }

    return {
        "schedule_id": schedule.id,
        "schedule_name": schedule.name,
        "ran_at": ran_at,
        "target": schedule.target,
        "diff": {
            "new": [finding_to_dict(f) for f in diff.new],
            "resolved": [finding_to_dict(f) for f in diff.resolved],
            "persistent_count": len(diff.persistent),
        },
    }


# ---------------------------------------------------------------------------
# Channel: file
# ---------------------------------------------------------------------------

def _dispatch_file(
    spec: str,
    diff: DiffResult,
    schedule: Schedule,
    ran_at: str,
    run_dir: Path | None = None,
) -> None:
    """Append one JSONL line to a file."""
    path_str = spec[len("file:"):] if spec.startswith("file:") else spec
    path = Path(path_str).expanduser()
    payload = _build_alert_payload(diff, schedule, ran_at)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
    except OSError as exc:
        import sys
        print(f"[koda-schedule] file alert write failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Channel: telegram
# ---------------------------------------------------------------------------

def _dispatch_telegram(
    diff: DiffResult,
    schedule: Schedule,
    ran_at: str,
    run_dir: Path | None = None,
) -> None:
    """Send a message via the Telegram bridge, if configured."""
    text = _build_alert_text(diff, schedule)
    try:
        from ..notify.telegram_daemon import send_message as _send
        _send(text)
    except Exception:
        # Telegram not configured or not running — skip silently.
        pass


# ---------------------------------------------------------------------------
# Channel: email
# ---------------------------------------------------------------------------

def _dispatch_email(
    spec: str,
    diff: DiffResult,
    schedule: Schedule,
    ran_at: str,
    run_dir: Path | None = None,
) -> None:
    """Send alert via SMTP.  Requires KODA_HOME/smtp.toml."""
    address = spec[len("email:"):]
    import smtplib
    import sys
    import tomllib

    koda_home = Path(os.environ.get("KODA_HOME", Path.home() / ".koda"))
    smtp_cfg_path = koda_home / "smtp.toml"
    if not smtp_cfg_path.exists():
        print(
            "[koda-schedule] email alert skipped: no smtp.toml found at "
            f"{smtp_cfg_path}",
            file=sys.stderr,
        )
        return

    try:
        with open(smtp_cfg_path, "rb") as fh:
            smtp_cfg = tomllib.load(fh)
    except Exception as exc:
        print(f"[koda-schedule] email alert: failed to read smtp.toml: {exc}", file=sys.stderr)
        return

    host = smtp_cfg.get("host", "localhost")
    port = int(smtp_cfg.get("port", 587))
    user = smtp_cfg.get("user", "")
    password = smtp_cfg.get("pass", "")
    from_addr = smtp_cfg.get("from_addr", user)

    subject = f"[K.O.D.A.] {schedule.name}: {diff.summary()}"
    body = _build_alert_text(diff, schedule)
    message = (
        f"From: {from_addr}\r\n"
        f"To: {address}\r\n"
        f"Subject: {subject}\r\n"
        f"\r\n"
        f"{body}\r\n"
    )
    try:
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            if port == 587:
                server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr, [address], message.encode("utf-8"))
    except Exception as exc:
        print(f"[koda-schedule] email alert failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Channel: webhook
# ---------------------------------------------------------------------------

def _dispatch_webhook(
    spec: str,
    diff: DiffResult,
    schedule: Schedule,
    ran_at: str,
    run_dir: Path | None = None,
    *,
    _audit: Any = None,
) -> None:
    """POST JSON to a webhook URL.  Retries once.  Audits both attempts."""
    import sys
    import urllib.error
    import urllib.request

    url = spec[len("webhook:"):]
    payload = json.dumps(_build_alert_payload(diff, schedule, ran_at)).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "koda-schedule/1"}
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    def _attempt(attempt: int) -> bool:
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
                status = resp.status
        except (urllib.error.URLError, OSError) as exc:
            print(
                f"[koda-schedule] webhook attempt {attempt} failed: {exc}",
                file=sys.stderr,
            )
            if _audit:
                try:
                    _audit.emit(
                        "schedule.tick.alert",
                        schedule_id=schedule.id,
                        channel="webhook",
                        url=url,
                        attempt=attempt,
                        success=False,
                        error=str(exc),
                    )
                except Exception:
                    pass
            return False
        else:
            if _audit:
                try:
                    _audit.emit(
                        "schedule.tick.alert",
                        schedule_id=schedule.id,
                        channel="webhook",
                        url=url,
                        attempt=attempt,
                        success=True,
                        http_status=status,
                    )
                except Exception:
                    pass
            return True

    if not _attempt(1):
        _attempt(2)


# ---------------------------------------------------------------------------
# Main dispatch entry point
# ---------------------------------------------------------------------------

def dispatch_alerts(
    diff: DiffResult,
    schedule: Schedule,
    run_dir: Path | None = None,
    *,
    audit: Any = None,
) -> None:
    """Fire all configured alert channels for *schedule*.

    Falls back to a file alert in ``KODA_HOME/schedules/<id>/alerts.jsonl``
    if no channel is specified.
    """
    ran_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    channels = list(schedule.alerts)

    if not channels:
        # Default: write to file alongside the schedule's run dir.
        koda_home = Path(os.environ.get("KODA_HOME", Path.home() / ".koda"))
        default_path = koda_home / "schedules" / schedule.id / "alerts.jsonl"
        channels = [f"file:{default_path}"]

    for spec in channels:
        try:
            if spec.startswith("file:") or spec == "file":
                # Use run-specific default if bare "file" spec somehow appears.
                if spec == "file":
                    koda_home = Path(os.environ.get("KODA_HOME", Path.home() / ".koda"))
                    spec = f"file:{koda_home / 'schedules' / schedule.id / 'alerts.jsonl'}"
                _dispatch_file(spec, diff, schedule, ran_at, run_dir)
            elif spec == "telegram":
                _dispatch_telegram(diff, schedule, ran_at, run_dir)
            elif spec.startswith("email:"):
                _dispatch_email(spec, diff, schedule, ran_at, run_dir)
            elif spec.startswith("webhook:"):
                _dispatch_webhook(spec, diff, schedule, ran_at, run_dir, _audit=audit)
            else:
                import sys
                print(f"[koda-schedule] unknown alert channel: {spec!r}", file=sys.stderr)
        except Exception as exc:
            import sys
            print(f"[koda-schedule] alert channel {spec!r} raised: {exc}", file=sys.stderr)


__all__ = [
    "dispatch_alerts",
    "DiffResult",
    "_build_alert_text",
    "_build_alert_payload",
    "_redact",
]
