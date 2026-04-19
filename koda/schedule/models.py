"""Schedule model + TOML serialisation.

A ``Schedule`` is an immutable descriptor that K.O.D.A. writes to
``KODA_HOME/schedules/<id>.toml`` and installs into the OS scheduler
(systemd user timer, falling back to crontab).  The ``schema_version``
field lets future readers detect breaking changes and refuse to load a
schedule they don't understand rather than silently misinterpreting it.

TOML is used because it is stdlib-free to *read* with a minimal hand-rolled
parser, and the files are human-editable.  For Python 3.11+ ``tomllib`` is in
the standard library; writes use a minimal formatter (no dependency on
``tomli-w``).
"""
from __future__ import annotations

import re
import tomllib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: Increment when the Schedule schema changes.  v1 = initial release.
SCHEDULE_SCHEMA_VERSION: int = 1

# 5-field cron expression.  Each field is one of:
#   *           — "every"
#   N           — exact value
#   N-M         — range
#   */N         — every-N step
#   a,b,c       — comma-separated list (each element: *, N, N-M, or */N)
_CRON_FIELD = r"(?:\*(?:/\d+)?|\d+(?:-\d+)?(?:/\d+)?(?:,(?:\*(?:/\d+)?|\d+(?:-\d+)?(?:/\d+)?))*)"
_CRON_RE = re.compile(rf"^\s*{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s*$")

# Characters allowed in a schedule ID slug.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

# Allowed alert channel prefixes.
_ALERT_PREFIXES = ("telegram", "email:", "webhook:", "file:")


def _validate_cron(expr: str) -> str | None:
    """Return an error string if *expr* is not a valid 5-field cron expression."""
    if not _CRON_RE.match(expr):
        return (
            f"invalid cron expression {expr!r}: must be 5 space-separated fields "
            "(minute hour dom month dow).  Each field: *, N, N-M, */N, or comma list."
        )
    return None


def _validate_alert_channel(spec: str) -> str | None:
    """Return an error string if *spec* is not a recognised alert channel spec."""
    for prefix in _ALERT_PREFIXES:
        if spec == prefix or spec.startswith(prefix):
            return None
    return (
        f"unknown alert channel {spec!r}: "
        "use telegram | email:<addr> | webhook:<url> | file:<path>"
    )


def _make_id(name: str) -> str:
    """Derive a short slug from *name* for use as a schedule id."""
    safe = re.sub(r"[^a-z0-9]", "-", name.lower())[:20].strip("-")
    suffix = uuid.uuid4().hex[:6]
    return f"{safe}-{suffix}" if safe else f"sched-{suffix}"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Schedule:
    """Immutable descriptor for a scheduled security scan.

    Parameters
    ----------
    id:
        Short URL-safe slug.  Auto-generated from *name* if not supplied.
    name:
        Human-readable label.
    target:
        Scan target — filesystem path, hostname, or ``user@host`` SSH target.
    preset:
        Name of a ``koda.missions`` preset, or ``None`` for explicit scanners.
    scanners:
        Explicit scanner list (used when *preset* is ``None``).
    cron:
        Standard 5-field cron expression.
    alerts:
        Tuple of alert channel specs (``telegram``, ``email:<addr>``, etc.).
        If empty, defaults to ``("file:<KODA_HOME>/schedules/<id>/alerts.jsonl",)``.
    engagement:
        Engagement name to write findings into.  Defaults to ``"schedule-<id>"``.
    created_at:
        ISO8601 UTC creation timestamp.
    last_run:
        ISO8601 UTC timestamp of the most recent tick, or ``None``.
    alert_on:
        One of ``"findings"`` | ``"change"`` | ``"empty"``.  Controls when
        alerts fire.  Default is ``"findings"``.
    schema_version:
        Set to :data:`SCHEDULE_SCHEMA_VERSION` at construction.  Do not pass.
    """

    id: str
    name: str
    target: str
    preset: str | None
    scanners: tuple[str, ...]
    cron: str
    alerts: tuple[str, ...]
    engagement: str
    created_at: str
    last_run: str | None
    alert_on: str
    schema_version: int = field(default=SCHEDULE_SCHEMA_VERSION, compare=False)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        name: str,
        target: str,
        cron: str,
        preset: str | None = None,
        scanners: tuple[str, ...] = (),
        alerts: tuple[str, ...] = (),
        engagement: str = "",
        alert_on: str = "findings",
        id: str = "",  # noqa: A002
    ) -> Schedule:
        """Construct a new Schedule with validation.

        Raises ``ValueError`` on invalid cron or alert channel specs.
        """
        err = _validate_cron(cron)
        if err:
            raise ValueError(err)

        if alert_on not in ("findings", "change", "empty"):
            raise ValueError(
                f"alert_on must be 'findings' | 'change' | 'empty', got {alert_on!r}"
            )

        for spec in alerts:
            err2 = _validate_alert_channel(spec)
            if err2:
                raise ValueError(err2)

        schedule_id = id or _make_id(name)
        eng = engagement or f"schedule-{schedule_id}"
        return cls(
            id=schedule_id,
            name=name,
            target=target,
            preset=preset,
            scanners=tuple(scanners),
            cron=cron,
            alerts=tuple(alerts),
            engagement=eng,
            created_at=_now_iso(),
            last_run=None,
            alert_on=alert_on,
            schema_version=SCHEDULE_SCHEMA_VERSION,
        )

    # ------------------------------------------------------------------
    # TOML serialisation
    # ------------------------------------------------------------------

    def to_toml(self) -> str:
        """Serialise schedule to a TOML string."""
        lines = [
            "[schedule]",
            f'id = "{self.id}"',
            f'name = "{self.name}"',
            f'target = "{self.target}"',
            f'cron = "{self.cron}"',
            f'engagement = "{self.engagement}"',
            f'created_at = "{self.created_at}"',
            f'last_run = "{self.last_run}"' if self.last_run else 'last_run = ""',
            f'alert_on = "{self.alert_on}"',
            f"schema_version = {self.schema_version}",
        ]
        if self.preset is not None:
            lines.append(f'preset = "{self.preset}"')
        else:
            lines.append('preset = ""')
        # Scanners as TOML array
        scanner_items = ", ".join(f'"{s}"' for s in self.scanners)
        lines.append(f"scanners = [{scanner_items}]")
        # Alerts as TOML array
        alert_items = ", ".join(f'"{a}"' for a in self.alerts)
        lines.append(f"alerts = [{alert_items}]")
        return "\n".join(lines) + "\n"

    @classmethod
    def from_toml(cls, text: str) -> Schedule:
        """Deserialise a schedule from TOML text."""
        data: dict[str, Any] = tomllib.loads(text)
        s = data.get("schedule") or data  # tolerate both [schedule] wrapper and flat
        ver = int(s.get("schema_version", 1))
        if ver > SCHEDULE_SCHEMA_VERSION:
            raise ValueError(
                f"schedule schema version {ver} is newer than this K.O.D.A. "
                f"installation (max {SCHEDULE_SCHEMA_VERSION}). Upgrade K.O.D.A."
            )
        preset_raw = s.get("preset") or None
        if preset_raw == "":
            preset_raw = None
        last_run_raw = s.get("last_run") or None
        if last_run_raw == "":
            last_run_raw = None
        return cls(
            id=s["id"],
            name=s["name"],
            target=s["target"],
            preset=preset_raw,
            scanners=tuple(s.get("scanners") or []),
            cron=s["cron"],
            alerts=tuple(s.get("alerts") or []),
            engagement=s.get("engagement") or f"schedule-{s['id']}",
            created_at=s.get("created_at") or _now_iso(),
            last_run=last_run_raw,
            alert_on=s.get("alert_on") or "findings",
            schema_version=ver,
        )

    def save(self, schedules_dir: Path) -> Path:
        """Write schedule to ``<schedules_dir>/<id>.toml``.  Returns the path."""
        schedules_dir.mkdir(parents=True, exist_ok=True)
        path = schedules_dir / f"{self.id}.toml"
        path.write_text(self.to_toml(), encoding="utf-8")
        try:
            import os
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def with_last_run(self, ts: str) -> Schedule:
        """Return a new Schedule with *last_run* updated."""
        return Schedule(
            id=self.id,
            name=self.name,
            target=self.target,
            preset=self.preset,
            scanners=self.scanners,
            cron=self.cron,
            alerts=self.alerts,
            engagement=self.engagement,
            created_at=self.created_at,
            last_run=ts,
            alert_on=self.alert_on,
            schema_version=self.schema_version,
        )


def load_schedule(path: Path) -> Schedule:
    """Load a Schedule from a TOML file."""
    return Schedule.from_toml(path.read_text(encoding="utf-8"))


def list_schedules(schedules_dir: Path) -> list[Schedule]:
    """Return all schedules in *schedules_dir*, sorted by creation time."""
    if not schedules_dir.is_dir():
        return []
    schedules: list[Schedule] = []
    for p in sorted(schedules_dir.glob("*.toml")):
        try:
            schedules.append(load_schedule(p))
        except Exception:
            pass
    return schedules


__all__ = [
    "SCHEDULE_SCHEMA_VERSION",
    "Schedule",
    "load_schedule",
    "list_schedules",
    "_validate_cron",
    "_validate_alert_channel",
]
