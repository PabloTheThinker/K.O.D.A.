"""Append-only JSONL audit logger.

Design notes:

  - One line per event, written atomically via a single ``write`` call
    so partial lines can't interleave with concurrent writers in the
    same process. External tail-followers see complete records every
    flush.
  - ``fsync`` is opt-in per event. Security-relevant events (approvals,
    refusals, scope violations, auth failures) request it; routine
    turn traces don't, to keep the hot path cheap.
  - Rotation is size-based with ``maxBytes``. When the active file
    crosses the threshold it's renamed to ``audit.jsonl.<unix_ts>``
    and a fresh file is opened. Rotated files are never touched
    again — preserves the tail for forensic integrity.
  - Argument payloads are hashed rather than logged verbatim by
    default. The hash proves *which* invocation was approved/refused
    without leaking client secrets into the audit trail. Callers can
    opt into full argument capture via ``include_arguments=True`` when
    they've verified the data is safe.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

# Events flagged as "fsync worthy" — a crash right after one of these
# must not lose the record. Approvals and refusals are load-bearing
# for chain-of-custody; routine turn metadata is not.
_CRITICAL_EVENTS: frozenset[str] = frozenset({
    "approval.blocked",
    "approval.escalated",
    "approval.refused",
    "approval.denied",
    "scope.violation",
    "auth.failure",
    "auth.cooldown",
    "tool.error",
    "session.open",
    "session.close",
    "engagement.boundary",
})


@dataclass
class AuditEvent:
    """One structured audit record.

    ``event`` is a dotted string like ``turn.complete``, ``tool.call``,
    ``approval.allowed``. ``fields`` is a free-form dict of
    event-specific context; stable top-level keys live on the dataclass
    so common queries (``jq 'select(.engagement=="acme")'``) just work.
    """
    event: str
    session_id: str = ""
    engagement: str = ""
    profile: str = ""
    ts: float = 0.0
    ts_iso: str = ""
    fields: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        data = asdict(self)
        # Hoist fields to top level so jq queries stay short.
        fields = data.pop("fields") or {}
        for k, v in fields.items():
            # Don't let free-form fields clobber stable keys.
            if k in data:
                continue
            data[k] = v
        return data


def default_log_path() -> Path:
    """Resolve the audit log path for the active KODA_HOME.

    Respects ``KODA_HOME`` so profile overrides (set in cli/__init__.py
    before any koda imports) land the log in the right profile dir.
    """
    root = Path(os.environ.get("KODA_HOME", str(Path.home() / ".koda")))
    return root / "logs" / "audit.jsonl"


def hash_arguments(arguments: Mapping[str, Any] | None) -> str:
    """Stable SHA-1 hash of canonicalized arguments. Safe to log."""
    if not arguments:
        return "da39a3ee"  # sha1("") prefix — consistent "no args" marker
    try:
        canonical = json.dumps(arguments, sort_keys=True, default=str)
    except (TypeError, ValueError):
        canonical = repr(arguments)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]


class NullAuditLogger:
    """No-op logger. Used when auditing is intentionally disabled
    (e.g. unit tests, MCP-server mode without a profile)."""

    def log(self, event: AuditEvent) -> None:  # noqa: D401 - trivial
        return None

    def emit(self, event_name: str, **fields: Any) -> None:
        return None

    def close(self) -> None:
        return None


class AuditLogger:
    """Append-only JSONL logger with size-based rotation."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        profile: str = "",
        max_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        self.path = Path(path) if path else default_log_path()
        self.profile = profile
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Open lazily so constructor never raises.
        self._fh: Any | None = None

    def _ensure_open(self) -> None:
        if self._fh is not None:
            return
        self._fh = open(self.path, "a", encoding="utf-8", buffering=1)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _maybe_rotate(self) -> None:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return
        if size < self.max_bytes:
            return
        self._close()
        ts = int(time.time())
        rotated = self.path.with_suffix(self.path.suffix + f".{ts}")
        try:
            self.path.rename(rotated)
        except OSError:
            # Race with concurrent writer in a multi-process setup:
            # bail silently. Next event will try again.
            return

    def _close(self) -> None:
        if self._fh is None:
            return
        try:
            self._fh.flush()
            self._fh.close()
        except OSError:
            pass
        self._fh = None

    def close(self) -> None:
        with self._lock:
            self._close()

    def log(self, event: AuditEvent) -> None:
        if not event.ts:
            event.ts = time.time()
        if not event.ts_iso:
            event.ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(event.ts)) + "Z"
        if not event.profile:
            event.profile = self.profile

        line = json.dumps(event.to_row(), sort_keys=False, default=str) + "\n"
        critical = event.event in _CRITICAL_EVENTS

        with self._lock:
            self._maybe_rotate()
            self._ensure_open()
            try:
                self._fh.write(line)  # type: ignore[union-attr]
                if critical:
                    self._fh.flush()  # type: ignore[union-attr]
                    os.fsync(self._fh.fileno())  # type: ignore[union-attr]
            except OSError:
                # Never let an audit-log failure bring down the agent.
                # A missing audit line is a bug to investigate, not a
                # reason to kill the active engagement.
                self._close()

    def emit(self, event_name: str, **fields: Any) -> None:
        """Shorthand. Call sites extract stable fields, leave the rest in kwargs."""
        session_id = fields.pop("session_id", "") or ""
        engagement = fields.pop("engagement", "") or ""
        self.log(
            AuditEvent(
                event=event_name,
                session_id=session_id,
                engagement=engagement,
                fields=fields,
            )
        )

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


__all__ = [
    "AuditEvent",
    "AuditLogger",
    "NullAuditLogger",
    "default_log_path",
    "hash_arguments",
]
