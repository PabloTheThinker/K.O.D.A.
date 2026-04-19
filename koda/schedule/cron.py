"""OS scheduler integration (systemd user timer or crontab).

K.O.D.A. never runs a background daemon.  This module installs entries into
the OS scheduler so that ``koda schedule _tick <id>`` fires at the
configured cron expression.

Auto-detection order:
  1. If ``systemctl --user`` is available *and* the user session has a
     running systemd instance, use systemd user timers.
  2. Fall back to the user crontab (``crontab -l`` / ``crontab -``).

The choice is cached to ``KODA_HOME/schedule-backend.toml`` after first use
so subsequent calls are consistent.

Each entry is tagged with ``# koda-schedule:<id>`` for safe removal.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Marker format embedded in crontab lines.
_CRON_MARKER = "# koda-schedule:{id}"
_CRON_MARKER_RE = re.compile(r"#\s*koda-schedule:(\S+)")


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def _koda_home() -> Path:
    return Path(os.environ.get("KODA_HOME", Path.home() / ".koda"))


def _backend_cache_path() -> Path:
    return _koda_home() / "schedule-backend.toml"


def _detect_systemd() -> bool:
    """Return True if systemd --user is functional on this system."""
    if not shutil.which("systemctl"):
        return False
    try:
        r = subprocess.run(
            ["systemctl", "--user", "is-system-running"],
            capture_output=True, text=True, timeout=5,
        )
        # "running" or "degraded" both mean a live user session.
        return r.stdout.strip() in ("running", "degraded")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def get_backend(*, force: str | None = None) -> str:
    """Return ``"systemd"`` or ``"crontab"``.

    If *force* is given it overrides detection and updates the cache.
    """
    if force is not None:
        if force not in ("systemd", "crontab"):
            raise ValueError(f"backend must be 'systemd' or 'crontab', got {force!r}")
        _write_backend_cache(force)
        return force

    cache = _read_backend_cache()
    if cache:
        return cache

    backend = "systemd" if _detect_systemd() else "crontab"
    _write_backend_cache(backend)
    return backend


def _read_backend_cache() -> str | None:
    path = _backend_cache_path()
    if not path.exists():
        return None
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            m = re.match(r'^\s*backend\s*=\s*"([^"]+)"', line)
            if m:
                val = m.group(1)
                if val in ("systemd", "crontab"):
                    return val
    except OSError:
        pass
    return None


def _write_backend_cache(backend: str) -> None:
    path = _backend_cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'backend = "{backend}"\n', encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Crontab helpers
# ---------------------------------------------------------------------------

def _read_crontab() -> str:
    """Return current user crontab content, or empty string."""
    result = subprocess.run(
        ["crontab", "-l"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return result.stdout
    # crontab -l exits 1 with "no crontab for user" — treat as empty.
    return ""


def _write_crontab(content: str) -> None:
    """Write *content* to the user's crontab."""
    proc = subprocess.run(
        ["crontab", "-"],
        input=content,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise OSError(f"crontab write failed: {proc.stderr.strip()}")


def _cron_line(schedule_id: str, cron_expr: str) -> str:
    """Build the crontab line for a schedule."""
    marker = _CRON_MARKER.format(id=schedule_id)
    koda_bin = shutil.which("koda") or "koda"
    return f"{cron_expr} {koda_bin} schedule _tick {schedule_id}  {marker}"


def install_cron_entry(schedule_id: str, cron_expr: str) -> None:
    """Append a cron line for *schedule_id* to the user's crontab.

    Does nothing if a line with the same marker already exists (idempotent).
    """
    existing = _read_crontab()
    # Idempotency check.
    if f"koda-schedule:{schedule_id}" in existing:
        return
    line = _cron_line(schedule_id, cron_expr)
    new_content = existing.rstrip("\n") + "\n" + line + "\n"
    _write_crontab(new_content)


def remove_cron_entry(schedule_id: str) -> bool:
    """Remove the cron line for *schedule_id*.  Returns True if a line was removed."""
    existing = _read_crontab()
    marker = f"koda-schedule:{schedule_id}"
    lines = existing.splitlines(keepends=True)
    filtered = [ln for ln in lines if marker not in ln]
    if len(filtered) == len(lines):
        return False  # nothing to remove
    _write_crontab("".join(filtered))
    return True


@dataclass
class CronRef:
    """A koda schedule entry found in the crontab."""
    schedule_id: str
    line: str


def list_cron_entries() -> list[CronRef]:
    """Parse the crontab and return all koda schedule entries."""
    existing = _read_crontab()
    entries: list[CronRef] = []
    for line in existing.splitlines():
        m = _CRON_MARKER_RE.search(line)
        if m:
            entries.append(CronRef(schedule_id=m.group(1), line=line.strip()))
    return entries


# ---------------------------------------------------------------------------
# systemd user timer helpers
# ---------------------------------------------------------------------------

def _systemd_unit_name(schedule_id: str) -> str:
    return f"koda-schedule-{schedule_id}"


def _user_systemd_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "systemd" / "user"


def _service_content(schedule_id: str) -> str:
    koda_bin = shutil.which("koda") or "koda"
    return (
        "[Unit]\n"
        f"Description=K.O.D.A. scheduled scan: {schedule_id}\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={koda_bin} schedule _tick {schedule_id}\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _timer_content(schedule_id: str, cron_expr: str) -> str:
    on_calendar = _cron_to_systemd_oncalendar(cron_expr)
    return (
        "[Unit]\n"
        f"Description=K.O.D.A. schedule timer: {schedule_id}\n\n"
        "[Timer]\n"
        f"OnCalendar={on_calendar}\n"
        "Persistent=true\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def _cron_to_systemd_oncalendar(cron_expr: str) -> str:
    """Convert a 5-field cron expression to a systemd OnCalendar spec.

    This handles the most common patterns that SMB/consultant users would
    type.  Complex expressions (ranges, step-values, comma-lists outside
    ``*``) fall back to the verbatim cron expression wrapped in a comment
    and a ``daily`` default — the operator should edit the unit manually.

    Supported patterns (per field):
      ``*``     → ``*``
      ``N``     → ``N``
      ``*/N``   → ``*/<N>`` (systemd step syntax)

    Unsupported patterns fall back to ``*-*-* *:*:00`` (every minute) with
    a warning — operators should adjust the generated ``.timer`` unit.
    """
    fields = cron_expr.strip().split()
    if len(fields) != 5:
        return "*-*-* *:*:00"  # fallback
    minute, hour, dom, month, dow = fields

    def _map(f: str) -> str:
        """Map one cron field to a systemd calendar field."""
        if f == "*":
            return "*"
        if re.match(r"^\d+$", f):
            return f
        if re.match(r"^\*/\d+$", f):
            # */N → */<N>
            return f
        # Anything more complex — return ``*`` as safe fallback.
        return "*"

    m = _map(minute)
    h = _map(hour)
    d = _map(dom)
    mo = _map(month)
    dw_raw = dow

    # Build date part.
    if dw_raw == "*":
        date_part = f"*-{mo}-{d}"
    else:
        # systemd uses Mon,Tue,… not 0-6; best-effort numeric pass-through.
        date_part = f"{dw_raw} *-{mo}-{d}"

    return f"{date_part} {h}:{m}:00"


def install_systemd_entry(schedule_id: str, cron_expr: str) -> None:
    """Write and enable a systemd user service + timer for *schedule_id*."""
    unit_dir = _user_systemd_dir()
    unit_dir.mkdir(parents=True, exist_ok=True)
    name = _systemd_unit_name(schedule_id)

    service_path = unit_dir / f"{name}.service"
    timer_path = unit_dir / f"{name}.timer"

    service_path.write_text(_service_content(schedule_id), encoding="utf-8")
    timer_path.write_text(_timer_content(schedule_id, cron_expr), encoding="utf-8")

    try:
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["systemctl", "--user", "enable", "--now", f"{name}.timer"],
            check=True, capture_output=True, timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise OSError(f"systemctl failed: {exc}") from exc


def remove_systemd_entry(schedule_id: str) -> bool:
    """Disable and remove the systemd user units for *schedule_id*.

    Returns True if units were found and removed.
    """
    name = _systemd_unit_name(schedule_id)
    unit_dir = _user_systemd_dir()
    service_path = unit_dir / f"{name}.service"
    timer_path = unit_dir / f"{name}.timer"

    if not service_path.exists() and not timer_path.exists():
        return False

    # Disable gracefully, ignore errors (unit may already be stopped).
    try:
        subprocess.run(
            ["systemctl", "--user", "disable", "--now", f"{name}.timer"],
            capture_output=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    try:
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            capture_output=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    removed = False
    for p in (service_path, timer_path):
        if p.exists():
            p.unlink()
            removed = True
    return removed


@dataclass
class SystemdRef:
    """A koda schedule timer found in systemd user units."""
    schedule_id: str
    timer_path: Path
    service_path: Path


def list_systemd_entries() -> list[SystemdRef]:
    """Return all koda schedule timers found in the systemd user unit dir."""
    unit_dir = _user_systemd_dir()
    if not unit_dir.is_dir():
        return []
    refs: list[SystemdRef] = []
    for timer in unit_dir.glob("koda-schedule-*.timer"):
        schedule_id = timer.stem[len("koda-schedule-"):]
        service = timer.with_suffix(".service")
        refs.append(SystemdRef(
            schedule_id=schedule_id,
            timer_path=timer,
            service_path=service,
        ))
    return refs


# ---------------------------------------------------------------------------
# Unified install / remove / list
# ---------------------------------------------------------------------------

def install_entry(schedule_id: str, cron_expr: str, *, backend: str | None = None) -> str:
    """Install scheduler entry.  Returns the backend that was used."""
    used = get_backend(force=backend)  # type: ignore[arg-type]
    if used == "systemd":
        try:
            install_systemd_entry(schedule_id, cron_expr)
        except OSError as exc:
            print(
                f"warning: systemd install failed ({exc}); falling back to crontab",
                file=sys.stderr,
            )
            _write_backend_cache("crontab")
            install_cron_entry(schedule_id, cron_expr)
            return "crontab"
    else:
        install_cron_entry(schedule_id, cron_expr)
    return used


def remove_entry(schedule_id: str, *, backend: str | None = None) -> bool:
    """Remove scheduler entry from the cached backend.  Returns True if found."""
    used = backend or get_backend()
    if used == "systemd":
        removed = remove_systemd_entry(schedule_id)
        if not removed:
            # Try crontab too in case of a mixed state.
            remove_cron_entry(schedule_id)
        return removed
    else:
        return remove_cron_entry(schedule_id)


__all__ = [
    "get_backend",
    "install_entry",
    "remove_entry",
    "install_cron_entry",
    "remove_cron_entry",
    "list_cron_entries",
    "install_systemd_entry",
    "remove_systemd_entry",
    "list_systemd_entries",
    "CronRef",
    "SystemdRef",
    "_cron_to_systemd_oncalendar",
]
