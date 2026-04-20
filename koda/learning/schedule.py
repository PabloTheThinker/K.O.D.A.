"""Install / remove the crontab entry that runs ``koda learn`` nightly.

Separate from :mod:`koda.schedule` because that subsystem is oriented around
scheduled security scans with diff-based alerts. The learning pipeline only
needs a single recurring entry, so we keep this small and focused.

One entry is installed with the marker ``# koda-learn``. The default
schedule is 2 AM daily, which dovetails with KODA's other nightly cognitive
chores.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

DEFAULT_CRON_EXPR = "0 2 * * *"
_MARKER = "# koda-learn"
_MARKER_RE = re.compile(r"#\s*koda-learn\b")


@dataclass
class LearnScheduleEntry:
    """One installed schedule line, parsed back from the crontab."""

    cron_expr: str
    command: str
    raw: str


def install_learn_schedule(
    cron_expr: str = DEFAULT_CRON_EXPR,
    *,
    extra_flags: str = "run",
) -> LearnScheduleEntry:
    """Add (or replace) the nightly ``koda learn`` cron entry.

    ``extra_flags`` is appended to ``koda learn`` — defaults to ``run`` so
    the entry executes the full pipeline. Idempotent by the ``# koda-learn``
    marker: any existing learn line is replaced.
    """
    existing = _read_crontab()
    lines = [ln for ln in existing.splitlines() if not _MARKER_RE.search(ln)]

    koda_bin = shutil.which("koda") or "koda"
    command = f"{koda_bin} learn {extra_flags}".strip()
    line = f"{cron_expr} {command}  {_MARKER}"
    lines.append(line)
    _write_crontab("\n".join(lines) + "\n")

    return LearnScheduleEntry(cron_expr=cron_expr, command=command, raw=line)


def remove_learn_schedule() -> bool:
    """Remove the ``koda learn`` cron entry. Returns True if one was found."""
    existing = _read_crontab()
    lines = existing.splitlines()
    filtered = [ln for ln in lines if not _MARKER_RE.search(ln)]
    if len(filtered) == len(lines):
        return False
    _write_crontab("\n".join(filtered) + "\n")
    return True


def get_learn_schedule() -> LearnScheduleEntry | None:
    """Return the installed learn entry, or ``None`` if nothing is scheduled."""
    for line in _read_crontab().splitlines():
        if not _MARKER_RE.search(line):
            continue
        # Cron format: "<minute> <hour> <dom> <mon> <dow> <command>  # koda-learn"
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        cron_expr = " ".join(parts[:5])
        rest = parts[5]
        # Strip trailing marker.
        command = rest.rsplit("#", 1)[0].strip()
        return LearnScheduleEntry(cron_expr=cron_expr, command=command, raw=line)
    return None


# ── crontab I/O — narrow copies of schedule.cron so we stay decoupled ────

def _read_crontab() -> str:
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout


def _write_crontab(content: str) -> None:
    subprocess.run(
        ["crontab", "-"],
        input=content,
        text=True,
        check=True,
    )
