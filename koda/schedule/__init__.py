"""Scheduled monitoring with diff-based alerts.

``koda schedule add`` registers a periodic security scan that fires via the
OS scheduler (systemd user timer or crontab — no long-running daemon).  On
each tick K.O.D.A. runs the configured scanners, computes the diff against
the previous run, and dispatches alerts only when new findings appear.

Modules
-------
models   -- Schedule dataclass + TOML serialisation.
differ   -- Fingerprint-based diff engine (new / resolved / persistent).
alerts   -- Alert channel callables (file, telegram, email, webhook).
cron     -- OS scheduler integration (crontab / systemd user timer).
"""
from .differ import DiffResult, diff_runs
from .models import SCHEDULE_SCHEMA_VERSION, Schedule

__all__ = [
    "Schedule",
    "SCHEDULE_SCHEMA_VERSION",
    "DiffResult",
    "diff_runs",
]
