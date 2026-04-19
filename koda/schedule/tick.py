"""``koda schedule _tick <id>`` — the actual scheduled scan runner.

Invoked by cron / systemd at the configured schedule.  Never raises;
always exits 0 so the OS scheduler does not flag a "failed" job.

Steps:
  1. Load schedule from ``KODA_HOME/schedules/<id>.toml``
  2. Compute run_id = ``run-<ISO8601Z>``
  3. Run scanners (preset-resolved via ``koda.missions`` if present,
     else explicit scanner list)
  4. Write ``findings.jsonl`` + ``meta.toml`` into the run directory
  5. Load previous run (via ``latest`` symlink)
  6. Compute diff; fire alerts if warranted
  7. Update ``latest`` symlink and ``last_run`` in schedule file
  8. Emit audit events
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id_from_ts(ts: str) -> str:
    """Normalise an ISO8601 timestamp to a safe run-id directory name."""
    return "run-" + ts.replace(":", "-").replace("T", "-").rstrip("Z")


def _is_remote_target(target: str) -> bool:
    """Return True if *target* looks like an SSH destination."""
    if "@" in target:
        return True
    # Check SSH config for a Host stanza match.
    ssh_config = Path.home() / ".ssh" / "config"
    if ssh_config.exists():
        try:
            content = ssh_config.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if line.strip().lower().startswith("host "):
                    hosts = line.strip()[5:].split()
                    if target in hosts:
                        return True
        except OSError:
            pass
    return False


def _resolve_scanners(schedule: Any) -> tuple[str, ...]:
    """Return the scanner list, resolving from preset if needed."""
    if schedule.preset:
        try:
            from ..missions import get_preset
            preset = get_preset(schedule.preset)
            if preset is not None:
                return preset.scanners
        except ImportError:
            pass
    if schedule.scanners:
        return schedule.scanners
    # Fallback: a minimal default set that always makes sense.
    return ("gitleaks", "trivy", "osv-scanner")


def _run_scanners(
    scanners: tuple[str, ...],
    target: str,
    preset_scanner_args: dict | None = None,
) -> tuple[list[Any], dict[str, float]]:
    """Run scanners and return (all_findings, scanner_durations)."""
    from ..security.scanners.registry import ScannerRegistry

    registry = ScannerRegistry()
    all_findings: list[Any] = []
    durations: dict[str, float] = {}
    args_map = preset_scanner_args or {}

    for name in scanners:
        start = time.monotonic()
        try:
            extra = args_map.get(name, {})
            result = registry.run(name, target, **extra)
            all_findings.extend(result.findings)
            durations[name] = round(time.monotonic() - start, 2)
        except Exception as exc:
            print(f"[koda-tick] scanner {name!r} failed: {exc}", file=sys.stderr)
            durations[name] = round(time.monotonic() - start, 2)

    return all_findings, durations


def _write_findings_jsonl(path: Path, findings: list[Any]) -> None:
    """Write findings as JSONL to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for f in findings:
        try:
            lines.append(json.dumps(f.to_dict()))
        except Exception:
            pass
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _write_meta_toml(
    path: Path,
    started_at: str,
    ended_at: str,
    exit_code: int,
    scanner_durations: dict[str, float],
    findings: list[Any],
) -> None:
    """Write run meta to *path* as TOML."""
    from ..security.findings import Severity

    count_by_sev: dict[str, int] = {}
    for sev in Severity:
        c = len([f for f in findings if f.severity == sev])
        if c:
            count_by_sev[sev.value] = c

    lines = [
        "[meta]",
        f'started_at = "{started_at}"',
        f'ended_at = "{ended_at}"',
        f"exit_code = {exit_code}",
        "",
        "[scanner_durations]",
    ]
    for scanner, dur in scanner_durations.items():
        lines.append(f"{scanner} = {dur}")
    lines.append("")
    lines.append("[finding_count_by_severity]")
    for sev_val, count in count_by_sev.items():
        lines.append(f"{sev_val} = {count}")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _update_latest_symlink(schedule_run_base: Path, run_dir: Path) -> None:
    """Update the ``latest`` symlink to point at *run_dir*."""
    symlink = schedule_run_base / "latest"
    # Remove stale symlink atomically: write new one to a temp name and rename.
    try:
        tmp = schedule_run_base / "latest.tmp"
        if tmp.is_symlink():
            tmp.unlink()
        tmp.symlink_to(run_dir)
        tmp.rename(symlink)
    except OSError:
        # Best effort — if symlink update fails, tick still succeeds.
        try:
            if symlink.exists() or symlink.is_symlink():
                symlink.unlink()
            symlink.symlink_to(run_dir)
        except OSError:
            pass


def _get_prev_run_dir(schedule_run_base: Path) -> Path | None:
    """Return the path of the previous run from the ``latest`` symlink."""
    symlink = schedule_run_base / "latest"
    if symlink.is_symlink():
        target = Path(os.readlink(symlink))
        if not target.is_absolute():
            target = schedule_run_base / target
        if target.is_dir():
            return target
    return None


def _should_alert(diff: Any, alert_on: str) -> bool:
    """Return True if alerts should fire given *alert_on* policy."""
    if alert_on == "empty":
        return True  # always alert
    if alert_on == "change":
        return diff.has_changes  # new or resolved
    # Default: "findings" — alert only when there are new findings
    return diff.has_new


def run_tick(schedule_id: str, koda_home: Path | None = None) -> int:
    """Execute one scheduled scan tick.  Always returns 0.

    Parameters
    ----------
    schedule_id:
        The id of the schedule to run.
    koda_home:
        Override KODA_HOME (used in tests).
    """
    if koda_home is None:
        koda_home = Path(os.environ.get("KODA_HOME", Path.home() / ".koda"))

    # --- audit setup ---
    audit: Any = None
    try:
        from ..audit import AuditLogger
        audit = AuditLogger()
    except Exception:
        pass

    def _emit(event: str, **fields: Any) -> None:
        if audit:
            try:
                audit.emit(event, schedule_id=schedule_id, **fields)
            except Exception:
                pass

    started_at = _now_iso()
    _emit("schedule.tick.start", started_at=started_at)

    # --- load schedule ---
    schedules_dir = koda_home / "schedules"
    schedule_toml = schedules_dir / f"{schedule_id}.toml"

    if not schedule_toml.exists():
        print(
            f"[koda-tick] schedule {schedule_id!r} not found at {schedule_toml}",
            file=sys.stderr,
        )
        _emit("schedule.tick.end", exit_code=0, error="schedule not found")
        return 0

    try:
        from .models import load_schedule
        schedule = load_schedule(schedule_toml)
    except Exception as exc:
        print(f"[koda-tick] failed to load schedule: {exc}", file=sys.stderr)
        _emit("schedule.tick.end", exit_code=0, error=f"load failed: {exc}")
        return 0

    # --- build run directory ---
    run_id = _run_id_from_ts(started_at)
    schedule_run_base = schedules_dir / schedule_id / "runs"
    run_dir = schedule_run_base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    findings_path = run_dir / "findings.jsonl"
    meta_path = run_dir / "meta.toml"

    # --- resolve scanners ---
    scanners = _resolve_scanners(schedule)

    # Get scanner args from preset if available.
    preset_scanner_args: dict | None = None
    if schedule.preset:
        try:
            from ..missions import get_preset
            p = get_preset(schedule.preset)
            if p is not None:
                preset_scanner_args = dict(p.scanner_args)
        except ImportError:
            pass

    # --- run scanners ---
    exit_code = 0
    try:
        target = schedule.target
        # Remote target dispatch: pass through as-is; scanners handle it.
        # (A future remote-SSH agent integration would intercept here.)
        findings, durations = _run_scanners(scanners, target, preset_scanner_args)
    except Exception as exc:
        print(f"[koda-tick] scanner run failed: {exc}", file=sys.stderr)
        findings, durations = [], {}
        exit_code = 1

    ended_at = _now_iso()

    # --- persist run artifacts ---
    try:
        _write_findings_jsonl(findings_path, findings)
        _write_meta_toml(meta_path, started_at, ended_at, exit_code, durations, findings)
    except Exception as exc:
        print(f"[koda-tick] failed to write run artifacts: {exc}", file=sys.stderr)

    # --- compute diff ---
    prev_run_dir = _get_prev_run_dir(schedule_run_base)
    try:
        from .differ import diff_run_dirs
        diff = diff_run_dirs(prev_run_dir, run_dir)
    except Exception as exc:
        print(f"[koda-tick] diff failed: {exc}", file=sys.stderr)
        # Fall back: treat everything as new.
        from .differ import DiffResult, _sort_by_severity
        diff = DiffResult(
            new=_sort_by_severity(findings),
            resolved=[],
            persistent=[],
        )

    _emit(
        "schedule.tick.diff",
        new=len(diff.new),
        resolved=len(diff.resolved),
        persistent=len(diff.persistent),
        prev_run=str(prev_run_dir) if prev_run_dir else None,
        curr_run=str(run_dir),
    )

    # --- fire alerts ---
    should_fire = _should_alert(diff, schedule.alert_on)
    if should_fire:
        try:
            from .alerts import dispatch_alerts
            dispatch_alerts(diff, schedule, run_dir, audit=audit)
            _emit("schedule.tick.alert", channels=list(schedule.alerts), fired=True)
        except Exception as exc:
            print(f"[koda-tick] alert dispatch failed: {exc}", file=sys.stderr)
            _emit("schedule.tick.alert", fired=False, error=str(exc))
    else:
        _emit("schedule.tick.alert", fired=False, reason=f"alert_on={schedule.alert_on!r}, no trigger")

    # --- update latest symlink ---
    try:
        _update_latest_symlink(schedule_run_base, run_dir)
    except Exception as exc:
        print(f"[koda-tick] symlink update failed: {exc}", file=sys.stderr)

    # --- update last_run in schedule file ---
    try:
        updated = schedule.with_last_run(ended_at)
        updated.save(schedules_dir)
    except Exception as exc:
        print(f"[koda-tick] last_run update failed: {exc}", file=sys.stderr)

    _emit("schedule.tick.end", exit_code=0, findings=len(findings))

    if audit:
        try:
            audit.close()
        except Exception:
            pass

    return 0  # always 0 — cron must not retry on error


__all__ = ["run_tick"]
