"""``koda schedule`` subcommand: scheduled monitoring with diff-based alerts.

Usage::

    koda schedule add --target <target> [--preset <name>] [--scanner <name>]...
                      --cron "<expr>" [--alert <channel>]... [--name <label>]
    koda schedule list
    koda schedule remove <id|name>
    koda schedule run <id|name>           force-run immediately
    koda schedule history [<id|name>] [--limit N]
    koda schedule diff <id|name> [--from RUN_ID] [--to RUN_ID]
    koda schedule _tick <id>              (internal — invoked by cron/systemd)

Alert channels (--alert, repeatable):
    telegram                  uses the configured Telegram bridge
    email:<address>           requires KODA_HOME/smtp.toml
    webhook:<url>             POST JSON; 5s timeout; 1 retry
    file:<path>               append JSONL; default when nothing else is given
"""
from __future__ import annotations

import sys
from pathlib import Path


def _koda_home() -> Path:
    from ..config import KODA_HOME
    return KODA_HOME


def _schedules_dir() -> Path:
    return _koda_home() / "schedules"


def _find_schedule(id_or_name: str):
    """Find a Schedule by id or name.  Returns Schedule or None."""
    from ..schedule.models import list_schedules
    schedules = list_schedules(_schedules_dir())
    # Exact id match first.
    for s in schedules:
        if s.id == id_or_name:
            return s
    # Name match (case-insensitive).
    for s in schedules:
        if s.name.lower() == id_or_name.lower():
            return s
    return None


# ---------------------------------------------------------------------------
# `koda schedule add`
# ---------------------------------------------------------------------------

def _cmd_add(argv: list[str]) -> int:
    target: str | None = None
    preset: str | None = None
    scanners: list[str] = []
    cron_expr: str | None = None
    alerts: list[str] = []
    name: str | None = None
    alert_on: str = "findings"

    i = 0
    while i < len(argv):
        a = argv[i]
        if a in {"-h", "--help"}:
            _print_add_usage()
            return 0
        if a == "--target" and i + 1 < len(argv):
            target = argv[i + 1]; i += 2; continue
        if a.startswith("--target="):
            target = a.split("=", 1)[1]; i += 1; continue
        if a == "--preset" and i + 1 < len(argv):
            preset = argv[i + 1]; i += 2; continue
        if a.startswith("--preset="):
            preset = a.split("=", 1)[1]; i += 1; continue
        if a == "--scanner" and i + 1 < len(argv):
            scanners.append(argv[i + 1]); i += 2; continue
        if a.startswith("--scanner="):
            scanners.append(a.split("=", 1)[1]); i += 1; continue
        if a == "--cron" and i + 1 < len(argv):
            cron_expr = argv[i + 1]; i += 2; continue
        if a.startswith("--cron="):
            cron_expr = a.split("=", 1)[1]; i += 1; continue
        if a == "--alert" and i + 1 < len(argv):
            alerts.append(argv[i + 1]); i += 2; continue
        if a.startswith("--alert="):
            alerts.append(a.split("=", 1)[1]); i += 1; continue
        if a == "--name" and i + 1 < len(argv):
            name = argv[i + 1]; i += 2; continue
        if a.startswith("--name="):
            name = a.split("=", 1)[1]; i += 1; continue
        if a == "--alert-on" and i + 1 < len(argv):
            alert_on = argv[i + 1]; i += 2; continue
        if a.startswith("--alert-on="):
            alert_on = a.split("=", 1)[1]; i += 1; continue
        print(f"error: unknown flag {a!r}", file=sys.stderr)
        _print_add_usage()
        return 2
        i += 1  # noqa: F401 — unreachable; ruff does not flag unreachable in this pattern

    if not target:
        print("error: --target is required", file=sys.stderr)
        _print_add_usage()
        return 2
    if not cron_expr:
        print("error: --cron is required", file=sys.stderr)
        _print_add_usage()
        return 2
    if not preset and not scanners:
        print(
            "error: either --preset or at least one --scanner is required",
            file=sys.stderr,
        )
        _print_add_usage()
        return 2

    # Validate preset exists (lazy — tolerate missions module missing).
    if preset:
        try:
            from ..missions import get_preset
            if get_preset(preset) is None:
                from ..missions import preset_names
                print(
                    f"error: unknown preset {preset!r}. "
                    f"Available: {', '.join(preset_names())}",
                    file=sys.stderr,
                )
                return 1
        except ImportError:
            pass  # missions module not available — accept any preset name

    # Validate email alerts have smtp.toml.
    for spec in alerts:
        if spec.startswith("email:"):
            smtp_path = _koda_home() / "smtp.toml"
            if not smtp_path.exists():
                print(
                    f"error: email alert configured but {smtp_path} not found.\n"
                    "       Create smtp.toml with: host, port, user, pass, from_addr",
                    file=sys.stderr,
                )
                return 1

    label = name or (f"{preset}-{target}" if preset else f"scan-{target}")
    label = label[:40]  # keep it sane

    try:
        from ..schedule.models import Schedule
        schedule = Schedule.create(
            name=label,
            target=target,
            cron=cron_expr,
            preset=preset,
            scanners=tuple(scanners),
            alerts=tuple(alerts),
            alert_on=alert_on,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Save TOML.
    schedules_dir = _schedules_dir()
    try:
        path = schedule.save(schedules_dir)
    except OSError as exc:
        print(f"error: could not write schedule: {exc}", file=sys.stderr)
        return 1

    # Install OS scheduler entry.
    try:
        from ..schedule.cron import install_entry
        backend = install_entry(schedule.id, cron_expr)
    except Exception as exc:
        print(
            f"warning: OS scheduler install failed ({exc})\n"
            f"         Schedule saved to {path}\n"
            f"         Manual cron line: {cron_expr} koda schedule _tick {schedule.id}",
            file=sys.stderr,
        )
        backend = "(failed)"

    print(f"schedule {schedule.id!r} created")
    print(f"  name:    {schedule.name}")
    print(f"  target:  {schedule.target}")
    if schedule.preset:
        print(f"  preset:  {schedule.preset}")
    else:
        print(f"  scanners: {', '.join(schedule.scanners)}")
    print(f"  cron:    {schedule.cron}")
    print(f"  alerts:  {', '.join(schedule.alerts) or '(default file)'}")
    print(f"  backend: {backend}")
    print(f"  file:    {path}")
    print()
    print(f"to force-run now: koda schedule run {schedule.id}")
    return 0


def _print_add_usage() -> None:
    print(
        "usage: koda schedule add --target <target> --cron \"<expr>\"\n"
        "                         [--preset <name>] [--scanner <name>]...\n"
        "                         [--alert telegram|email:<addr>|webhook:<url>|file:<path>]...\n"
        "                         [--name <label>] [--alert-on findings|change|empty]"
    )


# ---------------------------------------------------------------------------
# `koda schedule list`
# ---------------------------------------------------------------------------

def _cmd_list(argv: list[str]) -> int:
    from ..schedule.cron import get_backend, list_cron_entries, list_systemd_entries
    from ..schedule.models import list_schedules

    schedules = list_schedules(_schedules_dir())
    backend = get_backend()

    if not schedules:
        print("no schedules configured")
        print("  add one: koda schedule add --target <t> --preset <p> --cron \"<expr>\"")
        return 0

    print(f"schedules (backend: {backend}):")
    print()
    for s in schedules:
        last = s.last_run or "never"
        print(f"  {s.id}")
        print(f"    name:   {s.name}")
        print(f"    target: {s.target}")
        preset_info = f"preset:{s.preset}" if s.preset else f"scanners:{','.join(s.scanners)}"
        print(f"    scan:   {preset_info}")
        print(f"    cron:   {s.cron}")
        print(f"    alerts: {', '.join(s.alerts) or '(default file)'}")
        print(f"    last:   {last}")
        print()

    # Check for orphan markers (crontab entries without a TOML file).
    known_ids = {s.id for s in schedules}
    cron_entries = list_cron_entries()
    systemd_entries = list_systemd_entries()
    orphans = []
    for entry in cron_entries:
        if entry.schedule_id not in known_ids:
            orphans.append(f"crontab: {entry.schedule_id!r}")
    for entry in systemd_entries:
        if entry.schedule_id not in known_ids:
            orphans.append(f"systemd: {entry.schedule_id!r}")
    if orphans:
        print("warning: orphan OS scheduler entries (no matching .toml):")
        for o in orphans:
            print(f"  {o}")
        print("  to clean: koda schedule remove <id>")

    return 0


# ---------------------------------------------------------------------------
# `koda schedule remove`
# ---------------------------------------------------------------------------

def _cmd_remove(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage: koda schedule remove <id|name>")
        return 0

    id_or_name = argv[0]
    schedule = _find_schedule(id_or_name)

    if schedule is None:
        # Check if there is an orphan cron / systemd entry.
        from ..schedule.cron import remove_entry
        removed = remove_entry(id_or_name)
        if removed:
            print(f"removed orphan OS scheduler entry for {id_or_name!r}")
            return 0
        print(f"error: schedule {id_or_name!r} not found", file=sys.stderr)
        return 1

    # Remove OS scheduler entry.
    try:
        from ..schedule.cron import remove_entry
        remove_entry(schedule.id)
    except Exception as exc:
        print(f"warning: OS scheduler removal failed: {exc}", file=sys.stderr)

    # Remove TOML file.
    toml_path = _schedules_dir() / f"{schedule.id}.toml"
    try:
        if toml_path.exists():
            toml_path.unlink()
    except OSError as exc:
        print(f"error: could not remove schedule file: {exc}", file=sys.stderr)
        return 1

    print(f"removed schedule {schedule.id!r} ({schedule.name!r})")
    return 0


# ---------------------------------------------------------------------------
# `koda schedule run` (force-run)
# ---------------------------------------------------------------------------

def _cmd_run(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage: koda schedule run <id|name>")
        return 0

    id_or_name = argv[0]
    schedule = _find_schedule(id_or_name)
    if schedule is None:
        print(f"error: schedule {id_or_name!r} not found", file=sys.stderr)
        return 1

    print(f"running schedule {schedule.id!r} ({schedule.name!r}) now…")
    from ..schedule.tick import run_tick
    return run_tick(schedule.id, _koda_home())


# ---------------------------------------------------------------------------
# `koda schedule history`
# ---------------------------------------------------------------------------

def _cmd_history(argv: list[str]) -> int:
    limit = 10
    id_or_name: str | None = None

    i = 0
    while i < len(argv):
        a = argv[i]
        if a in {"-h", "--help"}:
            print("usage: koda schedule history [<id|name>] [--limit N]")
            return 0
        if a == "--limit" and i + 1 < len(argv):
            try:
                limit = int(argv[i + 1])
            except ValueError:
                print("error: --limit must be an integer", file=sys.stderr)
                return 2
            i += 2; continue
        if a.startswith("--limit="):
            try:
                limit = int(a.split("=", 1)[1])
            except ValueError:
                print("error: --limit must be an integer", file=sys.stderr)
                return 2
            i += 1; continue
        if not a.startswith("-"):
            id_or_name = a
        i += 1

    schedules_to_show = []
    if id_or_name:
        s = _find_schedule(id_or_name)
        if s is None:
            print(f"error: schedule {id_or_name!r} not found", file=sys.stderr)
            return 1
        schedules_to_show = [s]
    else:
        from ..schedule.models import list_schedules
        schedules_to_show = list_schedules(_schedules_dir())

    for s in schedules_to_show:
        runs_dir = _schedules_dir() / s.id / "runs"
        if not runs_dir.is_dir():
            print(f"{s.id}  ({s.name}) — no runs yet")
            continue
        run_dirs = sorted(
            [d for d in runs_dir.iterdir() if d.is_dir()],
            key=lambda d: d.name,
            reverse=True,
        )[:limit]

        print(f"{s.id}  ({s.name})")
        if not run_dirs:
            print("  (no runs recorded)")
            continue
        for rd in run_dirs:
            meta_path = rd / "meta.toml"
            findings_path = rd / "findings.jsonl"
            finding_count = 0
            started = "?"
            ended = "?"
            if meta_path.exists():
                try:
                    for line in meta_path.read_text(encoding="utf-8").splitlines():
                        if line.startswith("started_at"):
                            started = line.split("=", 1)[1].strip().strip('"')
                        elif line.startswith("ended_at"):
                            ended = line.split("=", 1)[1].strip().strip('"')  # noqa: F841
                except Exception:
                    pass
            if findings_path.exists():
                try:
                    finding_count = sum(
                        1 for ln in findings_path.read_text(encoding="utf-8").splitlines()
                        if ln.strip()
                    )
                except Exception:
                    pass
            print(f"  {rd.name}  started={started}  findings={finding_count}")
        print()
    return 0


# ---------------------------------------------------------------------------
# `koda schedule diff`
# ---------------------------------------------------------------------------

def _cmd_diff(argv: list[str]) -> int:
    from_run: str | None = None
    to_run: str | None = None
    id_or_name: str | None = None

    i = 0
    while i < len(argv):
        a = argv[i]
        if a in {"-h", "--help"}:
            print("usage: koda schedule diff <id|name> [--from RUN_ID] [--to RUN_ID]")
            return 0
        if a == "--from" and i + 1 < len(argv):
            from_run = argv[i + 1]; i += 2; continue
        if a.startswith("--from="):
            from_run = a.split("=", 1)[1]; i += 1; continue
        if a == "--to" and i + 1 < len(argv):
            to_run = argv[i + 1]; i += 2; continue
        if a.startswith("--to="):
            to_run = a.split("=", 1)[1]; i += 1; continue
        if not a.startswith("-"):
            id_or_name = a
        i += 1

    if not id_or_name:
        print("error: <id|name> is required", file=sys.stderr)
        print("usage: koda schedule diff <id|name> [--from RUN_ID] [--to RUN_ID]")
        return 2

    schedule = _find_schedule(id_or_name)
    if schedule is None:
        print(f"error: schedule {id_or_name!r} not found", file=sys.stderr)
        return 1

    runs_base = _schedules_dir() / schedule.id / "runs"
    if not runs_base.is_dir():
        print(f"no runs found for schedule {schedule.id!r}")
        return 0

    run_dirs = sorted(
        [d for d in runs_base.iterdir() if d.is_dir()],
        key=lambda d: d.name,
    )

    if not run_dirs:
        print("no runs found")
        return 0

    def _find_run(run_id: str) -> Path | None:
        for rd in run_dirs:
            if rd.name == run_id or rd.name.startswith(run_id):
                return rd
        return None

    if to_run:
        curr_dir = _find_run(to_run)
        if curr_dir is None:
            print(f"error: run {to_run!r} not found", file=sys.stderr)
            return 1
    else:
        curr_dir = run_dirs[-1]

    if from_run:
        prev_dir: Path | None = _find_run(from_run)
        if prev_dir is None:
            print(f"error: run {from_run!r} not found", file=sys.stderr)
            return 1
    elif len(run_dirs) >= 2:
        prev_dir = run_dirs[-2] if curr_dir == run_dirs[-1] else None
        # Try to find the run just before curr_dir.
        for idx, rd in enumerate(run_dirs):
            if rd == curr_dir and idx > 0:
                prev_dir = run_dirs[idx - 1]
                break
        else:
            prev_dir = None
    else:
        prev_dir = None

    from ..schedule.differ import diff_run_dirs
    diff = diff_run_dirs(prev_dir, curr_dir)

    print(f"diff for schedule {schedule.id!r} ({schedule.name!r})")
    print(f"  from: {prev_dir.name if prev_dir else '(first run)'}")
    print(f"  to:   {curr_dir.name}")
    print()
    print(f"summary: {diff.summary()}")

    if diff.new:
        print(f"\nNEW findings ({len(diff.new)}):")
        for f in diff.new:
            sev = getattr(f.severity, "value", str(f.severity)).upper()
            print(f"  [{sev}] {f.title or f.rule_id or f.id}  ({f.file_path or 'no path'})")

    if diff.resolved:
        print(f"\nRESOLVED findings ({len(diff.resolved)}):")
        for f in diff.resolved:
            sev = getattr(f.severity, "value", str(f.severity)).upper()
            print(f"  [{sev}] {f.title or f.rule_id or f.id}")

    if diff.persistent:
        print(f"\nPERSISTENT findings: {len(diff.persistent)}")

    return 0


# ---------------------------------------------------------------------------
# `koda schedule _tick` (internal)
# ---------------------------------------------------------------------------

def _cmd_tick(argv: list[str]) -> int:
    """Internal command invoked by cron / systemd.  Always exits 0."""
    if not argv:
        print("error: _tick requires a schedule id", file=sys.stderr)
        return 0  # always 0 for cron

    schedule_id = argv[0]
    from ..schedule.tick import run_tick
    return run_tick(schedule_id, _koda_home())


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        _print_usage()
        return 0

    sub = argv[0]
    rest = argv[1:]

    if sub == "add":
        return _cmd_add(rest)
    if sub in {"list", "ls"}:
        return _cmd_list(rest)
    if sub in {"remove", "rm", "delete"}:
        return _cmd_remove(rest)
    if sub in {"run", "trigger"}:
        return _cmd_run(rest)
    if sub in {"history", "hist"}:
        return _cmd_history(rest)
    if sub == "diff":
        return _cmd_diff(rest)
    if sub == "_tick":
        return _cmd_tick(rest)

    print(f"error: unknown schedule subcommand {sub!r}", file=sys.stderr)
    _print_usage()
    return 2


def _print_usage() -> None:
    print(
        "usage:\n"
        "  koda schedule add --target <t> --cron \"<expr>\"\n"
        "                    [--preset <name>] [--scanner <name>]...\n"
        "                    [--alert telegram|email:<addr>|webhook:<url>|file:<path>]...\n"
        "                    [--name <label>] [--alert-on findings|change|empty]\n"
        "  koda schedule list\n"
        "  koda schedule remove <id|name>\n"
        "  koda schedule run <id|name>            force-run now\n"
        "  koda schedule history [<id|name>] [--limit N]\n"
        "  koda schedule diff <id|name> [--from RUN_ID] [--to RUN_ID]"
    )


__all__ = ["main"]
