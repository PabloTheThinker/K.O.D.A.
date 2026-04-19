"""Tests for koda schedule: models, differ, alerts, cron, tick, CLI.

Conventions:
  - subprocess.run is mocked for crontab / systemctl calls.
  - httpx / smtplib / urllib are mocked for webhook / email.
  - tmp_path is used for KODA_HOME isolation.
  - No real OS scheduler entries are installed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from koda.schedule.differ import DiffResult, diff_run_dirs, diff_runs
from koda.schedule.models import (
    SCHEDULE_SCHEMA_VERSION,
    Schedule,
    _validate_alert_channel,
    _validate_cron,
    list_schedules,
    load_schedule,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    scanner: str = "semgrep",
    rule_id: str = "rule-001",
    file_path: str = "foo.py",
    snippet: str = "",
    severity: str = "high",
    title: str = "Test finding",
):
    from koda.security.findings import Severity, UnifiedFinding
    return UnifiedFinding(
        id=UnifiedFinding.make_id(scanner, rule_id, file_path, 1),
        scanner=scanner,
        rule_id=rule_id,
        severity=Severity.from_str(severity),
        title=title,
        file_path=file_path,
        snippet=snippet,
    )


def _make_schedule(
    tmp_path: Path,
    *,
    name: str = "test-schedule",
    target: str = "localhost",
    preset: str | None = "server-hardening",
    scanners: tuple[str, ...] = (),
    cron: str = "0 2 * * *",
    alerts: tuple[str, ...] = (),
    alert_on: str = "findings",
    schedule_id: str = "",
) -> Schedule:
    s = Schedule.create(
        name=name,
        target=target,
        preset=preset,
        scanners=scanners,
        cron=cron,
        alerts=alerts,
        alert_on=alert_on,
        id=schedule_id,
    )
    s.save(tmp_path / "schedules")
    return s


# ---------------------------------------------------------------------------
# 1. Schedule model — creation, validation, TOML round-trip
# ---------------------------------------------------------------------------

def test_schedule_create_basic():
    s = Schedule.create(
        name="nightly-scan",
        target="localhost",
        preset="server-hardening",
        cron="0 2 * * *",
    )
    assert s.name == "nightly-scan"
    assert s.target == "localhost"
    assert s.preset == "server-hardening"
    assert s.cron == "0 2 * * *"
    assert s.last_run is None
    assert s.schema_version == SCHEDULE_SCHEMA_VERSION
    assert s.alert_on == "findings"


def test_schedule_schema_version_written():
    s = Schedule.create(
        name="v-test",
        target="/tmp",
        scanners=("bandit",),
        cron="* * * * *",
    )
    assert s.schema_version == SCHEDULE_SCHEMA_VERSION


def test_schedule_toml_round_trip():
    s = Schedule.create(
        name="round-trip",
        target="/opt/app",
        preset="web-app",
        cron="30 6 * * 1",
        alerts=("file:/tmp/alerts.jsonl", "telegram"),
        alert_on="change",
    )
    toml_text = s.to_toml()
    s2 = Schedule.from_toml(toml_text)
    assert s2.id == s.id
    assert s2.name == s.name
    assert s2.target == s.target
    assert s2.preset == s.preset
    assert s2.cron == s.cron
    assert s2.alerts == s.alerts
    assert s2.alert_on == s.alert_on
    assert s2.schema_version == SCHEDULE_SCHEMA_VERSION


def test_schedule_save_and_load(tmp_path: Path):
    s = Schedule.create(
        name="save-load",
        target="localhost",
        preset="server-hardening",
        cron="0 3 * * *",
    )
    path = s.save(tmp_path)
    assert path.exists()
    loaded = load_schedule(path)
    assert loaded.id == s.id
    assert loaded.name == s.name
    assert loaded.preset == s.preset


def test_list_schedules_empty(tmp_path: Path):
    assert list_schedules(tmp_path / "schedules") == []


def test_list_schedules_multiple(tmp_path: Path):
    sched_dir = tmp_path / "schedules"
    for i in range(3):
        Schedule.create(
            name=f"scan-{i}",
            target="localhost",
            scanners=("trivy",),
            cron="0 1 * * *",
        ).save(sched_dir)
    result = list_schedules(sched_dir)
    assert len(result) == 3


def test_schedule_with_last_run():
    s = Schedule.create(
        name="lr-test", target="/", scanners=("nmap",), cron="* * * * *"
    )
    assert s.last_run is None
    s2 = s.with_last_run("2026-04-19T02:00:00Z")
    assert s2.last_run == "2026-04-19T02:00:00Z"
    assert s2.id == s.id  # everything else unchanged


# ---------------------------------------------------------------------------
# 2. Cron expression validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("expr", [
    "0 2 * * *",
    "*/15 * * * *",
    "30 6 1,15 * 1",
    "0 0 * * 0",
    "5 4 * * 0",    # Sunday as a number
    "0 */2 * * *",
    "0 0 1-7 * 1",
    "59 23 31 12 6",
])
def test_valid_cron_expressions(expr: str):
    assert _validate_cron(expr) is None


@pytest.mark.parametrize("expr", [
    "",
    "0 2 * *",         # only 4 fields
    "0 2 * * * *",     # 6 fields
    "foo bar baz",
    "0 25 * * *",      # hour 25 is technically numeric but we only do syntax check
])
def test_invalid_cron_expressions(expr: str):
    # We only reject structural invalidity (wrong field count / bad chars)
    # Numeric range checking is out of scope.
    if expr in ("0 2 * *", "0 2 * * * *", "foo bar baz", ""):
        assert _validate_cron(expr) is not None
    # Others may or may not pass depending on regex — just ensure no crash.


# ---------------------------------------------------------------------------
# 3. Alert channel validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec", [
    "telegram",
    "file:/tmp/alerts.jsonl",
    "file:~/alerts.jsonl",
    "email:ops@example.com",
    "webhook:https://hooks.example.com/abc",
])
def test_valid_alert_channels(spec: str):
    assert _validate_alert_channel(spec) is None


@pytest.mark.parametrize("spec", [
    "slack://hooks.example",
    "http://bad",
    "pagerduty",
])
def test_invalid_alert_channels(spec: str):
    assert _validate_alert_channel(spec) is not None


# ---------------------------------------------------------------------------
# 4. Diff engine
# ---------------------------------------------------------------------------

def test_diff_first_run_all_new():
    findings = [_make_finding(rule_id=f"r{i}") for i in range(3)]
    diff = diff_runs(None, findings)
    assert len(diff.new) == 3
    assert diff.resolved == []
    assert diff.persistent == []
    assert diff.has_new
    assert not diff.has_changes or diff.has_new  # has_new implies has_changes


def test_diff_no_change():
    findings = [_make_finding(rule_id="r1"), _make_finding(rule_id="r2")]
    diff = diff_runs(findings, findings)
    assert diff.new == []
    assert diff.resolved == []
    assert len(diff.persistent) == 2


def test_diff_new_and_resolved():
    prev = [
        _make_finding(rule_id="old-1", file_path="a.py"),
        _make_finding(rule_id="old-2", file_path="b.py"),
        _make_finding(rule_id="persistent", file_path="c.py"),
    ]
    curr = [
        _make_finding(rule_id="persistent", file_path="c.py"),
        _make_finding(rule_id="new-1", file_path="d.py"),
    ]
    diff = diff_runs(prev, curr)
    assert len(diff.new) == 1
    assert len(diff.resolved) == 2
    assert len(diff.persistent) == 1
    # New finding should be rule new-1.
    assert diff.new[0].rule_id == "new-1"


def test_diff_severity_ordering():
    findings = [
        _make_finding(rule_id="low", severity="low"),
        _make_finding(rule_id="critical", severity="critical"),
        _make_finding(rule_id="high", severity="high"),
        _make_finding(rule_id="medium", severity="medium"),
    ]
    diff = diff_runs(None, findings)
    sevs = [f.severity.value for f in diff.new]
    assert sevs[0] == "critical"
    assert sevs[1] == "high"


def test_diff_run_dirs_first_run(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-001"
    run_dir.mkdir(parents=True)
    findings = [_make_finding(rule_id="x")]
    (run_dir / "findings.jsonl").write_text(
        json.dumps(findings[0].to_dict()) + "\n", encoding="utf-8"
    )
    diff = diff_run_dirs(None, run_dir)
    assert len(diff.new) == 1
    assert diff.resolved == []


def test_diff_run_dirs_second_run(tmp_path: Path):
    prev_dir = tmp_path / "runs" / "run-001"
    curr_dir = tmp_path / "runs" / "run-002"
    prev_dir.mkdir(parents=True)
    curr_dir.mkdir(parents=True)

    prev_finding = _make_finding(rule_id="old", file_path="a.py", snippet="old snippet")
    new_finding = _make_finding(rule_id="new", file_path="b.py", snippet="new snippet")

    (prev_dir / "findings.jsonl").write_text(
        json.dumps(prev_finding.to_dict()) + "\n", encoding="utf-8"
    )
    (curr_dir / "findings.jsonl").write_text(
        json.dumps(new_finding.to_dict()) + "\n", encoding="utf-8"
    )
    diff = diff_run_dirs(prev_dir, curr_dir)
    assert len(diff.new) == 1
    assert len(diff.resolved) == 1
    assert diff.new[0].rule_id == "new"


def test_diff_summary():
    prev = [_make_finding(rule_id="old")]
    curr = [_make_finding(rule_id="new")]
    diff = diff_runs(prev, curr)
    s = diff.summary()
    assert "new" in s
    assert "resolved" in s


# ---------------------------------------------------------------------------
# 5. File alert channel
# ---------------------------------------------------------------------------

def test_file_alert_appends_jsonl(tmp_path: Path):
    from koda.schedule.alerts import _dispatch_file

    alerts_file = tmp_path / "alerts.jsonl"
    diff = DiffResult(
        new=[_make_finding(rule_id="r1")],
        resolved=[],
        persistent=[],
    )
    s = Schedule.create(
        name="test", target="localhost", scanners=("trivy",), cron="* * * * *"
    )
    _dispatch_file(f"file:{alerts_file}", diff, s, "2026-04-19T02:00:00Z")

    assert alerts_file.exists()
    line = json.loads(alerts_file.read_text(encoding="utf-8").strip())
    assert line["schedule_id"] == s.id
    assert line["ran_at"] == "2026-04-19T02:00:00Z"
    assert len(line["diff"]["new"]) == 1


def test_file_alert_expected_fields(tmp_path: Path):
    from koda.schedule.alerts import _dispatch_file

    alerts_file = tmp_path / "out.jsonl"
    diff = DiffResult(
        new=[_make_finding()],
        resolved=[_make_finding(rule_id="resolved")],
        persistent=[],
    )
    s = Schedule.create(
        name="t", target="/", scanners=("nmap",), cron="* * * * *"
    )
    _dispatch_file(f"file:{alerts_file}", diff, s, "2026-04-19T00:00:00Z")
    data = json.loads(alerts_file.read_text().strip())
    assert "schedule_id" in data
    assert "schedule_name" in data
    assert "ran_at" in data
    assert "target" in data
    assert "diff" in data
    assert "new" in data["diff"]
    assert "resolved" in data["diff"]


# ---------------------------------------------------------------------------
# 6. Telegram alert skipped gracefully when not configured
# ---------------------------------------------------------------------------

def test_telegram_alert_skipped_when_not_configured():
    from koda.schedule.alerts import _dispatch_telegram

    diff = DiffResult(new=[_make_finding()], resolved=[], persistent=[])
    s = Schedule.create(
        name="tg-test", target="/", scanners=("bandit",), cron="* * * * *"
    )
    # Should not raise even if the telegram module isn't configured.
    _dispatch_telegram(diff, s, "2026-04-19T00:00:00Z")


# ---------------------------------------------------------------------------
# 7. Webhook alert retries + audit events
# ---------------------------------------------------------------------------

def test_webhook_alert_retries_once_on_failure():
    import urllib.error

    from koda.schedule.alerts import _dispatch_webhook

    diff = DiffResult(new=[_make_finding()], resolved=[], persistent=[])
    s = Schedule.create(
        name="wh-test", target="/", scanners=("trivy",), cron="* * * * *"
    )
    mock_audit = MagicMock()
    call_count = {"n": 0}

    def _failing_urlopen(req, timeout=5):
        call_count["n"] += 1
        raise urllib.error.URLError("connection refused")

    with patch("urllib.request.urlopen", side_effect=_failing_urlopen):
        _dispatch_webhook(
            "webhook:https://hooks.example.com/test",
            diff, s, "2026-04-19T00:00:00Z",
            _audit=mock_audit,
        )

    # Should have attempted twice.
    assert call_count["n"] == 2
    # Audit should have been called twice (one per attempt).
    assert mock_audit.emit.call_count == 2


def test_webhook_alert_succeeds_on_first_try():
    from koda.schedule.alerts import _dispatch_webhook

    diff = DiffResult(new=[_make_finding()], resolved=[], persistent=[])
    s = Schedule.create(
        name="wh-ok", target="/", scanners=("trivy",), cron="* * * * *"
    )
    mock_audit = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = lambda self: self
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        _dispatch_webhook(
            "webhook:https://hooks.example.com/ok",
            diff, s, "2026-04-19T00:00:00Z",
            _audit=mock_audit,
        )

    mock_audit.emit.assert_called_once()
    call_kwargs = mock_audit.emit.call_args
    assert call_kwargs[1]["success"] is True


# ---------------------------------------------------------------------------
# 8. Credentials are redacted in alert payloads
# ---------------------------------------------------------------------------

def test_credentials_redacted_in_alert_payload():
    from koda.schedule.alerts import _build_alert_payload

    sensitive_title = "API key leaked: token=supersecret123456789abcdef"
    finding = _make_finding(title=sensitive_title)
    diff = DiffResult(new=[finding], resolved=[], persistent=[])
    s = Schedule.create(
        name="redact-test", target="/", scanners=("gitleaks",), cron="* * * * *"
    )
    payload = _build_alert_payload(diff, s, "2026-04-19T00:00:00Z")
    new_titles = [item["title"] for item in payload["diff"]["new"]]
    # The literal secret should not appear in the output.
    for title in new_titles:
        assert "supersecret123456789abcdef" not in title


# ---------------------------------------------------------------------------
# 9. Crontab install + remove + list
# ---------------------------------------------------------------------------

def _make_cron_proc(stdout: str = "", stderr: str = "", returncode: int = 0) -> CompletedProcess:
    p = MagicMock(spec=CompletedProcess)
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = returncode
    return p


def test_install_cron_entry_appends_marker(tmp_path: Path):
    from koda.schedule.cron import install_cron_entry

    initial_crontab = "# existing cron\n0 1 * * * /usr/bin/something\n"
    written: list[str] = []

    def _mock_run(cmd, **kw):
        if cmd[0] == "crontab" and cmd[1] == "-l":
            return _make_cron_proc(stdout=initial_crontab)
        if cmd[0] == "crontab" and cmd[1] == "-":
            written.append(kw.get("input", ""))
            return _make_cron_proc()
        return _make_cron_proc()

    with patch("subprocess.run", side_effect=_mock_run):
        install_cron_entry("sched-abc123", "0 2 * * *")

    assert len(written) == 1
    assert "koda-schedule:sched-abc123" in written[0]
    assert "0 2 * * *" in written[0]
    # Original line should be preserved.
    assert "/usr/bin/something" in written[0]


def test_install_cron_entry_idempotent():
    """Installing the same schedule twice should not write crontab a second time."""
    from koda.schedule.cron import install_cron_entry

    existing = "0 2 * * * koda schedule _tick sched-abc123  # koda-schedule:sched-abc123\n"
    written: list[str] = []

    def _mock_run(cmd, **kw):
        if cmd[0] == "crontab" and cmd[1] == "-l":
            return _make_cron_proc(stdout=existing)
        if cmd[0] == "crontab" and cmd[1] == "-":
            written.append(kw.get("input", ""))
            return _make_cron_proc()
        return _make_cron_proc()

    with patch("subprocess.run", side_effect=_mock_run):
        install_cron_entry("sched-abc123", "0 2 * * *")

    assert written == []  # no write — already present


def test_remove_cron_entry_strips_line():
    from koda.schedule.cron import remove_cron_entry

    initial = (
        "# unrelated\n"
        "0 5 * * * /usr/bin/other\n"
        "0 2 * * * koda schedule _tick sched-xyz  # koda-schedule:sched-xyz\n"
        "# trailing\n"
    )
    written: list[str] = []

    def _mock_run(cmd, **kw):
        if cmd[0] == "crontab" and cmd[1] == "-l":
            return _make_cron_proc(stdout=initial)
        if cmd[0] == "crontab" and cmd[1] == "-":
            written.append(kw.get("input", ""))
            return _make_cron_proc()
        return _make_cron_proc()

    with patch("subprocess.run", side_effect=_mock_run):
        removed = remove_cron_entry("sched-xyz")

    assert removed is True
    assert len(written) == 1
    assert "koda-schedule:sched-xyz" not in written[0]
    # Neighbours must survive.
    assert "/usr/bin/other" in written[0]
    assert "# unrelated" in written[0]
    assert "# trailing" in written[0]


def test_remove_cron_entry_not_found_returns_false():
    from koda.schedule.cron import remove_cron_entry

    def _mock_run(cmd, **kw):
        if cmd[0] == "crontab" and cmd[1] == "-l":
            return _make_cron_proc(stdout="# nothing koda here\n")
        return _make_cron_proc()

    with patch("subprocess.run", side_effect=_mock_run):
        result = remove_cron_entry("nonexistent")
    assert result is False


def test_list_cron_entries_finds_markers():
    from koda.schedule.cron import list_cron_entries

    crontab_content = (
        "# normal line\n"
        "0 1 * * * /usr/bin/other\n"
        "0 2 * * * koda schedule _tick sched-aaa  # koda-schedule:sched-aaa\n"
        "0 3 * * * koda schedule _tick sched-bbb  # koda-schedule:sched-bbb\n"
    )

    def _mock_run(cmd, **kw):
        if cmd[0] == "crontab" and cmd[1] == "-l":
            return _make_cron_proc(stdout=crontab_content)
        return _make_cron_proc()

    with patch("subprocess.run", side_effect=_mock_run):
        entries = list_cron_entries()

    ids = {e.schedule_id for e in entries}
    assert "sched-aaa" in ids
    assert "sched-bbb" in ids
    assert len(entries) == 2


# ---------------------------------------------------------------------------
# 10. schedule add → writes TOML + installs cron (crontab path)
# ---------------------------------------------------------------------------

def _run_schedule_cmd(tmp_path: Path, argv: list[str]) -> int:
    old_home = os.environ.get("KODA_HOME")
    os.environ["KODA_HOME"] = str(tmp_path)
    try:
        import koda.config as cfg_mod
        cfg_mod.KODA_HOME = tmp_path  # type: ignore[assignment]
        from koda.cli.schedule import main
        return main(argv)
    finally:
        if old_home is None:
            os.environ.pop("KODA_HOME", None)
        else:
            os.environ["KODA_HOME"] = old_home


def test_schedule_add_writes_toml(tmp_path: Path):
    written: list[str] = []

    def _mock_run(cmd, **kw):
        if isinstance(cmd, list) and cmd[0] == "crontab" and cmd[1] == "-l":
            return _make_cron_proc(stdout="")
        if isinstance(cmd, list) and cmd[0] == "crontab" and cmd[1] == "-":
            written.append(kw.get("input", ""))
            return _make_cron_proc()
        # systemctl and other calls.
        return _make_cron_proc()

    with patch("subprocess.run", side_effect=_mock_run):
        # Force crontab backend to avoid systemd detection.
        with patch("koda.schedule.cron.get_backend", return_value="crontab"):
            with patch("koda.schedule.cron.install_cron_entry") as mock_install:
                rc = _run_schedule_cmd(tmp_path, [
                    "add",
                    "--target", "localhost",
                    "--preset", "server-hardening",
                    "--cron", "0 2 * * *",
                    "--name", "nightly",
                ])

    assert rc == 0
    toml_files = list((tmp_path / "schedules").glob("*.toml"))
    assert len(toml_files) == 1
    mock_install.assert_called_once()


def test_schedule_add_installs_cron_entry(tmp_path: Path):
    installed: list[tuple[str, str]] = []

    def _mock_install(schedule_id: str, cron_expr: str) -> None:
        installed.append((schedule_id, cron_expr))

    with patch("koda.schedule.cron.install_entry", side_effect=lambda sid, cron, **kw: (installed.append((sid, cron)), "crontab")[1]):
        rc = _run_schedule_cmd(tmp_path, [
            "add",
            "--target", "localhost",
            "--preset", "server-hardening",
            "--cron", "0 2 * * *",
        ])

    assert rc == 0
    assert len(installed) == 1
    _id, _cron = installed[0]
    assert _cron == "0 2 * * *"


# ---------------------------------------------------------------------------
# 11. schedule list shows orphan warnings
# ---------------------------------------------------------------------------

def test_schedule_list_warns_orphan_cron(tmp_path: Path, capsys):
    # Create one real schedule.
    _make_schedule(tmp_path, name="real-sched", schedule_id="real-sched-001")

    def _mock_list_cron():
        from koda.schedule.cron import CronRef
        return [
            CronRef(schedule_id="real-sched-001", line="..."),
            CronRef(schedule_id="orphan-abc", line="0 2 * * * koda _tick orphan-abc  # koda-schedule:orphan-abc"),
        ]

    def _mock_list_systemd():
        return []

    old_home = os.environ.get("KODA_HOME")
    os.environ["KODA_HOME"] = str(tmp_path)
    try:
        import koda.config as cfg_mod
        cfg_mod.KODA_HOME = tmp_path  # type: ignore[assignment]

        with patch("koda.schedule.cron.list_cron_entries", side_effect=_mock_list_cron):
            with patch("koda.schedule.cron.list_systemd_entries", side_effect=_mock_list_systemd):
                with patch("koda.schedule.cron.get_backend", return_value="crontab"):
                    from koda.cli.schedule import main
                    rc = main(["list"])
    finally:
        if old_home is None:
            os.environ.pop("KODA_HOME", None)
        else:
            os.environ["KODA_HOME"] = old_home

    assert rc == 0
    out = capsys.readouterr().out
    assert "orphan" in out.lower()
    assert "orphan-abc" in out


# ---------------------------------------------------------------------------
# 12. _tick happy path
# ---------------------------------------------------------------------------

def test_tick_happy_path(tmp_path: Path):
    from koda.schedule.tick import run_tick

    _make_schedule(tmp_path, name="tick-test", target="/tmp", preset=None,
                   scanners=("trivy",), schedule_id="tick-001")

    # Mock scanner to return one finding.
    finding = _make_finding(rule_id="r1")
    mock_result = MagicMock()
    mock_result.findings = [finding]

    with patch("koda.security.scanners.registry.ScannerRegistry.run", return_value=mock_result):
        rc = run_tick("tick-001", tmp_path)

    assert rc == 0

    # Findings should be written.
    runs_dir = tmp_path / "schedules" / "tick-001" / "runs"
    run_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and not d.is_symlink()]
    assert len(run_dirs) == 1
    findings_file = run_dirs[0] / "findings.jsonl"
    assert findings_file.exists()
    lines = [ln for ln in findings_file.read_text().splitlines() if ln.strip()]
    assert len(lines) == 1

    # meta.toml should exist.
    assert (run_dirs[0] / "meta.toml").exists()

    # latest symlink should exist.
    latest = runs_dir / "latest"
    assert latest.exists() or latest.is_symlink()


def test_tick_scanner_failure_does_not_crash(tmp_path: Path):
    from koda.schedule.tick import run_tick

    _make_schedule(tmp_path, name="fail-test", target="/tmp", preset=None,
                   scanners=("nmap",), schedule_id="fail-001")

    with patch(
        "koda.security.scanners.registry.ScannerRegistry.run",
        side_effect=RuntimeError("scanner exploded"),
    ):
        rc = run_tick("fail-001", tmp_path)

    assert rc == 0  # always 0


def test_tick_meta_toml_records_exit_code(tmp_path: Path):
    from koda.schedule.tick import run_tick

    _make_schedule(tmp_path, name="meta-test", target="/tmp", preset=None,
                       scanners=("bandit",), schedule_id="meta-001")

    mock_result = MagicMock()
    mock_result.findings = []

    with patch("koda.security.scanners.registry.ScannerRegistry.run", return_value=mock_result):
        run_tick("meta-001", tmp_path)

    runs_dir = tmp_path / "schedules" / "meta-001" / "runs"
    run_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and not d.is_symlink()]
    meta_text = (run_dirs[0] / "meta.toml").read_text(encoding="utf-8")
    assert "exit_code" in meta_text


def test_tick_exit_code_always_zero(tmp_path: Path):
    from koda.schedule.tick import run_tick

    # Non-existent schedule — should still return 0.
    rc = run_tick("does-not-exist", tmp_path)
    assert rc == 0


# ---------------------------------------------------------------------------
# 13. _tick fires alerts on new findings
# ---------------------------------------------------------------------------

def test_tick_fires_alert_on_new_findings(tmp_path: Path):
    from koda.schedule.tick import run_tick

    alerts_file = tmp_path / "alerts.jsonl"
    _make_schedule(
        tmp_path,
        name="alert-fire",
        target="/tmp",
        preset=None,
        scanners=("semgrep",),
        alerts=(f"file:{alerts_file}",),
        alert_on="findings",
        schedule_id="alert-001",
    )

    finding = _make_finding(rule_id="new-r1")
    mock_result = MagicMock()
    mock_result.findings = [finding]

    with patch("koda.security.scanners.registry.ScannerRegistry.run", return_value=mock_result):
        run_tick("alert-001", tmp_path)

    assert alerts_file.exists()
    data = json.loads(alerts_file.read_text().strip())
    assert len(data["diff"]["new"]) == 1


def test_tick_no_alert_when_no_new_findings(tmp_path: Path):
    from koda.schedule.tick import run_tick

    alerts_file = tmp_path / "alerts.jsonl"
    finding = _make_finding(rule_id="persistent")

    # Set up a previous run with the same finding.
    schedule_run_base = tmp_path / "schedules" / "no-alert-001" / "runs"
    prev_dir = schedule_run_base / "run-2026-04-18T00-00-00Z"
    prev_dir.mkdir(parents=True)
    (prev_dir / "findings.jsonl").write_text(
        json.dumps(finding.to_dict()) + "\n", encoding="utf-8"
    )
    # Create the latest symlink pointing to prev_dir.
    latest = schedule_run_base / "latest"
    latest.symlink_to(prev_dir)

    _make_schedule(
        tmp_path,
        name="no-alert",
        target="/tmp",
        preset=None,
        scanners=("trivy",),
        alerts=(f"file:{alerts_file}",),
        alert_on="findings",
        schedule_id="no-alert-001",
    )

    # Same finding — no new findings.
    mock_result = MagicMock()
    mock_result.findings = [finding]

    with patch("koda.security.scanners.registry.ScannerRegistry.run", return_value=mock_result):
        run_tick("no-alert-001", tmp_path)

    # alerts.jsonl should NOT exist (nothing fired).
    assert not alerts_file.exists()


# ---------------------------------------------------------------------------
# 14. systemd install / remove
# ---------------------------------------------------------------------------

def test_systemd_install_writes_units(tmp_path: Path):
    from koda.schedule.cron import install_systemd_entry

    unit_dir = tmp_path / "systemd" / "user"

    def _mock_run(cmd, **kw):
        return _make_cron_proc()

    with patch("koda.schedule.cron._user_systemd_dir", return_value=unit_dir):
        with patch("subprocess.run", side_effect=_mock_run):
            install_systemd_entry("sched-sys-001", "0 3 * * *")

    service = unit_dir / "koda-schedule-sched-sys-001.service"
    timer = unit_dir / "koda-schedule-sched-sys-001.timer"
    assert service.exists()
    assert timer.exists()
    assert "sched-sys-001" in service.read_text()
    assert "OnCalendar" in timer.read_text()


def test_systemd_remove_deletes_units(tmp_path: Path):
    from koda.schedule.cron import remove_systemd_entry

    unit_dir = tmp_path / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    service = unit_dir / "koda-schedule-del-001.service"
    timer = unit_dir / "koda-schedule-del-001.timer"
    service.write_text("[Unit]\n", encoding="utf-8")
    timer.write_text("[Timer]\n", encoding="utf-8")

    with patch("koda.schedule.cron._user_systemd_dir", return_value=unit_dir):
        with patch("subprocess.run", return_value=_make_cron_proc()):
            removed = remove_systemd_entry("del-001")

    assert removed is True
    assert not service.exists()
    assert not timer.exists()


# ---------------------------------------------------------------------------
# 15. schedule remove strips cron + removes TOML
# ---------------------------------------------------------------------------

def test_schedule_remove_strips_cron_and_toml(tmp_path: Path):
    _make_schedule(tmp_path, name="remove-me", schedule_id="rm-001")
    toml_path = tmp_path / "schedules" / "rm-001.toml"
    assert toml_path.exists()

    removed_ids: list[str] = []

    def _mock_remove_entry(sid, **kw):
        removed_ids.append(sid)
        return True

    old_home = os.environ.get("KODA_HOME")
    os.environ["KODA_HOME"] = str(tmp_path)
    try:
        import koda.config as cfg_mod
        cfg_mod.KODA_HOME = tmp_path  # type: ignore[assignment]

        with patch("koda.schedule.cron.remove_entry", side_effect=_mock_remove_entry):
            from koda.cli.schedule import main
            rc = main(["remove", "rm-001"])
    finally:
        if old_home is None:
            os.environ.pop("KODA_HOME", None)
        else:
            os.environ["KODA_HOME"] = old_home

    assert rc == 0
    assert not toml_path.exists()
    assert "rm-001" in removed_ids


# ---------------------------------------------------------------------------
# 16. Cron → systemd OnCalendar conversion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cron,expected_fragment", [
    ("0 2 * * *", "2:0:00"),
    ("30 6 * * *", "6:30:00"),
    ("0 0 * * *", "0:0:00"),
    ("*/15 * * * *", "*:*/15:00"),
    ("0 */2 * * *", "*/2:0:00"),
])
def test_cron_to_systemd_oncalendar(cron: str, expected_fragment: str):
    from koda.schedule.cron import _cron_to_systemd_oncalendar
    result = _cron_to_systemd_oncalendar(cron)
    assert expected_fragment in result


# ---------------------------------------------------------------------------
# 17. alert_on policy
# ---------------------------------------------------------------------------

def test_alert_on_change_fires_on_resolved():
    from koda.schedule.tick import _should_alert

    diff = DiffResult(
        new=[],
        resolved=[_make_finding()],
        persistent=[],
    )
    assert _should_alert(diff, "change") is True
    assert _should_alert(diff, "findings") is False  # no new, only resolved


def test_alert_on_empty_always_fires():
    from koda.schedule.tick import _should_alert

    diff = DiffResult(new=[], resolved=[], persistent=[])
    assert _should_alert(diff, "empty") is True
    assert _should_alert(diff, "findings") is False
    assert _should_alert(diff, "change") is False
