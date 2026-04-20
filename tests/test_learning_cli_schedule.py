"""Tests for the simplified ``koda learn schedule`` / ``koda learn report`` surface."""
from __future__ import annotations

from typing import Any

import pytest

from koda.cli import learn as cli
from koda.learning import schedule as sched

# ── time parser ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("8am", "0 8 * * *"),
        ("8AM", "0 8 * * *"),
        ("12am", "0 0 * * *"),
        ("12pm", "0 12 * * *"),
        ("2:30pm", "30 14 * * *"),
        ("14:00", "0 14 * * *"),
        ("14:30", "30 14 * * *"),
        ("0 8 * * *", "0 8 * * *"),
        ("*/15 * * * *", "*/15 * * * *"),
        ("0 8 * * 1-5", "0 8 * * 1-5"),
    ],
)
def test_time_parser_accepts(text: str, expected: str) -> None:
    assert cli._parse_time_to_cron(text) == expected


@pytest.mark.parametrize(
    "text",
    ["", "potato", "25:00", "13pm", "8:99am", "not a time"],
)
def test_time_parser_rejects(text: str) -> None:
    assert cli._parse_time_to_cron(text) is None


# ── CLI surface ──────────────────────────────────────────────────────


class _FakeCrontab:
    def __init__(self) -> None:
        self.content = ""

    def run(self, argv, *, input=None, capture_output=False, text=True, check=False, **_kw: Any):
        if argv == ["crontab", "-l"]:
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            r = R()
            r.stdout = self.content
            return r
        if argv == ["crontab", "-"]:
            assert input is not None
            self.content = input

            class W:
                returncode = 0
            return W()
        raise AssertionError(f"unexpected argv: {argv}")


@pytest.fixture()
def fake_cron(monkeypatch: pytest.MonkeyPatch) -> _FakeCrontab:
    fake = _FakeCrontab()
    monkeypatch.setattr(sched.subprocess, "run", fake.run)
    return fake


def test_schedule_install_via_time(fake_cron: _FakeCrontab, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli._cmd_schedule(["8am"])
    assert rc == 0
    assert "0 8 * * *" in fake_cron.content
    assert "# koda-learn" in fake_cron.content
    assert "scheduled" in capsys.readouterr().out


def test_schedule_install_via_clock_time(fake_cron: _FakeCrontab) -> None:
    assert cli._cmd_schedule(["14:30"]) == 0
    assert "30 14 * * *" in fake_cron.content


def test_schedule_off_removes_entry(fake_cron: _FakeCrontab) -> None:
    cli._cmd_schedule(["8am"])
    assert cli._cmd_schedule(["off"]) == 0
    assert "# koda-learn" not in fake_cron.content


def test_schedule_bare_shows_status(
    fake_cron: _FakeCrontab, capsys: pytest.CaptureFixture[str],
) -> None:
    cli._cmd_schedule(["8am"])
    capsys.readouterr()  # drain install output
    cli._cmd_schedule([])
    out = capsys.readouterr().out
    assert "0 8 * * *" in out


def test_schedule_rejects_gibberish(
    fake_cron: _FakeCrontab, capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli._cmd_schedule(["bananas"])
    assert rc == 2
    assert "could not parse" in capsys.readouterr().err


def test_report_time_schedules_digest(
    fake_cron: _FakeCrontab, capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli._cmd_report(["8am"])
    assert rc == 0
    assert "# koda-learn-report" in fake_cron.content
    assert "0 8 * * *" in fake_cron.content


def test_report_off_removes_digest_schedule(fake_cron: _FakeCrontab) -> None:
    cli._cmd_report(["9am"])
    assert cli._cmd_report(["off"]) == 0
    assert "# koda-learn-report" not in fake_cron.content


def test_report_status_shows_schedule(
    fake_cron: _FakeCrontab, capsys: pytest.CaptureFixture[str],
) -> None:
    cli._cmd_report(["9am"])
    capsys.readouterr()
    cli._cmd_report(["status"])
    assert "0 9 * * *" in capsys.readouterr().out


def test_report_bare_generates_digest(
    fake_cron: _FakeCrontab, tmp_path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from koda.learning import report as report_mod
    from koda.learning import store as store_mod

    store = store_mod.LearnedSkillStore(tmp_path / "_learned")
    monkeypatch.setattr(report_mod, "default_store", lambda: store)
    monkeypatch.setattr(store_mod, "default_store", lambda: store)

    rc = cli._cmd_report([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "digest delivered" in out
    assert (tmp_path / "_learned" / "_reports").is_dir()


def test_report_stdout_still_works(
    fake_cron: _FakeCrontab, tmp_path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from koda.learning import report as report_mod
    from koda.learning import store as store_mod

    store = store_mod.LearnedSkillStore(tmp_path / "_learned")
    monkeypatch.setattr(report_mod, "default_store", lambda: store)

    rc = cli._cmd_report(["--stdout"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "KODA learning digest" in out


def test_report_and_schedule_coexist_via_time_args(fake_cron: _FakeCrontab) -> None:
    cli._cmd_schedule(["2am"])
    cli._cmd_report(["8am"])
    lines = fake_cron.content.splitlines()
    assert any("# koda-learn-report" in ln for ln in lines)
    assert any(
        "# koda-learn" in ln and "# koda-learn-report" not in ln for ln in lines
    )


# ── flag wiring: --format and --deliver ────────────────────────────


def test_report_schedule_bakes_format_and_deliver(fake_cron: _FakeCrontab) -> None:
    rc = cli._cmd_report(["8am", "--format", "pdf", "--deliver", "telegram"])
    assert rc == 0
    line = next(
        ln for ln in fake_cron.content.splitlines() if "# koda-learn-report" in ln
    )
    assert "--format pdf" in line
    assert "--deliver telegram" in line
    assert "--since 24h" in line


def test_report_schedule_bakes_custom_since(fake_cron: _FakeCrontab) -> None:
    rc = cli._cmd_report(["8am", "--since", "7d"])
    assert rc == 0
    line = next(
        ln for ln in fake_cron.content.splitlines() if "# koda-learn-report" in ln
    )
    assert "--since 7d" in line


def test_report_split_flags_before_time(fake_cron: _FakeCrontab) -> None:
    # Flags first, time last — the splitter should still find it.
    rc = cli._cmd_report(["--format", "pdf", "8am"])
    assert rc == 0
    assert "# koda-learn-report" in fake_cron.content
    assert "--format pdf" in fake_cron.content


def test_report_rejects_unknown_flag(
    fake_cron: _FakeCrontab, capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli._cmd_report(["--garbage"])
    assert rc == 2
    assert "unknown flag" in capsys.readouterr().err


def test_report_rejects_unknown_format(
    fake_cron: _FakeCrontab, tmp_path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from koda.learning import report as report_mod
    from koda.learning import store as store_mod

    store = store_mod.LearnedSkillStore(tmp_path / "_learned")
    monkeypatch.setattr(report_mod, "default_store", lambda: store)
    monkeypatch.setattr(store_mod, "default_store", lambda: store)

    rc = cli._cmd_report(["--format", "docx"])
    assert rc == 2
    assert "unknown --format" in capsys.readouterr().err


def test_report_deliver_stdout_via_flag(
    fake_cron: _FakeCrontab, tmp_path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from koda.learning import report as report_mod
    from koda.learning import store as store_mod

    store = store_mod.LearnedSkillStore(tmp_path / "_learned")
    monkeypatch.setattr(report_mod, "default_store", lambda: store)
    monkeypatch.setattr(store_mod, "default_store", lambda: store)

    rc = cli._cmd_report(["--deliver", "stdout"])
    assert rc == 0
    assert "KODA learning digest" in capsys.readouterr().out


def test_report_env_defaults_pick_up(
    fake_cron: _FakeCrontab, tmp_path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from koda.learning import report as report_mod
    from koda.learning import store as store_mod

    store = store_mod.LearnedSkillStore(tmp_path / "_learned")
    monkeypatch.setattr(report_mod, "default_store", lambda: store)
    monkeypatch.setattr(store_mod, "default_store", lambda: store)
    monkeypatch.setenv("KODA_REPORT_DELIVER", "stdout")
    monkeypatch.setenv("KODA_REPORT_FORMAT", "md")

    rc = cli._cmd_report([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "KODA learning digest" in out
