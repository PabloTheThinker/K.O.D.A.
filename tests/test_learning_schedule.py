"""Tests for ``koda.learning.schedule`` — install/remove/get the nightly cron entry."""
from __future__ import annotations

from typing import Any

import pytest

from koda.learning import schedule as sched


class _FakeCrontab:
    """In-memory stand-in for the user's crontab."""

    def __init__(self, initial: str = "") -> None:
        self.content = initial
        self.writes: list[str] = []

    def read(self, *_args: Any, **_kwargs: Any):
        class R:
            pass
        r = R()
        r.returncode = 0
        r.stdout = self.content
        r.stderr = ""
        return r

    def run(self, argv, *, input=None, capture_output=False, text=True, check=False, **_kw):
        if argv == ["crontab", "-l"]:
            return self.read()
        if argv == ["crontab", "-"]:
            assert input is not None
            self.content = input
            self.writes.append(input)

            class R:
                returncode = 0
            return R()
        raise AssertionError(f"unexpected argv: {argv}")


@pytest.fixture()
def fake_cron(monkeypatch: pytest.MonkeyPatch) -> _FakeCrontab:
    fake = _FakeCrontab()
    monkeypatch.setattr(sched.subprocess, "run", fake.run)
    return fake


def test_install_writes_entry(fake_cron: _FakeCrontab) -> None:
    entry = sched.install_learn_schedule()
    assert entry.cron_expr == sched.DEFAULT_CRON_EXPR
    assert "koda-learn" in entry.raw
    assert "koda learn run" in entry.command
    assert "# koda-learn" in fake_cron.content


def test_install_is_idempotent(fake_cron: _FakeCrontab) -> None:
    sched.install_learn_schedule()
    sched.install_learn_schedule(cron_expr="30 3 * * *")
    lines = [ln for ln in fake_cron.content.splitlines() if "koda-learn" in ln]
    assert len(lines) == 1
    assert lines[0].startswith("30 3 * * *")


def test_install_preserves_foreign_entries(fake_cron: _FakeCrontab) -> None:
    fake_cron.content = "0 5 * * * /home/alice/backup.sh\n"
    sched.install_learn_schedule()
    assert "/home/alice/backup.sh" in fake_cron.content
    assert "# koda-learn" in fake_cron.content


def test_remove_returns_true_when_present(fake_cron: _FakeCrontab) -> None:
    sched.install_learn_schedule()
    assert sched.remove_learn_schedule() is True
    assert "koda-learn" not in fake_cron.content


def test_remove_returns_false_when_absent(fake_cron: _FakeCrontab) -> None:
    assert sched.remove_learn_schedule() is False


def test_get_returns_parsed_entry(fake_cron: _FakeCrontab) -> None:
    sched.install_learn_schedule(cron_expr="15 4 * * *")
    entry = sched.get_learn_schedule()
    assert entry is not None
    assert entry.cron_expr == "15 4 * * *"
    assert "koda learn" in entry.command
    assert "# koda-learn" not in entry.command  # marker stripped


def test_get_returns_none_when_absent(fake_cron: _FakeCrontab) -> None:
    assert sched.get_learn_schedule() is None


# ── report schedule ───────────────────────────────────────────────


def test_report_install_writes_separate_entry(fake_cron: _FakeCrontab) -> None:
    entry = sched.install_report_schedule(cron_expr="0 8 * * *")
    assert entry.cron_expr == "0 8 * * *"
    assert "# koda-learn-report" in entry.raw
    assert "koda learn report" in entry.command


def test_learn_and_report_coexist(fake_cron: _FakeCrontab) -> None:
    sched.install_learn_schedule()
    sched.install_report_schedule()
    lines = fake_cron.content.splitlines()
    learn_lines = [
        ln for ln in lines
        if "# koda-learn" in ln and "# koda-learn-report" not in ln
    ]
    report_lines = [ln for ln in lines if "# koda-learn-report" in ln]
    assert len(learn_lines) == 1
    assert len(report_lines) == 1


def test_report_remove_does_not_touch_learn(fake_cron: _FakeCrontab) -> None:
    sched.install_learn_schedule()
    sched.install_report_schedule()
    assert sched.remove_report_schedule() is True
    assert "# koda-learn-report" not in fake_cron.content
    # Learn entry survives.
    assert sched.get_learn_schedule() is not None


def test_learn_remove_does_not_touch_report(fake_cron: _FakeCrontab) -> None:
    sched.install_learn_schedule()
    sched.install_report_schedule()
    assert sched.remove_learn_schedule() is True
    # The report entry survives.
    entry = sched.get_report_schedule()
    assert entry is not None
    assert "koda learn report" in entry.command


def test_report_install_is_idempotent(fake_cron: _FakeCrontab) -> None:
    sched.install_report_schedule()
    sched.install_report_schedule(cron_expr="15 7 * * *")
    lines = [ln for ln in fake_cron.content.splitlines() if "# koda-learn-report" in ln]
    assert len(lines) == 1
    assert lines[0].startswith("15 7 * * *")


def test_get_report_returns_none_when_absent(fake_cron: _FakeCrontab) -> None:
    assert sched.get_report_schedule() is None
