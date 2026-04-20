"""Tests for the MCP-facing learn.* tools."""
from __future__ import annotations

import asyncio

import pytest

from koda.learning import schedule as sched
from koda.learning import store as store_mod
from koda.tools import builtins  # noqa: F401 — ensures registration
from koda.tools.registry import global_registry

_ = builtins


def _invoke(name: str, args: dict):
    return asyncio.run(global_registry().invoke(name, args))


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Every test gets a temp learning store so we never touch $KODA_HOME."""
    store = store_mod.LearnedSkillStore(tmp_path / "_learned")
    monkeypatch.setattr("koda.learning.report.default_store", lambda: store)
    monkeypatch.setattr("koda.learning.store.default_store", lambda: store)
    monkeypatch.setattr("koda.learning.default_store", lambda: store)
    monkeypatch.setattr("koda.tools.builtins.learn.default_store", lambda: store)
    return store


class _FakeCrontab:
    def __init__(self) -> None:
        self.content = ""

    def run(self, argv, *, input=None, **_kw):
        if argv == ["crontab", "-l"]:
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            r = R()
            r.stdout = self.content
            return r
        if argv == ["crontab", "-"]:
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


# ── discovery ────────────────────────────────────────────────────────


def test_learn_tools_registered() -> None:
    names = set(global_registry().names())
    assert {"learn.report", "learn.status", "learn.list", "learn.schedule_digest"} <= names


def test_learn_schedule_is_sensitive() -> None:
    tool = global_registry().get("learn.schedule_digest")
    assert tool is not None
    assert tool.risk.value == "sensitive"


def test_learn_report_schema_exposes_deliver_enum() -> None:
    tool = global_registry().get("learn.report")
    props = tool.input_schema["properties"]
    assert props["deliver"]["enum"] == ["file", "stdout", "telegram", "webhook"]
    assert props["format"]["enum"] == ["md", "pdf"]


# ── learn.report ─────────────────────────────────────────────────────


def test_learn_report_file_backend_writes_digest(tmp_path) -> None:
    result = _invoke("learn.report", {"deliver": "file"})
    assert result.is_error is False
    assert "digest delivered" in result.content
    assert result.metadata["backend"] == "file"
    # The FileDelivery wrote under the temp store.
    reports = list((tmp_path / "_learned" / "_reports").glob("LEARNED-*.md"))
    assert len(reports) == 1


def test_learn_report_stdout_backend(capsys: pytest.CaptureFixture[str]) -> None:
    result = _invoke("learn.report", {"deliver": "stdout"})
    assert result.is_error is False
    assert "KODA learning digest" in capsys.readouterr().out


def test_learn_report_rejects_unknown_format() -> None:
    result = _invoke("learn.report", {"format": "docx"})
    assert result.is_error is True
    assert "unknown format" in result.content


def test_learn_report_rejects_unknown_delivery() -> None:
    result = _invoke("learn.report", {"deliver": "carrier-pigeon"})
    assert result.is_error is True


def test_learn_report_since_all_means_lifetime() -> None:
    result = _invoke("learn.report", {"deliver": "stdout", "since": "all"})
    assert result.is_error is False


# ── learn.status / list ───────────────────────────────────────────────


def test_learn_status_returns_zero_counts() -> None:
    result = _invoke("learn.status", {})
    assert result.is_error is False
    assert "pending  : 0" in result.content
    assert "approved : 0" in result.content
    assert result.metadata == {"pending": 0, "approved": 0, "scheduled": False}


def test_learn_list_empty_buckets() -> None:
    result = _invoke("learn.list", {})
    assert result.is_error is False
    assert "pending (0)" in result.content
    assert "approved (0)" in result.content


# ── learn.schedule_digest ─────────────────────────────────────────────


def test_schedule_digest_install(fake_cron: _FakeCrontab) -> None:
    result = _invoke("learn.schedule_digest", {"time": "10am"})
    assert result.is_error is False
    assert "0 10 * * *" in fake_cron.content
    assert "# koda-learn-report" in fake_cron.content


def test_schedule_digest_bakes_format_and_deliver(fake_cron: _FakeCrontab) -> None:
    result = _invoke("learn.schedule_digest", {
        "time": "8am", "format": "pdf", "deliver": "telegram",
    })
    assert result.is_error is False
    line = next(
        ln for ln in fake_cron.content.splitlines()
        if "# koda-learn-report" in ln
    )
    assert "--format pdf" in line
    assert "--deliver telegram" in line


def test_schedule_digest_off(fake_cron: _FakeCrontab) -> None:
    _invoke("learn.schedule_digest", {"time": "9am"})
    result = _invoke("learn.schedule_digest", {"time": "off"})
    assert result.is_error is False
    assert "# koda-learn-report" not in fake_cron.content


def test_schedule_digest_status_when_absent(fake_cron: _FakeCrontab) -> None:
    result = _invoke("learn.schedule_digest", {"time": "status"})
    assert result.is_error is False
    assert "no digest schedule" in result.content


def test_schedule_digest_status_when_installed(fake_cron: _FakeCrontab) -> None:
    _invoke("learn.schedule_digest", {"time": "14:00", "format": "pdf"})
    result = _invoke("learn.schedule_digest", {"time": "status"})
    assert result.is_error is False
    assert "0 14 * * *" in result.content


def test_schedule_digest_rejects_gibberish(fake_cron: _FakeCrontab) -> None:
    result = _invoke("learn.schedule_digest", {"time": "bananas"})
    assert result.is_error is True
    assert "could not parse" in result.content


def test_schedule_digest_rejects_bad_format(fake_cron: _FakeCrontab) -> None:
    result = _invoke("learn.schedule_digest", {"time": "8am", "format": "docx"})
    assert result.is_error is True
