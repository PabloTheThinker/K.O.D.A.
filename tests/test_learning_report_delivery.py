"""Tests for :mod:`koda.learning.report_delivery`.

Covers the factory, env defaults, and every backend (file/stdout/telegram/
webhook). Telegram and webhook tests stub ``httpx.post`` so nothing leaves
the test process.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from koda.learning.report import Report
from koda.learning.report_delivery import (
    DeliveryError,
    FileDelivery,
    StdoutDelivery,
    TelegramDelivery,
    WebhookDelivery,
    create_delivery,
    default_delivery_name,
    default_format_name,
)


def _report() -> Report:
    return Report(
        generated_at=datetime(2026, 4, 20, tzinfo=UTC),
        since=datetime(2026, 4, 19, tzinfo=UTC),
    )


# ── factory + env defaults ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "cls"),
    [
        ("file", FileDelivery),
        ("stdout", StdoutDelivery),
        ("telegram", TelegramDelivery),
        ("webhook", WebhookDelivery),
        ("FILE", FileDelivery),
        ("  stdout ", StdoutDelivery),
        ("", FileDelivery),
    ],
)
def test_create_delivery_returns_backend(name: str, cls: type) -> None:
    assert isinstance(create_delivery(name), cls)


def test_create_delivery_rejects_unknown() -> None:
    with pytest.raises(DeliveryError):
        create_delivery("carrier-pigeon")


def test_default_delivery_name_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KODA_REPORT_DELIVER", "Telegram")
    assert default_delivery_name() == "telegram"


def test_default_delivery_name_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KODA_REPORT_DELIVER", raising=False)
    assert default_delivery_name() == "file"


def test_default_format_name_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KODA_REPORT_FORMAT", "PDF")
    assert default_format_name() == "pdf"


def test_default_format_name_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KODA_REPORT_FORMAT", raising=False)
    assert default_format_name() == "md"


# ── file backend ───────────────────────────────────────────────────


def test_file_delivery_writes_payload(tmp_path) -> None:
    backend = FileDelivery(reports_dir=tmp_path)
    result = backend.send(
        report=_report(),
        payload=b"# digest\n",
        filename="LEARNED.md",
        fmt="md",
    )
    written = tmp_path / "LEARNED.md"
    assert written.read_bytes() == b"# digest\n"
    assert result.backend == "file"
    assert result.detail == str(written)


def test_file_delivery_is_atomic(tmp_path) -> None:
    """The tmp file used during write should be cleaned up after replace."""
    backend = FileDelivery(reports_dir=tmp_path)
    backend.send(
        report=_report(), payload=b"hi", filename="r.md", fmt="md",
    )
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []


def test_file_delivery_creates_directory(tmp_path) -> None:
    target = tmp_path / "nested" / "reports"
    backend = FileDelivery(reports_dir=target)
    backend.send(
        report=_report(), payload=b"x", filename="r.md", fmt="md",
    )
    assert (target / "r.md").is_file()


# ── stdout backend ─────────────────────────────────────────────────


def test_stdout_delivery_prints_markdown(capsys: pytest.CaptureFixture[str]) -> None:
    backend = StdoutDelivery()
    result = backend.send(
        report=_report(), payload=b"# hello", filename="r.md", fmt="md",
    )
    assert "# hello" in capsys.readouterr().out
    assert result.backend == "stdout"


def test_stdout_delivery_rejects_pdf() -> None:
    backend = StdoutDelivery()
    with pytest.raises(DeliveryError):
        backend.send(
            report=_report(), payload=b"%PDF-", filename="r.pdf", fmt="pdf",
        )


# ── telegram backend ───────────────────────────────────────────────


class _FakeHTTPResponse:
    def __init__(self, status_code: int = 200, text: str = "{\"ok\": true}") -> None:
        self.status_code = status_code
        self.text = text


def test_telegram_delivery_posts_document(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict = {}

    def fake_post(url, **kwargs):
        calls["url"] = url
        calls["data"] = kwargs.get("data")
        calls["files"] = kwargs.get("files")
        return _FakeHTTPResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    backend = TelegramDelivery(token="TKN", chat_id="42")
    result = backend.send(
        report=_report(),
        payload=b"# content",
        filename="LEARNED.md",
        fmt="md",
    )
    assert "bot" in calls["url"] and "sendDocument" in calls["url"]
    assert calls["data"]["chat_id"] == "42"
    assert "caption" in calls["data"]
    assert calls["files"]["document"][0] == "LEARNED.md"
    assert calls["files"]["document"][2] == "text/markdown"
    assert result.backend == "telegram"
    assert "42" in result.detail


def test_telegram_delivery_uses_pdf_mime(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return _FakeHTTPResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    backend = TelegramDelivery(token="TKN", chat_id="42")
    backend.send(
        report=_report(), payload=b"%PDF-", filename="r.pdf", fmt="pdf",
    )
    assert captured["files"]["document"][2] == "application/pdf"


def test_telegram_delivery_requires_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KODA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("KODA_TELEGRAM_CHAT_ID", raising=False)
    backend = TelegramDelivery()
    with pytest.raises(DeliveryError) as excinfo:
        backend.send(
            report=_report(), payload=b"x", filename="r.md", fmt="md",
        )
    assert "KODA_TELEGRAM" in str(excinfo.value)


def test_telegram_delivery_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KODA_TELEGRAM_BOT_TOKEN", "env-token")
    monkeypatch.setenv("KODA_TELEGRAM_CHAT_ID", "env-chat")

    captured: dict = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _FakeHTTPResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    TelegramDelivery().send(
        report=_report(), payload=b"x", filename="r.md", fmt="md",
    )
    assert "env-token" in captured["url"]
    assert captured["data"]["chat_id"] == "env-chat"


def test_telegram_delivery_raises_on_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_post(url, **kwargs):
        return _FakeHTTPResponse(status_code=500, text="kaboom")

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    backend = TelegramDelivery(token="TKN", chat_id="1")
    with pytest.raises(DeliveryError) as excinfo:
        backend.send(
            report=_report(), payload=b"x", filename="r.md", fmt="md",
        )
    assert "500" in str(excinfo.value)


def test_telegram_delivery_raises_on_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    def fake_post(url, **kwargs):
        raise httpx.ConnectError("unreachable")

    monkeypatch.setattr(httpx, "post", fake_post)

    backend = TelegramDelivery(token="TKN", chat_id="1")
    with pytest.raises(DeliveryError) as excinfo:
        backend.send(
            report=_report(), payload=b"x", filename="r.md", fmt="md",
        )
    assert "telegram send failed" in str(excinfo.value)


# ── webhook backend ────────────────────────────────────────────────


def test_webhook_delivery_posts(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _FakeHTTPResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    backend = WebhookDelivery(url="https://example.test/hook")
    result = backend.send(
        report=_report(), payload=b"x", filename="r.md", fmt="md",
    )
    assert captured["url"] == "https://example.test/hook"
    assert captured["files"]["file"][0] == "r.md"
    assert result.backend == "webhook"
    assert result.detail == "https://example.test/hook"


def test_webhook_delivery_requires_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KODA_REPORT_WEBHOOK_URL", raising=False)
    with pytest.raises(DeliveryError) as excinfo:
        WebhookDelivery().send(
            report=_report(), payload=b"x", filename="r.md", fmt="md",
        )
    assert "KODA_REPORT_WEBHOOK_URL" in str(excinfo.value)


def test_webhook_delivery_raises_on_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_post(url, **kwargs):
        return _FakeHTTPResponse(status_code=400, text="bad")

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    with pytest.raises(DeliveryError) as excinfo:
        WebhookDelivery(url="https://x.test/h").send(
            report=_report(), payload=b"x", filename="r.md", fmt="md",
        )
    assert "400" in str(excinfo.value)
