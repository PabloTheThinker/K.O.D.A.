"""Delivery backends for KODA learning digests.

A framework-level abstraction so any KODA install can pipe reports to the
channel the user actually reads — file, stdout, Telegram, or a generic
webhook. Adding another backend (email, Slack, Discord) is a new class
with a ``send()`` method plus a line in :func:`create_delivery`.

Configuration comes from environment variables so users can set channels
once in ``secrets.env`` and forget about them:

  ============================  ============================================
  KODA_REPORT_DELIVER           default delivery (file | stdout | telegram | webhook)
  KODA_REPORT_FORMAT            default format (md | pdf)
  KODA_TELEGRAM_BOT_TOKEN       Telegram Bot API token
  KODA_TELEGRAM_CHAT_ID         Telegram chat ID
  KODA_REPORT_WEBHOOK_URL       URL to POST the rendered file to
  ============================  ============================================

The CLI's ``--deliver`` flag overrides the env default.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from koda.learning.report import Report


@dataclass
class DeliveryResult:
    backend: str
    detail: str  # file path, URL, message_id — whatever the backend returns


class DeliveryError(RuntimeError):
    """Raised when a backend is misconfigured or the remote call fails."""


class Delivery(ABC):
    """Contract for a single delivery target."""

    name: str

    @abstractmethod
    def send(
        self,
        *,
        report: Report,
        payload: bytes,
        filename: str,
        fmt: str,
    ) -> DeliveryResult:
        ...


class FileDelivery(Delivery):
    """Default — write the rendered payload to ``_learned/_reports/``."""

    name = "file"

    def __init__(self, reports_dir: Path | None = None) -> None:
        self.reports_dir = reports_dir

    def send(self, *, report, payload, filename, fmt):
        target_dir = self.reports_dir
        if target_dir is None:
            from koda.learning.report import REPORTS_DIRNAME
            from koda.learning.store import default_store
            target_dir = default_store().root / REPORTS_DIRNAME
        target_dir.mkdir(parents=True, exist_ok=True)
        dest = target_dir / filename
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_bytes(payload)
        tmp.replace(dest)
        return DeliveryResult(backend=self.name, detail=str(dest))


class StdoutDelivery(Delivery):
    """Print to stdout. Only meaningful for Markdown payloads."""

    name = "stdout"

    def send(self, *, report, payload, filename, fmt):
        import sys

        if fmt == "pdf":
            raise DeliveryError("stdout delivery supports markdown only, not pdf")
        text = payload.decode("utf-8", errors="replace")
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return DeliveryResult(backend=self.name, detail=f"{len(payload)} bytes")


class TelegramDelivery(Delivery):
    """Send the rendered report as a Telegram document.

    Uses the Bot API's ``sendDocument`` endpoint. Bot token + chat id
    come from env vars so the scheduled cron line doesn't leak secrets.
    """

    name = "telegram"
    _API = "https://api.telegram.org"

    def __init__(
        self,
        *,
        token: str | None = None,
        chat_id: str | None = None,
        api_base: str | None = None,
    ) -> None:
        self.token = token or os.environ.get("KODA_TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("KODA_TELEGRAM_CHAT_ID", "")
        self.api_base = api_base or self._API

    def send(self, *, report, payload, filename, fmt):
        if not self.token or not self.chat_id:
            raise DeliveryError(
                "telegram delivery needs KODA_TELEGRAM_BOT_TOKEN + "
                "KODA_TELEGRAM_CHAT_ID in your environment"
            )
        import httpx

        url = f"{self.api_base}/bot{self.token}/sendDocument"
        caption = _caption(report)
        mime = "application/pdf" if fmt == "pdf" else "text/markdown"
        try:
            response = httpx.post(
                url,
                data={"chat_id": self.chat_id, "caption": caption},
                files={"document": (filename, payload, mime)},
                timeout=30.0,
            )
        except httpx.HTTPError as exc:
            raise DeliveryError(f"telegram send failed: {exc}") from exc
        if response.status_code >= 300:
            raise DeliveryError(
                f"telegram returned {response.status_code}: {response.text[:200]}"
            )
        return DeliveryResult(backend=self.name, detail=f"chat={self.chat_id}")


class WebhookDelivery(Delivery):
    """POST the rendered report as multipart/form-data to a user URL."""

    name = "webhook"

    def __init__(self, *, url: str | None = None) -> None:
        self.url = url or os.environ.get("KODA_REPORT_WEBHOOK_URL", "")

    def send(self, *, report, payload, filename, fmt):
        if not self.url:
            raise DeliveryError(
                "webhook delivery needs KODA_REPORT_WEBHOOK_URL in your environment"
            )
        import httpx

        mime = "application/pdf" if fmt == "pdf" else "text/markdown"
        try:
            response = httpx.post(
                self.url,
                files={"file": (filename, payload, mime)},
                data={"caption": _caption(report)},
                timeout=30.0,
            )
        except httpx.HTTPError as exc:
            raise DeliveryError(f"webhook POST failed: {exc}") from exc
        if response.status_code >= 300:
            raise DeliveryError(
                f"webhook returned {response.status_code}: {response.text[:200]}"
            )
        return DeliveryResult(backend=self.name, detail=self.url)


def create_delivery(name: str) -> Delivery:
    """Factory — returns a ready-to-use :class:`Delivery` for ``name``."""
    name = (name or "").strip().lower() or "file"
    if name == "file":
        return FileDelivery()
    if name == "stdout":
        return StdoutDelivery()
    if name == "telegram":
        return TelegramDelivery()
    if name == "webhook":
        return WebhookDelivery()
    raise DeliveryError(
        f"unknown delivery backend {name!r}; try file | stdout | telegram | webhook"
    )


def default_delivery_name() -> str:
    """The env-configured default if the user hasn't passed ``--deliver``."""
    return (os.environ.get("KODA_REPORT_DELIVER") or "file").strip().lower()


def default_format_name() -> str:
    return (os.environ.get("KODA_REPORT_FORMAT") or "md").strip().lower()


def _caption(report: Report) -> str:
    stamp = report.generated_at.strftime("%Y-%m-%d")
    return (
        f"KODA learning digest — {stamp}\n"
        f"pending={len(report.pending)} approved={len(report.approved)} "
        f"rejected={len(report.rejected)}"
    )
