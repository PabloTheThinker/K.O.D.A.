"""Telegram alert channel.

Sends messages to a chat via the Bot API. Credentials come from
~/.koda/secrets.env (KODA_TELEGRAM_BOT_TOKEN + KODA_TELEGRAM_CHAT_ID).
Stdlib-only. No third-party deps.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

_API_BASE = "https://api.telegram.org"


@dataclass
class TelegramResult:
    ok: bool
    detail: str


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str, timeout: float = 10.0) -> None:
        self.bot_token = bot_token.strip()
        self.chat_id = chat_id.strip()
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "TelegramNotifier | None":
        token = os.environ.get("KODA_TELEGRAM_BOT_TOKEN", "").strip()
        chat = os.environ.get("KODA_TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat:
            return None
        return cls(token, chat)

    def send(self, text: str, *, parse_mode: str = "Markdown") -> TelegramResult:
        if not text.strip():
            return TelegramResult(False, "empty message")

        url = f"{_API_BASE}/bot{self.bot_token}/sendMessage"
        payload = urllib.parse.urlencode({
            "chat_id": self.chat_id,
            "text": text[:4096],
            "parse_mode": parse_mode,
            "disable_web_page_preview": "true",
        }).encode("utf-8")

        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            if body.get("ok"):
                return TelegramResult(True, "delivered")
            desc = body.get("description", "unknown error")
            return TelegramResult(False, f"api: {desc}")
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8", errors="replace"))
                desc = body.get("description", exc.reason)
            except Exception:  # noqa: BLE001
                desc = exc.reason
            return TelegramResult(False, f"http {exc.code}: {desc}")
        except urllib.error.URLError as exc:
            return TelegramResult(False, f"network: {exc.reason}")
        except (OSError, json.JSONDecodeError) as exc:
            return TelegramResult(False, f"{type(exc).__name__}: {exc}")

    def verify(self) -> TelegramResult:
        """Call getMe to verify the token; does not touch the chat."""
        url = f"{_API_BASE}/bot{self.bot_token}/getMe"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            return TelegramResult(False, f"http {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            return TelegramResult(False, f"network: {exc.reason}")
        except (OSError, json.JSONDecodeError) as exc:
            return TelegramResult(False, f"{type(exc).__name__}: {exc}")

        if not body.get("ok"):
            return TelegramResult(False, body.get("description", "unknown error"))

        me = body.get("result", {})
        handle = me.get("username") or me.get("first_name") or "bot"
        return TelegramResult(True, f"authenticated as @{handle}")


def send_telegram(text: str) -> TelegramResult:
    """Convenience: build from env and send. Returns (False, ...) if unconfigured."""
    notifier = TelegramNotifier.from_env()
    if notifier is None:
        return TelegramResult(False, "telegram not configured")
    return notifier.send(text)


__all__ = ["TelegramNotifier", "TelegramResult", "send_telegram"]
