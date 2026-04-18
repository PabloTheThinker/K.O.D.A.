"""Telegram channel for K.O.D.A. — alerts, photos, documents, long-poll.

Stdlib-only. Credentials come from ~/.koda/secrets.env:
    KODA_TELEGRAM_BOT_TOKEN
    KODA_TELEGRAM_CHAT_ID     (authorised operator — only this chat is served)
"""
from __future__ import annotations

import json
import mimetypes
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_API_BASE = "https://api.telegram.org"


@dataclass
class TelegramResult:
    ok: bool
    detail: str
    data: dict[str, Any] | None = None


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
        return self._post_form("sendMessage", {
            "chat_id": self.chat_id,
            "text": text[:4096],
            "parse_mode": parse_mode,
            "disable_web_page_preview": "true",
        })

    def _post_form(self, endpoint: str, fields: dict[str, str]) -> TelegramResult:
        url = f"{_API_BASE}/bot{self.bot_token}/{endpoint}"
        payload = urllib.parse.urlencode(fields).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            if body.get("ok"):
                return TelegramResult(True, "delivered", data=body.get("result"))
            return TelegramResult(False, f"api: {body.get('description', 'unknown error')}")
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

    def _multipart(
        self,
        *,
        endpoint: str,
        fields: dict[str, str],
        file_field: str,
        file_path: Path,
    ) -> TelegramResult:
        boundary = f"----KODA{secrets.token_hex(12)}"
        body = bytearray()

        for name, value in fields.items():
            body += f"--{boundary}\r\n".encode()
            body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            body += value.encode("utf-8") + b"\r\n"

        mime = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            return TelegramResult(False, f"read failed: {exc}")

        body += f"--{boundary}\r\n".encode()
        body += (
            f'Content-Disposition: form-data; name="{file_field}"; '
            f'filename="{file_path.name}"\r\n'
        ).encode()
        body += f"Content-Type: {mime}\r\n\r\n".encode()
        body += content + b"\r\n"
        body += f"--{boundary}--\r\n".encode()

        url = f"{_API_BASE}/bot{self.bot_token}/{endpoint}"
        req = urllib.request.Request(url, data=bytes(body), method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        req.add_header("Content-Length", str(len(body)))

        try:
            # Files can be big; give multipart calls more time.
            with urllib.request.urlopen(req, timeout=max(self.timeout, 60)) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if data.get("ok"):
                return TelegramResult(True, "delivered", data=data.get("result"))
            return TelegramResult(False, f"api: {data.get('description', 'unknown error')}")
        except urllib.error.HTTPError as exc:
            return TelegramResult(False, f"http {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            return TelegramResult(False, f"network: {exc.reason}")
        except (OSError, json.JSONDecodeError) as exc:
            return TelegramResult(False, f"{type(exc).__name__}: {exc}")

    def send_photo(
        self,
        photo_path: str | Path,
        *,
        caption: str = "",
    ) -> TelegramResult:
        path = Path(photo_path)
        if not path.is_file():
            return TelegramResult(False, f"not a file: {path}")
        fields: dict[str, str] = {"chat_id": self.chat_id}
        if caption:
            fields["caption"] = caption[:1024]
            fields["parse_mode"] = "Markdown"
        return self._multipart(
            endpoint="sendPhoto",
            fields=fields,
            file_field="photo",
            file_path=path,
        )

    def send_document(
        self,
        doc_path: str | Path,
        *,
        caption: str = "",
    ) -> TelegramResult:
        path = Path(doc_path)
        if not path.is_file():
            return TelegramResult(False, f"not a file: {path}")
        fields: dict[str, str] = {"chat_id": self.chat_id}
        if caption:
            fields["caption"] = caption[:1024]
            fields["parse_mode"] = "Markdown"
        return self._multipart(
            endpoint="sendDocument",
            fields=fields,
            file_field="document",
            file_path=path,
        )

    def send_chat_action(self, action: str = "typing") -> TelegramResult:
        """Show 'typing...' (or similar) briefly. Fire-and-forget is fine."""
        return self._post_form("sendChatAction", {
            "chat_id": self.chat_id,
            "action": action,
        })

    def get_updates(
        self,
        *,
        offset: int | None = None,
        timeout: int = 25,
        allowed_updates: tuple[str, ...] = ("message",),
    ) -> TelegramResult:
        """Long-poll getUpdates. Returns TelegramResult.data = list[update]."""
        params: dict[str, str] = {
            "timeout": str(timeout),
            "allowed_updates": json.dumps(list(allowed_updates)),
        }
        if offset is not None:
            params["offset"] = str(offset)
        url = f"{_API_BASE}/bot{self.bot_token}/getUpdates?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout + timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            return TelegramResult(False, f"http {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            return TelegramResult(False, f"network: {exc.reason}")
        except (OSError, json.JSONDecodeError) as exc:
            return TelegramResult(False, f"{type(exc).__name__}: {exc}")
        if not body.get("ok"):
            return TelegramResult(False, body.get("description", "unknown error"))
        return TelegramResult(True, "ok", data={"updates": body.get("result", [])})

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
