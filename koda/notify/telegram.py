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
    def from_env(cls) -> TelegramNotifier | None:
        token = os.environ.get("KODA_TELEGRAM_BOT_TOKEN", "").strip()
        chat = os.environ.get("KODA_TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat:
            return None
        return cls(token, chat)

    def send(
        self,
        text: str,
        *,
        parse_mode: str = "Markdown",
        reply_markup: dict[str, Any] | None = None,
        disable_web_page_preview: bool = True,
    ) -> TelegramResult:
        if not text.strip():
            return TelegramResult(False, "empty message")
        fields: dict[str, str] = {
            "chat_id": self.chat_id,
            "text": text[:4096],
            "parse_mode": parse_mode,
            "disable_web_page_preview": "true" if disable_web_page_preview else "false",
        }
        if reply_markup is not None:
            fields["reply_markup"] = json.dumps(reply_markup)

        result = self._post_form_with_retry("sendMessage", fields)

        # Markdown / HTML can reject on stray chars — fall back to plain text.
        if not result.ok and parse_mode and "parse" in result.detail.lower():
            fallback = dict(fields)
            fallback.pop("parse_mode", None)
            return self._post_form_with_retry("sendMessage", fallback)
        return result

    def answer_callback_query(
        self,
        callback_query_id: str,
        *,
        text: str = "",
        show_alert: bool = False,
    ) -> TelegramResult:
        fields: dict[str, str] = {
            "callback_query_id": callback_query_id,
            "show_alert": "true" if show_alert else "false",
        }
        if text:
            fields["text"] = text[:200]
        return self._post_form("answerCallbackQuery", fields)

    def edit_message_text(
        self,
        message_id: int,
        text: str,
        *,
        parse_mode: str = "Markdown",
        reply_markup: dict[str, Any] | None = None,
    ) -> TelegramResult:
        fields: dict[str, str] = {
            "chat_id": self.chat_id,
            "message_id": str(message_id),
            "text": text[:4096],
            "parse_mode": parse_mode,
            "disable_web_page_preview": "true",
        }
        if reply_markup is not None:
            fields["reply_markup"] = json.dumps(reply_markup)
        return self._post_form("editMessageText", fields)

    def set_my_commands(self, commands: list[tuple[str, str]]) -> TelegramResult:
        payload = [{"command": name, "description": desc} for name, desc in commands]
        return self._post_form("setMyCommands", {"commands": json.dumps(payload)})

    def get_file_path(self, file_id: str) -> TelegramResult:
        result = self._post_form("getFile", {"file_id": file_id})
        if not result.ok:
            return result
        fp = (result.data or {}).get("file_path")
        if not fp:
            return TelegramResult(False, "no file_path in response")
        return TelegramResult(True, fp, data=result.data)

    def download_file(self, file_id: str, dest: str | Path) -> TelegramResult:
        """Download a Telegram file to `dest`. Returns TelegramResult(ok, path)."""
        info = self.get_file_path(file_id)
        if not info.ok:
            return info
        file_path = info.detail
        url = f"{_API_BASE}/file/bot{self.bot_token}/{file_path}"
        dest_path = Path(dest)
        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(url, timeout=max(self.timeout, 60)) as resp:
                dest_path.write_bytes(resp.read())
        except urllib.error.HTTPError as exc:
            return TelegramResult(False, f"http {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            return TelegramResult(False, f"network: {exc.reason}")
        except OSError as exc:
            return TelegramResult(False, f"io: {exc}")
        return TelegramResult(True, str(dest_path), data={"size": dest_path.stat().st_size})

    def _post_form_with_retry(
        self,
        endpoint: str,
        fields: dict[str, str],
        *,
        attempts: int = 3,
    ) -> TelegramResult:
        """POST with backoff for transient network failures. Non-retryable
        API errors (4xx other than 429) return immediately."""
        import time as _time
        last: TelegramResult | None = None
        for i in range(attempts):
            result = self._post_form(endpoint, fields)
            if result.ok:
                return result
            detail = result.detail.lower()
            transient = (
                "network:" in detail
                or "http 5" in detail
                or "http 429" in detail
                or "timed out" in detail
                or "timeout" in detail
            )
            last = result
            if not transient or i == attempts - 1:
                return result
            _time.sleep(0.5 * (2 ** i))
        return last or TelegramResult(False, "unknown error")

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
