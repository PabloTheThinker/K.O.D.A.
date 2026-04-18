"""Telegram bridge daemon for K.O.D.A.

Long-polls the Telegram Bot API and routes incoming messages from the
authorised chat_id into a single-session TurnLoop. Responses stream back
as text; photos and documents can be attached via in-band commands.

Security boundary: messages from any chat other than KODA_TELEGRAM_CHAT_ID
are dropped with an audit event. Tool approvals route to the chat as a
y/n prompt with a timeout, defaulting to deny.

Start it with:
    koda telegram

Or:
    python -m koda telegram
"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

from .telegram import TelegramNotifier, TelegramResult

_OFFSET_FILE_NAME = "telegram_offset"
_APPROVAL_TIMEOUT_SECONDS = 120
_FRAGMENT_WINDOW_SECONDS = 1.5
_FRAGMENT_MAX_CHARS = 50_000
_MEDIA_MAX_BYTES = 25 * 1024 * 1024  # 25 MB — Telegram's DM cap for bots
_INBOUND_MEDIA_DIR = "telegram_inbox"

_COMMAND_MENU: list[tuple[str, str]] = [
    ("help", "show commands"),
    ("new", "start a fresh session"),
    ("reset", "alias for /new"),
    ("status", "show session stats"),
    ("model", "show or change the model (e.g. /model claude-sonnet-4-6)"),
    ("models", "list models available for the active provider"),
    ("history", "show last few turns"),
    ("stop", "shut the daemon down"),
]

_COMMANDS_HELP = (
    "*K.O.D.A. Telegram bridge*\n"
    "Send text to run a turn. Attach photos or documents and the agent will "
    "read them alongside your caption.\n\n"
    "Commands:\n"
    "`/help` — this help\n"
    "`/new` or `/reset` — start a fresh session (clears memory)\n"
    "`/status` — show session stats\n"
    "`/model` — show the current model; `/model <id>` to switch\n"
    "`/models` — list known models for this provider\n"
    "`/history` — show the last few turns\n"
    "`/stop` — shut the daemon down"
)


def _approval_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [[
            {"text": "\u2713 Approve", "callback_data": "koda:approve"},
            {"text": "\u2717 Deny", "callback_data": "koda:deny"},
        ]],
    }


class _ApprovalBroker:
    """Routes approval questions to Telegram and waits for a reply.

    Prefers inline-keyboard buttons (callback_query). Falls back to matching
    text replies (`y` / `n`) so the operator can answer from any client that
    hides buttons. Every inbound message or callback goes through `feed()`.
    """

    def __init__(self, notifier: TelegramNotifier, timeout: float = _APPROVAL_TIMEOUT_SECONDS) -> None:
        self.notifier = notifier
        self.timeout = timeout
        self._pending: asyncio.Future[bool] | None = None
        self._message_id: int | None = None
        self._lock = asyncio.Lock()

    def feed_text(self, text: str) -> bool:
        if self._pending is None or self._pending.done():
            return False
        answer = text.strip().lower()
        if answer in {"y", "yes", "approve", "ok"}:
            self._resolve(True)
            return True
        if answer in {"n", "no", "deny", "stop"}:
            self._resolve(False)
            return True
        return False

    def feed_callback(self, data: str) -> bool:
        if self._pending is None or self._pending.done():
            return False
        if data == "koda:approve":
            self._resolve(True)
            return True
        if data == "koda:deny":
            self._resolve(False)
            return True
        return False

    def _resolve(self, approved: bool) -> None:
        if self._pending and not self._pending.done():
            self._pending.set_result(approved)
        if self._message_id is not None:
            label = "\u2713 approved" if approved else "\u2717 denied"
            self.notifier.edit_message_text(
                self._message_id,
                f"_approval {label}_",
                reply_markup={"inline_keyboard": []},
            )

    async def ask(self, tool_name: str, arguments: dict[str, Any], risk: str) -> bool:
        async with self._lock:
            fut: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
            self._pending = fut
            self._message_id = None
            args_preview = _format_args(arguments)
            prompt = (
                f"*Approval needed* \u2014 risk: `{risk}`\n"
                f"tool: `{tool_name}`\n"
                f"args: ```\n{args_preview}\n```\n"
                f"_default-deny in {int(self.timeout)}s. Tap a button, or reply `y`/`n`._"
            )
            result = self.notifier.send(prompt, reply_markup=_approval_keyboard())
            if result.ok and isinstance(result.data, dict):
                self._message_id = result.data.get("message_id")
            try:
                return await asyncio.wait_for(fut, timeout=self.timeout)
            except asyncio.TimeoutError:
                if self._message_id is not None:
                    self.notifier.edit_message_text(
                        self._message_id,
                        "_approval timed out \u2014 denied_",
                        reply_markup={"inline_keyboard": []},
                    )
                else:
                    self.notifier.send("_approval timed out \u2014 denied_")
                return False
            finally:
                self._pending = None
                self._message_id = None


def _format_args(arguments: dict[str, Any], limit: int = 800) -> str:
    import json
    try:
        text = json.dumps(arguments, indent=2, default=str)
    except (TypeError, ValueError):
        text = repr(arguments)
    if len(text) > limit:
        text = text[:limit] + "\n... (truncated)"
    return text


def _load_offset(home: Path) -> int | None:
    path = home / _OFFSET_FILE_NAME
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return None


def _save_offset(home: Path, offset: int) -> None:
    path = home / _OFFSET_FILE_NAME
    try:
        path.write_text(str(offset) + "\n", encoding="utf-8")
    except OSError:
        pass


def _chunk_message(text: str, size: int = 3800) -> list[str]:
    """Telegram caps at 4096 chars. Split on blank-line boundaries where we can."""
    text = text.rstrip()
    if len(text) <= size:
        return [text]
    out: list[str] = []
    remaining = text
    while len(remaining) > size:
        cut = remaining.rfind("\n\n", 0, size)
        if cut <= 0:
            cut = remaining.rfind("\n", 0, size)
        if cut <= 0:
            cut = size
        out.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()
    if remaining:
        out.append(remaining)
    return out


async def _serve(notifier: TelegramNotifier, chat_id: str) -> int:
    from ..adapters import create_provider
    from ..agent.loop import TurnLoop, TurnOptions
    from ..audit import AuditLogger
    from ..auth import CredentialBroker
    from ..config import KODA_HOME, config_exists, load_config
    from ..evidence import EvidenceStore
    from ..profiles import read_active_profile
    from ..session.store import SessionStore
    from ..tools import builtins as _builtins  # noqa: F401 — registers tools
    from ..tools.approval import ApprovalPolicy, threshold_from_config
    from ..tools.registry import global_registry

    if not config_exists():
        notifier.send("K.O.D.A. has no config. Run `koda setup` on the host first.")
        return 2

    config = load_config()
    provider_name = config.get("default_provider") or "ollama"
    provider_cfg = config.get("provider", {}).get(provider_name, {})
    if not provider_cfg:
        notifier.send(f"Provider `{provider_name}` missing from config. Run `koda setup`.")
        return 2

    provider = create_provider(provider_name, provider_cfg)
    registry = global_registry()

    active = read_active_profile()
    profile_label = active or "default"
    engagement = os.environ.get("KODA_ENGAGEMENT", "").strip() or \
        config.get("engagement", {}).get("default", "default")

    audit = AuditLogger(profile=profile_label)
    evidence = EvidenceStore()
    credentials = CredentialBroker(audit=audit)

    broker = _ApprovalBroker(notifier)

    async def _approval_callback(request, guardrail) -> bool:  # type: ignore[no-untyped-def]
        return await broker.ask(request.tool_name, request.arguments, str(request.risk))

    threshold_name = config.get("approvals", {}).get("auto_approve", "all")
    threshold = threshold_from_config(config)

    approvals = ApprovalPolicy(
        approvals_path=KODA_HOME / "approvals.json",
        auto_approve_threshold=threshold,
        callback=_approval_callback,
        audit=audit,
    )

    session = SessionStore(KODA_HOME / "sessions.db")
    session_id = session.create(title="telegram", engagement=engagement)
    audit.emit("session.open", session_id=session_id, engagement=engagement,
               profile=profile_label, surface="telegram")

    loop = TurnLoop(
        provider=provider,
        registry=registry,
        approvals=approvals,
        session=session,
        session_id=session_id,
        engagement=engagement,
        audit=audit,
        evidence=evidence,
        credentials=credentials,
    )

    notifier.set_my_commands(_COMMAND_MENU)
    notifier.send(
        f"*K.O.D.A. online*\n"
        f"provider: `{provider_name}` model: `{provider.get_model()}`\n"
        f"engagement: `{engagement}`\n"
        f"approvals: `{threshold_name}`\n"
        f"session: `{session_id}`\n"
        f"send `/help` for commands."
    )

    offset = _load_offset(KODA_HOME)
    running = True
    stats = {"turns": 0, "tool_calls": 0, "dropped_unauthorised": 0, "media_ingested": 0}
    turn_lock = asyncio.Lock()

    # Fragment buffer — coalesces multi-part messages within a short window.
    pending_parts: list[str] = []
    pending_attachments: list[str] = []
    pending_flush_task: asyncio.Task[None] | None = None

    def _stop(*_: Any) -> None:
        nonlocal running
        running = False

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (OSError, ValueError):
            pass

    async def _execute_turn(prompt_text: str, attachments: list[str]) -> None:
        nonlocal session_id
        async with turn_lock:
            notifier.send_chat_action("typing")
            try:
                trace = await loop.run(prompt_text, TurnOptions())
            except Exception as exc:  # noqa: BLE001
                audit.emit("telegram.turn_error", error=f"{type(exc).__name__}: {exc}")
                notifier.send(f"error: `{type(exc).__name__}: {exc}`")
                return

            stats["turns"] += 1
            stats["tool_calls"] += trace.tool_calls_made

            if trace.aborted:
                notifier.send(f"[aborted: {trace.abort_reason}]")
            else:
                text_out = trace.final_text or "(no response)"
                for chunk in _chunk_message(text_out):
                    notifier.send(chunk)

            footer = (
                f"_iterations: {trace.iterations}  "
                f"tool_calls: {trace.tool_calls_made}  "
                f"rejections: {trace.verifier_rejections}"
            )
            if attachments:
                footer += f"  attachments: {len(attachments)}"
            notifier.send(footer + "_")

    async def _deferred_flush() -> None:
        await asyncio.sleep(_FRAGMENT_WINDOW_SECONDS)
        nonlocal pending_parts, pending_attachments
        parts, atts = pending_parts, pending_attachments
        pending_parts = []
        pending_attachments = []
        if not parts and not atts:
            return
        coalesced = "\n\n".join(p for p in parts if p)[:_FRAGMENT_MAX_CHARS]
        if atts:
            suffix = "\n\nOperator attached: " + ", ".join(atts)
            coalesced = (coalesced + suffix).strip()
        await _execute_turn(coalesced, atts)

    def _schedule_flush() -> None:
        nonlocal pending_flush_task
        if pending_flush_task is not None and not pending_flush_task.done():
            pending_flush_task.cancel()
        pending_flush_task = asyncio.create_task(_deferred_flush())

    def _ingest_media(msg: dict[str, Any]) -> str | None:
        """Download the biggest file attached to `msg`. Return path or None."""
        media_dir = KODA_HOME / _INBOUND_MEDIA_DIR
        file_id: str | None = None
        suffix = ""
        kind = ""
        if "photo" in msg and msg["photo"]:
            # Photo is a list of resolutions — grab the largest.
            best = max(msg["photo"], key=lambda p: p.get("file_size", 0))
            file_id = best["file_id"]
            suffix = ".jpg"
            kind = "photo"
        elif "document" in msg:
            doc = msg["document"]
            if doc.get("file_size", 0) > _MEDIA_MAX_BYTES:
                notifier.send(f"_document too large ({doc.get('file_size')} bytes) \u2014 skipped_")
                return None
            file_id = doc["file_id"]
            name = doc.get("file_name", "")
            suffix = Path(name).suffix or ".bin"
            kind = "document"
        else:
            return None

        ts = int(time.time())
        dest = media_dir / f"{kind}_{ts}_{file_id[-8:]}{suffix}"
        result = notifier.download_file(file_id, dest)
        if not result.ok:
            notifier.send(f"_download failed: {result.detail}_")
            return None
        stats["media_ingested"] += 1
        audit.emit("telegram.media_ingested", kind=kind, path=str(dest), size=(result.data or {}).get("size", 0))
        return str(dest)

    def _handle_command(text: str) -> bool:
        """Return True if handled as a command."""
        nonlocal session_id, running
        cmd, _, arg = text.partition(" ")
        cmd = cmd.lower()
        arg = arg.strip()

        if cmd in {"/help", "/start"}:
            notifier.send(_COMMANDS_HELP)
            return True
        if cmd == "/status":
            notifier.send(
                f"turns: {stats['turns']}  tool_calls: {stats['tool_calls']}\n"
                f"media: {stats['media_ingested']}  dropped: {stats['dropped_unauthorised']}\n"
                f"session: `{session_id}`  engagement: `{engagement}`\n"
                f"provider: `{provider_name}`  model: `{provider.get_model()}`"
            )
            return True
        if cmd in {"/new", "/reset"}:
            session_id = session.create(title="telegram", engagement=engagement)
            loop.session_id = session_id
            audit.emit("session.open", session_id=session_id, engagement=engagement,
                       surface="telegram", reason=cmd)
            notifier.send(f"new session: `{session_id}`")
            return True
        if cmd == "/model":
            if not arg:
                notifier.send(f"current model: `{provider.get_model()}`\nswitch with `/model <id>`")
                return True
            if hasattr(provider, "set_model"):
                try:
                    provider.set_model(arg)  # type: ignore[attr-defined]
                except Exception as exc:  # noqa: BLE001
                    notifier.send(f"switch failed: `{exc}`")
                    return True
                audit.emit("telegram.model_switch", model=arg)
                notifier.send(f"model now: `{arg}`")
            else:
                notifier.send("_this provider does not support runtime model switching_")
            return True
        if cmd == "/models":
            listed = getattr(provider, "list_models", None)
            if callable(listed):
                try:
                    names = list(listed())
                except Exception as exc:  # noqa: BLE001
                    notifier.send(f"list failed: `{exc}`")
                    return True
                if not names:
                    notifier.send("_no models listed_")
                else:
                    notifier.send("available:\n" + "\n".join(f"\u2022 `{n}`" for n in names[:30]))
            else:
                notifier.send("_this provider does not advertise a model list_")
            return True
        if cmd == "/history":
            try:
                limit = int(arg) if arg else 5
            except ValueError:
                limit = 5
            try:
                msgs = session.messages(session_id)
            except Exception as exc:  # noqa: BLE001
                notifier.send(f"history error: `{exc}`")
                return True
            user_msgs = [m for m in msgs if getattr(m, "role", "") == "user"]
            if not user_msgs:
                notifier.send("_no prior turns in this session_")
                return True
            lines = []
            for m in user_msgs[-limit:]:
                body = str(getattr(m, "content", ""))[:80].replace("\n", " ")
                lines.append(f"\u2022 {body}")
            notifier.send("recent:\n" + "\n".join(lines))
            return True
        if cmd == "/stop":
            notifier.send("_shutting down_")
            running = False
            return True
        return False

    while running:
        result = await asyncio.to_thread(
            notifier.get_updates,
            offset=offset,
            timeout=25,
            allowed_updates=("message", "callback_query"),
        )
        if not result.ok:
            await asyncio.sleep(2)
            continue

        updates = (result.data or {}).get("updates", [])
        for update in updates:
            offset = update["update_id"] + 1
            _save_offset(KODA_HOME, offset)

            # Callback query — inline-button approval path.
            cb = update.get("callback_query")
            if cb:
                cb_chat = str((cb.get("message") or {}).get("chat", {}).get("id", ""))
                if cb_chat != chat_id:
                    stats["dropped_unauthorised"] += 1
                    audit.emit("telegram.unauthorised", chat_id=cb_chat,
                               from_user=(cb.get("from") or {}).get("id"))
                    notifier.answer_callback_query(cb["id"], text="not authorised")
                    continue
                data = cb.get("data", "")
                if broker.feed_callback(data):
                    notifier.answer_callback_query(cb["id"], text="recorded")
                else:
                    notifier.answer_callback_query(cb["id"], text="no pending approval")
                continue

            msg = update.get("message") or {}
            from_chat = str(msg.get("chat", {}).get("id", ""))
            if from_chat != chat_id:
                stats["dropped_unauthorised"] += 1
                audit.emit(
                    "telegram.unauthorised",
                    chat_id=from_chat,
                    from_user=msg.get("from", {}).get("id"),
                )
                continue

            text = (msg.get("text") or msg.get("caption") or "").strip()

            # Approval prefers buttons, but text reply is a fallback.
            if text and broker.feed_text(text):
                continue

            # Slash commands bypass the fragment buffer.
            if text.startswith("/") and _handle_command(text):
                if not running:
                    break
                continue

            # Inbound media — save to disk, record attachment path.
            media_path = _ingest_media(msg)
            if media_path:
                pending_attachments.append(media_path)

            if text:
                pending_parts.append(text)
            if text or media_path:
                _schedule_flush()

    audit.emit("session.close", session_id=session_id, engagement=engagement, surface="telegram")
    audit.close()
    notifier.send("_K.O.D.A. offline_")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else []
    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda telegram        start the Telegram bridge daemon")
        print()
        print("Requires KODA_TELEGRAM_BOT_TOKEN and KODA_TELEGRAM_CHAT_ID in")
        print("~/.koda/secrets.env (configured by `koda setup`).")
        return 0

    # Secrets must already be on PATH — caller (koda CLI) loads them.
    token = os.environ.get("KODA_TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("KODA_TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        sys.stderr.write(
            "Telegram not configured. Run `koda setup` and enable the\n"
            "alert channel stage, then retry.\n"
        )
        return 2

    notifier = TelegramNotifier(token, chat_id)
    verify = notifier.verify()
    if not verify.ok:
        sys.stderr.write(f"Telegram token rejected: {verify.detail}\n")
        return 2

    print(f"K.O.D.A. Telegram bridge \u2014 authenticated, chat {chat_id}")
    print("Press Ctrl-C to stop.\n")
    start = time.monotonic()
    try:
        rc = asyncio.run(_serve(notifier, chat_id))
    except KeyboardInterrupt:
        rc = 0
    elapsed = int(time.monotonic() - start)
    print(f"bridge exited after {elapsed}s (rc={rc})")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
