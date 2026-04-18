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
_COMMANDS_HELP = (
    "*K.O.D.A. Telegram bridge*\n"
    "Send a message to run a turn. Commands:\n"
    "`/help` — this help\n"
    "`/new` — start a fresh session (clears memory)\n"
    "`/status` — show session stats\n"
    "`/stop` — shut the daemon down"
)


class _ApprovalBroker:
    """Routes approval questions to Telegram and waits for a y/n reply.

    The daemon funnels every incoming text message through `feed()` so the
    broker can resolve a pending question. Messages that don't match a
    pending approval fall through to the caller.
    """

    def __init__(self, notifier: TelegramNotifier, timeout: float = _APPROVAL_TIMEOUT_SECONDS) -> None:
        self.notifier = notifier
        self.timeout = timeout
        self._pending: asyncio.Future[bool] | None = None
        self._lock = asyncio.Lock()

    def feed(self, text: str) -> bool:
        """Try to resolve the pending approval. Returns True if consumed."""
        if self._pending is None or self._pending.done():
            return False
        answer = text.strip().lower()
        if answer in {"y", "yes", "approve", "ok"}:
            self._pending.set_result(True)
            return True
        if answer in {"n", "no", "deny", "stop"}:
            self._pending.set_result(False)
            return True
        return False

    async def ask(self, tool_name: str, arguments: dict[str, Any], risk: str) -> bool:
        async with self._lock:
            fut: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
            self._pending = fut
            args_preview = _format_args(arguments)
            prompt = (
                f"*Approval needed* \u2014 risk: `{risk}`\n"
                f"tool: `{tool_name}`\n"
                f"args: ```\n{args_preview}\n```\n"
                f"reply `y` to approve, `n` to deny (default: deny in {int(self.timeout)}s)"
            )
            self.notifier.send(prompt)
            try:
                return await asyncio.wait_for(fut, timeout=self.timeout)
            except asyncio.TimeoutError:
                self.notifier.send("_approval timed out \u2014 denied_")
                return False
            finally:
                self._pending = None


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
    from ..tools.approval import ApprovalPolicy
    from ..tools.registry import RiskLevel, global_registry

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

    threshold_name = config.get("approvals", {}).get("auto_approve", "safe")
    threshold = {
        "safe": RiskLevel.SAFE,
        "medium": RiskLevel.SENSITIVE,
        "all": RiskLevel.DANGEROUS,
        "none": RiskLevel.SAFE,
    }.get(threshold_name, RiskLevel.SAFE)

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
    stats = {"turns": 0, "tool_calls": 0, "dropped_unauthorised": 0}

    def _stop(*_: Any) -> None:
        nonlocal running
        running = False

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (OSError, ValueError):
            pass

    while running:
        result = await asyncio.to_thread(
            notifier.get_updates, offset=offset, timeout=25
        )
        if not result.ok:
            await asyncio.sleep(2)
            continue

        updates = (result.data or {}).get("updates", [])
        for update in updates:
            offset = update["update_id"] + 1
            _save_offset(KODA_HOME, offset)

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

            text = (msg.get("text") or "").strip()
            if not text:
                continue

            # Let an in-flight approval consume the reply first.
            if broker.feed(text):
                continue

            if text in {"/help", "/start"}:
                notifier.send(_COMMANDS_HELP)
                continue
            if text == "/status":
                notifier.send(
                    f"turns: {stats['turns']}  tool_calls: {stats['tool_calls']}\n"
                    f"dropped: {stats['dropped_unauthorised']}\n"
                    f"session: `{session_id}`  engagement: `{engagement}`"
                )
                continue
            if text == "/new":
                session_id = session.create(title="telegram", engagement=engagement)
                loop.session_id = session_id
                audit.emit("session.open", session_id=session_id, engagement=engagement,
                           surface="telegram", reason="/new")
                notifier.send(f"new session: `{session_id}`")
                continue
            if text == "/stop":
                notifier.send("_shutting down_")
                running = False
                break

            notifier.send_chat_action("typing")
            try:
                trace = await loop.run(text, TurnOptions())
            except Exception as exc:  # noqa: BLE001
                audit.emit("telegram.turn_error", error=f"{type(exc).__name__}: {exc}")
                notifier.send(f"error: `{type(exc).__name__}: {exc}`")
                continue

            stats["turns"] += 1
            stats["tool_calls"] += trace.tool_calls_made

            if trace.aborted:
                notifier.send(f"[aborted: {trace.abort_reason}]")
            else:
                text_out = trace.final_text or "(no response)"
                for chunk in _chunk_message(text_out):
                    notifier.send(chunk)

            notifier.send(
                f"_iterations: {trace.iterations}  "
                f"tool_calls: {trace.tool_calls_made}  "
                f"rejections: {trace.verifier_rejections}_"
            )

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
