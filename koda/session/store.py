"""SQLite session store. One row per turn-message; ordered by (session_id, seq)."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Iterator

from ..adapters.base import Message, Role, ToolCall

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS messages (
    session_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    tool_calls TEXT NOT NULL DEFAULT '[]',
    tool_call_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    PRIMARY KEY (session_id, seq),
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, seq);
"""


def _message_to_row(session_id: str, seq: int, msg: Message) -> tuple:
    tool_calls_json = json.dumps([asdict(tc) for tc in (msg.tool_calls or [])])
    return (
        session_id,
        seq,
        msg.role.value,
        msg.content or "",
        tool_calls_json,
        msg.tool_call_id,
        json.dumps(msg.metadata or {}),
        time.time(),
    )


def _row_to_message(row: sqlite3.Row) -> Message:
    tool_calls_raw = json.loads(row["tool_calls"] or "[]")
    tool_calls = [ToolCall(**tc) for tc in tool_calls_raw] if tool_calls_raw else None
    return Message(
        role=Role(row["role"]),
        content=row["content"] or "",
        tool_calls=tool_calls,
        tool_call_id=row["tool_call_id"],
        metadata=json.loads(row["metadata"] or "{}"),
    )


class SessionStore:
    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
        finally:
            conn.close()

    def create(self, title: str = "", metadata: dict | None = None) -> str:
        sid = f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions(id, title, created_at, updated_at, metadata) VALUES(?,?,?,?,?)",
                (sid, title, now, now, json.dumps(metadata or {})),
            )
        return sid

    def append(self, session_id: str, msg: Message) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), -1) + 1 AS next_seq FROM messages WHERE session_id=?",
                (session_id,),
            ).fetchone()
            seq = int(row["next_seq"])
            conn.execute(
                "INSERT INTO messages(session_id, seq, role, content, tool_calls, tool_call_id, metadata, created_at) VALUES(?,?,?,?,?,?,?,?)",
                _message_to_row(session_id, seq, msg),
            )
            conn.execute("UPDATE sessions SET updated_at=? WHERE id=?", (time.time(), session_id))
        return seq

    def messages(self, session_id: str) -> list[Message]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE session_id=? ORDER BY seq ASC",
                (session_id,),
            ).fetchall()
        return [_row_to_message(r) for r in rows]

    def list_sessions(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, title, created_at, updated_at FROM sessions ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def exists(self, session_id: str) -> bool:
        with self._connect() as conn:
            return conn.execute("SELECT 1 FROM sessions WHERE id=?", (session_id,)).fetchone() is not None
