"""SQLite-backed session store with FTS5 search + engagement scoping.

Schema is built for security workflow, not generic chat:
  - `sessions` carries engagement / target / tags columns so an operator
    can filter "show me every conversation touching ACME's 192.168.1.100"
  - `parent_session_id` lets investigations spawn sub-investigations
    while preserving lineage (think IR case → finding drill-downs)
  - `message_search` is a contentless FTS5 table mirroring role + text +
    tool_name, kept in sync by triggers — so operator can grep the full
    trail in O(log n)
  - WAL mode for concurrent readers (dashboards, audit exports) while
    the agent is writing

Chain-of-custody guarantees:
  - Every message row is immutable; updates only touch `sessions.updated_at`
  - Tool calls land as separate rows (role='tool') with structured
    tool_name, not blobbed inside the assistant turn
  - Token counts and latency are captured per-message for forensics
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..adapters.base import Message, Role, ToolCall

_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    engagement TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    parent_session_id TEXT,
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
    tool_name TEXT NOT NULL DEFAULT '',
    tokens_prompt INTEGER NOT NULL DEFAULT 0,
    tokens_completion INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    PRIMARY KEY (session_id, seq),
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
"""

_AUX_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_sessions_engagement ON sessions(engagement);
CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target);
CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_session_id);
CREATE INDEX IF NOT EXISTS idx_messages_tool ON messages(tool_name);

CREATE VIRTUAL TABLE IF NOT EXISTS message_search USING fts5(
    session_id UNINDEXED,
    seq UNINDEXED,
    role,
    tool_name,
    content,
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO message_search(session_id, seq, role, tool_name, content)
    VALUES (new.session_id, new.seq, new.role, new.tool_name, new.content);
END;

CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    DELETE FROM message_search WHERE session_id = old.session_id AND seq = old.seq;
END;
"""

_SESSION_COLUMNS_TO_ENSURE = [
    ("engagement", "TEXT NOT NULL DEFAULT ''"),
    ("target", "TEXT NOT NULL DEFAULT ''"),
    ("tags", "TEXT NOT NULL DEFAULT '[]'"),
    ("parent_session_id", "TEXT"),
]

_MESSAGE_COLUMNS_TO_ENSURE = [
    ("tool_name", "TEXT NOT NULL DEFAULT ''"),
    ("tokens_prompt", "INTEGER NOT NULL DEFAULT 0"),
    ("tokens_completion", "INTEGER NOT NULL DEFAULT 0"),
    ("latency_ms", "INTEGER NOT NULL DEFAULT 0"),
]


def _existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r[1] for r in rows}


def _migrate_columns(conn: sqlite3.Connection) -> None:
    """ALTER pre-existing tables to add new columns. Runs before _AUX_SCHEMA
    so that indexes referencing new columns see the columns exist."""
    cols = _existing_columns(conn, "sessions")
    for name, ddl in _SESSION_COLUMNS_TO_ENSURE:
        if name not in cols:
            conn.execute(f"ALTER TABLE sessions ADD COLUMN {name} {ddl}")

    cols = _existing_columns(conn, "messages")
    for name, ddl in _MESSAGE_COLUMNS_TO_ENSURE:
        if name not in cols:
            conn.execute(f"ALTER TABLE messages ADD COLUMN {name} {ddl}")


def _backfill_fts(conn: sqlite3.Connection) -> None:
    """Populate FTS from existing messages. Runs after _AUX_SCHEMA creates
    the virtual table + triggers."""
    fts_count = conn.execute("SELECT COUNT(*) FROM message_search").fetchone()[0]
    if fts_count > 0:
        return
    msg_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    if msg_count == 0:
        return
    conn.execute(
        "INSERT INTO message_search(session_id, seq, role, tool_name, content) "
        "SELECT session_id, seq, role, tool_name, content FROM messages"
    )


def _extract_tool_name(msg: Message) -> str:
    if msg.role == Role.TOOL:
        return (msg.metadata or {}).get("tool_name", "") or ""
    if msg.tool_calls:
        return msg.tool_calls[0].name or ""
    return ""


def _message_to_row(session_id: str, seq: int, msg: Message) -> tuple:
    md = msg.metadata or {}
    tool_calls_json = json.dumps([asdict(tc) for tc in (msg.tool_calls or [])])
    return (
        session_id,
        seq,
        msg.role.value,
        msg.content or "",
        tool_calls_json,
        msg.tool_call_id,
        _extract_tool_name(msg),
        int(md.get("tokens_prompt", 0) or 0),
        int(md.get("tokens_completion", 0) or 0),
        int(md.get("latency_ms", 0) or 0),
        json.dumps(md),
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
            conn.executescript(_BASE_SCHEMA)
            _migrate_columns(conn)
            conn.executescript(_AUX_SCHEMA)
            _backfill_fts(conn)

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

    # --- Session lifecycle ---

    def create(
        self,
        title: str = "",
        *,
        engagement: str = "",
        target: str = "",
        tags: list[str] | None = None,
        parent_session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        sid = f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions"
                "(id, title, engagement, target, tags, parent_session_id,"
                " created_at, updated_at, metadata)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    sid,
                    title,
                    engagement,
                    target,
                    json.dumps(list(tags or [])),
                    parent_session_id,
                    now,
                    now,
                    json.dumps(metadata or {}),
                ),
            )
        return sid

    def annotate(
        self,
        session_id: str,
        *,
        engagement: str | None = None,
        target: str | None = None,
        tags: list[str] | None = None,
        title: str | None = None,
    ) -> None:
        """Update engagement metadata on an existing session."""
        updates = []
        params: list[Any] = []
        if engagement is not None:
            updates.append("engagement=?")
            params.append(engagement)
        if target is not None:
            updates.append("target=?")
            params.append(target)
        if tags is not None:
            updates.append("tags=?")
            params.append(json.dumps(list(tags)))
        if title is not None:
            updates.append("title=?")
            params.append(title)
        if not updates:
            return
        updates.append("updated_at=?")
        params.append(time.time())
        params.append(session_id)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE sessions SET {', '.join(updates)} WHERE id=?",
                tuple(params),
            )

    def branch(
        self,
        parent_session_id: str,
        *,
        title: str = "",
        engagement: str | None = None,
        target: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Create a child session. Inherits parent's engagement/target/tags
        unless explicitly overridden. Used for spinning off a sub-investigation
        from a finding."""
        parent = self._get_session_row(parent_session_id)
        if parent is None:
            raise ValueError(f"parent session {parent_session_id!r} not found")
        return self.create(
            title=title or f"branch of {parent['title']}",
            engagement=engagement if engagement is not None else parent["engagement"],
            target=target if target is not None else parent["target"],
            tags=tags if tags is not None else json.loads(parent["tags"] or "[]"),
            parent_session_id=parent_session_id,
        )

    def append(self, session_id: str, msg: Message) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), -1) + 1 AS next_seq FROM messages WHERE session_id=?",
                (session_id,),
            ).fetchone()
            seq = int(row["next_seq"])
            conn.execute(
                "INSERT INTO messages"
                "(session_id, seq, role, content, tool_calls, tool_call_id,"
                " tool_name, tokens_prompt, tokens_completion, latency_ms,"
                " metadata, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                _message_to_row(session_id, seq, msg),
            )
            conn.execute("UPDATE sessions SET updated_at=? WHERE id=?", (time.time(), session_id))
        return seq

    # --- Reads ---

    def messages(self, session_id: str) -> list[Message]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE session_id=? ORDER BY seq ASC",
                (session_id,),
            ).fetchall()
        return [_row_to_message(r) for r in rows]

    def list_sessions(
        self,
        *,
        engagement: str | None = None,
        target: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if engagement is not None:
            clauses.append("engagement=?")
            params.append(engagement)
        if target is not None:
            clauses.append("target=?")
            params.append(target)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, title, engagement, target, tags, parent_session_id,"
                " created_at, updated_at"
                f" FROM sessions{where} ORDER BY updated_at DESC LIMIT ?",
                tuple(params),
            ).fetchall()
        return [self._row_to_session_dict(r) for r in rows]

    def children(self, parent_session_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, title, engagement, target, tags, parent_session_id,"
                " created_at, updated_at"
                " FROM sessions WHERE parent_session_id=? ORDER BY created_at ASC",
                (parent_session_id,),
            ).fetchall()
        return [self._row_to_session_dict(r) for r in rows]

    def lineage(self, session_id: str) -> list[dict]:
        """Return parent chain ending at the given session (root first)."""
        chain: list[dict] = []
        current: str | None = session_id
        seen: set[str] = set()
        while current and current not in seen:
            seen.add(current)
            row = self._get_session_row(current)
            if row is None:
                break
            chain.append(self._row_to_session_dict(row))
            current = row["parent_session_id"]
        return list(reversed(chain))

    def exists(self, session_id: str) -> bool:
        with self._connect() as conn:
            return conn.execute("SELECT 1 FROM sessions WHERE id=?", (session_id,)).fetchone() is not None

    # --- Search ---

    def search(
        self,
        query: str,
        *,
        engagement: str | None = None,
        tool_name: str | None = None,
        role: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Full-text search across messages. Returns hits with session context.

        `query` accepts FTS5 syntax (phrases in quotes, OR, NEAR, prefix*).
        Optional filters narrow to a specific engagement, tool, or role.
        """
        if not query.strip():
            return []
        fts_clauses: list[str] = ["message_search MATCH ?"]
        params: list[Any] = [query]
        if tool_name:
            fts_clauses.append("message_search.tool_name = ?")
            params.append(tool_name)
        if role:
            fts_clauses.append("message_search.role = ?")
            params.append(role)

        engagement_clause = ""
        if engagement is not None:
            engagement_clause = " AND s.engagement = ?"
            params.append(engagement)

        params.append(limit)

        sql = f"""
            SELECT m.session_id, m.seq, m.role, m.tool_name, m.content,
                   m.created_at, s.title, s.engagement, s.target
            FROM message_search
            JOIN messages m
              ON m.session_id = message_search.session_id
             AND m.seq = message_search.seq
            JOIN sessions s ON s.id = m.session_id
            WHERE {' AND '.join(fts_clauses)}{engagement_clause}
            ORDER BY bm25(message_search), m.created_at DESC
            LIMIT ?
        """
        with self._connect() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    # --- Internal helpers ---

    def _get_session_row(self, session_id: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)
            ).fetchone()

    @staticmethod
    def _row_to_session_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        if "tags" in data and isinstance(data["tags"], str):
            try:
                data["tags"] = json.loads(data["tags"] or "[]")
            except json.JSONDecodeError:
                data["tags"] = []
        return data
