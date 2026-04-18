"""Tamper-evident evidence store — the chain-of-custody artifact layer.

Why this exists separately from the audit log:

  - The audit log records *actions* (which tool was called, approved, ran).
    The evidence store records *artifacts* — raw tool output, scanner JSON,
    packet captures, files pulled off a target. When a client challenges
    what was found on their asset, the answer lives here, not in the log.
  - Every artifact is immutable once written: chmod 0o400, content-addressed
    via SHA-256, entries chained via ``prev_hash``/``chain_hash`` so a later
    edit to a mid-chain artifact is detectable.
  - Writes are atomic (write-to-temp + fsync + rename). ``capture`` never
    raises — a crash mid-engagement is worse than a missed artifact, so
    failures come back as a sentinel ``Artifact`` plus an audit event.
  - Per-engagement locking keeps the merkle chain race-free under concurrent
    tool calls. Cross-engagement writes don't block each other.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_EXT_MAP: dict[str, str] = {
    "text": ".txt",
    "sarif": ".sarif.json",
    "json": ".json",
    "pcap": ".pcap",
    "binary": ".bin",
}

_GENESIS = "0" * 64


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    path: str
    size: int
    sha256: str
    prev_hash: str
    chain_hash: str
    captured_at: float
    captured_at_iso: str
    content_type: str
    tool: str
    engagement: str
    session_id: str
    target: str
    tool_args_hash: str
    producer_cmd: tuple[str, ...] = ()

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row["producer_cmd"] = list(self.producer_cmd)
        return row


@dataclass
class ChainVerification:
    ok: bool
    engagement: str
    checked: int
    first_divergence: str = ""
    reason: str = ""


def default_evidence_path() -> Path:
    root = Path(os.environ.get("KODA_HOME", str(Path.home() / ".koda")))
    return root / "evidence"


def compute_chain_hash(prev_hash: str, sha256: str, artifact_id: str, captured_at: float) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(sha256.encode())
    h.update(artifact_id.encode())
    h.update(f"{captured_at:.6f}".encode())
    return h.hexdigest()


def _safe_segment(value: str, fallback: str) -> str:
    """Slugify a path segment so engagements / session_ids never escape the tree."""
    value = (value or "").strip()
    if not value:
        return fallback
    safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in value)
    return safe[:64] or fallback


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _atomic_copy(src: Path, dst: Path) -> None:
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    with open(src, "rb") as src_fh, open(tmp, "wb") as dst_fh:
        shutil.copyfileobj(src_fh, dst_fh, length=1 << 20)
        dst_fh.flush()
        os.fsync(dst_fh.fileno())
    os.replace(tmp, dst)


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


_SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id     TEXT PRIMARY KEY,
    engagement      TEXT NOT NULL DEFAULT '',
    session_id      TEXT NOT NULL DEFAULT '',
    tool            TEXT NOT NULL DEFAULT '',
    target          TEXT NOT NULL DEFAULT '',
    content_type    TEXT NOT NULL DEFAULT 'text',
    path            TEXT NOT NULL,
    size            INTEGER NOT NULL DEFAULT 0,
    sha256          TEXT NOT NULL DEFAULT '',
    prev_hash       TEXT NOT NULL DEFAULT '',
    chain_hash      TEXT NOT NULL DEFAULT '',
    captured_at     REAL NOT NULL,
    captured_at_iso TEXT NOT NULL DEFAULT '',
    tool_args_hash  TEXT NOT NULL DEFAULT '',
    producer_cmd    TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS artifacts_engagement ON artifacts(engagement, captured_at);
CREATE INDEX IF NOT EXISTS artifacts_session    ON artifacts(session_id, captured_at);
CREATE INDEX IF NOT EXISTS artifacts_tool       ON artifacts(tool, captured_at);
"""

_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS artifacts_fts USING fts5(
    artifact_id UNINDEXED,
    tool, target, engagement,
    tokenize='unicode61'
);
"""


class NullEvidenceStore:
    """No-op. Used in tests and MCP-server mode where evidence is off."""

    def capture(self, *_, **__) -> Artifact:  # type: ignore[override]
        return Artifact(
            artifact_id="", path="", size=0, sha256="",
            prev_hash="", chain_hash="", captured_at=0.0, captured_at_iso="",
            content_type="text", tool="", engagement="", session_id="",
            target="", tool_args_hash="", producer_cmd=(),
        )

    def query(self, *, engagement: str = "", session_id: str = "", tool: str = "") -> list[Artifact]:
        return []

    def verify_chain(self, engagement: str = "") -> ChainVerification:
        return ChainVerification(ok=True, engagement=engagement, checked=0, reason="null store")

    def close(self) -> None:
        return None


class EvidenceStore:
    """Append-only, content-addressed, chained artifact store."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        audit: Any = None,
    ) -> None:
        self.root = Path(path) if path else default_evidence_path()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "index.db"
        self.audit = audit
        # Global lock guards sqlite connection + file handle; per-engagement
        # lock guards the chain tail so concurrent captures into the same
        # engagement stay ordered without serializing unrelated work.
        self._lock = threading.Lock()
        self._engagement_locks: dict[str, threading.Lock] = {}
        self._conn: sqlite3.Connection | None = None
        self._ensure_open()

    # --- lifecycle ---

    def _ensure_open(self) -> None:
        if self._conn is not None:
            return
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA)
        try:
            conn.executescript(_FTS_SCHEMA)
        except sqlite3.OperationalError:
            # FTS5 compiled out — index still works, just no full-text search.
            pass
        self._conn = conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                    self._conn.close()
                finally:
                    self._conn = None

    def _engagement_lock(self, engagement: str) -> threading.Lock:
        key = engagement or "_unscoped"
        with self._lock:
            lock = self._engagement_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._engagement_locks[key] = lock
            return lock

    # --- capture ---

    def _emit(self, event: str, **fields: Any) -> None:
        if self.audit is None:
            return
        try:
            self.audit.emit(event, **fields)
        except Exception:
            # Audit should never bring capture down.
            pass

    def _row_to_artifact(self, row: sqlite3.Row | dict[str, Any]) -> Artifact:
        data = dict(row)
        producer = data.get("producer_cmd") or "[]"
        try:
            parsed = json.loads(producer) if isinstance(producer, str) else list(producer)
        except (TypeError, ValueError):
            parsed = []
        return Artifact(
            artifact_id=data["artifact_id"],
            path=data["path"],
            size=int(data.get("size") or 0),
            sha256=data.get("sha256") or "",
            prev_hash=data.get("prev_hash") or "",
            chain_hash=data.get("chain_hash") or "",
            captured_at=float(data.get("captured_at") or 0.0),
            captured_at_iso=data.get("captured_at_iso") or "",
            content_type=data.get("content_type") or "text",
            tool=data.get("tool") or "",
            engagement=data.get("engagement") or "",
            session_id=data.get("session_id") or "",
            target=data.get("target") or "",
            tool_args_hash=data.get("tool_args_hash") or "",
            producer_cmd=tuple(str(x) for x in parsed),
        )

    def _prev_chain_hash(self, engagement: str) -> str:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT chain_hash FROM artifacts WHERE engagement=? "
            "ORDER BY captured_at DESC, artifact_id DESC LIMIT 1",
            (engagement,),
        ).fetchone()
        return row["chain_hash"] if row else _GENESIS

    def _insert(self, artifact: Artifact) -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT INTO artifacts("
            " artifact_id, engagement, session_id, tool, target, content_type,"
            " path, size, sha256, prev_hash, chain_hash,"
            " captured_at, captured_at_iso, tool_args_hash, producer_cmd"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                artifact.artifact_id,
                artifact.engagement,
                artifact.session_id,
                artifact.tool,
                artifact.target,
                artifact.content_type,
                artifact.path,
                artifact.size,
                artifact.sha256,
                artifact.prev_hash,
                artifact.chain_hash,
                artifact.captured_at,
                artifact.captured_at_iso,
                artifact.tool_args_hash,
                json.dumps(list(artifact.producer_cmd)),
            ),
        )
        # FTS is best-effort.
        try:
            self._conn.execute(
                "INSERT INTO artifacts_fts(artifact_id, tool, target, engagement)"
                " VALUES(?,?,?,?)",
                (artifact.artifact_id, artifact.tool, artifact.target, artifact.engagement),
            )
        except sqlite3.OperationalError:
            pass
        self._conn.commit()

    def capture(
        self,
        content: bytes | str | None = None,
        *,
        from_path: Path | str | None = None,
        tool: str,
        engagement: str = "",
        session_id: str = "",
        target: str = "",
        content_type: str = "text",
        tool_args_hash: str = "",
        producer_cmd: list[str] | None = None,
    ) -> Artifact:
        artifact_id = uuid.uuid4().hex
        now = time.time()
        iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + "Z"
        ext = _EXT_MAP.get(content_type, ".bin")
        eng_seg = _safe_segment(engagement, "_unscoped")
        sess_seg = _safe_segment(session_id, "_orphan")
        dirpath = self.root / eng_seg / sess_seg
        try:
            dirpath.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._emit(
                "evidence.capture_failed",
                reason=f"mkdir failed: {exc}",
                tool=tool, engagement=engagement, session_id=session_id,
            )
            return Artifact(
                artifact_id=artifact_id, path="", size=0, sha256="",
                prev_hash="", chain_hash="", captured_at=now, captured_at_iso=iso,
                content_type=content_type, tool=tool, engagement=engagement,
                session_id=session_id, target=target,
                tool_args_hash=tool_args_hash, producer_cmd=tuple(producer_cmd or ()),
            )

        artifact_path = dirpath / f"{artifact_id}{ext}"
        meta_path = dirpath / f"{artifact_id}.meta.json"

        # Write content first so we can compute a real SHA before chaining.
        try:
            if from_path is not None:
                src = Path(from_path)
                _atomic_copy(src, artifact_path)
            else:
                if content is None:
                    content = b""
                payload = content.encode("utf-8") if isinstance(content, str) else content
                _atomic_write_bytes(artifact_path, payload)
            sha, size = _sha256_file(artifact_path)
            try:
                os.chmod(artifact_path, 0o400)
            except OSError:
                pass
        except OSError as exc:
            self._emit(
                "evidence.capture_failed",
                reason=f"write failed: {exc}",
                tool=tool, engagement=engagement, session_id=session_id,
            )
            return Artifact(
                artifact_id=artifact_id, path=str(artifact_path), size=0, sha256="",
                prev_hash="", chain_hash="", captured_at=now, captured_at_iso=iso,
                content_type=content_type, tool=tool, engagement=engagement,
                session_id=session_id, target=target,
                tool_args_hash=tool_args_hash, producer_cmd=tuple(producer_cmd or ()),
            )

        # Chain + index under the engagement lock so prev_hash is race-free.
        with self._engagement_lock(engagement):
            with self._lock:
                self._ensure_open()
                prev = self._prev_chain_hash(engagement)
            chain = compute_chain_hash(prev, sha, artifact_id, now)

            artifact = Artifact(
                artifact_id=artifact_id,
                path=str(artifact_path),
                size=size,
                sha256=sha,
                prev_hash=prev,
                chain_hash=chain,
                captured_at=now,
                captured_at_iso=iso,
                content_type=content_type,
                tool=tool,
                engagement=engagement,
                session_id=session_id,
                target=target,
                tool_args_hash=tool_args_hash,
                producer_cmd=tuple(producer_cmd or ()),
            )

            # Sidecar manifest next to the artifact — self-describing if the
            # index DB ever gets corrupted or lost.
            try:
                _atomic_write_bytes(
                    meta_path,
                    json.dumps(artifact.to_row(), indent=2, sort_keys=True).encode(),
                )
                try:
                    os.chmod(meta_path, 0o400)
                except OSError:
                    pass
            except OSError as exc:
                self._emit(
                    "evidence.index_error",
                    reason=f"manifest write failed: {exc}",
                    artifact_id=artifact_id, engagement=engagement,
                )

            with self._lock:
                try:
                    self._insert(artifact)
                except sqlite3.Error as exc:
                    self._emit(
                        "evidence.index_error",
                        reason=f"index insert failed: {exc}",
                        artifact_id=artifact_id, engagement=engagement,
                    )
                    # File + sidecar survive; operator can reconcile from disk.

        self._emit(
            "evidence.capture",
            artifact_id=artifact_id,
            sha256=sha[:12],
            content_type=content_type,
            engagement=engagement,
            session_id=session_id,
            tool=tool,
            size=size,
        )
        return artifact

    # --- query + verification ---

    def query(
        self,
        *,
        engagement: str = "",
        session_id: str = "",
        tool: str = "",
    ) -> list[Artifact]:
        with self._lock:
            self._ensure_open()
            assert self._conn is not None
            clauses: list[str] = []
            params: list[Any] = []
            if engagement:
                clauses.append("engagement=?")
                params.append(engagement)
            if session_id:
                clauses.append("session_id=?")
                params.append(session_id)
            if tool:
                clauses.append("tool=?")
                params.append(tool)
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            rows = self._conn.execute(
                f"SELECT * FROM artifacts {where} ORDER BY captured_at ASC, artifact_id ASC",
                params,
            ).fetchall()
        return [self._row_to_artifact(r) for r in rows]

    def verify_chain(self, engagement: str = "") -> ChainVerification:
        artifacts = self.query(engagement=engagement) if engagement else self._all_by_engagement()
        if engagement:
            return self._verify_sequence(engagement, artifacts)

        # No engagement pinned → verify each group independently, return the
        # first failure we hit. Everything-clean returns ok=True.
        by_eng: dict[str, list[Artifact]] = {}
        for a in artifacts:
            by_eng.setdefault(a.engagement, []).append(a)
        total = 0
        for eng, group in by_eng.items():
            report = self._verify_sequence(eng, group)
            total += report.checked
            if not report.ok:
                return ChainVerification(
                    ok=False,
                    engagement=eng,
                    checked=total,
                    first_divergence=report.first_divergence,
                    reason=report.reason,
                )
        return ChainVerification(ok=True, engagement="", checked=total)

    def _all_by_engagement(self) -> list[Artifact]:
        with self._lock:
            self._ensure_open()
            assert self._conn is not None
            rows = self._conn.execute(
                "SELECT * FROM artifacts ORDER BY engagement, captured_at ASC, artifact_id ASC",
            ).fetchall()
        return [self._row_to_artifact(r) for r in rows]

    def _verify_sequence(self, engagement: str, artifacts: list[Artifact]) -> ChainVerification:
        prev = _GENESIS
        for a in artifacts:
            if a.prev_hash != prev:
                return ChainVerification(
                    ok=False, engagement=engagement, checked=0,
                    first_divergence=a.artifact_id,
                    reason=f"prev_hash mismatch: expected {prev[:12]}, got {a.prev_hash[:12]}",
                )
            expected = compute_chain_hash(a.prev_hash, a.sha256, a.artifact_id, a.captured_at)
            if expected != a.chain_hash:
                return ChainVerification(
                    ok=False, engagement=engagement, checked=0,
                    first_divergence=a.artifact_id,
                    reason="chain_hash recomputation mismatch",
                )
            path = Path(a.path)
            if path.exists():
                try:
                    sha, _ = _sha256_file(path)
                except OSError as exc:
                    return ChainVerification(
                        ok=False, engagement=engagement, checked=0,
                        first_divergence=a.artifact_id,
                        reason=f"artifact unreadable: {exc}",
                    )
                if sha != a.sha256:
                    return ChainVerification(
                        ok=False, engagement=engagement, checked=0,
                        first_divergence=a.artifact_id,
                        reason="artifact sha256 mismatch on disk",
                    )
            prev = a.chain_hash
        return ChainVerification(ok=True, engagement=engagement, checked=len(artifacts))


__all__ = [
    "Artifact",
    "ChainVerification",
    "EvidenceStore",
    "NullEvidenceStore",
    "compute_chain_hash",
    "default_evidence_path",
]
