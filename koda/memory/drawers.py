"""Drawer store — verbatim-chunk retrieval.

Complements Helix DSEM. Where Helix stores *concepts* (structured facts
consolidated from episodes), drawers store *verbatim chunks* of source
material — raw paragraphs from files, ready to be surfaced whole.

Concepts borrowed from MemPalace (without the ChromaDB dependency):
  - wing:  project/scope label          (e.g. "koda", "lineage")
  - room:  aspect within a wing         (e.g. "docs", "code", "notes")
  - drawer: a verbatim chunk + metadata (the thing stored)
  - closet: keyword index used as a ranking *signal*, never a gate

Retrieval is hybrid: vector similarity via nomic-embed-text (reusing
helix.embeddings), re-ranked with a small keyword boost. Keyword hits
never filter — they only boost — so narrative content with weak
entity extraction still returns results.

Re-ingest is cheap: files whose mtime is unchanged are skipped.
"""
from __future__ import annotations

import fnmatch
import hashlib
import logging
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .helix.embeddings import (
    cosine_similarity,
    embed_text,
    pack_embedding,
    unpack_embedding,
)

logger = logging.getLogger("koda.memory.drawers")

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "dist", "build", ".mypy_cache"}
_STOPWORDS = {
    "this", "that", "with", "from", "have", "been", "they", "were",
    "your", "will", "about", "which", "their", "there", "these", "those",
    "other", "could", "would", "should", "while", "where", "after",
    "before", "because", "through", "between", "against", "during",
}
_TOKEN_RE = re.compile(r"[a-z][a-z0-9_\-]{3,23}")


# ── Chunking + keywords ──────────────────────────────────────────────

def _chunk_text(text: str, max_chars: int = 800) -> list[str]:
    """Split text into drawer-sized chunks. Paragraph-aware with hard-cap fallback."""
    out: list[str] = []
    for para in re.split(r"\n\s*\n", text):
        para = para.strip()
        if not para:
            continue
        if len(para) <= max_chars:
            out.append(para)
            continue
        # Too big — try single-newline split, then hard-cut.
        buf = ""
        for line in para.split("\n"):
            if len(buf) + len(line) + 1 <= max_chars:
                buf = f"{buf}\n{line}" if buf else line
            else:
                if buf:
                    out.append(buf.strip())
                if len(line) <= max_chars:
                    buf = line
                else:
                    for i in range(0, len(line), max_chars):
                        out.append(line[i:i + max_chars])
                    buf = ""
        if buf.strip():
            out.append(buf.strip())
    return [c for c in out if len(c) >= 40]


def _extract_keywords(text: str, limit: int = 30) -> list[str]:
    """Lowercase tokens, drop stopwords, dedupe by frequency."""
    counts: dict[str, int] = {}
    for tok in _TOKEN_RE.findall(text.lower()):
        if tok in _STOPWORDS:
            continue
        counts[tok] = counts.get(tok, 0) + 1
    return [w for w, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:limit]]


def _drawer_id(source_file: str, chunk_ix: int, content: str) -> str:
    h = hashlib.sha1(f"{source_file}:{chunk_ix}:{content}".encode())
    return h.hexdigest()[:16]


# ── Data shape ───────────────────────────────────────────────────────

@dataclass
class _Candidate:
    id: str
    content: str
    wing: str
    room: str
    source_file: str
    chunk_ix: int
    vector_score: float = 0.0
    keyword_hits: int = 0

    @property
    def score(self) -> float:
        return self.vector_score + 0.05 * min(self.keyword_hits, 5)


# ── Store ────────────────────────────────────────────────────────────

class DrawerStore:
    """SQLite-backed verbatim chunk store with hybrid retrieval."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
            isolation_level=None,
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS drawers (
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            wing TEXT DEFAULT '',
            room TEXT DEFAULT '',
            source_file TEXT DEFAULT '',
            chunk_ix INTEGER DEFAULT 0,
            mtime REAL DEFAULT 0,
            embedding BLOB,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_drawers_src ON drawers(source_file);
        CREATE INDEX IF NOT EXISTS idx_drawers_wing ON drawers(wing);
        CREATE INDEX IF NOT EXISTS idx_drawers_room ON drawers(room);
        CREATE TABLE IF NOT EXISTS keywords (
            drawer_id TEXT,
            keyword TEXT,
            PRIMARY KEY(drawer_id, keyword),
            FOREIGN KEY(drawer_id) REFERENCES drawers(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_keywords_kw ON keywords(keyword);
        """)

    def close(self) -> None:
        if self.conn:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except Exception:
                pass
            self.conn.close()
            self.conn = None  # type: ignore[assignment]

    # ── Ingest ───────────────────────────────────────────────────────

    def purge_file(self, source_file: str) -> None:
        self.conn.execute("DELETE FROM drawers WHERE source_file = ?", (source_file,))

    def _stored_mtime(self, source_file: str) -> float | None:
        row = self.conn.execute(
            "SELECT MAX(mtime) AS m FROM drawers WHERE source_file = ?",
            (source_file,),
        ).fetchone()
        return float(row["m"]) if row and row["m"] is not None else None

    def ingest_file(self, path: Path, wing: str = "", room: str = "") -> dict:
        p = Path(path)
        src = str(p)
        if not p.is_file():
            return {"file": src, "chunks": 0, "skipped": True}

        try:
            mtime = p.stat().st_mtime
        except OSError as e:
            logger.debug("stat failed for %s: %s", src, e)
            return {"file": src, "chunks": 0, "skipped": True}

        prior = self._stored_mtime(src)
        if prior is not None and abs(prior - mtime) < 1e-6:
            return {"file": src, "chunks": 0, "skipped": True}

        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            logger.debug("read failed for %s: %s", src, e)
            return {"file": src, "chunks": 0, "skipped": True}

        chunks = _chunk_text(text)
        now = datetime.now(UTC).isoformat()

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute("DELETE FROM drawers WHERE source_file = ?", (src,))
            for ix, content in enumerate(chunks):
                did = _drawer_id(src, ix, content)
                vec = None
                try:
                    vec = embed_text(content)
                except Exception as e:
                    logger.debug("embed failed on %s#%d: %s", src, ix, e)
                blob = pack_embedding(vec) if vec else None

                self.conn.execute(
                    """INSERT INTO drawers
                       (id, content, wing, room, source_file, chunk_ix, mtime, embedding, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (did, content, wing, room, src, ix, float(mtime), blob, now),
                )

                kws = _extract_keywords(content)
                if kws:
                    self.conn.executemany(
                        "INSERT OR IGNORE INTO keywords(drawer_id, keyword) VALUES (?, ?)",
                        [(did, k) for k in kws],
                    )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

        return {"file": src, "chunks": len(chunks), "skipped": False}

    def ingest_dir(
        self,
        dir: Path,
        wing: str = "",
        room: str = "",
        patterns: tuple[str, ...] = (
            "*.md", "*.txt", "*.py", "*.json", "*.yaml", "*.yml", "*.rst",
        ),
        max_bytes: int = 2_000_000,
    ) -> dict:
        root = Path(dir)
        if not root.is_dir():
            return {"files": 0, "chunks": 0, "skipped": 0}

        files = chunks = skipped = 0
        import os
        for cur, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for n in names:
                if not any(fnmatch.fnmatch(n, pat) for pat in patterns):
                    continue
                fp = Path(cur) / n
                try:
                    if fp.stat().st_size > max_bytes:
                        skipped += 1
                        continue
                except OSError:
                    skipped += 1
                    continue
                res = self.ingest_file(fp, wing=wing, room=room)
                files += 1
                chunks += int(res.get("chunks", 0))
                if res.get("skipped"):
                    skipped += 1
        return {"files": files, "chunks": chunks, "skipped": skipped}

    # ── Search ───────────────────────────────────────────────────────

    def _keyword_hits(
        self, ids: Iterable[str], query_kws: list[str]
    ) -> dict[str, int]:
        ids_l = list(ids)
        if not ids_l or not query_kws:
            return {}
        ip = ",".join("?" for _ in ids_l)
        kp = ",".join("?" for _ in query_kws)
        rows = self.conn.execute(
            f"""SELECT drawer_id, COUNT(*) AS hits
                FROM keywords
                WHERE drawer_id IN ({ip}) AND keyword IN ({kp})
                GROUP BY drawer_id""",
            [*ids_l, *query_kws],
        ).fetchall()
        return {r["drawer_id"]: int(r["hits"]) for r in rows}

    def search(
        self,
        query: str,
        wing: str = "",
        room: str = "",
        n_results: int = 5,
        min_score: float = 0.25,
    ) -> list[dict]:
        q = query.strip()
        if not q or n_results <= 0:
            return []

        query_kws = _extract_keywords(q)
        qvec = None
        try:
            qvec = embed_text(q)
        except Exception as e:
            logger.debug("query embed failed: %s", e)

        clauses: list[str] = []
        params: list = []
        if wing:
            clauses.append("wing = ?"); params.append(wing)
        if room:
            clauses.append("room = ?"); params.append(room)

        top_k = max(1, n_results * 3)
        candidates: list[_Candidate] = []

        if qvec:
            where = " AND ".join(["embedding IS NOT NULL", *clauses])
            rows = self.conn.execute(
                f"""SELECT id, content, wing, room, source_file, chunk_ix, embedding
                    FROM drawers WHERE {where} LIMIT 2000""",
                params,
            ).fetchall()
            scored: list[_Candidate] = []
            for r in rows:
                try:
                    v = unpack_embedding(r["embedding"])
                    sc = float(cosine_similarity(qvec, v))
                except Exception:
                    continue
                scored.append(_Candidate(
                    id=r["id"], content=r["content"], wing=r["wing"],
                    room=r["room"], source_file=r["source_file"],
                    chunk_ix=int(r["chunk_ix"]), vector_score=sc,
                ))
            scored.sort(key=lambda c: c.vector_score, reverse=True)
            candidates = scored[:top_k]
        elif query_kws:
            kp = ",".join("?" for _ in query_kws)
            sql = f"""SELECT d.id, d.content, d.wing, d.room, d.source_file, d.chunk_ix,
                            COUNT(k.keyword) AS hits
                     FROM drawers d JOIN keywords k ON k.drawer_id = d.id
                     WHERE k.keyword IN ({kp})"""
            p2: list = list(query_kws)
            for c in clauses:
                sql += f" AND d.{c}"
            p2 += params
            sql += " GROUP BY d.id ORDER BY hits DESC LIMIT ?"
            p2.append(top_k)
            rows = self.conn.execute(sql, p2).fetchall()
            candidates = [
                _Candidate(
                    id=r["id"], content=r["content"], wing=r["wing"],
                    room=r["room"], source_file=r["source_file"],
                    chunk_ix=int(r["chunk_ix"]), keyword_hits=int(r["hits"]),
                )
                for r in rows
            ]

        if not candidates:
            return []

        if query_kws:
            hits = self._keyword_hits((c.id for c in candidates), query_kws)
            for c in candidates:
                c.keyword_hits = hits.get(c.id, c.keyword_hits)

        if qvec:
            candidates = [c for c in candidates if c.vector_score >= min_score]
        else:
            candidates = [c for c in candidates if c.keyword_hits >= 1]

        candidates.sort(key=lambda c: (c.score, c.vector_score, c.keyword_hits), reverse=True)
        return [
            {
                "id": c.id, "content": c.content, "wing": c.wing, "room": c.room,
                "source_file": c.source_file, "chunk_ix": c.chunk_ix,
                "score": c.score, "vector_score": c.vector_score,
                "keyword_hits": c.keyword_hits,
            }
            for c in candidates[:n_results]
        ]

    # ── Stats ────────────────────────────────────────────────────────

    def stats(self) -> dict:
        c = self.conn
        drawers = int(c.execute("SELECT COUNT(*) FROM drawers").fetchone()[0])
        files = int(c.execute("SELECT COUNT(DISTINCT source_file) FROM drawers").fetchone()[0])
        wings = int(c.execute("SELECT COUNT(DISTINCT wing) FROM drawers WHERE wing != ''").fetchone()[0])
        rooms = int(c.execute("SELECT COUNT(DISTINCT room) FROM drawers WHERE room != ''").fetchone()[0])
        db_bytes = 0
        try:
            db_bytes = self.db_path.stat().st_size
            for ext in ("-wal", "-shm"):
                p = self.db_path.with_name(self.db_path.name + ext)
                if p.exists():
                    db_bytes += p.stat().st_size
        except OSError:
            pass
        return {"drawers": drawers, "files": files, "wings": wings,
                "rooms": rooms, "db_bytes": db_bytes}
