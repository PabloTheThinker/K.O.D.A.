"""Helix SQLite Storage Backend.

Replaces JSON file storage with WAL-mode SQLite. Thread-safe,
atomic writes, FTS5 full-text search, embedding storage.

Single HelixDB instance handles all stores: episodes, concepts,
connections, conflicts, incidents, embeddings.
"""
from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger("helix.storage")

SCHEMA_VERSION = 1


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class HelixDB:
    """SQLite storage backend for all Helix subsystems."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._migrate()

    def close(self):
        if self._conn:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except Exception:
                pass
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @contextmanager
    def _tx(self):
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            try:
                self._conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    # ── Schema Migration ───────────────────────────────────────────

    def _migrate(self):
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS episodes (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            content TEXT NOT NULL,
            context TEXT DEFAULT '',
            outcome TEXT DEFAULT '',
            significance REAL DEFAULT 0.5,
            severity TEXT DEFAULT '',
            links TEXT DEFAULT '[]',
            reinforcement_count INTEGER DEFAULT 0,
            last_recalled TEXT DEFAULT '',
            decay_rate REAL DEFAULT 0.02,
            consolidated INTEGER DEFAULT 0,
            contradiction_flags INTEGER DEFAULT 0,
            metadata TEXT DEFAULT '{}',
            content_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ep_ts ON episodes(timestamp);
        CREATE INDEX IF NOT EXISTS idx_ep_type ON episodes(event_type);
        CREATE INDEX IF NOT EXISTS idx_ep_sev ON episodes(severity);
        CREATE INDEX IF NOT EXISTS idx_ep_hash ON episodes(content_hash);
        CREATE INDEX IF NOT EXISTS idx_ep_consol ON episodes(consolidated);

        CREATE TABLE IF NOT EXISTS concepts (
            id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            confidence REAL DEFAULT 0.3,
            evidence_count INTEGER DEFAULT 0,
            evidence_ids TEXT DEFAULT '[]',
            contradictions INTEGER DEFAULT 0,
            first_derived TEXT NOT NULL,
            last_reinforced TEXT NOT NULL,
            decay_rate REAL DEFAULT 0.01,
            metadata TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_con_cat ON concepts(category);
        CREATE INDEX IF NOT EXISTS idx_con_conf ON concepts(confidence);

        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id TEXT NOT NULL REFERENCES concepts(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES concepts(id) ON DELETE CASCADE,
            relation TEXT NOT NULL,
            strength REAL DEFAULT 0.5,
            UNIQUE(source_id, target_id, relation)
        );
        CREATE INDEX IF NOT EXISTS idx_conn_src ON connections(source_id);
        CREATE INDEX IF NOT EXISTS idx_conn_tgt ON connections(target_id);

        CREATE TABLE IF NOT EXISTS conflicts (
            id TEXT PRIMARY KEY,
            alpha_episode_id TEXT NOT NULL,
            beta_concept_id TEXT NOT NULL,
            alpha_claim TEXT DEFAULT '',
            beta_claim TEXT DEFAULT '',
            created TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            resolution TEXT DEFAULT '',
            resolution_date TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_cfl_res ON conflicts(resolved);

        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            episode_id TEXT NOT NULL,
            finding TEXT NOT NULL,
            severity TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            verdict TEXT DEFAULT '',
            verified_at TEXT DEFAULT '',
            enrichment TEXT DEFAULT '',
            enriched_at TEXT DEFAULT '',
            containment_actions TEXT DEFAULT '[]',
            contained_at TEXT DEFAULT '',
            reported INTEGER DEFAULT 0,
            reported_at TEXT DEFAULT '',
            report_channels TEXT DEFAULT '[]',
            total_response_ms INTEGER DEFAULT 0,
            status TEXT DEFAULT 'detected',
            closed_reason TEXT DEFAULT '',
            metadata TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_inc_stat ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_inc_sev ON incidents(severity);

        CREATE TABLE IF NOT EXISTS embeddings (
            item_id TEXT NOT NULL,
            item_type TEXT NOT NULL,
            embedding BLOB NOT NULL,
            updated TEXT NOT NULL,
            PRIMARY KEY (item_id, item_type)
        );

        CREATE TABLE IF NOT EXISTS dedup_hashes (
            content_hash TEXT PRIMARY KEY,
            created TEXT NOT NULL
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS episodes_fts
            USING fts5(content, content=episodes, content_rowid=rowid);

        CREATE VIRTUAL TABLE IF NOT EXISTS concepts_fts
            USING fts5(title, description, content=concepts, content_rowid=rowid);
        """)

        # FTS sync triggers — separate because executescript can't mix DDL types reliably
        for sql in [
            """CREATE TRIGGER IF NOT EXISTS ep_fts_ai AFTER INSERT ON episodes BEGIN
                INSERT INTO episodes_fts(rowid, content) VALUES (new.rowid, new.content);
            END""",
            """CREATE TRIGGER IF NOT EXISTS ep_fts_ad AFTER DELETE ON episodes BEGIN
                INSERT INTO episodes_fts(episodes_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
            END""",
            """CREATE TRIGGER IF NOT EXISTS ep_fts_au AFTER UPDATE ON episodes BEGIN
                INSERT INTO episodes_fts(episodes_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
                INSERT INTO episodes_fts(rowid, content) VALUES (new.rowid, new.content);
            END""",
            """CREATE TRIGGER IF NOT EXISTS con_fts_ai AFTER INSERT ON concepts BEGIN
                INSERT INTO concepts_fts(rowid, title, description) VALUES (new.rowid, new.title, new.description);
            END""",
            """CREATE TRIGGER IF NOT EXISTS con_fts_ad AFTER DELETE ON concepts BEGIN
                INSERT INTO concepts_fts(concepts_fts, rowid, title, description) VALUES ('delete', old.rowid, old.title, old.description);
            END""",
            """CREATE TRIGGER IF NOT EXISTS con_fts_au AFTER UPDATE ON concepts BEGIN
                INSERT INTO concepts_fts(concepts_fts, rowid, title, description) VALUES ('delete', old.rowid, old.title, old.description);
                INSERT INTO concepts_fts(rowid, title, description) VALUES (new.rowid, new.title, new.description);
            END""",
        ]:
            try:
                self._conn.execute(sql)
            except sqlite3.OperationalError:
                pass

        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )

    # ── Episodes ───────────────────────────────────────────────────

    def insert_episode(self, d: dict) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT INTO episodes
                (id, timestamp, event_type, content, context, outcome,
                 significance, severity, links, reinforcement_count,
                 last_recalled, decay_rate, consolidated, contradiction_flags,
                 metadata, content_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (d["id"], d["timestamp"], d["event_type"], d["content"],
                 d.get("context", ""), d.get("outcome", ""),
                 d.get("significance", 0.5), d.get("severity", ""),
                 d.get("links", "[]"), d.get("reinforcement_count", 0),
                 d.get("last_recalled", ""), d.get("decay_rate", 0.02),
                 d.get("consolidated", 0), d.get("contradiction_flags", 0),
                 d.get("metadata", "{}"), d["content_hash"]),
            )

    def get_episode(self, episode_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM episodes WHERE id = ?", (episode_id,)
        ).fetchone()
        return dict(row) if row else None

    def query_episodes(
        self, query: str = "", event_type: str = "",
        min_significance: float = 0.0, max_age_days: int = 90,
        limit: int = 20,
    ) -> list[dict]:
        cutoff = (datetime.now(UTC) - timedelta(days=max_age_days)).isoformat()
        conditions = ["timestamp >= ?"]
        params: list = [cutoff]
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if min_significance > 0:
            conditions.append("significance >= ?")
            params.append(min_significance)
        where = " AND ".join(conditions)

        if query:
            fts_query = '"' + query.replace('"', '""') + '"'
            try:
                rows = self._conn.execute(
                    f"""SELECT e.* FROM episodes e
                        JOIN episodes_fts f ON e.rowid = f.rowid
                        WHERE {where} AND episodes_fts MATCH ?
                        ORDER BY e.significance DESC LIMIT ?""",
                    params + [fts_query, limit],
                ).fetchall()
            except Exception:
                rows = []
            if not rows:
                rows = self._conn.execute(
                    f"""SELECT * FROM episodes
                        WHERE {where} AND (content LIKE ? OR context LIKE ?)
                        ORDER BY significance DESC LIMIT ?""",
                    params + [f"%{query}%", f"%{query}%", limit],
                ).fetchall()
        else:
            rows = self._conn.execute(
                f"SELECT * FROM episodes WHERE {where} ORDER BY significance DESC LIMIT ?",
                params + [limit],
            ).fetchall()
        return [dict(r) for r in rows]

    def recent_episodes(self, hours: int = 24, limit: int = 50) -> list[dict]:
        cutoff = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
        rows = self._conn.execute(
            "SELECT * FROM episodes WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
            (cutoff, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def update_episode(self, episode_id: str, **fields) -> bool:
        if not fields:
            return False
        sets = ", ".join(f"{k} = ?" for k in fields)
        vals = list(fields.values()) + [episode_id]
        with self._tx() as c:
            cur = c.execute(f"UPDATE episodes SET {sets} WHERE id = ?", vals)
            return cur.rowcount > 0

    def search_episodes_fts(self, query: str, limit: int = 20) -> list[dict]:
        fts_query = '"' + query.replace('"', '""') + '"'
        try:
            rows = self._conn.execute(
                """SELECT e.* FROM episodes e
                   JOIN episodes_fts f ON e.rowid = f.rowid
                   WHERE episodes_fts MATCH ?
                   ORDER BY rank LIMIT ?""",
                (fts_query, limit),
            ).fetchall()
        except Exception:
            rows = []
        return [dict(r) for r in rows]

    def episode_exists_hash(self, content_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM dedup_hashes WHERE content_hash = ?", (content_hash,)
        ).fetchone()
        return row is not None

    def add_dedup_hash(self, content_hash: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO dedup_hashes (content_hash, created) VALUES (?, ?)",
            (content_hash, _now_iso()),
        )

    def prune_dedup_hashes(self, max_count: int = 500) -> int:
        count = self._conn.execute("SELECT COUNT(*) FROM dedup_hashes").fetchone()[0]
        if count <= max_count:
            return 0
        excess = count - max_count
        with self._tx() as c:
            c.execute(
                "DELETE FROM dedup_hashes WHERE content_hash IN "
                "(SELECT content_hash FROM dedup_hashes ORDER BY created ASC LIMIT ?)",
                (excess,),
            )
            return excess

    def cluster_episodes(self, max_age_hours: int = 72, limit: int = 200) -> list[dict]:
        cutoff = (datetime.now(UTC) - timedelta(hours=max_age_hours)).isoformat()
        rows = self._conn.execute(
            """SELECT * FROM episodes
               WHERE consolidated = 0 AND timestamp >= ?
               ORDER BY timestamp DESC LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def count_episodes(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM episodes").fetchone()[0]

    def episode_stats(self) -> dict:
        total = self.count_episodes()
        if total == 0:
            return {"total_episodes": 0, "oldest": None, "newest": None}
        oldest = self._conn.execute(
            "SELECT MIN(timestamp) FROM episodes"
        ).fetchone()[0]
        newest = self._conn.execute(
            "SELECT MAX(timestamp) FROM episodes"
        ).fetchone()[0]
        return {"total_episodes": total, "oldest": oldest, "newest": newest}

    def prune_episodes(self, min_significance: float = 0.01, max_age_days: int = 180) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=max_age_days)).isoformat()
        with self._tx() as c:
            cur = c.execute(
                "DELETE FROM episodes WHERE timestamp < ? AND significance < ?",
                (cutoff, min_significance),
            )
            return cur.rowcount

    # ── Concepts ───────────────────────────────────────────────────

    def insert_concept(self, d: dict) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT OR REPLACE INTO concepts
                (id, category, title, description, confidence, evidence_count,
                 evidence_ids, contradictions, first_derived, last_reinforced,
                 decay_rate, metadata)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (d["id"], d["category"], d["title"], d.get("description", ""),
                 d.get("confidence", 0.3), d.get("evidence_count", 0),
                 d.get("evidence_ids", "[]"), d.get("contradictions", 0),
                 d["first_derived"], d["last_reinforced"],
                 d.get("decay_rate", 0.01), d.get("metadata", "{}")),
            )

    def get_concept(self, concept_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM concepts WHERE id = ?", (concept_id,)
        ).fetchone()
        return dict(row) if row else None

    def update_concept(self, concept_id: str, **fields) -> bool:
        if not fields:
            return False
        sets = ", ".join(f"{k} = ?" for k in fields)
        vals = list(fields.values()) + [concept_id]
        with self._tx() as c:
            cur = c.execute(f"UPDATE concepts SET {sets} WHERE id = ?", vals)
            return cur.rowcount > 0

    def replace_concept(self, d: dict) -> None:
        self.insert_concept(d)

    def delete_concept(self, concept_id: str) -> bool:
        with self._tx() as c:
            c.execute("DELETE FROM connections WHERE source_id = ? OR target_id = ?",
                      (concept_id, concept_id))
            cur = c.execute("DELETE FROM concepts WHERE id = ?", (concept_id,))
            return cur.rowcount > 0

    def query_concepts(self, category: str = "", min_confidence: float = 0.0,
                       limit: int = 20) -> list[dict]:
        conditions = []
        params: list = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        if min_confidence > 0:
            conditions.append("confidence >= ?")
            params.append(min_confidence)
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        rows = self._conn.execute(
            f"SELECT * FROM concepts {where} ORDER BY confidence DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [dict(r) for r in rows]

    def search_concepts_fts(self, query: str, limit: int = 20) -> list[dict]:
        fts_query = '"' + query.replace('"', '""') + '"'
        try:
            rows = self._conn.execute(
                """SELECT c.* FROM concepts c
                   JOIN concepts_fts f ON c.rowid = f.rowid
                   WHERE concepts_fts MATCH ?
                   ORDER BY rank LIMIT ?""",
                (fts_query, limit),
            ).fetchall()
        except Exception:
            rows = []
        return [dict(r) for r in rows]

    def all_concepts(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM concepts").fetchall()
        return [dict(r) for r in rows]

    def concept_stats(self) -> dict:
        total = self._conn.execute("SELECT COUNT(*) FROM concepts").fetchone()[0]
        if total == 0:
            return {"total_concepts": 0, "categories": {}, "connections": 0}
        cats = self._conn.execute(
            "SELECT category, COUNT(*) FROM concepts GROUP BY category"
        ).fetchall()
        conns = self._conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
        avg_conf = self._conn.execute(
            "SELECT AVG(confidence) FROM concepts"
        ).fetchone()[0] or 0
        return {
            "total_concepts": total,
            "categories": {r[0]: r[1] for r in cats},
            "connections": conns,
            "avg_confidence": round(avg_conf, 3),
        }

    # ── Connections ────────────────────────────────────────────────

    def upsert_connection(self, source_id: str, target_id: str,
                          relation: str, strength: float = 0.5) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT INTO connections (source_id, target_id, relation, strength)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(source_id, target_id, relation)
                   DO UPDATE SET strength = MIN(1.0, strength + 0.1)""",
                (source_id, target_id, relation, strength),
            )

    def get_connections(self, concept_id: str, relation: str = "") -> list[dict]:
        if relation:
            rows = self._conn.execute(
                "SELECT * FROM connections WHERE source_id = ? AND relation = ?",
                (concept_id, relation),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM connections WHERE source_id = ?",
                (concept_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_connections_for(self, concept_id: str) -> int:
        with self._tx() as c:
            cur = c.execute(
                "DELETE FROM connections WHERE source_id = ? OR target_id = ?",
                (concept_id, concept_id),
            )
            return cur.rowcount

    def update_connection_strength(self, source_id: str, target_id: str,
                                   relation: str, strength: float) -> bool:
        with self._tx() as c:
            cur = c.execute(
                """UPDATE connections SET strength = ?
                   WHERE source_id = ? AND target_id = ? AND relation = ?""",
                (strength, source_id, target_id, relation),
            )
            return cur.rowcount > 0

    # ── Conflicts ──────────────────────────────────────────────────

    def insert_conflict(self, d: dict) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT OR IGNORE INTO conflicts
                (id, alpha_episode_id, beta_concept_id, alpha_claim,
                 beta_claim, created, resolved, resolution, resolution_date)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (d["id"], d["alpha_episode_id"], d["beta_concept_id"],
                 d.get("alpha_claim", ""), d.get("beta_claim", ""),
                 d["created"], d.get("resolved", 0),
                 d.get("resolution", ""), d.get("resolution_date", "")),
            )

    def get_conflict(self, conflict_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM conflicts WHERE id = ?", (conflict_id,)
        ).fetchone()
        return dict(row) if row else None

    def active_conflicts(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM conflicts WHERE resolved = 0"
        ).fetchall()
        return [dict(r) for r in rows]

    def resolve_conflict(self, conflict_id: str, resolution: str,
                         resolution_date: str) -> bool:
        with self._tx() as c:
            cur = c.execute(
                """UPDATE conflicts SET resolved = 1, resolution = ?,
                   resolution_date = ? WHERE id = ?""",
                (resolution, resolution_date, conflict_id),
            )
            return cur.rowcount > 0

    def prune_resolved(self, before_date: str) -> int:
        with self._tx() as c:
            cur = c.execute(
                """DELETE FROM conflicts
                   WHERE resolved = 1 AND resolution_date != '' AND resolution_date < ?""",
                (before_date,),
            )
            return cur.rowcount

    # ── Incidents ──────────────────────────────────────────────────

    def insert_incident(self, d: dict) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT OR REPLACE INTO incidents
                (id, episode_id, finding, severity, detected_at, verdict,
                 verified_at, enrichment, enriched_at, containment_actions,
                 contained_at, reported, reported_at, report_channels,
                 total_response_ms, status, closed_reason, metadata)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (d["id"], d["episode_id"], d["finding"], d["severity"],
                 d["detected_at"], d.get("verdict", ""),
                 d.get("verified_at", ""), d.get("enrichment", ""),
                 d.get("enriched_at", ""), d.get("containment_actions", "[]"),
                 d.get("contained_at", ""), d.get("reported", 0),
                 d.get("reported_at", ""), d.get("report_channels", "[]"),
                 d.get("total_response_ms", 0), d.get("status", "detected"),
                 d.get("closed_reason", ""), d.get("metadata", "{}")),
            )

    def get_incident(self, incident_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return dict(row) if row else None

    def update_incident(self, d: dict) -> None:
        self.insert_incident(d)

    def active_incidents(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM incidents WHERE status != 'closed'"
        ).fetchall()
        return [dict(r) for r in rows]

    def incident_stats(self) -> dict:
        active = self._conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status != 'closed'"
        ).fetchone()[0]
        if active == 0:
            return {"active_incidents": 0, "avg_response_ms": 0}
        avg = self._conn.execute(
            "SELECT AVG(total_response_ms) FROM incidents WHERE status != 'closed'"
        ).fetchone()[0] or 0
        by_sev = self._conn.execute(
            "SELECT severity, COUNT(*) FROM incidents WHERE status != 'closed' GROUP BY severity"
        ).fetchall()
        return {
            "active_incidents": active,
            "avg_response_ms": round(avg),
            "by_severity": {r[0]: r[1] for r in by_sev},
        }

    # ── Embeddings ─────────────────────────────────────────────────

    def store_embedding(self, item_id: str, item_type: str,
                        embedding: bytes, updated: str) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO embeddings
               (item_id, item_type, embedding, updated)
               VALUES (?, ?, ?, ?)""",
            (item_id, item_type, embedding, updated),
        )

    def get_embedding(self, item_id: str, item_type: str) -> bytes | None:
        row = self._conn.execute(
            "SELECT embedding FROM embeddings WHERE item_id = ? AND item_type = ?",
            (item_id, item_type),
        ).fetchone()
        return row[0] if row else None

    def all_embeddings(self, item_type: str) -> list[tuple[str, bytes]]:
        rows = self._conn.execute(
            "SELECT item_id, embedding FROM embeddings WHERE item_type = ?",
            (item_type,),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    # ── Maintenance ────────────────────────────────────────────────

    def vacuum(self) -> None:
        self._conn.execute("VACUUM")

    def stats(self) -> dict:
        tables = ["episodes", "concepts", "connections", "conflicts",
                  "incidents", "embeddings", "dedup_hashes"]
        counts = {}
        for t in tables:
            counts[t] = self._conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        size = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {"counts": counts, "size_bytes": size, "schema_version": SCHEMA_VERSION}
