"""Beta Store — Semantic Memory (The Analyst).

Stores what is true: patterns, rules, generalizations, causal models.
SQLite-backed concept graph with typed edges. Confidence decay.
Optional vector embeddings via Ollama for semantic search.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .storage import HelixDB

logger = logging.getLogger("helix.beta")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Connection (Edge in Concept Graph) ────────────────────────────

@dataclass
class Connection:
    target_id: str
    relation: str
    strength: float

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Connection:
        return cls(
            target_id=d["target_id"],
            relation=d["relation"],
            strength=d.get("strength", 0.5),
        )


# ── Concept (Node in Concept Graph) ──────────────────────────────

VALID_CATEGORIES = {"pattern", "rule", "causal", "entity", "baseline", "procedure"}
VALID_RELATIONS = {"causes", "prevents", "correlates", "contradicts", "requires"}


@dataclass
class Concept:
    id: str
    category: str
    title: str
    description: str
    confidence: float = 0.3
    evidence_count: int = 0
    evidence_ids: list[str] = field(default_factory=list)
    contradictions: int = 0
    first_derived: str = ""
    last_reinforced: str = ""
    connections: list[Connection] = field(default_factory=list)
    decay_rate: float = 0.01
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.first_derived:
            self.first_derived = _now().isoformat()
        if not self.last_reinforced:
            self.last_reinforced = self.first_derived

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence_ids"] = json.dumps(d["evidence_ids"])
        d["metadata"] = json.dumps(d["metadata"])
        d.pop("connections", None)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Concept:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        clean = {}
        for k, v in d.items():
            if k not in known or k == "connections":
                continue
            if k == "evidence_ids" and isinstance(v, str):
                v = json.loads(v)
            elif k == "metadata" and isinstance(v, str):
                v = json.loads(v)
            clean[k] = v
        return cls(**clean)

    @property
    def effective_confidence(self) -> float:
        try:
            ts = datetime.fromisoformat(self.last_reinforced.replace("Z", "+00:00"))
            age_days = (_now() - ts).days
        except (ValueError, TypeError):
            age_days = 0
        decay = self.decay_rate * max(0, age_days - 14)
        contradiction_penalty = self.contradictions * 0.05
        return max(0.0, min(1.0, self.confidence - decay - contradiction_penalty))

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(
            f"{self.category}:{self.title[:100]}".encode()
        ).hexdigest()[:12]

    def reinforce(self, evidence_ids: list[str], boost: float = 0.05) -> None:
        self.evidence_count += len(evidence_ids)
        for eid in evidence_ids:
            if eid not in self.evidence_ids:
                self.evidence_ids.append(eid)
        self.confidence = min(1.0, self.confidence + boost * len(evidence_ids))
        self.last_reinforced = _now().isoformat()

    def weaken(self, amount: float = 0.1) -> None:
        self.contradictions += 1
        self.confidence = max(0.0, self.confidence - amount)

    def connect(self, target_id: str, relation: str, strength: float = 0.5) -> None:
        for conn in self.connections:
            if conn.target_id == target_id and conn.relation == relation:
                conn.strength = min(1.0, conn.strength + 0.1)
                return
        self.connections.append(Connection(
            target_id=target_id, relation=relation, strength=strength,
        ))

    def disconnect(self, target_id: str) -> None:
        self.connections = [c for c in self.connections if c.target_id != target_id]


# ── Semantic Store ────────────────────────────────────────────────

class SemanticStore:
    """Beta store — SQLite-backed concept graph with optional embeddings."""

    def __init__(self, db: HelixDB):
        self.db = db
        self._embedding_available: Optional[bool] = None

    def _check_embeddings(self) -> bool:
        if self._embedding_available is None:
            from .embeddings import is_available
            self._embedding_available = is_available()
            if self._embedding_available:
                logger.info("Embedding model available — using vector search")
            else:
                logger.info("Embedding model unavailable — using keyword matching")
        return self._embedding_available

    def _store_concept_embedding(self, concept: Concept) -> None:
        if not self._check_embeddings():
            return
        from .embeddings import embed_text, pack_embedding
        text = f"{concept.title} {concept.description}"
        vec = embed_text(text)
        if vec:
            self.db.store_embedding(
                concept.id, "concept", pack_embedding(vec), _now().isoformat()
            )

    def add(self, concept: Concept) -> Concept:
        self.db.insert_concept(concept.to_dict())
        for conn in concept.connections:
            self.db.upsert_connection(
                concept.id, conn.target_id, conn.relation, conn.strength
            )
        self._store_concept_embedding(concept)
        logger.info("Added concept [%s]: %s", concept.id, concept.title)
        return concept

    def get(self, concept_id: str) -> Optional[Concept]:
        row = self.db.get_concept(concept_id)
        if not row:
            return None
        concept = Concept.from_dict(row)
        conn_rows = self.db.get_connections(concept_id)
        concept.connections = [
            Connection(target_id=r["target_id"], relation=r["relation"],
                       strength=r["strength"])
            for r in conn_rows
        ]
        return concept

    def remove(self, concept_id: str) -> bool:
        return self.db.delete_concept(concept_id)

    def find_similar(self, title: str, threshold: float = 0.3) -> list[Concept]:
        if not title.strip():
            return []

        if self._check_embeddings():
            from .embeddings import embed_text, nearest_neighbors
            query_vec = embed_text(title)
            if query_vec:
                candidates = self.db.all_embeddings("concept")
                if candidates:
                    matches = nearest_neighbors(
                        query_vec, candidates, top_k=10, min_score=threshold
                    )
                    results = []
                    for cid, score in matches:
                        concept = self.get(cid)
                        if concept:
                            results.append(concept)
                    if results:
                        return results

        from .matching import semantic_match
        scored = []
        for row in self.db.all_concepts():
            concept = Concept.from_dict(row)
            score = semantic_match(title, concept.title, concept.description)
            if score >= threshold:
                scored.append((score, concept))
        scored.sort(key=lambda x: -x[0])
        return [c for _, c in scored]

    def find_by_category(self, category: str, min_confidence: float = 0.0) -> list[Concept]:
        rows = self.db.query_concepts(category=category, min_confidence=min_confidence)
        return [Concept.from_dict(r) for r in rows]

    def find_by_evidence(self, episode_id: str) -> list[Concept]:
        results = []
        for row in self.db.all_concepts():
            eids = json.loads(row.get("evidence_ids", "[]"))
            if episode_id in eids:
                results.append(Concept.from_dict(row))
        return results

    def recall(
        self,
        query: str = "",
        category: str = "",
        min_confidence: float = 0.0,
        limit: int = 20,
    ) -> list[Concept]:
        if query and self._check_embeddings():
            from .embeddings import embed_text, nearest_neighbors
            query_vec = embed_text(query)
            if query_vec:
                candidates = self.db.all_embeddings("concept")
                if candidates:
                    matches = nearest_neighbors(
                        query_vec, candidates, top_k=limit, min_score=0.2
                    )
                    results = []
                    for cid, _ in matches:
                        concept = self.get(cid)
                        if not concept:
                            continue
                        if category and concept.category != category:
                            continue
                        if concept.effective_confidence < min_confidence:
                            continue
                        results.append(concept)
                    if results:
                        return results[:limit]

        all_rows = self.db.all_concepts()
        results = []
        for row in all_rows:
            concept = Concept.from_dict(row)
            if category and concept.category != category:
                continue
            if concept.effective_confidence < min_confidence:
                continue
            if query:
                from .matching import semantic_match
                if semantic_match(query, concept.title, concept.description) < 0.2:
                    continue
            results.append(concept)

        results.sort(key=lambda c: -c.effective_confidence)
        return results[:limit]

    def reinforce_concept(self, concept_id: str, evidence_ids: list[str]) -> bool:
        concept = self.get(concept_id)
        if not concept:
            return False
        concept.reinforce(evidence_ids)
        self.db.replace_concept(concept.to_dict())
        return True

    def weaken_concept(self, concept_id: str, amount: float = 0.1) -> bool:
        concept = self.get(concept_id)
        if not concept:
            return False
        concept.weaken(amount)
        self.db.replace_concept(concept.to_dict())
        return True

    def connect_concepts(
        self, source_id: str, target_id: str, relation: str, strength: float = 0.5,
    ) -> bool:
        if not self.db.get_concept(source_id) or not self.db.get_concept(target_id):
            return False
        self.db.upsert_connection(source_id, target_id, relation, strength)
        return True

    def neighbors(self, concept_id: str, relation: str = "") -> list[tuple[Concept, Connection]]:
        conn_rows = self.db.get_connections(concept_id, relation=relation)
        results = []
        for r in conn_rows:
            target = self.get(r["target_id"])
            if target:
                conn = Connection(
                    target_id=r["target_id"],
                    relation=r["relation"],
                    strength=r["strength"],
                )
                results.append((target, conn))
        return results

    def decay_all(self) -> int:
        below = 0
        for row in self.db.all_concepts():
            c = Concept.from_dict(row)
            if c.effective_confidence < 0.05:
                below += 1
        return below

    def prune(self, min_confidence: float = 0.05) -> int:
        to_remove = []
        for row in self.db.all_concepts():
            c = Concept.from_dict(row)
            if c.effective_confidence < min_confidence:
                to_remove.append(c.id)
        for cid in to_remove:
            self.db.delete_concept(cid)
        if to_remove:
            logger.info("Pruned %d low-confidence concepts", len(to_remove))
        return len(to_remove)

    def stats(self) -> dict:
        return self.db.concept_stats()

    @property
    def all_concepts(self) -> list[Concept]:
        return [Concept.from_dict(r) for r in self.db.all_concepts()]
