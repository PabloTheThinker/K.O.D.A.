"""Entanglement Protocol — Cross-Store Verification.

Alpha and Beta don't trust each other. They verify, disagree,
and surface contradictions as first-class objects.

Three flows:
  Alpha -> Beta (consolidation): episodes become concepts
  Beta -> Alpha (predictive recall): concepts guide retrieval
  Conflict resolution: disagreements are tracked and surfaced
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from .alpha import Episode, EpisodicStore
from .beta import Concept, SemanticStore

if TYPE_CHECKING:
    from .storage import HelixDB

logger = logging.getLogger("helix.entanglement")


def _now() -> datetime:
    return datetime.now(UTC)


# ── Conflict Model ─────────────────────────────────────────────────

@dataclass
class Conflict:
    id: str
    alpha_episode_id: str
    beta_concept_id: str
    alpha_claim: str
    beta_claim: str
    created: str = ""
    resolved: bool = False
    resolution: str = ""
    resolution_date: str = ""

    def __post_init__(self):
        if not self.created:
            self.created = _now().isoformat()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["resolved"] = int(d["resolved"])
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Conflict:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        clean = {k: v for k, v in d.items() if k in known}
        if "resolved" in clean:
            clean["resolved"] = bool(clean["resolved"])
        return cls(**clean)

    def resolve(self, resolution: str) -> None:
        self.resolved = True
        self.resolution = resolution
        self.resolution_date = _now().isoformat()


# ── Consolidation Result ───────────────────────────────────────────

@dataclass
class ConsolidationResult:
    concepts_created: int = 0
    concepts_reinforced: int = 0
    conflicts_detected: int = 0
    episodes_consolidated: int = 0
    details: list[str] = field(default_factory=list)


# ── Entanglement Protocol ──────────────────────────────────────────

class EntanglementProtocol:
    """Cross-store verification and synchronization. SQLite-backed."""

    def __init__(self, alpha: EpisodicStore, beta: SemanticStore, db: HelixDB):
        self.alpha = alpha
        self.beta = beta
        self.db = db

    # ── Alpha -> Beta: Consolidation ───────────────────────────────

    def consolidate(
        self,
        min_cluster_size: int = 3,
        max_age_hours: int = 72,
    ) -> ConsolidationResult:
        result = ConsolidationResult()
        clusters = self.alpha.cluster_recent(
            min_episodes=min_cluster_size,
            max_age_hours=max_age_hours,
        )

        for cluster in clusters:
            evidence_ids = [ep.id for ep in cluster]
            title = self._derive_cluster_title(cluster)
            description = self._derive_cluster_description(cluster)

            similar = self.beta.find_similar(title, threshold=0.5)

            if similar:
                concept = similar[0]
                concept.reinforce(evidence_ids)
                self.db.replace_concept(concept.to_dict())

                for ep in cluster:
                    if self._contradicts(ep, concept):
                        self._record_conflict(ep, concept)
                        result.conflicts_detected += 1

                result.concepts_reinforced += 1
                result.details.append(
                    f"Reinforced [{concept.id[:8]}]: {concept.title} "
                    f"(+{len(evidence_ids)} evidence, now {concept.confidence:.0%})"
                )
            else:
                concept_id = hashlib.sha256(
                    f"{_now().isoformat()}:{title}".encode()
                ).hexdigest()[:16]

                concept = Concept(
                    id=concept_id,
                    category=self._infer_category(cluster),
                    title=title,
                    description=description,
                    confidence=min(0.8, 0.3 + 0.1 * len(cluster)),
                    evidence_count=len(cluster),
                    evidence_ids=evidence_ids,
                )
                self.beta.add(concept)
                result.concepts_created += 1
                result.details.append(
                    f"Created [{concept_id[:8]}]: {title} "
                    f"(from {len(cluster)} episodes, {concept.confidence:.0%})"
                )

            consolidated = self.alpha.mark_consolidated(evidence_ids)
            result.episodes_consolidated += consolidated

        return result

    # ── Beta -> Alpha: Predictive Recall ───────────────────────────

    def predictive_recall(
        self,
        context: str,
        min_concept_confidence: float = 0.3,
        max_episodes: int = 10,
    ) -> dict:
        relevant_concepts = self.beta.recall(
            query=context, min_confidence=min_concept_confidence, limit=5,
        )

        if not relevant_concepts:
            return {
                "concepts": [],
                "episodes": self.alpha.recall(query=context, limit=max_episodes),
                "conflicts": [],
            }

        grounding_episodes: list[Episode] = []
        seen_ids: set[str] = set()

        for concept in relevant_concepts:
            for eid in concept.evidence_ids[-5:]:
                if eid in seen_ids:
                    continue
                ep_data = self.db.get_episode(eid)
                if ep_data:
                    ep = Episode.from_dict(ep_data)
                    grounding_episodes.append(ep)
                    seen_ids.add(ep.id)
                    self.alpha.reinforce(ep.id)

        direct = self.alpha.recall(query=context, limit=max_episodes)
        for ep in direct:
            if ep.id not in seen_ids:
                grounding_episodes.append(ep)
                seen_ids.add(ep.id)

        conflict_rows = self.db.active_conflicts()
        active_conflicts = []
        concept_ids = {c.id for c in relevant_concepts}
        for row in conflict_rows:
            if row.get("beta_concept_id") in concept_ids:
                active_conflicts.append(Conflict.from_dict(row))

        return {
            "concepts": relevant_concepts,
            "episodes": grounding_episodes[:max_episodes],
            "conflicts": active_conflicts,
        }

    # ── Conflict Management ────────────────────────────────────────

    def _contradicts(self, episode: Episode, concept: Concept) -> bool:
        ep_lower = episode.content.lower()

        negation_signals = ["not ", "no longer", "incorrect", "wrong", "false",
                           "failed", "disproved", "contradicts", "opposite"]
        ep_negates = any(neg in ep_lower for neg in negation_signals)

        concept_keywords = set(concept.title.lower().split())
        ep_mentions_concept = bool(concept_keywords & set(ep_lower.split()))

        if ep_mentions_concept and ep_negates:
            return True

        if episode.outcome:
            outcome_lower = episode.outcome.lower()
            if any(neg in outcome_lower for neg in negation_signals):
                if ep_mentions_concept:
                    return True

        return False

    def _record_conflict(self, episode: Episode, concept: Concept) -> Conflict:
        conflict_id = hashlib.sha256(
            f"{episode.id}:{concept.id}".encode()
        ).hexdigest()[:16]

        existing = self.db.get_conflict(conflict_id)
        if existing:
            return Conflict.from_dict(existing)

        conflict = Conflict(
            id=conflict_id,
            alpha_episode_id=episode.id,
            beta_concept_id=concept.id,
            alpha_claim=f"[{episode.event_type}] {episode.content[:200]}",
            beta_claim=f"[{concept.category}] {concept.title}: {concept.description[:200]}",
        )

        self.db.insert_conflict(conflict.to_dict())
        concept.weaken(0.05)
        self.db.replace_concept(concept.to_dict())
        return conflict

    def resolve_conflict(self, conflict_id: str, resolution: str) -> bool:
        return self.db.resolve_conflict(
            conflict_id, resolution, _now().isoformat()
        )

    def active_conflicts(self) -> list[Conflict]:
        rows = self.db.active_conflicts()
        return [Conflict.from_dict(r) for r in rows]

    def prune_resolved_conflicts(self, max_age_days: int = 30) -> int:
        cutoff = (_now() - timedelta(days=max_age_days)).isoformat()
        return self.db.prune_resolved(cutoff)

    def verify_concept(self, concept_id: str) -> dict:
        concept = self.beta.get(concept_id)
        if not concept:
            return {"status": "not_found"}

        supporting = 0
        contradicting = 0
        missing = 0

        for eid in concept.evidence_ids:
            ep_data = self.db.get_episode(eid)
            if not ep_data:
                missing += 1
            else:
                ep = Episode.from_dict(ep_data)
                if self._contradicts(ep, concept):
                    contradicting += 1
                else:
                    supporting += 1

        total = supporting + contradicting + missing
        if total == 0:
            return {"status": "ungrounded", "concept": concept.title}

        support_ratio = supporting / total

        if support_ratio >= 0.7:
            status = "grounded"
        elif support_ratio >= 0.3:
            status = "weakened"
            concept.weaken(0.05)
            self.db.replace_concept(concept.to_dict())
        else:
            status = "ungrounded"
            concept.weaken(0.15)
            self.db.replace_concept(concept.to_dict())

        return {
            "status": status,
            "concept": concept.title,
            "supporting": supporting,
            "contradicting": contradicting,
            "missing": missing,
            "support_ratio": round(support_ratio, 2),
        }

    # ── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _derive_cluster_title(episodes: list[Episode]) -> str:
        best = max(episodes, key=lambda e: e.significance)
        content = best.content.strip()
        if len(content) > 80:
            content = content[:77] + "..."
        return f"{best.event_type}: {content}"

    @staticmethod
    def _derive_cluster_description(episodes: list[Episode]) -> str:
        lines = []
        for ep in sorted(episodes, key=lambda e: e.timestamp)[:5]:
            line = ep.content[:100].strip()
            if ep.outcome:
                line += f" -> {ep.outcome[:60]}"
            lines.append(f"- {line}")
        return f"Observed {len(episodes)} times:\n" + "\n".join(lines)

    @staticmethod
    def _infer_category(episodes: list[Episode]) -> str:
        type_counts: dict[str, int] = {}
        for ep in episodes:
            type_counts[ep.event_type] = type_counts.get(ep.event_type, 0) + 1
        dominant = max(type_counts, key=type_counts.get)
        category_map = {
            "finding": "pattern", "scan": "baseline", "action": "procedure",
            "error": "pattern", "config_change": "rule",
            "observation": "pattern", "conversation": "entity",
        }
        return category_map.get(dominant, "pattern")

    def stats(self) -> dict:
        rows = self.db.active_conflicts()
        active = len(rows)
        total_row = self.db._conn.execute("SELECT COUNT(*) FROM conflicts").fetchone()
        total = total_row[0] if total_row else 0
        return {
            "total_conflicts": total,
            "active_conflicts": active,
            "resolved_conflicts": total - active,
        }
