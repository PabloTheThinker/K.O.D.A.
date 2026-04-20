"""Find Helix concepts that have earned promotion to skill drafts.

The promoter is pure read-side logic: it scans Beta (semantic store), picks
concepts that cross thresholds, and pulls back the grounding episodes from
Alpha. It does not write anything — :mod:`koda.learning.store` handles
persistence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

DEFAULT_MIN_CONFIDENCE = 0.7
DEFAULT_MIN_EVIDENCE = 5
DEFAULT_CATEGORIES = ("pattern", "procedure", "rule")


@dataclass
class PromotionCandidate:
    """A concept ready for synthesis, packaged with its evidence episodes."""

    concept: Any  # koda.memory.helix.Concept
    episodes: list[Any]  # koda.memory.helix.Episode

    @property
    def concept_id(self) -> str:
        return str(getattr(self.concept, "id", ""))

    @property
    def title(self) -> str:
        return str(getattr(self.concept, "title", ""))

    @property
    def confidence(self) -> float:
        return float(getattr(self.concept, "confidence", 0.0))


def find_candidates(
    *,
    helix: Any,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    min_evidence: int = DEFAULT_MIN_EVIDENCE,
    categories: tuple[str, ...] = DEFAULT_CATEGORIES,
    limit: int = 20,
    exclude_concept_ids: set[str] | None = None,
) -> list[PromotionCandidate]:
    """Scan Helix for concepts eligible for promotion.

    Criteria:
      * confidence ≥ ``min_confidence``
      * evidence_count ≥ ``min_evidence``
      * category ∈ ``categories``
      * concept_id ∉ ``exclude_concept_ids`` (for skipping already-pending)

    Returns up to ``limit`` candidates sorted by confidence × evidence_count
    descending — the strongest signal first.
    """
    exclude = exclude_concept_ids or set()

    seen: dict[str, Any] = {}
    for category in categories:
        for concept in helix.beta.find_by_category(
            category=category, min_confidence=min_confidence,
        ):
            cid = str(getattr(concept, "id", ""))
            if not cid or cid in seen or cid in exclude:
                continue
            if int(getattr(concept, "evidence_count", 0)) < min_evidence:
                continue
            seen[cid] = concept

    ranked = sorted(
        seen.values(),
        key=lambda c: (
            float(getattr(c, "confidence", 0.0))
            * max(1, int(getattr(c, "evidence_count", 1)))
        ),
        reverse=True,
    )[:limit]

    candidates: list[PromotionCandidate] = []
    for concept in ranked:
        episodes = _pull_evidence(helix, concept)
        candidates.append(PromotionCandidate(concept=concept, episodes=episodes))
    return candidates


def _pull_evidence(helix: Any, concept: Any) -> list[Any]:
    """Fetch the Episode records referenced in ``concept.evidence_ids``."""
    from koda.memory.helix.alpha import Episode

    ids = list(getattr(concept, "evidence_ids", []) or [])
    if not ids:
        return []
    episodes: list[Any] = []
    for eid in ids[:20]:
        try:
            row = helix.db.get_episode(eid)
        except Exception:
            row = None
        if row:
            episodes.append(Episode.from_dict(row))
    return episodes
