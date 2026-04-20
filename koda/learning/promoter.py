"""Find Helix concepts that have earned promotion to skill drafts.

The promoter is pure read-side logic: it scans Beta (semantic store), picks
concepts that cross thresholds, and pulls back the grounding episodes from
Alpha. It does not write anything — :mod:`koda.learning.store` handles
persistence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from koda.learning.scoring import ScoreBreakdown, compute_score

DEFAULT_MIN_CONFIDENCE = 0.7
DEFAULT_MIN_EVIDENCE = 5
DEFAULT_CATEGORIES = ("pattern", "procedure", "rule")
# Composite-score floor for Phase-2 gating. Callers opt in by passing
# min_score > 0; the default is permissive so the legacy confidence+evidence
# gate still runs on its own.
DEFAULT_MIN_SCORE = 0.0


@dataclass
class PromotionCandidate:
    """A concept ready for synthesis, packaged with its evidence episodes."""

    concept: Any  # koda.memory.helix.Concept
    episodes: list[Any]  # koda.memory.helix.Episode
    score: ScoreBreakdown | None = field(default=None)

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
    min_score: float = DEFAULT_MIN_SCORE,
) -> list[PromotionCandidate]:
    """Scan Helix for concepts eligible for promotion.

    Legacy gates:
      * confidence ≥ ``min_confidence``
      * evidence_count ≥ ``min_evidence``
      * category ∈ ``categories``
      * concept_id ∉ ``exclude_concept_ids`` (skip already-pending)

    When ``min_score > 0``, the 6-signal composite score in
    :mod:`koda.learning.scoring` runs over concept + fetched episodes; any
    candidate below the floor is dropped and the remainder are ranked by
    composite score instead of ``confidence × evidence_count``.
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

    if min_score <= 0.0:
        ranked = sorted(
            seen.values(),
            key=lambda c: (
                float(getattr(c, "confidence", 0.0))
                * max(1, int(getattr(c, "evidence_count", 1)))
            ),
            reverse=True,
        )[:limit]
        return [
            PromotionCandidate(
                concept=c, episodes=_pull_evidence(helix, c), score=None,
            )
            for c in ranked
        ]

    # Score-gated path. Fetch episodes once per surviving concept to build
    # the scorer's inputs; drop anything below ``min_score``.
    scored: list[tuple[float, Any, list[Any], ScoreBreakdown]] = []
    for concept in seen.values():
        episodes = _pull_evidence(helix, concept)
        breakdown = compute_score(concept=concept, episodes=episodes)
        if breakdown.total < min_score:
            continue
        scored.append((breakdown.total, concept, episodes, breakdown))
    scored.sort(key=lambda row: row[0], reverse=True)
    return [
        PromotionCandidate(concept=c, episodes=eps, score=bd)
        for _total, c, eps, bd in scored[:limit]
    ]


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
