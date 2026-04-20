"""Multi-signal promotion scoring for Helix concepts.

Helix's native gates (``confidence ≥ X AND evidence_count ≥ Y``) are a
coarse filter — plenty of false positives pass because a single noisy
query can fabricate a high-confidence cluster. OpenClaw's "Deep Sleep"
phase solves this with a weighted blend of six signals computed across
the episodes behind each concept. We port that idea, adapted to the data
KODA already carries (Episodes + Concepts) so no schema change is needed.

Signals (weights in ``_WEIGHTS``):

  frequency           0.24   how often the pattern recurs (evidence count)
  relevance           0.30   avg quality of match (concept.confidence)
  query_diversity     0.15   distinct event_types across episodes
  recency             0.15   exp decay, 14-day half-life on last_reinforced
  consolidation       0.10   distinct days spanned by the evidence
  conceptual_richness 0.06   distinct tool/metadata tags across episodes
                    = 1.00

All signals normalize to [0.0, 1.0]; the weighted sum is the composite
score. ``find_candidates`` can gate on ``min_score`` to adopt the scorer;
callers that don't opt in keep the original behaviour.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_WEIGHTS: dict[str, float] = {
    "frequency": 0.24,
    "relevance": 0.30,
    "query_diversity": 0.15,
    "recency": 0.15,
    "consolidation": 0.10,
    "conceptual_richness": 0.06,
}

# Evidence-count saturation. 12 episodes is plenty — more gives diminishing
# returns so we don't let a single viral pattern dominate.
_FREQ_SATURATION = 12
_RECENCY_HALF_LIFE_DAYS = 14.0
# Distinct-day saturation for consolidation — 7 distinct days = max signal.
_CONSOLIDATION_SATURATION = 7
# Distinct-tag saturation for richness — 6 distinct tools/metadata keys = max.
_RICHNESS_SATURATION = 6
# Distinct event-type saturation for query diversity — 4 types = max.
_DIVERSITY_SATURATION = 4


@dataclass
class ScoreBreakdown:
    """Normalized per-signal scores plus the weighted composite."""

    frequency: float
    relevance: float
    query_diversity: float
    recency: float
    consolidation: float
    conceptual_richness: float
    total: float

    def as_dict(self) -> dict[str, float]:
        return {
            "frequency": round(self.frequency, 3),
            "relevance": round(self.relevance, 3),
            "query_diversity": round(self.query_diversity, 3),
            "recency": round(self.recency, 3),
            "consolidation": round(self.consolidation, 3),
            "conceptual_richness": round(self.conceptual_richness, 3),
            "total": round(self.total, 3),
        }


def compute_score(*, concept: Any, episodes: Iterable[Any]) -> ScoreBreakdown:
    """Compute the 6-signal score for a concept + its evidence episodes."""
    eps = list(episodes)

    frequency = min(1.0, float(getattr(concept, "evidence_count", len(eps))) / _FREQ_SATURATION)
    relevance = max(0.0, min(1.0, float(getattr(concept, "confidence", 0.0))))
    query_diversity = _query_diversity(eps)
    recency = _recency(concept)
    consolidation = _consolidation(eps)
    conceptual_richness = _conceptual_richness(eps)

    total = (
        _WEIGHTS["frequency"] * frequency
        + _WEIGHTS["relevance"] * relevance
        + _WEIGHTS["query_diversity"] * query_diversity
        + _WEIGHTS["recency"] * recency
        + _WEIGHTS["consolidation"] * consolidation
        + _WEIGHTS["conceptual_richness"] * conceptual_richness
    )

    return ScoreBreakdown(
        frequency=frequency,
        relevance=relevance,
        query_diversity=query_diversity,
        recency=recency,
        consolidation=consolidation,
        conceptual_richness=conceptual_richness,
        total=total,
    )


# ── Signal helpers ─────────────────────────────────────────────────────

def _query_diversity(episodes: list[Any]) -> float:
    """Distinct event_types across evidence — proxy for context diversity."""
    if not episodes:
        return 0.0
    types: set[str] = set()
    for ep in episodes:
        t = str(getattr(ep, "event_type", "")).strip()
        if t:
            types.add(t)
    if not types:
        return 0.0
    return min(1.0, len(types) / _DIVERSITY_SATURATION)


def _recency(concept: Any) -> float:
    """Exponential decay on concept.last_reinforced with a 14-day half-life."""
    raw = str(getattr(concept, "last_reinforced", "")).strip()
    if not raw:
        return 0.0
    ts = _parse_ts(raw)
    if ts is None:
        return 0.0
    age_days = max(0.0, (datetime.now(UTC) - ts).total_seconds() / 86_400)
    return math.exp(-math.log(2) * age_days / _RECENCY_HALF_LIFE_DAYS)


def _consolidation(episodes: list[Any]) -> float:
    """Distinct calendar days spanned by the episodes — multi-day recurrence."""
    if not episodes:
        return 0.0
    days: set[str] = set()
    for ep in episodes:
        raw = str(getattr(ep, "timestamp", "")).strip()
        ts = _parse_ts(raw)
        if ts is None:
            continue
        days.add(ts.date().isoformat())
    if not days:
        return 0.0
    return min(1.0, len(days) / _CONSOLIDATION_SATURATION)


def _conceptual_richness(episodes: list[Any]) -> float:
    """Distinct tool/metadata tags across episodes — schema tag density."""
    if not episodes:
        return 0.0
    tags: set[str] = set()
    for ep in episodes:
        meta = getattr(ep, "metadata", None) or {}
        if not isinstance(meta, dict):
            continue
        tool = meta.get("tool")
        if isinstance(tool, str) and tool.strip():
            tags.add(f"tool:{tool.strip()}")
        for k in meta:
            if k != "tool":
                tags.add(f"key:{k}")
    if not tags:
        return 0.0
    return min(1.0, len(tags) / _RICHNESS_SATURATION)


def _parse_ts(raw: str) -> datetime | None:
    """Best-effort ISO-8601 parser — returns None on anything weird."""
    if not raw:
        return None
    value = raw.replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts
