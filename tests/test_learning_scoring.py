"""Tests for the 6-signal promotion scorer and its integration with the promoter."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from koda.learning.promoter import find_candidates
from koda.learning.scoring import compute_score


@dataclass
class FakeConcept:
    id: str = "c1"
    title: str = "pattern"
    description: str = "desc"
    category: str = "pattern"
    confidence: float = 0.9
    evidence_count: int = 7
    evidence_ids: list = field(default_factory=list)
    last_reinforced: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )


@dataclass
class FakeEpisode:
    id: str
    timestamp: str
    event_type: str = "finding"
    content: str = "x"
    outcome: str = ""
    severity: str = ""
    metadata: dict = field(default_factory=dict)


def test_fresh_rich_concept_scores_high() -> None:
    now = datetime.now(UTC)
    concept = FakeConcept(confidence=0.95, evidence_count=12)
    episodes = [
        FakeEpisode(
            id=f"e{i}",
            timestamp=(now - timedelta(days=i)).isoformat(),
            event_type=["finding", "action", "observation", "decision"][i % 4],
            metadata={"tool": f"tool-{i % 3}", "host": f"h{i}"},
        )
        for i in range(8)
    ]
    s = compute_score(concept=concept, episodes=episodes)
    assert s.frequency == 1.0
    assert s.relevance >= 0.9
    assert s.query_diversity == 1.0
    assert s.recency > 0.6
    assert s.consolidation == 1.0
    assert s.conceptual_richness > 0.5
    assert s.total > 0.80


def test_stale_concept_recency_decays() -> None:
    old = (datetime.now(UTC) - timedelta(days=60)).isoformat()
    concept = FakeConcept(confidence=0.9, evidence_count=6, last_reinforced=old)
    episodes = [FakeEpisode(id="e0", timestamp=old)]
    s = compute_score(concept=concept, episodes=episodes)
    assert s.recency < 0.1


def test_single_day_evidence_lowers_consolidation() -> None:
    same = datetime.now(UTC).isoformat()
    concept = FakeConcept(confidence=0.9, evidence_count=6)
    episodes = [FakeEpisode(id=f"e{i}", timestamp=same) for i in range(6)]
    s = compute_score(concept=concept, episodes=episodes)
    # 1 distinct day / 7 saturation ≈ 0.14
    assert 0.10 < s.consolidation < 0.20


def test_missing_metadata_yields_zero_richness() -> None:
    concept = FakeConcept()
    eps = [FakeEpisode(id="e0", timestamp=datetime.now(UTC).isoformat())]
    s = compute_score(concept=concept, episodes=eps)
    assert s.conceptual_richness == 0.0


def test_empty_episodes_still_scores() -> None:
    s = compute_score(concept=FakeConcept(), episodes=[])
    # No episodes ⇒ diversity, consolidation, richness all zero. Relevance and
    # frequency and recency can still contribute. total must stay in [0, 1].
    assert 0.0 <= s.total <= 1.0
    assert s.query_diversity == 0.0
    assert s.consolidation == 0.0
    assert s.conceptual_richness == 0.0


def test_malformed_timestamps_gracefully_zero() -> None:
    concept = FakeConcept(last_reinforced="not-a-timestamp")
    eps = [FakeEpisode(id="e0", timestamp="also-garbage")]
    s = compute_score(concept=concept, episodes=eps)
    assert s.recency == 0.0
    assert s.consolidation == 0.0


# ── promoter integration ──────────────────────────────────────────────


class _FakeBeta:
    def __init__(self, concepts: list) -> None:
        self.concepts = concepts

    def find_by_category(self, *, category, min_confidence):
        return [
            c for c in self.concepts
            if c.category == category and c.confidence >= min_confidence
        ]


class _FakeDB:
    def __init__(self, eps: dict) -> None:
        self._eps = eps

    def get_episode(self, eid):
        return self._eps.get(eid)


def test_promoter_min_score_drops_weak_candidates() -> None:
    now = datetime.now(UTC)
    strong = FakeConcept(
        id="strong", confidence=0.95, evidence_count=12,
        evidence_ids=["s0", "s1"],
        last_reinforced=now.isoformat(),
    )
    weak = FakeConcept(
        id="weak", confidence=0.72, evidence_count=5,
        evidence_ids=["w0"],
        last_reinforced=(now - timedelta(days=90)).isoformat(),
    )
    # _pull_evidence uses helix.db.get_episode + Episode.from_dict. Simplest
    # way to exercise the scoring path without pulling the real Helix stack
    # is to make get_episode return None — scorer handles empty episodes.
    helix = SimpleNamespace(beta=_FakeBeta([strong, weak]), db=_FakeDB({}))

    scored = find_candidates(helix=helix, min_score=0.5)
    ids = [c.concept_id for c in scored]
    assert "strong" in ids
    assert "weak" not in ids
    # The surviving candidate carries its breakdown.
    assert scored[0].score is not None
    assert scored[0].score.total >= 0.5


def test_promoter_without_min_score_keeps_legacy_ranking() -> None:
    mid = FakeConcept(id="mid", confidence=0.75, evidence_count=6)
    top = FakeConcept(id="top", confidence=0.95, evidence_count=15)
    helix = SimpleNamespace(beta=_FakeBeta([mid, top]), db=_FakeDB({}))
    ranked = find_candidates(helix=helix)
    # Legacy path: no score attached, ranked by confidence * evidence_count.
    assert [c.concept_id for c in ranked] == ["top", "mid"]
    assert all(c.score is None for c in ranked)
