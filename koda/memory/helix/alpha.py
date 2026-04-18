"""Alpha Store — Episodic Memory (The Historian).

Stores what happened: events, observations, tool outputs, decisions, errors.
SQLite-backed with WAL mode. Priority-gated encoding. Confidence decay.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .storage import HelixDB

logger = logging.getLogger("helix.alpha")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Significance Scoring ──────────────────────────────────────────

_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
_TYPE_WEIGHT = {
    "finding": 0.7, "scan": 0.6, "action": 0.5, "error": 0.6,
    "config_change": 0.5, "conversation": 0.2, "observation": 0.3,
}
SIGNIFICANCE_THRESHOLD = 0.25


def score_significance(
    event_type: str, severity: str = "", content: str = "",
) -> float:
    score = _TYPE_WEIGHT.get(event_type, 0.3)
    if severity:
        score = max(score, _SEVERITY_WEIGHT.get(severity, 0.3))
    lower = content.lower()
    if any(w in lower for w in ("cve-", "exploit", "critical", "breach", "0day", "rce")):
        score = min(1.0, score + 0.3)
    elif any(w in lower for w in ("error", "fail", "denied", "timeout", "crash")):
        score = min(1.0, score + 0.1)
    return round(score, 3)


# ── Episode Model ─────────────────────────────────────────────────

@dataclass
class Episode:
    id: str
    timestamp: str
    event_type: str
    content: str
    context: str = ""
    outcome: str = ""
    significance: float = 0.5
    severity: str = ""
    links: list[str] = field(default_factory=list)
    reinforcement_count: int = 0
    last_recalled: str = ""
    decay_rate: float = 0.02
    consolidated: bool = False
    contradiction_flags: int = 0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["links"] = json.dumps(d["links"])
        d["metadata"] = json.dumps(d["metadata"])
        d["consolidated"] = int(d["consolidated"])
        d["content_hash"] = self.content_hash
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Episode:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        clean = {}
        for k, v in d.items():
            if k not in known:
                continue
            if k == "links" and isinstance(v, str):
                v = json.loads(v)
            elif k == "metadata" and isinstance(v, str):
                v = json.loads(v)
            elif k == "consolidated":
                v = bool(v)
            clean[k] = v
        return cls(**clean)

    @property
    def effective_confidence(self) -> float:
        try:
            ts = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
            age_days = (_now() - ts).days
        except (ValueError, TypeError):
            age_days = 0
        base = self.significance
        decay = self.decay_rate * max(0, age_days - 7)
        reinforcement_bonus = min(0.3, self.reinforcement_count * 0.05)
        return max(0.0, min(1.0, base - decay + reinforcement_bonus))

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(
            f"{self.event_type}:{self.content[:200]}".encode()
        ).hexdigest()[:12]


# ── Episodic Store ────────────────────────────────────────────────

class EpisodicStore:
    """Alpha store — SQLite-backed episodic memory."""

    def __init__(self, db: HelixDB):
        self.db = db

    def encode(
        self,
        event_type: str,
        content: str,
        context: str = "",
        outcome: str = "",
        severity: str = "",
        metadata: dict | None = None,
    ) -> Optional[Episode]:
        sig = score_significance(event_type, severity, content)
        if sig < SIGNIFICANCE_THRESHOLD:
            return None

        episode = Episode(
            id=hashlib.sha256(
                f"{_now().isoformat()}:{content[:100]}".encode()
            ).hexdigest()[:16],
            timestamp=_now().isoformat(),
            event_type=event_type,
            content=content,
            context=context,
            outcome=outcome,
            significance=sig,
            severity=severity,
            metadata=metadata or {},
        )

        if self.db.episode_exists_hash(episode.content_hash):
            return None
        self.db.add_dedup_hash(episode.content_hash)
        self.db.prune_dedup_hashes(500)

        self.db.insert_episode(episode.to_dict())
        return episode

    def recall(
        self,
        query: str = "",
        event_type: str = "",
        min_confidence: float = 0.0,
        max_age_days: int = 90,
        limit: int = 20,
    ) -> list[Episode]:
        rows = self.db.query_episodes(
            query=query, event_type=event_type,
            min_significance=min_confidence, max_age_days=max_age_days,
            limit=limit * 3,
        )
        episodes = [Episode.from_dict(r) for r in rows]
        episodes.sort(key=lambda e: -e.effective_confidence)
        return episodes[:limit]

    def recall_recent(self, hours: int = 24, limit: int = 50) -> list[Episode]:
        rows = self.db.recent_episodes(hours=hours, limit=limit)
        return [Episode.from_dict(r) for r in rows]

    def reinforce(self, episode_id: str) -> bool:
        ep = self.db.get_episode(episode_id)
        if not ep:
            return False
        return self.db.update_episode(
            episode_id,
            reinforcement_count=ep["reinforcement_count"] + 1,
            last_recalled=_now().isoformat(),
        )

    def mark_consolidated(self, episode_ids: list[str]) -> int:
        marked = 0
        for eid in episode_ids:
            ep = self.db.get_episode(eid)
            if not ep:
                continue
            new_decay = min(1.0, ep["decay_rate"] * 1.5)
            if self.db.update_episode(eid, consolidated=1, decay_rate=new_decay):
                marked += 1
        return marked

    @staticmethod
    def _normalize_for_clustering(text: str) -> str:
        t = text.lower().strip()
        t = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '<IP>', t)
        t = re.sub(r'[a-f0-9]{8,}', '<HASH>', t)
        t = re.sub(r'(?:host|server|node|vm|container)[-_]?\d+', '<HOST>', t)
        t = re.sub(r'\b\d+\b', '<N>', t)
        return t[:60]

    def cluster_recent(
        self, min_episodes: int = 3, max_age_hours: int = 72,
    ) -> list[list[Episode]]:
        rows = self.db.cluster_episodes(max_age_hours=max_age_hours)
        episodes = [Episode.from_dict(r) for r in rows]
        groups: dict[str, list[Episode]] = {}
        for ep in episodes:
            normalized = self._normalize_for_clustering(ep.content)
            key = f"{ep.event_type}:{normalized}"
            groups.setdefault(key, []).append(ep)
        return [eps for eps in groups.values() if len(eps) >= min_episodes]

    def stats(self) -> dict:
        return self.db.episode_stats()

    def prune(self, min_confidence: float = 0.01, max_age_days: int = 180) -> int:
        return self.db.prune_episodes(min_significance=min_confidence, max_age_days=max_age_days)
