"""Helix — Dual-Store Entangled Memory System.

Main orchestrator binding Alpha + Beta + Entanglement + ResponseChain
through a shared SQLite database.

Usage:
    helix = Helix(Path("~/.koda/memory"))
    helix.encode("finding", "SSH root login enabled on host-03", severity="high")
    helix.consolidate()
    context = helix.build_context("scanning network hosts")
"""
from __future__ import annotations

import logging
from pathlib import Path

from .alpha import Episode, EpisodicStore
from .beta import Concept, SemanticStore
from .entanglement import ConsolidationResult, EntanglementProtocol
from .response_chain import (
    ContainHook,
    EnrichHook,
    Incident,
    ReportHook,
    ResponseChain,
    VerifyHook,
)
from .storage import HelixDB

logger = logging.getLogger("helix")


class Helix:
    """Dual-Store Entangled Memory — the complete system.

    Alpha (episodic) stores what happened.
    Beta (semantic) stores what is true.
    Entanglement keeps them honest.
    ResponseChain acts on threats before they're even memories.

    All stores share a single SQLite database (WAL mode).
    """

    def __init__(
        self,
        base_dir: Path,
        verify_hook: VerifyHook | None = None,
        enrich_hook: EnrichHook | None = None,
        contain_hook: ContainHook | None = None,
        report_hook: ReportHook | None = None,
        auto_contain: bool = False,
    ):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.db = HelixDB(base_dir / "helix.db")

        self.alpha = EpisodicStore(self.db)
        self.beta = SemanticStore(self.db)
        self.entanglement = EntanglementProtocol(
            alpha=self.alpha, beta=self.beta, db=self.db,
        )
        self.response_chain = ResponseChain(
            db=self.db,
            verify_hook=verify_hook,
            enrich_hook=enrich_hook,
            contain_hook=contain_hook,
            report_hook=report_hook,
            auto_contain=auto_contain,
        )

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ── Encoding (Alpha intake) ────────────────────────────────────

    _HOT_KEYWORDS = {"cve-", "exploit", "0day", "rce", "breach", "ransomware",
                     "backdoor", "rootkit", "c2 ", "exfiltrat"}

    def encode(
        self,
        event_type: str,
        content: str,
        context: str = "",
        outcome: str = "",
        severity: str = "",
        metadata: dict | None = None,
    ) -> Episode | None:
        episode = self.alpha.encode(
            event_type=event_type,
            content=content,
            context=context,
            outcome=outcome,
            severity=severity,
            metadata=metadata,
        )
        if episode and self._is_hot(episode):
            self._hot_promote(episode)
            self._respond(episode, metadata or {})
        return episode

    def _respond(self, episode: Episode, metadata: dict) -> Incident | None:
        try:
            incident = self.response_chain.respond(
                incident_id=episode.id,
                episode_id=episode.id,
                finding=episode.content,
                severity=episode.severity,
                metadata=metadata,
            )
            if incident.verdict:
                self.alpha.encode(
                    event_type="action",
                    content=f"Response Chain: {incident.verdict} — {incident.finding[:80]}",
                    context=f"incident:{incident.id}",
                    outcome=f"status:{incident.status}, response_time:{incident.total_response_ms}ms",
                    severity=incident.severity,
                )
            return incident
        except Exception as e:
            logger.error("Response Chain failed for [%s]: %s", episode.id[:8], e)
            return None

    def _is_hot(self, episode: Episode) -> bool:
        if episode.severity == "critical":
            return True
        if episode.severity == "high":
            lower = episode.content.lower()
            if any(kw in lower for kw in self._HOT_KEYWORDS):
                return True
        return False

    def _hot_promote(self, episode: Episode) -> None:
        import hashlib

        from .beta import Concept
        from .entanglement import _now

        similar = self.beta.find_similar(episode.content[:80], threshold=0.4)
        if similar:
            similar[0].reinforce([episode.id], boost=0.15)
            self.db.replace_concept(similar[0].to_dict())
        else:
            concept = Concept(
                id=hashlib.sha256(
                    f"hot:{_now().isoformat()}:{episode.content[:50]}".encode()
                ).hexdigest()[:16],
                category="pattern",
                title=episode.content[:80],
                description=f"Hot-promoted from single {episode.severity} episode: {episode.content}",
                confidence=0.7 if episode.severity == "critical" else 0.5,
                evidence_count=1,
                evidence_ids=[episode.id],
            )
            self.beta.add(concept)

    # ── Recall ─────────────────────────────────────────────────────

    def recall(
        self,
        query: str = "",
        min_confidence: float = 0.0,
        limit: int = 20,
    ) -> dict:
        if query:
            return self.entanglement.predictive_recall(
                context=query,
                min_concept_confidence=min_confidence,
                max_episodes=limit,
            )
        return {
            "concepts": self.beta.recall(min_confidence=min_confidence, limit=limit),
            "episodes": self.alpha.recall_recent(limit=limit),
            "conflicts": self.entanglement.active_conflicts(),
        }

    def recall_episodes(self, query: str = "", event_type: str = "",
                        min_confidence: float = 0.0, limit: int = 20) -> list[Episode]:
        return self.alpha.recall(
            query=query, event_type=event_type,
            min_confidence=min_confidence, limit=limit,
        )

    def recall_concepts(self, query: str = "", category: str = "",
                        min_confidence: float = 0.0, limit: int = 20) -> list[Concept]:
        return self.beta.recall(
            query=query, category=category,
            min_confidence=min_confidence, limit=limit,
        )

    # ── Consolidation ──────────────────────────────────────────────

    def consolidate(self, min_cluster_size: int = 3, max_age_hours: int = 72) -> ConsolidationResult:
        return self.entanglement.consolidate(
            min_cluster_size=min_cluster_size,
            max_age_hours=max_age_hours,
        )

    # ── Context Injection ──────────────────────────────────────────

    def build_context(self, current_task: str = "", max_tokens: int = 2000) -> str:
        sections = []

        concepts = self.beta.recall(query=current_task, min_confidence=0.3, limit=8)
        if concepts:
            lines = []
            for c in concepts:
                evidence_note = f"{c.evidence_count} episodes"
                conf = f"{c.effective_confidence:.0%}"
                contradiction_note = f", {c.contradictions} contradictions" if c.contradictions else ""
                lines.append(f"- {c.title} ({conf} confidence, {evidence_note}{contradiction_note})")
            sections.append("## Known Patterns\n" + "\n".join(lines))

        if current_task:
            episodes = self.alpha.recall(query=current_task, limit=8)
        else:
            episodes = self.alpha.recall_recent(hours=48, limit=8)
        if episodes:
            lines = []
            for ep in episodes:
                sev = f" [{ep.severity}]" if ep.severity else ""
                lines.append(f"- [{ep.timestamp[:16]}]{sev} {ep.content[:120]}")
            sections.append("## Recent Activity\n" + "\n".join(lines))

        conflicts = self.entanglement.active_conflicts()
        if conflicts:
            lines = []
            for c in conflicts[:5]:
                lines.append(
                    f"- **Alpha says:** {c.alpha_claim[:100]}\n"
                    f"  **Beta says:** {c.beta_claim[:100]}"
                )
            sections.append("## Uncertainties\n" + "\n".join(lines))

        if not sections:
            return ""

        context = "\n\n".join(sections)
        if len(context) > max_tokens * 4:
            context = context[:max_tokens * 4] + "\n\n[... truncated for token budget]"
        return context

    # ── Maintenance ────────────────────────────────────────────────

    def decay_and_prune(self) -> dict:
        alpha_pruned = self.alpha.prune(min_confidence=0.01, max_age_days=180)
        beta_pruned = self.beta.prune(min_confidence=0.05)
        conflicts_pruned = self.entanglement.prune_resolved_conflicts(max_age_days=30)
        return {
            "alpha_episodes_pruned": alpha_pruned,
            "beta_concepts_pruned": beta_pruned,
            "conflicts_pruned": conflicts_pruned,
        }

    def verify_all_concepts(self) -> list[dict]:
        results = []
        for concept in self.beta.all_concepts:
            verification = self.entanglement.verify_concept(concept.id)
            if verification.get("status") != "grounded":
                results.append(verification)
        return results

    # ── Statistics ─────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "alpha": self.alpha.stats(),
            "beta": self.beta.stats(),
            "entanglement": self.entanglement.stats(),
            "storage": self.db.stats(),
        }

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"Helix("
            f"episodes={s['alpha'].get('total_episodes', 0)}, "
            f"concepts={s['beta'].get('total_concepts', 0)}, "
            f"conflicts={s['entanglement'].get('active_conflicts', 0)})"
        )
