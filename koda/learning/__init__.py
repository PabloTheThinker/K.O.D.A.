"""K.O.D.A. learning layer — promote Helix concepts into reusable skills.

Hermes Agent uses LLM self-reflection on turn-counter to decide when to save
a skill. KODA already has structural consolidation (Helix): recurring
episodes cluster into concepts with confidence scores, evidence counts, and
decay. The learning layer sits one step higher: it watches for concepts that
have matured past a threshold and promotes them into SKILL.md drafts for
human review.

Flow:

    Episode (alpha) → Concept (beta) → SkillDraft (_pending) → SKILL.md (_learned)

Each stage is independently testable. The LLM synthesizer is optional —
falling back to a deterministic template ensures the pipeline is useful on
day one without network access.
"""
from __future__ import annotations

from koda.learning.guard import GuardReport, scan_skill_draft
from koda.learning.hook import (
    LearningHook,
    LearningHookStats,
    disable_global_hook,
    get_global_hook,
    install_global_hook,
)
from koda.learning.promoter import PromotionCandidate, find_candidates
from koda.learning.store import (
    LearnedSkillStore,
    PendingSkill,
    default_store,
)
from koda.learning.synthesizer import draft_skill_from_concept

__all__ = [
    "GuardReport", "scan_skill_draft",
    "PromotionCandidate", "find_candidates",
    "LearnedSkillStore", "PendingSkill", "default_store",
    "draft_skill_from_concept",
    "LearningHook", "LearningHookStats",
    "install_global_hook", "get_global_hook", "disable_global_hook",
]
