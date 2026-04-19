"""Rule-based NLU layer: intent, scope, risk, skill selection.

Pure-Python first pass. No LLM calls. Sits in front of the agent loop so
the harness can route on intent, enforce risk tier, and surface a
clarifying question before burning tokens.
"""
from __future__ import annotations

from koda.nlu.router import (
    ExtractedTargets,
    Intent,
    IntentRouter,
    RiskTier,
    RouterDecision,
    build_clarify,
    classify_intent,
    extract_targets,
    infer_risk,
    rank_skills,
)

__all__ = [
    "ExtractedTargets",
    "Intent",
    "IntentRouter",
    "RiskTier",
    "RouterDecision",
    "build_clarify",
    "classify_intent",
    "extract_targets",
    "infer_risk",
    "rank_skills",
]
