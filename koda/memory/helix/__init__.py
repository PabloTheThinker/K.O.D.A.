"""Helix — Dual-Store Entangled Memory System.

Two independent memory stores (Alpha: episodic, Beta: semantic) that
cross-verify each other. SQLite-backed with WAL mode. Optional vector
embeddings via Ollama. Async response chain with timeouts.

Vektra AI — For KODA Framework
"""

from .storage import HelixDB
from .alpha import EpisodicStore, Episode
from .beta import SemanticStore, Concept, Connection
from .entanglement import EntanglementProtocol, Conflict, ConsolidationResult
from .response_chain import ResponseChain, Incident, ThreatEnrichment, ContainmentAction, Verdict
from .helix import Helix

__all__ = [
    "HelixDB",
    "Helix",
    "EpisodicStore", "Episode",
    "SemanticStore", "Concept", "Connection",
    "EntanglementProtocol", "Conflict", "ConsolidationResult",
    "ResponseChain", "Incident", "ThreatEnrichment", "ContainmentAction", "Verdict",
]
