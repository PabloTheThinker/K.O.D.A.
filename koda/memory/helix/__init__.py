"""Helix — Dual-Store Entangled Memory System.

Two independent memory stores (Alpha: episodic, Beta: semantic) that
cross-verify each other. SQLite-backed with WAL mode. Optional vector
embeddings via Ollama. Async response chain with timeouts.

Vektra AI — For KODA Framework
"""

from .alpha import Episode, EpisodicStore
from .beta import Concept, Connection, SemanticStore
from .entanglement import Conflict, ConsolidationResult, EntanglementProtocol
from .helix import Helix
from .response_chain import ContainmentAction, Incident, ResponseChain, ThreatEnrichment, Verdict
from .storage import HelixDB

__all__ = [
    "HelixDB",
    "Helix",
    "EpisodicStore", "Episode",
    "SemanticStore", "Concept", "Connection",
    "EntanglementProtocol", "Conflict", "ConsolidationResult",
    "ResponseChain", "Incident", "ThreatEnrichment", "ContainmentAction", "Verdict",
]
