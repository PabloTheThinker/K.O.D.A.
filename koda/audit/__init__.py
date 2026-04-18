"""Audit log — structured JSONL trail of every significant agent action.

Chain-of-custody artifact for security engagements. Every LLM turn,
tool call, approval decision, and error lands as one JSON line so an
operator can reconstruct exactly what the agent did on a client's
assets, in order, and why.
"""
from .logger import AuditEvent, AuditLogger, NullAuditLogger, default_log_path, hash_arguments

__all__ = [
    "AuditEvent",
    "AuditLogger",
    "NullAuditLogger",
    "default_log_path",
    "hash_arguments",
]
