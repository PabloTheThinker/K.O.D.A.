"""Embedding client for Helix semantic matching.

Uses nomic-embed-text via Ollama for vector embeddings.
Falls back to keyword matching if Ollama is unavailable.
Cosine similarity for nearest-neighbor search.
"""
from __future__ import annotations

import json
import logging
import math
import struct
import urllib.request
from typing import Optional

logger = logging.getLogger("helix.embeddings")

OLLAMA_URL = "http://127.0.0.1:11434/api/embeddings"
MODEL = "nomic-embed-text"
DIMS = 768


def embed_text(text: str, timeout: float = 10.0) -> Optional[list[float]]:
    """Get embedding vector from Ollama. Returns None if unavailable."""
    if not text.strip():
        return None
    try:
        payload = json.dumps({"model": MODEL, "prompt": text[:2000]}).encode()
        req = urllib.request.Request(
            OLLAMA_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return data.get("embedding")
    except Exception as e:
        logger.debug("Embedding failed: %s", e)
        return None


def pack_embedding(vec: list[float]) -> bytes:
    """Pack float vector into bytes for SQLite BLOB storage."""
    return struct.pack(f"{len(vec)}f", *vec)


def unpack_embedding(blob: bytes) -> list[float]:
    """Unpack bytes back to float vector."""
    n = len(blob) // 4
    return list(struct.unpack(f"{n}f", blob))


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two vectors."""
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def nearest_neighbors(
    query_vec: list[float],
    candidates: list[tuple[str, bytes]],
    top_k: int = 10,
    min_score: float = 0.3,
) -> list[tuple[str, float]]:
    """Find nearest neighbors by cosine similarity.

    Args:
        query_vec: The query embedding
        candidates: List of (item_id, packed_embedding_bytes)
        top_k: Max results
        min_score: Minimum cosine similarity threshold

    Returns:
        List of (item_id, score) sorted by descending score
    """
    scored = []
    for item_id, blob in candidates:
        vec = unpack_embedding(blob)
        sim = cosine_similarity(query_vec, vec)
        if sim >= min_score:
            scored.append((item_id, sim))

    scored.sort(key=lambda x: -x[1])
    return scored[:top_k]


def is_available() -> bool:
    """Check if Ollama embedding model is available."""
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/tags",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            models = [m["name"] for m in data.get("models", [])]
            return any(MODEL in m for m in models)
    except Exception:
        return False
