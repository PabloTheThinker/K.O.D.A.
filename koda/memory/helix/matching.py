"""Semantic matching for Helix concept recall.

Multi-signal matching: substring, stemmed tokens, acronym/prefix,
bigrams, keyword expansion, and CVE/CWE ID exact matching. Stdlib only.
"""
from __future__ import annotations

import re

_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "into",
    "is", "it", "of", "on", "or", "that", "the", "to", "was", "were", "with",
    "about", "after", "before", "during", "over", "under", "this", "these", "those",
    "host", "hosts",
    "what", "which", "where", "when", "who", "whom", "whose", "why", "how",
    "i", "me", "my", "we", "us", "our", "you", "your", "he", "him", "his",
    "she", "her", "they", "them", "their", "its",
    "do", "does", "did", "can", "could", "would", "should", "will", "shall",
    "may", "might", "must", "has", "have", "had", "been",
    "exist", "exists", "any", "all", "some", "each", "every", "there",
    "here", "also", "just", "very", "too", "not", "no", "so", "if", "but",
    "then", "than", "more", "most", "much", "many", "other", "give",
}

_EQUIV = {
    "vulnerabil": {"cve", "cwe", "rce", "exploit", "issue", "find", "vuln", "flaw", "weak"},
    "assess": {"scan", "audit", "check", "review", "test"},
    "scan": {"assess", "enumer", "probe"},
    "result": {"report", "output", "find"},
    "ssh": {"openssh", "sshd", "permitrootlogin"},
    "nginx": {"web", "http", "server"},
    "mysql": {"database", "db", "sql", "mariadb"},
    "secur": {"vulnerabil", "threat", "risk", "attack", "defend", "protect", "find"},
    "infrastruct": {"server", "host", "network", "system", "cluster"},
    "postur": {"status", "state", "health", "overview", "summary", "find"},
    "config": {"set", "configur", "misconfig", "setup"},
    "misconfig": {"config", "wrong", "insecur", "bad"},
}


def _tokenize(text: str) -> list[str]:
    return re.findall(r"cve-\d{4}-\d+|cwe-\d+|[a-z0-9]+", text.lower())


def _extract_ids(text: str) -> set[str]:
    return set(re.findall(r"cve-\d{4}-\d+|cwe-\d+", text.lower()))


def _stem(token: str) -> str:
    if len(token) <= 3:
        return token
    if token.endswith("ies") and len(token) > 5:
        return token[:-3]
    if token.endswith("es") and len(token) > 4:
        return token[:-2]
    for suffix in ("tion", "ness", "able", "ment", "ity", "ing", "ous", "ive", "ed", "ly", "er", "al", "s"):
        if len(token) > len(suffix) + 2 and token.endswith(suffix):
            return token[:-len(suffix)]
    return token


def _bigrams(tokens: list[str]) -> set[tuple[str, str]]:
    return set(zip(tokens, tokens[1:])) if len(tokens) > 1 else set()


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def _partial_match(q: str, targets: set[str]) -> bool:
    if q in targets:
        return True
    if len(q) < 3:
        return False
    return any(q in t or t in q for t in targets if len(t) >= 3)


def _equiv_match(token: str, target_raw: set[str], target_stems: set[str]) -> bool:
    """Check if token matches any target through synonym expansion.

    Uses prefix matching on _EQUIV keys so "vulnerabilit" matches
    the "vulnerabil" key without needing exact stem alignment.
    """
    for key, synonyms in _EQUIV.items():
        if token.startswith(key) or key.startswith(token) and len(token) >= 3:
            if any(s in target_stems or _partial_match(s, target_raw) for s in synonyms):
                return True
    return False


def _keyword_match(q: str, target_raw: set[str], target_stems: set[str]) -> bool:
    if q in target_stems or _partial_match(q, target_raw):
        return True
    return _equiv_match(q, target_raw, target_stems)


def semantic_match(query: str, title: str, description: str = "") -> float:
    """Score how well a query matches a concept's title and description. 0-1."""
    query_l = query.strip().lower()
    text_l = f"{title} {description}".strip().lower()
    if not query_l or not text_l:
        return 0.0

    if _extract_ids(query_l) & _extract_ids(text_l):
        return 1.0

    substring_score = 0.92 if query_l in text_l else 0.0

    q_raw = _tokenize(query_l)
    t_raw = _tokenize(text_l)
    if not q_raw or not t_raw:
        return substring_score

    t_stems = [_stem(t) for t in t_raw]
    t_raw_set = set(t_raw)
    t_set = set(t_stems)

    q_keywords = [_stem(t) for t in q_raw if t not in _STOPWORDS]
    if not q_keywords:
        q_keywords = [_stem(t) for t in q_raw]

    q_kw_set = set(q_keywords)

    stem_overlap = _jaccard(q_kw_set, t_set)
    bigram_overlap = _jaccard(_bigrams(q_keywords), _bigrams(t_stems))

    prefix_hits = sum(_partial_match(q, t_raw_set) for q in q_keywords)
    prefix_score = prefix_hits / len(q_keywords)

    keyword_hits = sum(_keyword_match(q, t_raw_set, t_set) for q in q_keywords)
    keyword_score = keyword_hits / len(q_keywords)

    score = (
        0.20 * stem_overlap
        + 0.20 * prefix_score
        + 0.15 * bigram_overlap
        + 0.35 * keyword_score
    )

    return min(1.0, max(substring_score, score))
