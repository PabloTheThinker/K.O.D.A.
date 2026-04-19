from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from koda.security.skills.registry import DEFAULT_REGISTRY, SkillRegistry


class Intent(str, Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    IR = "ir"
    AUDIT = "audit"
    LOOKUP = "lookup"
    ADMIN = "admin"
    CHAT = "chat"
    AMBIGUOUS = "ambiguous"


class RiskTier(str, Enum):
    SAFE = "safe"
    SENSITIVE = "sensitive"
    DANGEROUS = "dangerous"


@dataclass(frozen=True)
class ExtractedTargets:
    usernames: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    ipv4s: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class RouterDecision:
    intent: Intent
    confidence: float
    risk: RiskTier
    targets: ExtractedTargets
    matched_skills: tuple[str, ...]
    reasons: tuple[str, ...]
    clarify: str | None


DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
PATH_RE = re.compile(r"(?:/[\w.-]+){2,}/?")
USERNAME_HINT_RE = re.compile(
    r"\b(find|search|check|lookup)\b\s+(?:username|user|account)\b(?:\s+(?:of\s+)?|(?<=of\s))([\"']?)([\w.-]+)\3|\b(?:username|user|account)\b(?:\s+(?:of\s+)?|(?<=of\s))([\"']?)([\w.-]+)\5",
    re.I,
)

RECON_KW = frozenset(
    {
        "scan", "recon", "enumerate", "nmap", "sherlock", "osint", "whois",
        "dig", "subdomain", "port", "username", "account", "identity", "profile",
    }
)
EXPLOIT_KW = frozenset(
    {
        "exploit",
        "attack",
        "pwn",
        "shell",
        "rce",
        "payload",
        "msfconsole",
        "reverse shell",
        "privesc",
    }
)
IR_KW = frozenset(
    {
        "incident",
        "breach",
        "compromised",
        "malware",
        "ransomware",
        "forensic",
        "containment",
        "triage",
        "investigate",
    }
)
AUDIT_KW = frozenset({"audit", "compliance", "cis", "benchmark", "harden", "configuration review", "posture"})
LOOKUP_KW = frozenset({"what is", "lookup", "cve", "explain", "describe", "reference", "define"})
ADMIN_KW = frozenset({"set scope", "set mode", "engagement", "roe", "switch mode", "status"})

INTENT_KEYWORDS = {
    Intent.RECON: RECON_KW,
    Intent.EXPLOIT: EXPLOIT_KW,
    Intent.IR: IR_KW,
    Intent.AUDIT: AUDIT_KW,
    Intent.LOOKUP: LOOKUP_KW,
    Intent.ADMIN: ADMIN_KW,
}

ACTIVE_RECON_VERBS = frozenset({"scan", "nmap", "enumerate"})


def extract_targets(text: str) -> ExtractedTargets:
    domains = tuple(dict.fromkeys(DOMAIN_RE.findall(text.lower())))
    ipv4s = tuple(dict.fromkeys(IPV4_RE.findall(text)))
    cves = tuple(dict.fromkeys(CVE_RE.findall(text.upper())))
    paths = tuple(dict.fromkeys(PATH_RE.findall(text)))

    username_matches = USERNAME_HINT_RE.findall(text)
    usernames = tuple(dict.fromkeys(m[3] or m[6] for m in username_matches if m[3] or m[6]))

    return ExtractedTargets(
        usernames=usernames,
        domains=domains,
        ipv4s=ipv4s,
        cves=cves,
        paths=paths,
    )


def classify_intent(text: str) -> tuple[Intent, float, tuple[str, ...]]:
    words = re.findall(r"\b\w+\b", text.lower())
    scores: dict[Intent, tuple[int, list[str]]] = {}

    for intent, keywords in INTENT_KEYWORDS.items():
        hits = [w for w in words if w in keywords]
        if hits:
            scores[intent] = (len(hits), hits)

    if not scores:
        word_count = len(words)
        if word_count < 5:
            return (Intent.CHAT, 0.4, ("short message",))
        return (Intent.AMBIGUOUS, 0.2, ("no keyword matches",))

    sorted_scores = sorted(scores.items(), key=lambda x: x[1][0], reverse=True)
    top_score = sorted_scores[0][1][0]

    if len(sorted_scores) > 1 and sorted_scores[1][1][0] == top_score:
        return (Intent.AMBIGUOUS, min(1.0, top_score / 2.0), ("tie between intents",))

    top_intent = sorted_scores[0][0]
    confidence = min(1.0, top_score / 2.0)
    reasons = tuple(sorted_scores[0][1][1])
    return (top_intent, confidence, reasons)


def infer_risk(intent: Intent, text: str) -> RiskTier:
    if intent == Intent.EXPLOIT:
        return RiskTier.DANGEROUS
    if intent == Intent.RECON:
        words = set(re.findall(r"\b\w+\b", text.lower()))
        if words & ACTIVE_RECON_VERBS:
            return RiskTier.SENSITIVE
        return RiskTier.SAFE
    if intent in (Intent.IR, Intent.AMBIGUOUS):
        return RiskTier.SENSITIVE
    return RiskTier.SAFE


def rank_skills(intent: Intent, targets: ExtractedTargets, registry: SkillRegistry) -> tuple[str, ...]:
    all_skills = registry.all_skills()

    if intent == Intent.RECON:
        filtered = [
            s
            for s in all_skills
            if s.mode == "red" and s.phase in {"recon", "enumeration"}
        ]
    elif intent == Intent.EXPLOIT:
        filtered = [
            s for s in all_skills if s.mode == "red" and s.phase not in {"recon", "report"}
        ]
    elif intent == Intent.IR:
        filtered = [s for s in all_skills if s.mode == "blue"]
    elif intent == Intent.AUDIT:
        filtered = [
            s
            for s in all_skills
            if s.phase in {"audit", "harden"} or s.mode == "blue"
        ]
    else:
        return ()

    target_tools: set[str] = set()
    if targets.domains:
        target_tools.update({"dns", "whois", "subdomain"})
    if targets.ipv4s:
        target_tools.update({"nmap", "port"})
    if targets.usernames:
        target_tools.update({"username", "account"})
    if targets.cves:
        target_tools.update({"cve", "nvd"})
    if targets.paths:
        target_tools.update({"file", "path"})

    scored = []
    for skill in filtered:
        bump = 0
        if target_tools:
            tools = set(skill.tools_required) if skill.tools_required else set()
            if tools & target_tools:
                bump = 1
        scored.append((-bump, skill.name))

    scored.sort(key=lambda x: (x[0], x[1]))
    return tuple(name for _, name in scored)


def build_clarify(intent: Intent, targets: ExtractedTargets) -> str | None:
    if intent == Intent.AMBIGUOUS:
        return "Are you asking me to recon, investigate an incident, or look something up?"
    if intent == Intent.RECON and not (targets.domains or targets.ipv4s or targets.usernames or targets.paths):
        return "What target should I recon — a domain, IP, or username?"
    if intent == Intent.EXPLOIT and not (targets.domains or targets.ipv4s or targets.paths):
        return "Confirm the target and that it is in authorized ROE scope."
    return None


class IntentRouter:
    def __init__(self, registry: SkillRegistry = DEFAULT_REGISTRY):
        self._registry = registry

    def route(self, text: str) -> RouterDecision:
        targets = extract_targets(text)
        intent, confidence, reasons = classify_intent(text)
        risk = infer_risk(intent, text)
        matched_skills = rank_skills(intent, targets, self._registry)
        clarify = build_clarify(intent, targets)

        return RouterDecision(
            intent=intent,
            confidence=confidence,
            risk=risk,
            targets=targets,
            matched_skills=matched_skills,
            reasons=reasons,
            clarify=clarify,
        )


__all__ = [
    "Intent",
    "RiskTier",
    "ExtractedTargets",
    "RouterDecision",
    "IntentRouter",
    "extract_targets",
    "classify_intent",
    "infer_risk",
    "rank_skills",
    "build_clarify",
]