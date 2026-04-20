"""Security scanner for agent-generated skill drafts.

Before any learned skill is written to disk (even to the pending area), it
runs through this scanner. The same pattern set covers both agent-authored
drafts and community hub imports so there's one place to audit.

Patterns are conservative — we block, we don't rewrite. False positives are
cheaper than prompt-injection escapes making it into a user's skill library.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Patterns that should never appear in a benign procedural skill. Keyed by
# short slug so downstream messages stay readable.
_INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_previous": re.compile(
        r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+"
        r"(instructions?|prompts?|rules?)",
        re.IGNORECASE,
    ),
    "role_override": re.compile(
        r"\byou\s+are\s+now\s+(?:a\s+)?(?:different|new)\s+"
        r"(?:agent|assistant|model|ai)",
        re.IGNORECASE,
    ),
    "system_prompt_leak": re.compile(
        r"(?:print|reveal|show|output|dump)\s+(?:the\s+)?"
        r"(?:system\s+)?(?:prompt|instructions|rules)",
        re.IGNORECASE,
    ),
    "credential_exfil": re.compile(
        r"\b(?:curl|wget|nc|netcat|python\s+-c).*"
        r"(?:\$\{?(?:HOME|USER|PATH)|/etc/(?:passwd|shadow)|"
        r"\.ssh/|\.aws/|\.env|secrets?\.|api[_-]?key)",
        re.IGNORECASE,
    ),
    "remote_fetch_exec": re.compile(
        r"(?:curl|wget)\s+[^|\n]*\|\s*(?:bash|sh|zsh|python|perl|ruby)\b",
        re.IGNORECASE,
    ),
    "encoded_payload": re.compile(
        r"\b(?:base64|hex)\s+(?:-d|--decode|decode)\b",
        re.IGNORECASE,
    ),
    "shell_obfuscation": re.compile(
        r"\$\(\s*echo\s+[^)]{40,}\s*\|\s*(?:base64|xxd|od)",
        re.IGNORECASE,
    ),
}

# Hard ceilings — a learned skill has no business being huge.
_MAX_BODY_CHARS = 20_000
_MAX_NAME_LEN = 64
_MAX_DESCRIPTION_LEN = 1024


@dataclass
class GuardReport:
    """Result of scanning a draft.

    ``clean`` is the single-bit verdict used by the pipeline. ``violations``
    carries the pattern slugs and line excerpts so the review UI can explain
    why a draft was rejected.
    """

    clean: bool
    violations: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.clean:
            return "clean" + (f" ({len(self.warnings)} warnings)" if self.warnings else "")
        slugs = ", ".join(sorted({slug for slug, _ in self.violations}))
        return f"blocked: {slugs}"


def scan_skill_draft(
    *,
    name: str,
    description: str,
    body: str,
) -> GuardReport:
    """Scan a skill draft for injection / exfil patterns and size limits.

    Returns a :class:`GuardReport` — callers decide how to act. ``clean``
    collapses to ``False`` if any violation fired or any hard ceiling was
    crossed.
    """
    violations: list[tuple[str, str]] = []
    warnings: list[str] = []

    # ── Structural bounds ────────────────────────────────────────────
    if not name or not name.strip():
        violations.append(("empty_name", "name is required"))
    elif len(name) > _MAX_NAME_LEN:
        violations.append((
            "name_too_long",
            f"name is {len(name)} chars (limit {_MAX_NAME_LEN})",
        ))
    elif not re.match(r"^[a-z0-9][a-z0-9_\-]*$", name):
        violations.append((
            "name_format",
            f"name {name!r} must be lowercase alphanumeric + _/-",
        ))

    if not description or not description.strip():
        violations.append(("empty_description", "description is required"))
    elif len(description) > _MAX_DESCRIPTION_LEN:
        violations.append((
            "description_too_long",
            f"description is {len(description)} chars (limit {_MAX_DESCRIPTION_LEN})",
        ))

    if len(body) > _MAX_BODY_CHARS:
        violations.append((
            "body_too_long",
            f"body is {len(body)} chars (limit {_MAX_BODY_CHARS})",
        ))

    # ── Content patterns ────────────────────────────────────────────
    haystack = f"{name}\n{description}\n{body}"
    for slug, pattern in _INJECTION_PATTERNS.items():
        match = pattern.search(haystack)
        if match:
            excerpt = _excerpt(haystack, match.start(), match.end())
            violations.append((slug, excerpt))

    # ── Soft warnings ───────────────────────────────────────────────
    if body and len(body) < 60:
        warnings.append("body is very short — skill may not be actionable")
    if not body.strip():
        warnings.append("body is empty")

    return GuardReport(
        clean=not violations,
        violations=violations,
        warnings=warnings,
    )


def _excerpt(text: str, start: int, end: int, pad: int = 20) -> str:
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    snippet = text[lo:hi].replace("\n", " ")
    if lo > 0:
        snippet = "…" + snippet
    if hi < len(text):
        snippet = snippet + "…"
    return snippet.strip()
