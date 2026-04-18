"""Regex grounding verifier — rejects drafts citing evidence absent from the tool transcript."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

__all__ = [
    "UngroundedClaim",
    "VerificationResult",
    "verify_draft",
    "format_rejection",
]


@dataclass
class UngroundedClaim:
    kind: str
    value: str
    span: tuple[int, int]


@dataclass
class VerificationResult:
    ok: bool
    ungrounded: list[UngroundedClaim]
    draft: str


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{1,7}\b")
_CWE_RE = re.compile(r"\bCWE-\d{1,4}\b")
_CVSS_RE = re.compile(r"\bCVSS\s*[:v]?\s*\d+\.\d+\b", re.IGNORECASE)
_PATH_RE = re.compile(r"/(?!/)[\w./\-]+\.[a-zA-Z0-9]+\b")
_LINE_RE = re.compile(r"\bline\s+\d+\b|:\d+\b", re.IGNORECASE)
_PKG_RE = re.compile(r"\b[a-z0-9._\-]+@\d[\w.\-]+\b")

_PATTERNS = [
    ("cve", _CVE_RE),
    ("cwe", _CWE_RE),
    ("cvss", _CVSS_RE),
    ("path", _PATH_RE),
    ("line", _LINE_RE),
    ("package", _PKG_RE),
]


def _normalize_cvss(text: str) -> str:
    m = re.search(r"cvss\s*[:v]?\s*(\d+\.\d+)", text, re.IGNORECASE)
    return f"CVSS {m.group(1)}" if m else text.strip()


def _code_fence_spans(text: str) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    starts = list(re.finditer(r"```", text))
    for i in range(0, len(starts) - 1, 2):
        spans.append((starts[i].start(), starts[i + 1].end()))
    return spans


def _in_spans(start: int, end: int, spans: List[Tuple[int, int]]) -> bool:
    return any(start >= s and end <= e for s, e in spans)


def _near_tool_result(text: str, start: int, end: int, window: int = 40) -> bool:
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    return "tool_result" in text[lo:hi].lower()


def _extract_claims(draft: str) -> List[UngroundedClaim]:
    claims: List[UngroundedClaim] = []
    fence_spans = _code_fence_spans(draft)

    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(draft):
            start, end = m.span()
            value = m.group(0)

            if kind == "path":
                if _in_spans(start, end, fence_spans):
                    continue
                if _near_tool_result(draft, start, end):
                    continue

            claims.append(UngroundedClaim(kind=kind, value=value, span=(start, end)))

    claims.sort(key=lambda c: (c.span[0], c.span[1], c.kind))
    deduped: List[UngroundedClaim] = []
    seen = set()
    for c in claims:
        key = (c.kind, c.value, c.span)
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    return deduped


def _is_grounded(claim: UngroundedClaim, tool_transcript: str) -> bool:
    if claim.kind == "cvss":
        normalized_transcript = " ".join(
            _normalize_cvss(m.group(0)) for m in _CVSS_RE.finditer(tool_transcript)
        )
        return _normalize_cvss(claim.value) in normalized_transcript
    return claim.value in tool_transcript


def verify_draft(draft: str, tool_transcript: str) -> VerificationResult:
    claims = _extract_claims(draft)
    ungrounded = [c for c in claims if not _is_grounded(c, tool_transcript)]
    return VerificationResult(ok=not ungrounded, ungrounded=ungrounded, draft=draft)


def format_rejection(result: VerificationResult) -> str:
    if result.ok:
        return "Draft is grounded."
    values = []
    seen = set()
    for claim in result.ungrounded:
        if claim.value not in seen:
            seen.add(claim.value)
            values.append(claim.value)
    joined = ", ".join(values)
    return (
        "Your previous draft contained ungrounded claims: "
        f"[{joined}]. Re-answer using only facts present in prior tool_result blocks."
    )


if __name__ == "__main__":
    cases = [
        (
            "Ungrounded CVE detection",
            "The issue is CVE-2024-1234.",
            "tool_result: scanner found no CVEs",
            False,
        ),
        (
            "Grounded CVE passes",
            "Confirmed finding: CVE-2024-1234 is present.",
            "tool_result: matched CVE-2024-1234 in advisory output",
            True,
        ),
        (
            "Ungrounded file path detection",
            "Sensitive file seen at /etc/shadow.txt and should be reviewed.",
            "tool_result: listed /var/log/app.log only",
            False,
        ),
    ]

    for name, draft, transcript, expected_ok in cases:
        result = verify_draft(draft, transcript)
        print(f"{name}: ok={result.ok}, expected={expected_ok}")
        if not result.ok:
            print(format_rejection(result))
        assert result.ok == expected_ok, name

    print("Self-tests passed.")
