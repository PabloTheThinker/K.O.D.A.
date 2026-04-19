"""Unit tests for koda.security.verifier — grounding verifier."""
from __future__ import annotations

from koda.security.verifier import (
    format_rejection,
    verify_draft,
)

# ---------------------------------------------------------------------------
# Happy path — grounded claims pass
# ---------------------------------------------------------------------------


def test_clean_draft_no_claims():
    """A draft with no structured claims is always ok."""
    result = verify_draft("Recon complete. No significant findings.", "tool_result: done")
    assert result.ok is True
    assert result.ungrounded == []


def test_grounded_cve_passes():
    """A CVE present in the tool transcript is accepted."""
    result = verify_draft(
        "The scanner found CVE-2024-1234.",
        "tool_result: matched CVE-2024-1234 in advisory output",
    )
    assert result.ok is True


def test_grounded_cwe_passes():
    """A CWE present in the transcript passes grounding."""
    result = verify_draft(
        "Root cause classified as CWE-89.",
        "tool_result: CWE-89 sql injection pattern detected",
    )
    assert result.ok is True


def test_grounded_package_version_passes():
    """A package@version string present in the transcript passes."""
    result = verify_draft(
        "Dependency lodash@4.17.20 is outdated.",
        "tool_result: lodash@4.17.20 found in package-lock.json",
    )
    assert result.ok is True


def test_grounded_cvss_passes():
    """CVSS score present in transcript passes after normalization."""
    result = verify_draft(
        "CVSS: 9.8 critical severity.",
        "tool_result: CVSS 9.8 from NVD",
    )
    assert result.ok is True


# ---------------------------------------------------------------------------
# Failure path — ungrounded claims flagged
# ---------------------------------------------------------------------------


def test_ungrounded_cve_flagged():
    """A CVE not mentioned in the transcript is surfaced as ungrounded."""
    result = verify_draft(
        "The vulnerability CVE-2024-9999 is exploitable.",
        "tool_result: scanner found no CVEs",
    )
    assert result.ok is False
    kinds = {c.kind for c in result.ungrounded}
    assert "cve" in kinds


def test_ungrounded_path_flagged():
    """A file path not near a tool_result block is flagged."""
    result = verify_draft(
        "Sensitive data was found at /etc/shadow.txt on the host.",
        "tool_result: checked /var/log/app.log",
    )
    assert result.ok is False
    values = {c.value for c in result.ungrounded}
    assert any("/etc/shadow" in v for v in values)


def test_multiple_ungrounded_all_reported():
    """Multiple ungrounded claims are all listed."""
    result = verify_draft(
        "Found CVE-2024-1111 and CVE-2024-2222 on target.",
        "tool_result: no results",
    )
    assert result.ok is False
    cve_claims = [c for c in result.ungrounded if c.kind == "cve"]
    assert len(cve_claims) >= 2


# ---------------------------------------------------------------------------
# format_rejection
# ---------------------------------------------------------------------------


def test_format_rejection_clean_draft():
    """format_rejection returns a positive message when draft is ok."""
    result = verify_draft("No issues found.", "tool_result: clean")
    msg = format_rejection(result)
    assert "grounded" in msg.lower()


def test_format_rejection_lists_ungrounded_values():
    """format_rejection includes the ungrounded value in its output."""
    result = verify_draft(
        "CVE-2025-9999 is critical.",
        "tool_result: nothing",
    )
    msg = format_rejection(result)
    assert "CVE-2025-9999" in msg


# ---------------------------------------------------------------------------
# ATT&CK / CVE / CWE identity preservation
# ---------------------------------------------------------------------------


def test_cve_id_preserved_exactly_in_claim():
    """The exact CVE string is stored in UngroundedClaim.value."""
    result = verify_draft("Found CVE-2021-44228.", "tool_result: empty")
    assert any(c.value == "CVE-2021-44228" for c in result.ungrounded)


def test_cwe_id_preserved_in_claim():
    """CWE IDs are extracted with their exact text."""
    result = verify_draft("Root cause: CWE-79.", "tool_result: empty")
    assert any(c.kind == "cwe" and "CWE-79" in c.value for c in result.ungrounded)
