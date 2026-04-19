"""Unit tests for the Dependency-Track scanner wrapper.

All tests mock ``httpx.get`` — no real HTTP connections are made.

Dependency-Track API shape (abbreviated):
  GET /api/v1/finding/project/{uuid}
  → 200 [ { vulnerability: {...}, component: {...}, analysis: {...} }, ... ]

Key fields used:
  vulnerability.vulnId         — CVE ID or DT-internal ID
  vulnerability.source         — "NVD", "GITHUB", etc.
  vulnerability.severity       — CRITICAL/HIGH/MEDIUM/LOW/INFO/UNASSIGNED
  vulnerability.cvssV3BaseScore — float, preferred
  vulnerability.cvssV2BaseScore — float, fallback
  vulnerability.cwe.cweId      — int
  vulnerability.description    — str
  component.name / .version / .purl
  analysis.isSuppressed        — bool; True → skip entirely
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from koda.security.findings import Severity
from koda.security.scanners.exit_codes import SCANNER_EXIT_POLICY, ExitStatus
from koda.security.scanners.registry import run_dependency_track

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID = "c9f5e7a0-1234-5678-abcd-ef0123456789"
_BASE_URL = "https://dtrack.example.com"
_API_KEY = "test-api-key"


def _make_http_response(
    status_code: int,
    body: list | dict | str | None = None,
    *,
    as_json: bool = True,
) -> MagicMock:
    """Build a fake ``httpx.Response``-shaped mock."""
    resp = MagicMock()
    resp.status_code = status_code
    if body is None:
        body = []
    if as_json and isinstance(body, (list, dict)):
        resp.json.return_value = body
        resp.text = json.dumps(body)
    else:
        resp.json.side_effect = ValueError("not JSON")
        resp.text = str(body) if body else ""
    return resp


def _make_finding(
    vuln_id: str = "CVE-2024-1234",
    source: str = "NVD",
    severity: str = "HIGH",
    cvss_v3: float | None = 7.5,
    cvss_v2: float | None = None,
    cwe_id: int | None = 79,
    description: str = "Test vulnerability",
    comp_name: str = "test-lib",
    comp_version: str = "1.0.0",
    purl: str = "pkg:pypi/test-lib@1.0.0",
    is_suppressed: bool = False,
) -> dict:
    """Build a minimal DT finding dict."""
    return {
        "vulnerability": {
            "vulnId": vuln_id,
            "source": source,
            "severity": severity,
            "cvssV3BaseScore": cvss_v3,
            "cvssV2BaseScore": cvss_v2,
            "cwe": {"cweId": cwe_id} if cwe_id is not None else None,
            "description": description,
        },
        "component": {
            "name": comp_name,
            "version": comp_version,
            "purl": purl,
        },
        "analysis": {
            "state": "NOT_SET",
            "justification": None,
            "isSuppressed": is_suppressed,
        },
    }


# ---------------------------------------------------------------------------
# Exit-code policy
# ---------------------------------------------------------------------------


def test_dependency_track_in_exit_policy():
    """dependency_track entry must exist in SCANNER_EXIT_POLICY."""
    assert "dependency_track" in SCANNER_EXIT_POLICY


def test_dependency_track_exit_policy_empty_sets():
    """Both code sets must be empty — HTTP-only scanner, no process exit codes."""
    policy = SCANNER_EXIT_POLICY["dependency_track"]
    assert policy["findings_codes"] == set()
    assert policy["error_codes"] == set()


# ---------------------------------------------------------------------------
# Happy path — 3 findings of varied severity
# ---------------------------------------------------------------------------

_THREE_FINDINGS = [
    _make_finding(vuln_id="CVE-2024-0001", severity="CRITICAL", cvss_v3=9.8),
    _make_finding(vuln_id="CVE-2024-0002", severity="MEDIUM", cvss_v3=5.4,
                  comp_name="another-lib", comp_version="2.0", purl="pkg:npm/another-lib@2.0"),
    _make_finding(vuln_id="GHSA-abcd-1234-5678", source="GITHUB", severity="LOW",
                  cvss_v3=None, cvss_v2=3.5, cwe_id=None,
                  comp_name="third-lib", purl="pkg:npm/third-lib@0.1"),
]


def test_success_finding_count():
    """Three non-suppressed findings → three UnifiedFindings."""
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    assert result.success is True
    assert len(result.findings) == 3


def test_success_scanner_name():
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    assert all(f.scanner == "dependency_track" for f in result.findings)


def test_severity_critical():
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 1
    assert critical_findings[0].rule_id == "CVE-2024-0001"


def test_severity_medium():
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    med_findings = [f for f in result.findings if f.severity == Severity.MEDIUM]
    assert len(med_findings) == 1
    assert med_findings[0].rule_id == "CVE-2024-0002"


def test_severity_low():
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    low_findings = [f for f in result.findings if f.severity == Severity.LOW]
    assert len(low_findings) == 1


def test_cve_extracted_for_nvd_source():
    """CVE IDs are only attached when source == NVD and vulnId starts with CVE-."""
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    by_rule = {f.rule_id: f for f in result.findings}
    assert "CVE-2024-0001" in by_rule["CVE-2024-0001"].cve
    # GHSA source → no CVE extracted
    assert by_rule["GHSA-abcd-1234-5678"].cve == []


def test_cvss_v3_preferred_over_v2():
    """cvss_score uses V3 when available."""
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["CVE-2024-0001"].cvss_score == 9.8
    assert by_rule["CVE-2024-0002"].cvss_score == 5.4


def test_cvss_v2_fallback():
    """cvss_score falls back to V2 when V3 is absent."""
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["GHSA-abcd-1234-5678"].cvss_score == 3.5


def test_cwe_extraction():
    """CWE ID from vulnerability.cwe.cweId → formatted as 'CWE-<id>'."""
    with patch("httpx.get", return_value=_make_http_response(200, _THREE_FINDINGS)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    by_rule = {f.rule_id: f for f in result.findings}
    assert "CWE-79" in by_rule["CVE-2024-0001"].cwe
    # finding with no cwe → empty list
    assert by_rule["GHSA-abcd-1234-5678"].cwe == []


# ---------------------------------------------------------------------------
# UNASSIGNED severity → UNKNOWN
# ---------------------------------------------------------------------------


def test_severity_unassigned_maps_to_unknown():
    findings = [_make_finding(severity="UNASSIGNED")]
    with patch("httpx.get", return_value=_make_http_response(200, findings)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.UNKNOWN


# ---------------------------------------------------------------------------
# Suppression filter
# ---------------------------------------------------------------------------


def test_suppressed_findings_are_filtered():
    """isSuppressed == True findings must be skipped entirely."""
    findings = [
        _make_finding(vuln_id="CVE-2024-KEPT", is_suppressed=False),
        _make_finding(vuln_id="CVE-2024-SKIP", is_suppressed=True),
        _make_finding(vuln_id="CVE-2024-ALSO-KEPT", is_suppressed=False),
    ]
    with patch("httpx.get", return_value=_make_http_response(200, findings)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    assert len(result.findings) == 2
    rule_ids = {f.rule_id for f in result.findings}
    assert "CVE-2024-SKIP" not in rule_ids
    assert "CVE-2024-KEPT" in rule_ids
    assert "CVE-2024-ALSO-KEPT" in rule_ids


# ---------------------------------------------------------------------------
# Empty findings list
# ---------------------------------------------------------------------------


def test_empty_findings_list():
    """200 response with empty array → success, no findings."""
    with patch("httpx.get", return_value=_make_http_response(200, [])):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    assert result.success is True
    assert result.findings == []
    assert result.error is None
    assert result.exit_status == ExitStatus.SUCCESS


# ---------------------------------------------------------------------------
# HTTP error codes
# ---------------------------------------------------------------------------


def test_401_returns_error():
    """HTTP 401 → error result with helpful message about API key."""
    with patch("httpx.get", return_value=_make_http_response(401, as_json=False)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key="bad-key")
    assert result.success is False
    assert result.exit_status == ExitStatus.ERROR
    assert "401" in (result.error or "") or "Authentication" in (result.error or "")


def test_403_returns_error():
    """HTTP 403 → same auth-failure path as 401."""
    with patch("httpx.get", return_value=_make_http_response(403, as_json=False)):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key="no-perms")
    assert result.success is False
    assert result.exit_status == ExitStatus.ERROR
    assert "403" in (result.error or "") or "Authentication" in (result.error or "")


def test_404_returns_error():
    """HTTP 404 → clear 'project not found' message."""
    with patch("httpx.get", return_value=_make_http_response(404, as_json=False)):
        result = run_dependency_track("no-such-uuid", base_url=_BASE_URL, api_key=_API_KEY)
    assert result.success is False
    assert result.exit_status == ExitStatus.ERROR
    assert "404" in (result.error or "") or "not found" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# Network errors
# ---------------------------------------------------------------------------


def test_timeout_returns_error():
    """TimeoutException → descriptive error, not a Python exception."""
    import httpx as httpx_mod
    with patch("httpx.get", side_effect=httpx_mod.TimeoutException("timed out")):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    assert result.success is False
    assert result.exit_status == ExitStatus.ERROR
    assert "timed out" in (result.error or "").lower() or "timeout" in (result.error or "").lower()


def test_network_error_returns_error():
    """Generic RequestError (DNS failure, refused connection, etc.) → error."""
    import httpx as httpx_mod
    with patch("httpx.get", side_effect=httpx_mod.ConnectError("connection refused")):
        result = run_dependency_track(_UUID, base_url=_BASE_URL, api_key=_API_KEY)
    assert result.success is False
    assert result.exit_status == ExitStatus.ERROR
    assert result.error is not None


# ---------------------------------------------------------------------------
# Scanner map and detect_installed_scanners
# ---------------------------------------------------------------------------


def test_dependency_track_in_scanner_map():
    from koda.security.scanners.registry import _SCANNER_MAP
    assert "dependency_track" in _SCANNER_MAP


def test_detect_installed_scanners_includes_dependency_track():
    from koda.security.scanners.registry import detect_installed_scanners
    result = detect_installed_scanners()
    assert "dependency_track" in result


def test_detect_installed_scanners_false_without_env_vars(monkeypatch):
    """Without env vars, dependency_track is not available."""
    monkeypatch.delenv("KODA_DTRACK_URL", raising=False)
    monkeypatch.delenv("KODA_DTRACK_API_KEY", raising=False)
    from koda.security.scanners.registry import detect_installed_scanners
    result = detect_installed_scanners()
    assert result["dependency_track"] is False


def test_detect_installed_scanners_true_with_env_vars(monkeypatch):
    """Both env vars set → dependency_track is considered available."""
    monkeypatch.setenv("KODA_DTRACK_URL", "https://dtrack.example.com")
    monkeypatch.setenv("KODA_DTRACK_API_KEY", "some-key")
    from koda.security.scanners.registry import detect_installed_scanners
    result = detect_installed_scanners()
    assert result["dependency_track"] is True
