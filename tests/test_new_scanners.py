"""Unit tests for checkov, kics, and falco scanner wrappers.

All tests mock subprocess.run — no real binaries are invoked.
"""
from __future__ import annotations

import json
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from koda.security.scanners.exit_codes import ExitStatus, classify_exit
from koda.security.scanners.registry import ScanResult, run_checkov, run_falco, run_kics

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EMPTY_ENV = {}  # _scrubbed_env is patched away in subprocess.run mock


def _make_proc(stdout: str, stderr: str = "", returncode: int = 0) -> CompletedProcess:
    """Build a fake CompletedProcess for subprocess.run mocking."""
    proc = MagicMock(spec=CompletedProcess)
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


# ===========================================================================
# EXIT-CODE POLICY TESTS
# ===========================================================================

# ---------------------------------------------------------------------------
# Checkov exit-code policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.FINDINGS),
    (2, ExitStatus.ERROR),
    (3, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_checkov_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("checkov", code) == expected


def test_checkov_code_127_is_error():
    """Undocumented high codes fall through to ERROR."""
    assert classify_exit("checkov", 127) == ExitStatus.ERROR


# ---------------------------------------------------------------------------
# KICS exit-code policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (20, ExitStatus.FINDINGS),   # LOW severity
    (30, ExitStatus.FINDINGS),   # MEDIUM severity
    (40, ExitStatus.FINDINGS),   # HIGH severity
    (50, ExitStatus.FINDINGS),   # scan completed (no issues technically, but additive)
    (60, ExitStatus.FINDINGS),   # CRITICAL severity
    (70, ExitStatus.FINDINGS),   # HIGH + MEDIUM combined
    (130, ExitStatus.CANCELED),
    (1, ExitStatus.ERROR),
    (2, ExitStatus.ERROR),
])
def test_kics_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("kics", code) == expected


def test_kics_undocumented_code_is_error():
    """Codes not in kics policy (e.g. 99) fall through to ERROR."""
    assert classify_exit("kics", 99) == ExitStatus.ERROR


# ---------------------------------------------------------------------------
# Falco exit-code policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.ERROR),
    (2, ExitStatus.ERROR),
    (127, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_falco_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("falco", code) == expected


def test_falco_has_no_findings_exit_codes():
    """Falco never uses a non-zero exit code to signal findings."""
    from koda.security.scanners.exit_codes import SCANNER_EXIT_POLICY
    assert SCANNER_EXIT_POLICY["falco"]["findings_codes"] == set()


# ===========================================================================
# JSON PARSER TESTS
# ===========================================================================

# ---------------------------------------------------------------------------
# Checkov JSON parser
# ---------------------------------------------------------------------------

_CHECKOV_FIXTURE = json.dumps({
    "check_type": "terraform",
    "results": {
        "passed_checks": [],
        "failed_checks": [
            {
                "check_id": "CKV_AWS_8",
                "check_type": "terraform",
                "resource": "aws_instance.web",
                "file_path": "/infra/main.tf",
                "file_line_range": [12, 30],
                "severity": "MEDIUM",
                "guideline": "https://docs.bridgecrew.io/docs/CKV_AWS_8",
            },
            {
                "check_id": "CKV_AWS_79",
                "check_type": "terraform",
                "resource": "aws_instance.db",
                "file_path": "/infra/main.tf",
                "file_line_range": [45, 60],
                "severity": "HIGH",
                "guideline": "",
            },
        ],
        "skipped_checks": [],
    },
    "summary": {"passed": 5, "failed": 2, "skipped": 0},
})


def test_checkov_parser_findings_count():
    """Parser emits one UnifiedFinding per failed check."""
    with patch("subprocess.run", return_value=_make_proc(_CHECKOV_FIXTURE, returncode=1)):
        result = run_checkov("/infra")
    assert isinstance(result, ScanResult)
    assert result.success is True
    assert len(result.findings) == 2


def test_checkov_parser_rule_ids():
    with patch("subprocess.run", return_value=_make_proc(_CHECKOV_FIXTURE, returncode=1)):
        result = run_checkov("/infra")
    rule_ids = {f.rule_id for f in result.findings}
    assert rule_ids == {"CKV_AWS_8", "CKV_AWS_79"}


def test_checkov_parser_severity_mapping():
    with patch("subprocess.run", return_value=_make_proc(_CHECKOV_FIXTURE, returncode=1)):
        result = run_checkov("/infra")
    by_rule = {f.rule_id: f for f in result.findings}
    from koda.security.findings import Severity
    assert by_rule["CKV_AWS_79"].severity == Severity.HIGH
    assert by_rule["CKV_AWS_8"].severity == Severity.MEDIUM


def test_checkov_parser_file_line():
    with patch("subprocess.run", return_value=_make_proc(_CHECKOV_FIXTURE, returncode=1)):
        result = run_checkov("/infra")
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["CKV_AWS_8"].file_path == "/infra/main.tf"
    assert by_rule["CKV_AWS_8"].start_line == 12
    assert by_rule["CKV_AWS_8"].end_line == 30


def test_checkov_parser_list_wrapping():
    """Checkov can emit a JSON list of check-type blocks."""
    wrapped = json.dumps([json.loads(_CHECKOV_FIXTURE)])
    with patch("subprocess.run", return_value=_make_proc(wrapped, returncode=1)):
        result = run_checkov("/infra")
    assert len(result.findings) == 2


def test_checkov_success_no_findings():
    """Exit 0 + empty output → success, no findings."""
    with patch("subprocess.run", return_value=_make_proc("", returncode=0)):
        result = run_checkov("/infra")
    assert result.success is True
    assert result.findings == []


def test_checkov_error_exit():
    """Exit 2 → error result."""
    with patch("subprocess.run", return_value=_make_proc("", stderr="parse error", returncode=2)):
        result = run_checkov("/infra")
    assert result.success is False
    assert result.exit_status == ExitStatus.ERROR


def test_checkov_canceled():
    """Exit 130 → canceled."""
    with patch("subprocess.run", return_value=_make_proc("", returncode=130)):
        result = run_checkov("/infra")
    assert result.success is False
    assert result.exit_status == ExitStatus.CANCELED


def test_checkov_not_installed():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_checkov("/infra")
    assert result.success is False
    assert "not installed" in (result.error or "")


# ---------------------------------------------------------------------------
# KICS JSON parser
# ---------------------------------------------------------------------------

_KICS_FIXTURE = json.dumps({
    "kics_version": "v1.7.13",
    "files_scanned": 3,
    "queries": [
        {
            "query_id": "ade824b7-b9c3-4ade-9e2a-27a25b4bd1ef",
            "query_name": "S3 Bucket Without Versioning",
            "severity": "MEDIUM",
            "category": "Insecure Configurations",
            "description": "S3 Bucket should have versioning enabled",
            "cis_descriptions": [{"id": "MITRE_T1530"}],
            "files": [
                {
                    "file_name": "s3.tf",
                    "line": 14,
                    "issue_type": "MissingAttribute",
                    "expected_value": "aws_s3_bucket_versioning[*].versioning_configuration.status = enabled",
                    "actual_value": "undefined",
                },
            ],
        },
        {
            "query_id": "7f65be75-9d53-41c0-8bcd-674901bb2cf5",
            "query_name": "IAM Policy With Admin Permissions",
            "severity": "HIGH",
            "category": "Access Control",
            "description": "IAM policy grants admin permissions",
            "cis_descriptions": [],
            "files": [
                {
                    "file_name": "iam.tf",
                    "line": 5,
                    "issue_type": "IncorrectValue",
                    "expected_value": "Action != *",
                    "actual_value": "Action = *",
                },
                {
                    "file_name": "iam_role.tf",
                    "line": 22,
                    "issue_type": "IncorrectValue",
                    "expected_value": "Resource != *",
                    "actual_value": "Resource = *",
                },
            ],
        },
    ],
    "total_counter": 3,
})


def test_kics_parser_findings_count():
    """Three file-level results across two queries → three UnifiedFindings."""
    with patch("subprocess.run", return_value=_make_proc(_KICS_FIXTURE, returncode=40)):
        result = run_kics("/infra")
    assert result.success is True
    assert len(result.findings) == 3


def test_kics_parser_rule_ids():
    with patch("subprocess.run", return_value=_make_proc(_KICS_FIXTURE, returncode=40)):
        result = run_kics("/infra")
    rule_ids = {f.rule_id for f in result.findings}
    assert "ade824b7-b9c3-4ade-9e2a-27a25b4bd1ef" in rule_ids
    assert "7f65be75-9d53-41c0-8bcd-674901bb2cf5" in rule_ids


def test_kics_parser_severity():
    with patch("subprocess.run", return_value=_make_proc(_KICS_FIXTURE, returncode=40)):
        result = run_kics("/infra")
    from koda.security.findings import Severity
    by_rule = {}
    for f in result.findings:
        by_rule.setdefault(f.rule_id, f)
    assert by_rule["7f65be75-9d53-41c0-8bcd-674901bb2cf5"].severity == Severity.HIGH
    assert by_rule["ade824b7-b9c3-4ade-9e2a-27a25b4bd1ef"].severity == Severity.MEDIUM


def test_kics_parser_mitre_tags():
    """MITRE IDs from cis_descriptions are extracted into mitre_attack."""
    with patch("subprocess.run", return_value=_make_proc(_KICS_FIXTURE, returncode=40)):
        result = run_kics("/infra")
    mitre_finding = next(
        f for f in result.findings
        if f.rule_id == "ade824b7-b9c3-4ade-9e2a-27a25b4bd1ef"
    )
    assert "MITRE_T1530" in mitre_finding.mitre_attack


def test_kics_parser_file_line():
    with patch("subprocess.run", return_value=_make_proc(_KICS_FIXTURE, returncode=40)):
        result = run_kics("/infra")
    s3_finding = next(f for f in result.findings if f.file_path == "s3.tf")
    assert s3_finding.start_line == 14


def test_kics_success_no_findings():
    empty = json.dumps({"queries": [], "total_counter": 0})
    with patch("subprocess.run", return_value=_make_proc(empty, returncode=0)):
        result = run_kics("/infra")
    assert result.success is True
    assert result.findings == []


def test_kics_error_exit():
    with patch("subprocess.run", return_value=_make_proc("", stderr="fatal", returncode=1)):
        result = run_kics("/infra")
    assert result.success is False
    assert result.exit_status == ExitStatus.ERROR


def test_kics_canceled():
    with patch("subprocess.run", return_value=_make_proc("", returncode=130)):
        result = run_kics("/infra")
    assert result.exit_status == ExitStatus.CANCELED


def test_kics_not_installed():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_kics("/infra")
    assert result.success is False
    assert "not installed" in (result.error or "")


# ---------------------------------------------------------------------------
# Falco JSON parser
# ---------------------------------------------------------------------------

# Realistic Falco JSONL output — each event is a separate line.
_FALCO_FIXTURE_LINES = "\n".join([
    json.dumps({
        "output": "15:04:05.000000000: Warning Sensitive file opened for reading by non-trusted program "
                  "(user=root command=cat file=/etc/shadow)",
        "priority": "Warning",
        "rule": "Read sensitive file untrusted",
        "time": "2026-04-19T15:04:05.000Z",
        "output_fields": {
            "fd.name": "/etc/shadow",
            "user.name": "root",
            "proc.cmdline": "cat /etc/shadow",
        },
        "tags": ["filesystem", "mitre_credential_access", "MITRE_T1003"],
    }),
    json.dumps({
        "output": "15:04:06.000000000: Error Shell spawned in a container (container=nginx)",
        "priority": "Error",
        "rule": "Terminal shell in container",
        "time": "2026-04-19T15:04:06.000Z",
        "output_fields": {
            "container.name": "nginx",
            "fd.name": "",
        },
        "tags": ["container", "shell", "MITRE_T1059"],
    }),
])


def test_falco_parser_findings_count():
    with patch("subprocess.run", return_value=_make_proc(_FALCO_FIXTURE_LINES, returncode=0)):
        result = run_falco("/captures/trace.scap")
    assert result.success is True
    assert len(result.findings) == 2


def test_falco_parser_rule_ids():
    with patch("subprocess.run", return_value=_make_proc(_FALCO_FIXTURE_LINES, returncode=0)):
        result = run_falco("/captures/trace.scap")
    rule_ids = {f.rule_id for f in result.findings}
    assert "Read sensitive file untrusted" in rule_ids
    assert "Terminal shell in container" in rule_ids


def test_falco_parser_severity_from_priority():
    """Falco 'Warning' → MEDIUM, 'Error' → HIGH."""
    with patch("subprocess.run", return_value=_make_proc(_FALCO_FIXTURE_LINES, returncode=0)):
        result = run_falco("/captures/trace.scap")
    from koda.security.findings import Severity
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["Read sensitive file untrusted"].severity == Severity.MEDIUM
    assert by_rule["Terminal shell in container"].severity == Severity.HIGH


def test_falco_parser_mitre_tags():
    with patch("subprocess.run", return_value=_make_proc(_FALCO_FIXTURE_LINES, returncode=0)):
        result = run_falco("/captures/trace.scap")
    by_rule = {f.rule_id: f for f in result.findings}
    assert any("MITRE" in t.upper() for t in
               by_rule["Read sensitive file untrusted"].mitre_attack)


def test_falco_parser_file_path_from_output_fields():
    with patch("subprocess.run", return_value=_make_proc(_FALCO_FIXTURE_LINES, returncode=0)):
        result = run_falco("/captures/trace.scap")
    shadow_finding = next(
        f for f in result.findings if f.rule_id == "Read sensitive file untrusted"
    )
    assert shadow_finding.file_path == "/etc/shadow"


def test_falco_exit_success_with_findings():
    """Falco exit 0 + JSONL findings → success (no special findings exit code)."""
    with patch("subprocess.run", return_value=_make_proc(_FALCO_FIXTURE_LINES, returncode=0)):
        result = run_falco("/captures/trace.scap")
    assert result.success is True
    assert result.exit_status == ExitStatus.SUCCESS
    assert len(result.findings) == 2


def test_falco_empty_stream_is_success():
    with patch("subprocess.run", return_value=_make_proc("", returncode=0)):
        result = run_falco("/captures/trace.scap")
    assert result.success is True
    assert result.findings == []


def test_falco_runtime_error():
    with patch("subprocess.run",
               return_value=_make_proc("", stderr="driver load error", returncode=1)):
        result = run_falco("/captures/trace.scap")
    assert result.success is False
    assert result.exit_status == ExitStatus.ERROR


def test_falco_canceled():
    with patch("subprocess.run", return_value=_make_proc("", returncode=130)):
        result = run_falco("/captures/trace.scap")
    assert result.exit_status == ExitStatus.CANCELED


def test_falco_not_installed():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_falco("/captures/trace.scap")
    assert result.success is False
    assert "not installed" in (result.error or "")


def test_falco_skips_bad_json_lines():
    """Malformed lines in the JSONL stream are silently skipped."""
    mixed = "not-json\n" + json.dumps({
        "output": "test", "priority": "Warning",
        "rule": "TestRule", "time": "t",
        "output_fields": {}, "tags": [],
    }) + "\nalso-bad"
    with patch("subprocess.run", return_value=_make_proc(mixed, returncode=0)):
        result = run_falco("/captures/trace.scap")
    assert result.success is True
    assert len(result.findings) == 1


# ===========================================================================
# Registry integration — new scanners are registered
# ===========================================================================


def test_new_scanners_in_scanner_map():
    """checkov, kics, falco must be discoverable via the registry."""
    from koda.security.scanners.registry import _SCANNER_MAP
    assert "checkov" in _SCANNER_MAP
    assert "kics" in _SCANNER_MAP
    assert "falco" in _SCANNER_MAP


def test_new_scanners_in_detect_installed():
    """detect_installed_scanners checks for all three new binaries."""
    from koda.security.scanners.registry import detect_installed_scanners
    # Call with no binaries present — all three should appear in the result dict.
    result = detect_installed_scanners()
    assert "checkov" in result
    assert "kics" in result
    assert "falco" in result


def test_registry_run_checkov_unknown_target():
    """ScannerRegistry.run dispatches to run_checkov."""
    from koda.security.scanners.registry import ScannerRegistry
    registry = ScannerRegistry()
    with patch("subprocess.run", return_value=_make_proc("", returncode=0)):
        result = registry.run("checkov", "/some/path")
    assert result.scanner == "checkov"


def test_registry_run_kics_unknown_target():
    from koda.security.scanners.registry import ScannerRegistry
    registry = ScannerRegistry()
    with patch("subprocess.run", return_value=_make_proc("", returncode=0)):
        result = registry.run("kics", "/some/path")
    assert result.scanner == "kics"


def test_registry_run_falco_unknown_target():
    from koda.security.scanners.registry import ScannerRegistry
    registry = ScannerRegistry()
    with patch("subprocess.run", return_value=_make_proc("", returncode=0)):
        result = registry.run("falco", "/some/path")
    assert result.scanner == "falco"
