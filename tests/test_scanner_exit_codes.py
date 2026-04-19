"""Unit tests for koda.security.scanners.exit_codes.

All tests are pure — no real binaries, no subprocess calls.
"""
from __future__ import annotations

import pytest

from koda.security.scanners.exit_codes import (
    ExitStatus,
    classify_exit,
)

# ---------------------------------------------------------------------------
# Universal rules (apply regardless of scanner)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scanner", [
    "semgrep", "gitleaks", "bandit", "osv-scanner",
    "grype", "trivy", "nuclei", "nmap", "unknown-tool",
])
def test_exit_0_is_success_for_all_scanners(scanner: str):
    """Exit code 0 is always SUCCESS, regardless of scanner."""
    assert classify_exit(scanner, 0) == ExitStatus.SUCCESS


@pytest.mark.parametrize("scanner", [
    "semgrep", "gitleaks", "bandit", "osv-scanner",
    "grype", "trivy", "nuclei", "nmap", "unknown-tool",
])
def test_exit_130_is_canceled_for_all_scanners(scanner: str):
    """Exit code 130 (SIGINT) is always CANCELED, regardless of scanner."""
    assert classify_exit(scanner, 130) == ExitStatus.CANCELED


# ---------------------------------------------------------------------------
# Unknown scanner fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", [1, 2, 3, 127, 255])
def test_unknown_scanner_nonzero_non130_is_error(code: int):
    """For unknown scanners any non-zero, non-130 code is an error."""
    assert classify_exit("unknown-scanner", code) == ExitStatus.ERROR


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.FINDINGS),
    (2, ExitStatus.ERROR),
    (3, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_semgrep_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("semgrep", code) == expected


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.FINDINGS),
    (126, ExitStatus.ERROR),
    (127, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_gitleaks_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("gitleaks", code) == expected


def test_gitleaks_code_2_is_error():
    """Code 2 is not a documented findings code for gitleaks — treat as error."""
    assert classify_exit("gitleaks", 2) == ExitStatus.ERROR


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.FINDINGS),
    (2, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_bandit_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("bandit", code) == expected


def test_bandit_code_3_is_error():
    """Any code above 2 that is not 130 is an error for bandit."""
    assert classify_exit("bandit", 3) == ExitStatus.ERROR


# ---------------------------------------------------------------------------
# OSV-Scanner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.FINDINGS),
    (127, ExitStatus.ERROR),
    (128, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_osv_scanner_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("osv-scanner", code) == expected


def test_osv_scanner_code_2_is_error():
    """Code 2 is not FINDINGS for osv-scanner."""
    assert classify_exit("osv-scanner", 2) == ExitStatus.ERROR


# ---------------------------------------------------------------------------
# Grype
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.FINDINGS),   # triggered by --fail-on
    (130, ExitStatus.CANCELED),
])
def test_grype_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("grype", code) == expected


def test_grype_code_2_is_error():
    """Code 2 should be an error for grype (not in findings_codes or error_codes,
    so falls through to the default ERROR path)."""
    assert classify_exit("grype", 2) == ExitStatus.ERROR


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.FINDINGS),
    (2, ExitStatus.ERROR),
    (5, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_trivy_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("trivy", code) == expected


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.ERROR),   # 1 is not a findings code for nuclei
    (2, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_nuclei_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("nuclei", code) == expected


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, expected", [
    (0, ExitStatus.SUCCESS),
    (1, ExitStatus.ERROR),
    (2, ExitStatus.ERROR),
    (3, ExitStatus.ERROR),
    (130, ExitStatus.CANCELED),
])
def test_nmap_exit_codes(code: int, expected: ExitStatus):
    assert classify_exit("nmap", code) == expected


# ---------------------------------------------------------------------------
# ExitStatus enum membership
# ---------------------------------------------------------------------------


def test_exit_status_values():
    """All four status values exist and have correct string forms."""
    assert ExitStatus.SUCCESS == "success"
    assert ExitStatus.FINDINGS == "findings"
    assert ExitStatus.CANCELED == "canceled"
    assert ExitStatus.ERROR == "error"


def test_exit_status_is_str():
    """ExitStatus members are str instances (str, Enum)."""
    for member in ExitStatus:
        assert isinstance(member, str)


# ---------------------------------------------------------------------------
# classify_exit with stdout/stderr arguments (reserved — must not crash)
# ---------------------------------------------------------------------------


def test_classify_exit_accepts_stdout_stderr():
    """classify_exit should accept stdout/stderr kwargs without raising."""
    result = classify_exit("semgrep", 1, stdout="some output", stderr="")
    assert result == ExitStatus.FINDINGS


def test_classify_exit_stderr_does_not_change_outcome():
    """stderr content must not alter the classification (reserved for future use)."""
    result_with = classify_exit("semgrep", 1, stderr="some error text")
    result_without = classify_exit("semgrep", 1, stderr="")
    assert result_with == result_without
