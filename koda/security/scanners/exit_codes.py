"""Exit-code normalization for security scanner tools.

Security scanners routinely use non-zero exit codes as *signals* rather than
errors.  For example, ``semgrep`` exits 1 when findings are present — that is
expected and successful behaviour.  Without normalizing these codes the harness
would misclassify "found issues" as "tool crashed", swallowing real results.

This module encodes the documented exit-code semantics for every scanner K.O.D.A.
supports and exposes a single :func:`classify_exit` function that maps a raw
``(scanner, returncode)`` pair onto one of four :class:`ExitStatus` values.
"""
from __future__ import annotations

from enum import Enum
from typing import Any


class ExitStatus(str, Enum):
    """Normalized meaning of a scanner's exit code."""

    SUCCESS = "success"    # clean run, no findings
    FINDINGS = "findings"  # non-zero but expected — findings detected
    CANCELED = "canceled"  # SIGINT / user abort (exit 130)
    ERROR = "error"        # actual tool failure


# ---------------------------------------------------------------------------
# Per-scanner exit-code policy
#
# Each entry may contain:
#   findings_codes  — set of int codes that mean "ran fine, found things"
#   error_codes     — set of int codes that are *always* errors regardless of
#                     stdout content (e.g. invocation/permission failures)
#
# Codes not in either set follow the default:
#   0      → SUCCESS
#   130    → CANCELED
#   other  → ERROR
#
# A code can appear in findings_codes without appearing in error_codes, and
# vice-versa.  The classifier checks findings_codes first, then error_codes,
# then falls through to the universal defaults (0 / 130 / ERROR).
# ---------------------------------------------------------------------------

SCANNER_EXIT_POLICY: dict[str, dict[str, Any]] = {
    "semgrep": {
        # 0 = no findings; 1 = findings; 2+ = real error (config/auth/parse)
        "findings_codes": {1},
        "error_codes": set(range(2, 256)) - {130},
    },
    "gitleaks": {
        # 0 = no leaks; 1 = leaks found; 126/127 = invocation error
        "findings_codes": {1},
        "error_codes": {126, 127},
    },
    "bandit": {
        # 0 = no issues; 1 = findings; 2 = real error (invalid args, parse failure)
        "findings_codes": {1},
        "error_codes": {2},
    },
    "osv-scanner": {
        # 0 = no vulns; 1 = vulns found; 127/128 = invocation/fatal error
        "findings_codes": {1},
        "error_codes": {127, 128},
    },
    "grype": {
        # Default: 0 always; 1 = findings only when --fail-on is configured.
        # We treat 1 as FINDINGS so users who set --fail-on get correct status.
        "findings_codes": {1},
        "error_codes": set(),
    },
    "trivy": {
        # 0 by default; configurable via --exit-code.
        # Treat 1 as FINDINGS (matches typical --exit-code 1 usage); 2+ = error.
        "findings_codes": {1},
        "error_codes": set(range(2, 256)) - {130},
    },
    "nuclei": {
        # 0 unless fatal; 2+ = error; 1 is not a documented findings code.
        "findings_codes": set(),
        "error_codes": set(range(2, 256)) - {130},
    },
    "nmap": {
        # 0 always on successful scan; non-zero = real error (DNS, perms, network)
        "findings_codes": set(),
        "error_codes": set(range(1, 256)) - {130},
    },
    "checkov": {
        # 0 = no violations; 1 = violations found (documented, exit-code-on-failure).
        # 2 = config/parse error or invalid invocation.
        # ref: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html
        "findings_codes": {1},
        "error_codes": {2},
    },
    "kics": {
        # KICS uses a bitmask-style additive exit code scheme.
        # Source: https://docs.kics.io/latest/results/#exit-status-codes
        #   50 = files found (scan completed)
        #   +0 = no issues           → 50
        #   +1 = HIGH severity       → 50 | 1 = ?
        # The documented codes (verbatim from KICS docs) are:
        #   0  = no files found / scan not executed
        #   50 = scan executed, no findings
        #   20 = LOW severity findings
        #   30 = MEDIUM severity findings (lower digit wins in severity ordering)
        #   40 = HIGH severity findings
        #   60 = CRITICAL severity findings (added in KICS 1.6+)
        # These codes can be combined additively, e.g. HIGH+MEDIUM = 40+30 = 70.
        # Assumption (documented here because the docs show additive examples):
        #   Any code in {20, 30, 40, 60, 70, 50} where the scan ran is FINDINGS
        #   if non-zero.  We treat every non-zero, non-error, non-130 code as
        #   FINDINGS because the bitmask arithmetic makes exhaustive enumeration
        #   impractical. Codes 1 and 2 are invocation/parse errors per KICS docs.
        "findings_codes": {20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120},
        "error_codes": {1, 2},
    },
    "falco": {
        # Falco in one-shot mode (--list or -d with timeout) emits findings via
        # stdout JSON stream, not via exit code.  Exit codes:
        #   0  = clean execution (stream ended without runtime error)
        #   non-zero = actual runtime / startup failure
        # There are no "findings" exit codes — findings travel via stdout only.
        "findings_codes": set(),
        "error_codes": set(range(1, 256)) - {130},
    },
}

# Universal constants applied *before* per-scanner policy is checked.
_SIGINT = 130


def classify_exit(
    scanner: str,
    returncode: int,
    stdout: str = "",  # noqa: ARG001 — reserved for future content-based heuristics
    stderr: str = "",  # noqa: ARG001 — reserved for future content-based heuristics
) -> ExitStatus:
    """Return the normalized :class:`ExitStatus` for a scanner's exit code.

    Args:
        scanner:    Canonical scanner name (e.g. ``"semgrep"``).  Unknown names
                    fall back to the universal default policy.
        returncode: Raw process return code from :mod:`subprocess`.
        stdout:     Process stdout (reserved — not used yet, present for
                    future content-based disambiguation).
        stderr:     Process stderr (reserved — same as above).

    Returns:
        An :class:`ExitStatus` member.

    The classification order is:

    1. CANCELED if returncode == 130 (SIGINT), regardless of scanner.
    2. SUCCESS  if returncode == 0, regardless of scanner.
    3. FINDINGS if returncode is in the scanner's ``findings_codes``.
    4. ERROR    if returncode is in the scanner's ``error_codes``.
    5. For unknown scanners (or codes not covered by the policy): ERROR.
    """
    # Step 1 — universal SIGINT guard
    if returncode == _SIGINT:
        return ExitStatus.CANCELED

    # Step 2 — clean exit
    if returncode == 0:
        return ExitStatus.SUCCESS

    policy = SCANNER_EXIT_POLICY.get(scanner)

    if policy is None:
        # Unknown scanner: any non-zero, non-130 code is an error.
        return ExitStatus.ERROR

    # Step 3 — findings signal takes precedence over generic error catch-all
    if returncode in policy.get("findings_codes", set()):
        return ExitStatus.FINDINGS

    # Step 4 — explicit error codes
    if returncode in policy.get("error_codes", set()):
        return ExitStatus.ERROR

    # Step 5 — fall-through: unrecognised code for a known scanner is an error
    return ExitStatus.ERROR
