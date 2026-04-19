"""Scanner registry — wraps security CLI tools with a unified interface.

Each scanner wrapper detects if the tool is installed, executes it with
appropriate flags for JSON/SARIF output, and returns structured results.
All execution goes through subprocess with timeout, env scrubbing, and
graceful error handling.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..findings import Severity, UnifiedFinding
from ..sarif.parser import SarifLog
from .exit_codes import ExitStatus, classify_exit

logger = logging.getLogger("koda.security.scanners")


@dataclass
class ScanResult:
    """Result from running a scanner."""
    success: bool
    scanner: str
    output: Any = None           # Parsed JSON/dict output
    findings: list[UnifiedFinding] = field(default_factory=list)
    error: str | None = None
    elapsed: float = 0.0
    raw_output: str = ""         # Raw stdout for debugging
    command: str = ""            # The command that was run
    exit_status: ExitStatus = ExitStatus.SUCCESS  # Normalized exit classification

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "scanner": self.scanner,
            "finding_count": len(self.findings),
            "elapsed": round(self.elapsed, 2),
            "error": self.error,
            "exit_status": self.exit_status.value,
        }


def _scrubbed_env() -> dict[str, str]:
    """Environment with sensitive vars removed."""
    return {k: v for k, v in os.environ.items()
            if not any(s in k.upper() for s in
                       ("SECRET", "TOKEN", "KEY", "PASSWORD", "CREDENTIAL", "AUTH"))}


def _run_cmd(
    cmd: list[str],
    timeout: int = 300,
    cwd: str | None = None,
) -> tuple[bool, str, str, int]:
    """Run a command, return (success, stdout, stderr, exit_code)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_scrubbed_env(),
            cwd=cwd,
        )
        return r.returncode == 0, r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return False, "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return False, "", f"Command not found: {cmd[0]}", -2
    except Exception as e:
        return False, "", str(e), -3


def detect_installed_scanners() -> dict[str, bool]:
    """Check which security scanners are available on the system.

    For CLI scanners the check is ``shutil.which`` (binary on PATH).
    For server-backed scanners (Dependency-Track) availability is
    signalled by environment variables instead of a binary:
      - ``KODA_DTRACK_URL``    — base URL of the running DT instance
      - ``KODA_DTRACK_API_KEY`` — API key for authentication
    Both must be set (non-empty) for ``dependency_track`` to be considered
    available.
    """
    scanners = {
        "semgrep": "semgrep",
        "trivy": "trivy",
        "gitleaks": "gitleaks",
        "nuclei": "nuclei",
        "bandit": "bandit",
        "osv-scanner": "osv-scanner",
        "nmap": "nmap",
        "grype": "grype",
        "checkov": "checkov",
        "kics": "kics",
        "falco": "falco",
    }
    result = {name: shutil.which(binary) is not None for name, binary in scanners.items()}
    # Dependency-Track is a running HTTP server — detect via env vars, not PATH.
    result["dependency_track"] = bool(
        os.environ.get("KODA_DTRACK_URL", "").strip()
        and os.environ.get("KODA_DTRACK_API_KEY", "").strip()
    )
    return result


# ── Scanner implementations ─────────────────────────────────────────

def run_semgrep(target: str, config: str = "auto", timeout: int = 300,
                extra_args: list[str] | None = None) -> ScanResult:
    """Run Semgrep SAST scanner."""
    start = time.monotonic()
    cmd = ["semgrep", "scan", "--json", "--config", config, target]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "semgrep", error="semgrep not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("semgrep", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "semgrep", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "semgrep",
                          error=f"semgrep exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings = []
    output = None
    try:
        output = json.loads(stdout)
        for result in output.get("results", []):
            f = UnifiedFinding(
                id=UnifiedFinding.make_id("semgrep", result.get("check_id", ""),
                                           result.get("path", ""), result.get("start", {}).get("line", 0)),
                scanner="semgrep",
                rule_id=result.get("check_id", ""),
                severity=Severity.from_str(result.get("extra", {}).get("severity", "WARNING")),
                title=result.get("check_id", "").split(".")[-1].replace("-", " ").title(),
                description=result.get("extra", {}).get("message", ""),
                file_path=result.get("path", ""),
                start_line=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line", 0),
                start_col=result.get("start", {}).get("col", 0),
                end_col=result.get("end", {}).get("col", 0),
                snippet=result.get("extra", {}).get("lines", ""),
                cwe=[f"CWE-{c}" for c in result.get("extra", {}).get("metadata", {}).get("cwe", [])
                     if isinstance(c, (int, str))],
                confidence={"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}.get(
                    result.get("extra", {}).get("metadata", {}).get("confidence", ""), 0.5),
                fix_suggestion=result.get("extra", {}).get("fix", ""),
                raw=result,
            )
            findings.append(f)
    except (json.JSONDecodeError, KeyError) as e:
        if not findings:
            return ScanResult(False, "semgrep", error=f"Parse error: {e}",
                              elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "semgrep", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_trivy(target: str, scan_type: str = "fs", timeout: int = 300,
              extra_args: list[str] | None = None) -> ScanResult:
    """Run Trivy vulnerability scanner."""
    start = time.monotonic()
    cmd = ["trivy", scan_type, "--format", "json", "--quiet", target]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "trivy", error="trivy not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("trivy", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "trivy", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "trivy",
                          error=f"trivy exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings = []
    output = None
    try:
        output = json.loads(stdout)
        for result_block in output.get("Results", []):
            target_name = result_block.get("Target", "")
            for vuln in result_block.get("Vulnerabilities", []):
                sev = Severity.from_str(vuln.get("Severity", "UNKNOWN"))
                f = UnifiedFinding(
                    id=UnifiedFinding.make_id("trivy", vuln.get("VulnerabilityID", ""),
                                               target_name, 0),
                    scanner="trivy",
                    rule_id=vuln.get("VulnerabilityID", ""),
                    severity=sev,
                    title=f"{vuln.get('VulnerabilityID', '')} in {vuln.get('PkgName', '')}",
                    description=vuln.get("Description", ""),
                    file_path=target_name,
                    cve=[vuln["VulnerabilityID"]] if vuln.get("VulnerabilityID", "").startswith("CVE-") else [],
                    cwe=[f"CWE-{c}" for c in vuln.get("CweIDs", [])],
                    cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                    fix_suggestion=f"Update {vuln.get('PkgName', '')} to {vuln.get('FixedVersion', 'latest')}"
                                   if vuln.get("FixedVersion") else "",
                    raw=vuln,
                )
                findings.append(f)
    except (json.JSONDecodeError, KeyError) as e:
        if not findings:
            return ScanResult(False, "trivy", error=f"Parse error: {e}",
                              elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "trivy", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_gitleaks(target: str, timeout: int = 300,
                 extra_args: list[str] | None = None) -> ScanResult:
    """Run Gitleaks secret detection scanner."""
    start = time.monotonic()
    cmd = ["gitleaks", "detect", "--source", target,
           "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner"]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "gitleaks", error="gitleaks not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("gitleaks", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "gitleaks", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "gitleaks",
                          error=f"gitleaks exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings = []
    output = None
    try:
        # exit_status SUCCESS (code 0)  → no leaks, stdout may be empty
        # exit_status FINDINGS (code 1) → leaks reported on stdout as JSON
        output = json.loads(stdout) if stdout.strip() else []
        if isinstance(output, list):
            for leak in output:
                f = UnifiedFinding(
                    id=UnifiedFinding.make_id("gitleaks", leak.get("RuleID", ""),
                                               leak.get("File", ""), leak.get("StartLine", 0)),
                    scanner="gitleaks",
                    rule_id=leak.get("RuleID", ""),
                    severity=Severity.HIGH,  # Leaked secrets are always high
                    title=f"Secret detected: {leak.get('Description', leak.get('RuleID', ''))}",
                    description=leak.get("Description", ""),
                    file_path=leak.get("File", ""),
                    start_line=leak.get("StartLine", 0),
                    end_line=leak.get("EndLine", 0),
                    snippet=leak.get("Match", "")[:80] + "..." if len(leak.get("Match", "")) > 80 else leak.get("Match", ""),
                    category="secret-leak",
                    confidence=0.95,
                    raw=leak,
                )
                findings.append(f)
    except (json.JSONDecodeError, KeyError) as e:
        if exit_status == ExitStatus.SUCCESS:
            # Exit code 0 with no parseable output = no leaks found
            return ScanResult(True, "gitleaks", output=[], findings=[],
                              elapsed=elapsed, command=" ".join(cmd),
                              exit_status=ExitStatus.SUCCESS)
        return ScanResult(False, "gitleaks", error=f"Parse error: {e}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "gitleaks", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_bandit(target: str, timeout: int = 300,
               extra_args: list[str] | None = None) -> ScanResult:
    """Run Bandit Python security linter."""
    start = time.monotonic()
    cmd = ["bandit", "-r", "-f", "json", target]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "bandit", error="bandit not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("bandit", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "bandit", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "bandit",
                          error=f"bandit exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings = []
    output = None
    try:
        output = json.loads(stdout)
        for result in output.get("results", []):
            sev = Severity.from_str(result.get("issue_severity", "MEDIUM"))
            conf_map = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}
            f = UnifiedFinding(
                id=UnifiedFinding.make_id("bandit", result.get("test_id", ""),
                                           result.get("filename", ""), result.get("line_number", 0)),
                scanner="bandit",
                rule_id=result.get("test_id", ""),
                severity=sev,
                title=result.get("test_name", ""),
                description=result.get("issue_text", ""),
                file_path=result.get("filename", ""),
                start_line=result.get("line_number", 0),
                end_line=result.get("end_col_offset", result.get("line_number", 0)),
                snippet=result.get("code", ""),
                cwe=[f"CWE-{result['issue_cwe']['id']}"] if result.get("issue_cwe") else [],
                confidence=conf_map.get(result.get("issue_confidence", ""), 0.5),
                raw=result,
            )
            findings.append(f)
    except (json.JSONDecodeError, KeyError) as e:
        if not findings:
            return ScanResult(False, "bandit", error=f"Parse error: {e}",
                              elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "bandit", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_nuclei(target: str, timeout: int = 300,
               extra_args: list[str] | None = None) -> ScanResult:
    """Run Nuclei vulnerability scanner."""
    start = time.monotonic()
    cmd = ["nuclei", "-target", target, "-jsonl", "-silent"]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "nuclei", error="nuclei not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("nuclei", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "nuclei", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "nuclei",
                          error=f"nuclei exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings = []
    for line in stdout.strip().split("\n"):
        if not line.strip():
            continue
        try:
            result = json.loads(line)
            sev = Severity.from_str(result.get("info", {}).get("severity", "info"))
            f = UnifiedFinding(
                id=UnifiedFinding.make_id("nuclei", result.get("template-id", ""),
                                           result.get("matched-at", ""), 0),
                scanner="nuclei",
                rule_id=result.get("template-id", ""),
                severity=sev,
                title=result.get("info", {}).get("name", ""),
                description=result.get("info", {}).get("description", ""),
                file_path=result.get("matched-at", ""),
                cve=[ref for ref in result.get("info", {}).get("reference", [])
                     if isinstance(ref, str) and "CVE-" in ref],
                cwe=[f"CWE-{c}" for c in result.get("info", {}).get("classification", {}).get("cwe-id", [])],
                category=result.get("info", {}).get("tags", [""])[0] if result.get("info", {}).get("tags") else "",
                raw=result,
            )
            findings.append(f)
        except (json.JSONDecodeError, KeyError):
            continue

    return ScanResult(True, "nuclei", output=findings, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_osv_scanner(target: str, timeout: int = 300,
                    extra_args: list[str] | None = None) -> ScanResult:
    """Run OSV-Scanner for known vulnerability detection."""
    start = time.monotonic()
    cmd = ["osv-scanner", "--format", "json", target]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "osv-scanner", error="osv-scanner not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("osv-scanner", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "osv-scanner", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "osv-scanner",
                          error=f"osv-scanner exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings = []
    output = None
    try:
        output = json.loads(stdout)
        for result in output.get("results", []):
            source = result.get("source", {}).get("path", "")
            for pkg in result.get("packages", []):
                pkg_info = pkg.get("package", {})
                for vuln in pkg.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "")
                    sev = Severity.MEDIUM
                    # Try to extract severity from database_specific
                    db_sev = vuln.get("database_specific", {}).get("severity")
                    if db_sev:
                        sev = Severity.from_str(db_sev)

                    f = UnifiedFinding(
                        id=UnifiedFinding.make_id("osv-scanner", vuln_id, source, 0),
                        scanner="osv-scanner",
                        rule_id=vuln_id,
                        severity=sev,
                        title=f"{vuln_id} in {pkg_info.get('name', '')}",
                        description=vuln.get("summary", ""),
                        file_path=source,
                        cve=[a.get("value", "") for a in vuln.get("aliases", [])
                             if a.get("value", "").startswith("CVE-")] if isinstance(vuln.get("aliases"), list) else
                            [a for a in vuln.get("aliases", []) if isinstance(a, str) and a.startswith("CVE-")],
                        raw=vuln,
                    )
                    findings.append(f)
    except (json.JSONDecodeError, KeyError) as e:
        if not findings:
            return ScanResult(False, "osv-scanner", error=f"Parse error: {e}",
                              elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "osv-scanner", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_nmap(target: str, ports: str = "1-1000", timeout: int = 300,
             extra_args: list[str] | None = None) -> ScanResult:
    """Run Nmap network scanner."""
    start = time.monotonic()
    cmd = ["nmap", "-oX", "-", "-p", ports, target]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "nmap", error="nmap not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("nmap", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "nmap", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "nmap",
                          error=f"nmap exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings = []
    output = {}
    try:
        root = ET.fromstring(stdout)
        hosts = []
        for host in root.findall(".//host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", "") if addr_el is not None else ""
            host_info = {"address": addr, "ports": []}

            for port in host.findall(".//port"):
                state_el = port.find("state")
                service_el = port.find("service")
                port_info = {
                    "port": port.get("portid", ""),
                    "protocol": port.get("protocol", ""),
                    "state": state_el.get("state", "") if state_el is not None else "",
                    "service": service_el.get("name", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                }
                host_info["ports"].append(port_info)

                # Open ports are findings
                if port_info["state"] == "open":
                    f = UnifiedFinding(
                        id=UnifiedFinding.make_id("nmap", f"open-port-{port_info['port']}",
                                                   addr, 0),
                        scanner="nmap",
                        rule_id=f"open-port-{port_info['port']}",
                        severity=Severity.INFO,
                        title=f"Open port {port_info['port']}/{port_info['protocol']}: {port_info['service']}",
                        description=f"Service: {port_info['product']} {port_info['version']}".strip(),
                        file_path=addr,
                        category="network",
                        raw=port_info,
                    )
                    findings.append(f)

            hosts.append(host_info)
        output = {"hosts": hosts}
    except ET.ParseError as e:
        return ScanResult(False, "nmap", error=f"XML parse error: {e}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "nmap", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_grype(target: str, timeout: int = 300,
              extra_args: list[str] | None = None) -> ScanResult:
    """Run Grype vulnerability scanner (SBOM/image/directory)."""
    start = time.monotonic()
    cmd = ["grype", target, "-o", "json"]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "grype", error="grype not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("grype", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "grype", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "grype",
                          error=f"grype exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings = []
    output = None
    try:
        output = json.loads(stdout)
        for match in output.get("matches", []):
            vuln = match.get("vulnerability", {}) or {}
            artifact = match.get("artifact", {}) or {}
            vuln_id = vuln.get("id", "")
            sev = Severity.from_str(vuln.get("severity", "UNKNOWN"))
            # Grype nests CVSS in a list; take first V3 vector if present
            cvss_score = 0.0
            for entry in vuln.get("cvss", []) or []:
                metrics = entry.get("metrics", {}) or {}
                base = metrics.get("baseScore")
                if isinstance(base, (int, float)) and base > cvss_score:
                    cvss_score = float(base)
            locations = artifact.get("locations", []) or []
            file_path = locations[0].get("path", "") if locations else ""
            fixed_versions = (vuln.get("fix", {}) or {}).get("versions", []) or []
            fix_text = ""
            if fixed_versions:
                fix_text = f"Upgrade {artifact.get('name', '')} to {fixed_versions[0]}"
            f = UnifiedFinding(
                id=UnifiedFinding.make_id("grype", vuln_id, file_path or artifact.get("name", ""), 0),
                scanner="grype",
                rule_id=vuln_id,
                severity=sev,
                title=f"{vuln_id} in {artifact.get('name', '')} {artifact.get('version', '')}".strip(),
                description=vuln.get("description", ""),
                file_path=file_path or artifact.get("name", ""),
                cve=[vuln_id] if vuln_id.startswith("CVE-") else [],
                cvss_score=cvss_score,
                fix_suggestion=fix_text,
                raw=match,
            )
            findings.append(f)
    except (json.JSONDecodeError, KeyError) as e:
        if not findings:
            return ScanResult(False, "grype", error=f"Parse error: {e}",
                              elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "grype", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_checkov(target: str, timeout: int = 300,
                extra_args: list[str] | None = None) -> ScanResult:
    """Run Checkov IaC misconfiguration scanner (Terraform, CF, K8s, Helm, Dockerfile)."""
    start = time.monotonic()
    cmd = ["checkov", "-d", target, "-o", "json", "--quiet"]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "checkov", error="checkov not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("checkov", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "checkov", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "checkov",
                          error=f"checkov exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings: list[UnifiedFinding] = []
    output = None
    try:
        # Checkov may emit a list of check-type result blocks or a single object.
        raw = json.loads(stdout) if stdout.strip() else {}
        # Normalise to a list — checkov wraps multi-type scans in a list.
        blocks = raw if isinstance(raw, list) else [raw]
        output = raw

        for block in blocks:
            check_results = block.get("results", {})
            for result in check_results.get("failed_checks", []):
                check = result.get("check_id", "")
                resource = result.get("resource", "")
                file_path = result.get("file_path", "")
                file_line_range = result.get("file_line_range", [0, 0])
                start_line = file_line_range[0] if file_line_range else 0
                end_line = file_line_range[1] if len(file_line_range) > 1 else start_line
                # Checkov doesn't expose per-check CVSS; use rule prefix to guess severity.
                sev = Severity.MEDIUM
                check_upper = check.upper()
                if any(check_upper.startswith(p) for p in ("CKV_K8S_", "CKV2_")):
                    sev = Severity.MEDIUM
                if result.get("severity"):
                    sev = Severity.from_str(result["severity"])
                mitre: list[str] = []
                guideline = result.get("guideline", "")
                f = UnifiedFinding(
                    id=UnifiedFinding.make_id("checkov", check, file_path, start_line),
                    scanner="checkov",
                    rule_id=check,
                    severity=sev,
                    title=result.get("check_type", check),
                    description=result.get("check_id", ""),
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=resource,
                    category="iac-misconfiguration",
                    mitre_attack=mitre,
                    fix_suggestion=guideline,
                    raw=result,
                )
                findings.append(f)
    except (json.JSONDecodeError, KeyError) as e:
        if exit_status == ExitStatus.SUCCESS:
            return ScanResult(True, "checkov", output={}, findings=[],
                              elapsed=elapsed, command=" ".join(cmd),
                              exit_status=ExitStatus.SUCCESS)
        return ScanResult(False, "checkov", error=f"Parse error: {e}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "checkov", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_kics(target: str, timeout: int = 300,
             extra_args: list[str] | None = None) -> ScanResult:
    """Run KICS IaC misconfiguration scanner (broader runtime/cloud coverage)."""
    start = time.monotonic()
    cmd = ["kics", "scan", "-p", target, "--report-formats", "json",
           "--output-path", "/dev/stdout", "--no-progress"]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "kics", error="kics not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("kics", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "kics", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "kics",
                          error=f"kics exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings: list[UnifiedFinding] = []
    output = None
    try:
        output = json.loads(stdout) if stdout.strip() else {}
        for query in output.get("queries", []):
            query_id = query.get("query_id", "")
            query_name = query.get("query_name", "")
            severity_str = query.get("severity", "MEDIUM")
            sev = Severity.from_str(severity_str)
            category = query.get("category", "")
            description = query.get("description", "")
            # KICS places MITRE ATT&CK IDs in query.files[].expected_value or
            # top-level query metadata; extract from description_id if present.
            mitre: list[str] = []
            cis_descriptions = query.get("cis_descriptions", []) or []
            for cis in cis_descriptions:
                mid = cis.get("id", "")
                if mid:
                    mitre.append(mid)

            for file_result in query.get("files", []):
                file_path = file_result.get("file_name", "")
                line = file_result.get("line", 0)
                issue_type = file_result.get("issue_type", "")
                expected = file_result.get("expected_value", "")
                actual = file_result.get("actual_value", "")
                snippet = f"Expected: {expected}\nActual: {actual}" if expected or actual else ""
                f = UnifiedFinding(
                    id=UnifiedFinding.make_id("kics", query_id, file_path, line),
                    scanner="kics",
                    rule_id=query_id,
                    severity=sev,
                    title=query_name,
                    description=description or issue_type,
                    file_path=file_path,
                    start_line=line,
                    snippet=snippet,
                    category=category,
                    mitre_attack=mitre,
                    raw=file_result,
                )
                findings.append(f)
    except (json.JSONDecodeError, KeyError) as e:
        if exit_status == ExitStatus.SUCCESS:
            return ScanResult(True, "kics", output={}, findings=[],
                              elapsed=elapsed, command=" ".join(cmd),
                              exit_status=ExitStatus.SUCCESS)
        return ScanResult(False, "kics", error=f"Parse error: {e}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    return ScanResult(True, "kics", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_falco(target: str, rules: str | None = None, timeout: int = 60,
              extra_args: list[str] | None = None) -> ScanResult:
    """Run Falco one-shot eBPF/runtime security scan (IR/hunt workflows).

    Falco is normally a daemon; here we run it in one-shot mode via
    ``falco -d`` (read from driver capture file) or ``falco --list`` for
    rule enumeration.  Findings arrive as JSON lines on stdout; exit code
    carries only success/error — never findings.
    """
    start = time.monotonic()
    if target == "--list":
        # Rule listing mode — useful for audit/hunt preparation.
        cmd = ["falco", "--list", "-o", "json_output=true"]
    else:
        # One-shot trace-file mode (e.g. a .scap capture file).
        cmd = ["falco", "-e", target, "-o", "json_output=true",
               "-o", "json_include_output_property=true"]
        if rules:
            cmd += ["-r", rules]
    if extra_args:
        cmd.extend(extra_args)

    ok, stdout, stderr, code = _run_cmd(cmd, timeout=timeout)
    elapsed = time.monotonic() - start

    if not ok and code == -2:
        return ScanResult(False, "falco", error="falco not installed", elapsed=elapsed,
                          exit_status=ExitStatus.ERROR)

    exit_status = classify_exit("falco", code, stdout, stderr)
    if exit_status == ExitStatus.CANCELED:
        return ScanResult(False, "falco", error="Scan canceled by user (SIGINT)",
                          elapsed=elapsed, exit_status=ExitStatus.CANCELED)
    if exit_status == ExitStatus.ERROR:
        return ScanResult(False, "falco",
                          error=f"falco exited with code {code}: {stderr[:500] or '(no stderr)'}",
                          elapsed=elapsed, raw_output=stdout[:2000], exit_status=ExitStatus.ERROR)

    findings: list[UnifiedFinding] = []
    # Falco emits one JSON object per line (JSONL); parse each line independently.
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            # Standard Falco JSON event shape:
            # { "output": "...", "priority": "Warning", "rule": "...",
            #   "time": "...", "output_fields": {...} }
            priority = event.get("priority", "")
            rule = event.get("rule", "")
            output_msg = event.get("output", "")
            output_fields = event.get("output_fields", {}) or {}
            file_path = (output_fields.get("fd.name")
                         or output_fields.get("container.name")
                         or "")
            # Map Falco priority strings → Severity
            sev = Severity.from_str(priority) if priority else Severity.MEDIUM
            tags: list[str] = event.get("tags", []) or []
            # Extract MITRE tags (Falco uses "MITRE_..." tag naming convention)
            mitre = [t for t in tags if t.upper().startswith("MITRE")]
            f = UnifiedFinding(
                id=UnifiedFinding.make_id("falco", rule, file_path,
                                          hash(event.get("time", "")) & 0xFFFF),
                scanner="falco",
                rule_id=rule,
                severity=sev,
                title=rule,
                description=output_msg,
                file_path=file_path,
                category="runtime",
                mitre_attack=mitre,
                raw=event,
            )
            findings.append(f)
        except (json.JSONDecodeError, KeyError):
            continue

    # Falco: findings via stdout stream — exit_status stays SUCCESS even when
    # events were emitted (no special "findings" exit code exists).
    return ScanResult(True, "falco", output=findings, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd), exit_status=exit_status)


def run_dependency_track(
    project_uuid: str,
    *,
    base_url: str,
    api_key: str,
    timeout: int = 30,
) -> ScanResult:
    """Query Dependency-Track for findings on an already-uploaded project.

    Unlike CLI-based scanners, Dependency-Track is a running HTTP server.
    This function performs a single GET request against the DT REST API and
    maps the returned findings to :class:`UnifiedFinding` objects.

    Args:
        project_uuid: UUID of the project in Dependency-Track.
        base_url:     Base URL of the DT instance, e.g. ``https://dtrack.example.com``.
        api_key:      Dependency-Track API key (``X-Api-Key`` header).
        timeout:      HTTP request timeout in seconds (default 30).

    Returns:
        A :class:`ScanResult`.  Suppressed findings (``analysis.isSuppressed``
        == True) are excluded — they represent triaged false-positives.

    Note on dispatch mismatch:
        All other scanner runners accept ``target: str`` (a filesystem path or
        URL).  This runner accepts ``project_uuid`` instead.  The standard
        :class:`ScannerRegistry` dispatch (``registry.run(scanner, target)``)
        cannot forward ``base_url`` / ``api_key`` through the generic interface
        without kwargs.  Call ``run_dependency_track`` directly, or use
        ``registry.run("dependency_track", project_uuid,
        base_url=..., api_key=...)`` — the kwargs are forwarded as-is.
    """
    start = time.monotonic()
    url = f"{base_url.rstrip('/')}/api/v1/finding/project/{project_uuid}"
    headers = {"X-Api-Key": api_key, "Accept": "application/json"}

    try:
        response = httpx.get(url, headers=headers, timeout=timeout)
    except httpx.TimeoutException:
        elapsed = time.monotonic() - start
        return ScanResult(
            False, "dependency_track",
            error=f"Request timed out after {timeout}s connecting to {base_url}",
            elapsed=elapsed, exit_status=ExitStatus.ERROR,
        )
    except httpx.RequestError as exc:
        elapsed = time.monotonic() - start
        return ScanResult(
            False, "dependency_track",
            error=f"Network error reaching {base_url}: {exc}",
            elapsed=elapsed, exit_status=ExitStatus.ERROR,
        )

    elapsed = time.monotonic() - start

    if response.status_code in (401, 403):
        return ScanResult(
            False, "dependency_track",
            error=f"Authentication failed (HTTP {response.status_code}): check KODA_DTRACK_API_KEY",
            elapsed=elapsed, exit_status=ExitStatus.ERROR,
        )
    if response.status_code == 404:
        return ScanResult(
            False, "dependency_track",
            error=f"Project '{project_uuid}' not found in Dependency-Track (HTTP 404)",
            elapsed=elapsed, exit_status=ExitStatus.ERROR,
        )
    if response.status_code != 200:
        return ScanResult(
            False, "dependency_track",
            error=f"Unexpected HTTP {response.status_code} from Dependency-Track: {response.text[:300]}",
            elapsed=elapsed, exit_status=ExitStatus.ERROR,
        )

    try:
        raw_findings: list[dict[str, Any]] = response.json()
    except Exception as exc:
        return ScanResult(
            False, "dependency_track",
            error=f"Failed to parse JSON response: {exc}",
            elapsed=elapsed, exit_status=ExitStatus.ERROR,
        )

    findings: list[UnifiedFinding] = []
    for item in raw_findings:
        # --- suppression filter ---
        analysis = item.get("analysis") or {}
        if analysis.get("isSuppressed", False):
            continue

        vuln: dict[str, Any] = item.get("vulnerability") or {}
        component: dict[str, Any] = item.get("component") or {}

        vuln_id: str = vuln.get("vulnId", "") or ""
        source: str = vuln.get("source", "") or ""
        description: str = vuln.get("description", "") or ""

        # Severity: DT uses CRITICAL/HIGH/MEDIUM/LOW/INFO/UNASSIGNED
        sev_str: str = (vuln.get("severity") or "UNKNOWN").upper()
        if sev_str == "UNASSIGNED":
            sev = Severity.UNKNOWN
        else:
            sev = Severity.from_str(sev_str)

        # CVE: only attach when the source is NVD and the ID is CVE-prefixed
        cve_list: list[str] = []
        if source.upper() == "NVD" and vuln_id.upper().startswith("CVE-"):
            cve_list = [vuln_id]

        # CVSS: prefer V3 base score, fall back to V2
        cvss_score: float = 0.0
        v3 = vuln.get("cvssV3BaseScore")
        v2 = vuln.get("cvssV2BaseScore")
        if isinstance(v3, (int, float)) and v3 > 0:
            cvss_score = float(v3)
        elif isinstance(v2, (int, float)) and v2 > 0:
            cvss_score = float(v2)

        # CWE
        cwe_list: list[str] = []
        cwe_obj = vuln.get("cwe") or {}
        if isinstance(cwe_obj, dict):
            cwe_id = cwe_obj.get("cweId")
            if cwe_id is not None:
                cwe_list = [f"CWE-{cwe_id}"]
        elif isinstance(cwe_obj, (int, str)) and str(cwe_obj):
            cwe_list = [f"CWE-{cwe_obj}"]

        comp_name: str = component.get("name", "") or ""
        comp_version: str = component.get("version", "") or ""
        purl: str = component.get("purl", "") or ""

        # Use PURL as file_path proxy — it uniquely identifies the component.
        file_path_proxy = purl or comp_name

        f = UnifiedFinding(
            id=UnifiedFinding.make_id(
                "dependency_track", vuln_id, file_path_proxy, 0
            ),
            scanner="dependency_track",
            rule_id=vuln_id,
            severity=sev,
            title=f"{vuln_id} in {comp_name} {comp_version}".strip(),
            description=description,
            file_path=file_path_proxy,
            cve=cve_list,
            cwe=cwe_list,
            cvss_score=cvss_score,
            raw=item,
        )
        findings.append(f)

    exit_status = ExitStatus.FINDINGS if findings else ExitStatus.SUCCESS
    return ScanResult(
        True, "dependency_track",
        output=raw_findings,
        findings=findings,
        elapsed=elapsed,
        command=url,
        exit_status=exit_status,
    )


def run_sarif_file(path: str) -> ScanResult:
    """Parse a SARIF file directly and extract findings."""
    start = time.monotonic()
    try:
        sarif = SarifLog.from_file(path)
        findings = sarif.all_findings()
        tool_names = [r.tool_name for r in sarif.runs]
        scanner = tool_names[0] if tool_names else "sarif"
        return ScanResult(
            True, scanner, output=sarif.stats(), findings=findings,
            elapsed=time.monotonic() - start, command=f"sarif:{path}",
        )
    except Exception as e:
        return ScanResult(False, "sarif", error=str(e), elapsed=time.monotonic() - start)


# ── Scanner Registry ────────────────────────────────────────────────

# Maps scanner names to their runner functions.
#
# Note on dependency_track dispatch:
#   All other runners share the signature ``(target: str, **kwargs)``.
#   run_dependency_track takes ``(project_uuid: str, *, base_url, api_key, ...)``
#   instead — it is URL-based, not file-based.  ScannerRegistry.run() forwards
#   kwargs transparently, so callers must supply ``base_url`` and ``api_key``
#   as keyword arguments:
#
#       registry.run("dependency_track", project_uuid,
#                    base_url="https://dtrack.example.com",
#                    api_key="...")
#
#   run_all() will skip dependency_track automatically because it requires
#   these extra kwargs that the generic path cannot supply.
_SCANNER_MAP: dict[str, Callable[..., ScanResult]] = {
    "semgrep": run_semgrep,
    "trivy": run_trivy,
    "gitleaks": run_gitleaks,
    "nuclei": run_nuclei,
    "bandit": run_bandit,
    "osv-scanner": run_osv_scanner,
    "nmap": run_nmap,
    "grype": run_grype,
    "checkov": run_checkov,
    "kics": run_kics,
    "falco": run_falco,
    "sarif": run_sarif_file,
    # dependency_track uses project_uuid (not a path) + base_url/api_key kwargs;
    # see comment above for dispatch details.
    "dependency_track": run_dependency_track,
}


class ScannerRegistry:
    """Registry of available scanners with unified run interface."""

    def __init__(self):
        self._scanners = dict(_SCANNER_MAP)
        self._installed: dict[str, bool] | None = None

    def register(self, name: str, runner: Callable[..., ScanResult]) -> None:
        """Register a custom scanner."""
        self._scanners[name] = runner

    def installed(self) -> dict[str, bool]:
        """Check which scanners are installed (cached)."""
        if self._installed is None:
            self._installed = detect_installed_scanners()
        return self._installed

    def available(self) -> list[str]:
        """List scanners that are both registered and installed."""
        inst = self.installed()
        return [name for name in self._scanners if inst.get(name, name == "sarif")]

    def run(self, scanner: str, target: str, **kwargs) -> ScanResult:
        """Run a scanner by name."""
        if scanner not in self._scanners:
            return ScanResult(False, scanner, error=f"Unknown scanner: {scanner}")
        runner = self._scanners[scanner]
        try:
            return runner(target, **kwargs)
        except Exception as e:
            return ScanResult(False, scanner, error=f"Runner error: {e}")

    def run_all(self, target: str, scanners: list[str] | None = None,
                **kwargs) -> list[ScanResult]:
        """Run multiple scanners against a target."""
        to_run = scanners or self.available()
        # Don't include nmap/nuclei for filesystem targets
        if Path(target).is_dir() or Path(target).is_file():
            to_run = [s for s in to_run if s not in ("nmap", "nuclei")]
        results = []
        for name in to_run:
            logger.info("Running scanner: %s against %s", name, target)
            result = self.run(name, target, **kwargs)
            results.append(result)
            logger.info("Scanner %s: %d findings in %.1fs",
                        name, len(result.findings), result.elapsed)
        return results

    def status(self) -> dict[str, Any]:
        inst = self.installed()
        return {
            "registered": list(self._scanners.keys()),
            "installed": {k: v for k, v in inst.items() if v},
            "missing": {k: v for k, v in inst.items() if not v},
        }
