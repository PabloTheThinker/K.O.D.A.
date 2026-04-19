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

from ..findings import Severity, UnifiedFinding
from ..sarif.parser import SarifLog

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "scanner": self.scanner,
            "finding_count": len(self.findings),
            "elapsed": round(self.elapsed, 2),
            "error": self.error,
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
    """Check which security scanners are available on the system."""
    scanners = {
        "semgrep": "semgrep",
        "trivy": "trivy",
        "gitleaks": "gitleaks",
        "nuclei": "nuclei",
        "bandit": "bandit",
        "osv-scanner": "osv-scanner",
        "nmap": "nmap",
        "grype": "grype",
    }
    return {name: shutil.which(binary) is not None for name, binary in scanners.items()}


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
        return ScanResult(False, "semgrep", error="semgrep not installed", elapsed=elapsed)

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
                              elapsed=elapsed, raw_output=stdout[:2000])

    return ScanResult(True, "semgrep", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd))


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
        return ScanResult(False, "trivy", error="trivy not installed", elapsed=elapsed)

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
                              elapsed=elapsed, raw_output=stdout[:2000])

    return ScanResult(True, "trivy", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd))


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
        return ScanResult(False, "gitleaks", error="gitleaks not installed", elapsed=elapsed)

    findings = []
    output = None
    try:
        # Gitleaks returns exit code 1 when leaks found — that's success for us
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
        # Exit code 0 with no output = no leaks found
        if code == 0:
            return ScanResult(True, "gitleaks", output=[], findings=[],
                              elapsed=elapsed, command=" ".join(cmd))
        return ScanResult(False, "gitleaks", error=f"Parse error: {e}",
                          elapsed=elapsed, raw_output=stdout[:2000])

    return ScanResult(True, "gitleaks", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd))


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
        return ScanResult(False, "bandit", error="bandit not installed", elapsed=elapsed)

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
                              elapsed=elapsed, raw_output=stdout[:2000])

    return ScanResult(True, "bandit", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd))


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
        return ScanResult(False, "nuclei", error="nuclei not installed", elapsed=elapsed)

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
                      elapsed=elapsed, command=" ".join(cmd))


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
        return ScanResult(False, "osv-scanner", error="osv-scanner not installed", elapsed=elapsed)

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
                              elapsed=elapsed, raw_output=stdout[:2000])

    return ScanResult(True, "osv-scanner", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd))


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
        return ScanResult(False, "nmap", error="nmap not installed", elapsed=elapsed)

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
                          elapsed=elapsed, raw_output=stdout[:2000])

    return ScanResult(True, "nmap", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd))


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
        return ScanResult(False, "grype", error="grype not installed", elapsed=elapsed)

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
                              elapsed=elapsed, raw_output=stdout[:2000])

    return ScanResult(True, "grype", output=output, findings=findings,
                      elapsed=elapsed, command=" ".join(cmd))


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

# Maps scanner names to their runner functions
_SCANNER_MAP: dict[str, Callable[..., ScanResult]] = {
    "semgrep": run_semgrep,
    "trivy": run_trivy,
    "gitleaks": run_gitleaks,
    "nuclei": run_nuclei,
    "bandit": run_bandit,
    "osv-scanner": run_osv_scanner,
    "nmap": run_nmap,
    "grype": run_grype,
    "sarif": run_sarif_file,
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
