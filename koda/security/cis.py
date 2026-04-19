"""CIS-style baseline audit runner.

A minimal, stdlib-only harness that runs shell-level audit commands and
classifies their output against an expected value. It is deliberately not
a full CIS Benchmark implementation — it is the thin runtime the blue
hardening skill calls into.

Safety model:
  - every ``run_check`` call is time-bounded;
  - evidence is truncated (``_MAX_EVIDENCE`` bytes);
  - no exception ever escapes ``run_check``. A failed spawn returns a
    ``CISResult(passed=False, evidence="ERROR: ...")``;
  - commands are parsed with ``shlex.split`` and run with ``shell=False``
    whenever the command is representable as a single argv. Commands that
    contain shell metacharacters fall back to ``shell=True`` — use that
    sparingly in check definitions.
"""
from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass, field


_MAX_EVIDENCE = 2048


@dataclass(frozen=True)
class CISCheck:
    """A single CIS-style audit check."""
    id: str
    name: str
    profile: str
    scored: bool
    description: str
    rationale: str
    audit_cmd: str
    matcher: str       # "equal" | "contains" | "regex" | "empty" | "nonempty" | "exit_zero" | "exit_nonzero"
    expected: str = ""
    remediation: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CISResult:
    """Outcome of running a CISCheck."""
    check_id: str
    passed: bool
    actual: str
    expected: str
    evidence: str


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_SHELL_METACHARS = re.compile(r"[|&;<>()$`\\\"'*?\[\]{}]")


def _needs_shell(cmd: str) -> bool:
    """Return True when the command uses shell metacharacters."""
    return bool(_SHELL_METACHARS.search(cmd))


def _truncate(data: str) -> str:
    if len(data) <= _MAX_EVIDENCE:
        return data
    return data[:_MAX_EVIDENCE] + "\n...[truncated]"


def _evaluate(
    matcher: str,
    expected: str,
    stdout: str,
    returncode: int,
) -> tuple[bool, str]:
    """Return (passed, actual_summary)."""
    m = matcher.strip().lower()
    out = stdout.strip()
    if m == "equal":
        return (out == expected, out)
    if m == "contains":
        return (expected in stdout, out)
    if m == "regex":
        try:
            return (re.search(expected, stdout, re.MULTILINE) is not None, out)
        except re.error as e:
            return (False, f"bad regex: {e}")
    if m == "empty":
        return (out == "", out)
    if m == "nonempty":
        return (out != "", out)
    if m == "exit_zero":
        return (returncode == 0, f"exit={returncode}")
    if m == "exit_nonzero":
        return (returncode != 0, f"exit={returncode}")
    return (False, f"unknown matcher: {matcher}")


def run_check(check: CISCheck, *, timeout: float = 10.0) -> CISResult:
    """Execute a single check. Never raises."""
    cmd = check.audit_cmd
    try:
        if _needs_shell(cmd):
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        else:
            argv = shlex.split(cmd)
            proc = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        passed, actual = _evaluate(check.matcher, check.expected, stdout, proc.returncode)
        evidence_raw = stdout
        if stderr:
            evidence_raw = evidence_raw + "\n--- stderr ---\n" + stderr
        return CISResult(
            check_id=check.id,
            passed=passed,
            actual=actual,
            expected=check.expected,
            evidence=_truncate(evidence_raw),
        )
    except subprocess.TimeoutExpired:
        return CISResult(
            check_id=check.id,
            passed=False,
            actual="timeout",
            expected=check.expected,
            evidence=f"ERROR: timeout after {timeout}s",
        )
    except FileNotFoundError as e:
        return CISResult(
            check_id=check.id,
            passed=False,
            actual="missing",
            expected=check.expected,
            evidence=f"ERROR: {e}",
        )
    except Exception as e:  # noqa: BLE001 — never raise out of run_check
        return CISResult(
            check_id=check.id,
            passed=False,
            actual="error",
            expected=check.expected,
            evidence=f"ERROR: {e}",
        )


def run_profile(
    profile: list[CISCheck],
    *,
    timeout: float = 10.0,
) -> list[CISResult]:
    """Run every check in ``profile`` and return the results in order."""
    return [run_check(c, timeout=timeout) for c in profile]


# ---------------------------------------------------------------------------
# Bundled baselines
# ---------------------------------------------------------------------------

# Debian / Ubuntu Level 1 — a small, operational slice of CIS-style checks.
DEBIAN_UBUNTU_L1: tuple[CISCheck, ...] = (
    CISCheck(
        id="CIS-1.1.1",
        name="Ensure /etc/shadow permissions are 640 or stricter",
        profile="Level 1",
        scored=True,
        description="/etc/shadow holds password hashes; only root and shadow group may read.",
        rationale="World-readable hashes enable offline cracking.",
        audit_cmd="stat -c %a /etc/shadow",
        matcher="regex",
        expected=r"^(0?(640|600|400|000))$",
        remediation="chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
    ),
    CISCheck(
        id="CIS-1.1.2",
        name="Ensure /etc/passwd is 644 and owned by root:root",
        profile="Level 1",
        scored=True,
        description="Verify /etc/passwd permissions.",
        rationale="Incorrect permissions expose account metadata or enable tampering.",
        audit_cmd="stat -c '%a %U:%G' /etc/passwd",
        matcher="equal",
        expected="644 root:root",
        remediation="chmod 644 /etc/passwd && chown root:root /etc/passwd",
    ),
    CISCheck(
        id="CIS-1.1.3",
        name="Ensure /etc/group is 644 and owned by root:root",
        profile="Level 1",
        scored=True,
        description="Verify /etc/group permissions.",
        rationale="Prevent group-membership tampering.",
        audit_cmd="stat -c '%a %U:%G' /etc/group",
        matcher="equal",
        expected="644 root:root",
        remediation="chmod 644 /etc/group && chown root:root /etc/group",
    ),
    CISCheck(
        id="CIS-2.1.1",
        name="Ensure SSH PermitRootLogin is no",
        profile="Level 1",
        scored=True,
        description="Root SSH login must be disabled.",
        rationale="Forces attackers to guess both a username and a password.",
        audit_cmd="sshd -T 2>/dev/null | grep -i '^permitrootlogin'",
        matcher="regex",
        expected=r"(?i)^permitrootlogin\s+no",
        remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.",
    ),
    CISCheck(
        id="CIS-2.1.2",
        name="Ensure SSH PasswordAuthentication is no",
        profile="Level 1",
        scored=True,
        description="Password auth over SSH must be disabled.",
        rationale="Keys only defeats credential-spray and phishing attacks.",
        audit_cmd="sshd -T 2>/dev/null | grep -i '^passwordauthentication'",
        matcher="regex",
        expected=r"(?i)^passwordauthentication\s+no",
        remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config.",
    ),
    CISCheck(
        id="CIS-2.1.3",
        name="Ensure SSH Protocol is 2",
        profile="Level 1",
        scored=True,
        description="Only SSH protocol 2 is acceptable.",
        rationale="Protocol 1 has cryptographic weaknesses.",
        audit_cmd="sshd -T 2>/dev/null | grep -i '^protocol'",
        matcher="regex",
        expected=r"(?i)^protocol\s+2",
        remediation="Ensure 'Protocol 2' in /etc/ssh/sshd_config.",
    ),
    CISCheck(
        id="CIS-3.1.1",
        name="Ensure UFW is enabled",
        profile="Level 1",
        scored=True,
        description="A host firewall must be active.",
        rationale="Defense in depth against lateral-movement attempts.",
        audit_cmd="ufw status",
        matcher="contains",
        expected="Status: active",
        remediation="ufw enable",
    ),
    CISCheck(
        id="CIS-4.1.1",
        name="Ensure auditd is active",
        profile="Level 1",
        scored=True,
        description="auditd must be running to collect security-relevant events.",
        rationale="Without auditd, incident reconstruction is impossible.",
        audit_cmd="systemctl is-active auditd",
        matcher="equal",
        expected="active",
        remediation="systemctl enable --now auditd",
    ),
    CISCheck(
        id="CIS-4.2.1",
        name="Ensure rsyslog is active",
        profile="Level 1",
        scored=True,
        description="rsyslog must forward logs for tamper-evident storage.",
        rationale="Local logs can be wiped; central logs are your evidence.",
        audit_cmd="systemctl is-active rsyslog",
        matcher="equal",
        expected="active",
        remediation="systemctl enable --now rsyslog",
    ),
    CISCheck(
        id="CIS-5.1.1",
        name="Ensure /etc/crontab is mode 600",
        profile="Level 1",
        scored=True,
        description="Crontab must not be world- or group-readable.",
        rationale="Cron jobs frequently encode secrets; restrict access.",
        audit_cmd="stat -c %a /etc/crontab",
        matcher="regex",
        expected=r"^(0?600)$",
        remediation="chmod 600 /etc/crontab",
    ),
    CISCheck(
        id="CIS-5.2.1",
        name="Ensure sudo Defaults use_pty is set",
        profile="Level 1",
        scored=True,
        description="sudo must allocate a PTY to prevent input-injection.",
        rationale="Mitigates CVE-2017-1000367 class bugs and session hijacking.",
        audit_cmd="grep -E '^[^#]*Defaults.*use_pty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
        matcher="contains",
        expected="use_pty",
        remediation="Add 'Defaults use_pty' to /etc/sudoers (via visudo).",
    ),
    CISCheck(
        id="CIS-5.2.2",
        name="Ensure sudo logfile is configured",
        profile="Level 1",
        scored=True,
        description="sudo must write an audit logfile.",
        rationale="Separate sudo log is a first-class forensic artifact.",
        audit_cmd="grep -E '^[^#]*Defaults.*logfile' /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
        matcher="contains",
        expected="logfile",
        remediation="Add 'Defaults logfile=\"/var/log/sudo.log\"' to /etc/sudoers.",
    ),
    CISCheck(
        id="CIS-6.1.1",
        name="Ensure kernel ASLR is enabled (randomize_va_space=2)",
        profile="Level 1",
        scored=True,
        description="Full ASLR must be enabled.",
        rationale="Defeats return-to-libc and common memory-corruption exploits.",
        audit_cmd="sysctl -n kernel.randomize_va_space",
        matcher="equal",
        expected="2",
        remediation="sysctl -w kernel.randomize_va_space=2 and persist in /etc/sysctl.d/",
    ),
    CISCheck(
        id="CIS-6.1.2",
        name="Ensure IP forwarding is disabled (net.ipv4.ip_forward=0)",
        profile="Level 1",
        scored=True,
        description="Non-routers must not forward IP traffic.",
        rationale="Prevents the host from being used as a pivot.",
        audit_cmd="sysctl -n net.ipv4.ip_forward",
        matcher="equal",
        expected="0",
        remediation="sysctl -w net.ipv4.ip_forward=0 and persist.",
    ),
    CISCheck(
        id="CIS-6.1.3",
        name="Ensure TCP SYN cookies are enabled",
        profile="Level 1",
        scored=True,
        description="net.ipv4.tcp_syncookies must be 1.",
        rationale="Mitigates SYN-flood denial-of-service.",
        audit_cmd="sysctl -n net.ipv4.tcp_syncookies",
        matcher="equal",
        expected="1",
        remediation="sysctl -w net.ipv4.tcp_syncookies=1 and persist.",
    ),
    CISCheck(
        id="CIS-6.1.4",
        name="Ensure suid core dumps are restricted (fs.suid_dumpable=0)",
        profile="Level 1",
        scored=True,
        description="Suid binaries must not produce core dumps.",
        rationale="Prevents credential leakage via core files.",
        audit_cmd="sysctl -n fs.suid_dumpable",
        matcher="equal",
        expected="0",
        remediation="sysctl -w fs.suid_dumpable=0 and persist.",
    ),
    CISCheck(
        id="CIS-7.1.1",
        name="Ensure cramfs filesystem is disabled",
        profile="Level 1",
        scored=False,
        description="Unused legacy filesystems should be blacklisted.",
        rationale="Reduces attack surface against kernel fs parsers.",
        audit_cmd="modprobe -n -v cramfs 2>&1",
        matcher="contains",
        expected="install /bin/true",
        remediation="echo 'install cramfs /bin/true' > /etc/modprobe.d/cramfs.conf",
    ),
    CISCheck(
        id="CIS-7.2.1",
        name="Ensure /tmp is mounted with nodev,nosuid,noexec",
        profile="Level 1",
        scored=True,
        description="/tmp must be mounted with restrictive flags.",
        rationale="Blocks common staging/launch patterns for implants.",
        audit_cmd="findmnt -n /tmp",
        matcher="regex",
        expected=r"nodev.*nosuid.*noexec|nosuid.*nodev.*noexec",
        remediation="Remount /tmp with the flags (fstab entry).",
    ),
)


# Generic Linux Level 1 — a smaller, distro-agnostic slice.
GENERIC_LINUX_L1: tuple[CISCheck, ...] = (
    CISCheck(
        id="LNX-1.1",
        name="Ensure /etc/shadow exists and is root-owned",
        profile="Level 1",
        scored=True,
        description="/etc/shadow must exist and be owned by root.",
        rationale="Shadow file is the authoritative password store.",
        audit_cmd="stat -c '%U' /etc/shadow",
        matcher="equal",
        expected="root",
        remediation="chown root /etc/shadow",
    ),
    CISCheck(
        id="LNX-1.2",
        name="Ensure core dumps are restricted (soft nofile)",
        profile="Level 1",
        scored=False,
        description="Core dumps must be disabled for privileged users.",
        rationale="Prevents credential leakage via core files.",
        audit_cmd="grep -E '^\\*.*hard.*core' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null",
        matcher="nonempty",
        remediation="Add '* hard core 0' to /etc/security/limits.conf.",
    ),
    CISCheck(
        id="LNX-2.1",
        name="Ensure kernel.randomize_va_space is 2",
        profile="Level 1",
        scored=True,
        description="Full ASLR.",
        rationale="Defense against memory-corruption exploits.",
        audit_cmd="sysctl -n kernel.randomize_va_space",
        matcher="equal",
        expected="2",
        remediation="sysctl -w kernel.randomize_va_space=2",
    ),
    CISCheck(
        id="LNX-2.2",
        name="Ensure net.ipv4.conf.all.rp_filter=1",
        profile="Level 1",
        scored=True,
        description="Reverse-path filtering must be enabled.",
        rationale="Rejects spoofed source addresses.",
        audit_cmd="sysctl -n net.ipv4.conf.all.rp_filter",
        matcher="equal",
        expected="1",
        remediation="sysctl -w net.ipv4.conf.all.rp_filter=1",
    ),
    CISCheck(
        id="LNX-2.3",
        name="Ensure net.ipv4.conf.all.accept_source_route=0",
        profile="Level 1",
        scored=True,
        description="Source-routed packets must be dropped.",
        rationale="Mitigates trust-relationship spoofing.",
        audit_cmd="sysctl -n net.ipv4.conf.all.accept_source_route",
        matcher="equal",
        expected="0",
        remediation="sysctl -w net.ipv4.conf.all.accept_source_route=0",
    ),
    CISCheck(
        id="LNX-3.1",
        name="Ensure SSH is not running as root-only password auth",
        profile="Level 1",
        scored=True,
        description="Reject a common insecure combination.",
        rationale="Password root SSH is a top initial-access vector.",
        audit_cmd="sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication)'",
        matcher="regex",
        expected=r"(?i)(permitrootlogin\s+no|passwordauthentication\s+no)",
        remediation="Disable root login and/or password auth in sshd_config.",
    ),
    CISCheck(
        id="LNX-4.1",
        name="Ensure auditd binary is present",
        profile="Level 1",
        scored=False,
        description="auditd must be installed.",
        rationale="Without it, no incident telemetry.",
        audit_cmd="command -v auditd",
        matcher="nonempty",
        remediation="Install auditd from the distro package manager.",
    ),
    CISCheck(
        id="LNX-4.2",
        name="Ensure rsyslog binary is present",
        profile="Level 1",
        scored=False,
        description="rsyslog must be installed.",
        rationale="Log shipping is non-negotiable.",
        audit_cmd="command -v rsyslogd",
        matcher="nonempty",
        remediation="Install rsyslog from the distro package manager.",
    ),
    CISCheck(
        id="LNX-5.1",
        name="Ensure cron daemon is active (cron or crond)",
        profile="Level 1",
        scored=False,
        description="A cron daemon must be running.",
        rationale="Scheduled hardening tasks depend on it.",
        audit_cmd="systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null",
        matcher="contains",
        expected="active",
        remediation="systemctl enable --now cron (or crond)",
    ),
    CISCheck(
        id="LNX-5.2",
        name="Ensure /var/log is not world-writable",
        profile="Level 1",
        scored=True,
        description="/var/log must not be world-writable.",
        rationale="World-writable log dir enables log tampering.",
        audit_cmd="find /var/log -maxdepth 0 -perm -0002",
        matcher="empty",
        remediation="chmod o-w /var/log",
    ),
)


__all__ = [
    "CISCheck",
    "CISResult",
    "run_check",
    "run_profile",
    "DEBIAN_UBUNTU_L1",
    "GENERIC_LINUX_L1",
]
