"""Remote scan orchestrator.

Ties together: probe → provision → approval → run → pull → parse → store.

The approval gate is called locally (on the operator's box) before each
scanner dispatch — the remote box is an untrusted scan target, not a
trusted execution environment.  Every scanner invocation still clears the
same guardrails and risk-tier policy as a local scan.

Audit events emitted
--------------------
- ``scan.remote.connect``  — after ControlMaster established
- ``scan.remote.upload``   — for each binary uploaded (not preinstalled)
- ``scan.remote.run``      — for each scanner executed (args REDACTED of sudo pw)
- ``scan.remote.pull``     — for each result set received (stdout capture)
- ``scan.remote.cleanup``  — at end of run
"""
from __future__ import annotations

import getpass
import time
import uuid
from typing import Any

from ..audit import AuditLogger, NullAuditLogger
from ..security.scanners.registry import _SCANNER_MAP, ScanResult, replay_run_cmd
from .probe import probe_remote_os
from .provision import ensure_scanner
from .ssh import SSHSession

# ---------------------------------------------------------------------------
# Scanner commands — how each tool is invoked on the remote box
# ---------------------------------------------------------------------------

def _build_remote_cmd(
    scanner_name: str,
    binary_path: str,
    remote_target: str,
    *,
    use_sudo: bool = False,
) -> str:
    """Build the shell command to run a scanner on the remote host.

    Args:
        scanner_name:   Name key (e.g. "trivy", "gitleaks").
        binary_path:    Absolute remote path or just the name if on PATH.
        remote_target:  The filesystem path or URL to scan on the remote.
        use_sudo:       Prefix with sudo.

    Returns:
        A shell command string ready to pass to :meth:`SSHSession.exec`.
    """
    sudo_prefix = "sudo -n " if use_sudo else ""

    _CMD_TEMPLATES: dict[str, str] = {
        "trivy":
            "{sudo}{bin} fs --format json --quiet {target}",
        "gitleaks":
            "{sudo}{bin} detect --source {target} "
            "--report-format json --report-path /dev/stdout --no-banner",
        "nuclei":
            "{sudo}{bin} -target {target} -jsonl -silent",
        "osv-scanner":
            "{sudo}{bin} --format json {target}",
        "grype":
            "{sudo}{bin} {target} -o json",
        "semgrep":
            "{sudo}{bin} scan --json --config auto {target}",
        "bandit":
            "{sudo}{bin} -r -f json {target}",
        "nmap":
            "{sudo}{bin} -oX - -p 1-1000 {target}",
        "checkov":
            "{sudo}{bin} -d {target} -o json --quiet",
        "kics":
            "{sudo}{bin} scan -p {target} --report-formats json "
            "--output-path /dev/stdout --no-progress",
        "falco":
            "{sudo}{bin} -e {target} -o json_output=true "
            "-o json_include_output_property=true",
    }

    template = _CMD_TEMPLATES.get(scanner_name)
    if template is None:
        # Generic fallback: run binary with target as positional arg.
        template = "{sudo}{bin} {target}"

    return template.format(sudo=sudo_prefix, bin=binary_path, target=remote_target)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_remote_scan(
    ssh_target: str,
    remote_target: str,
    scanner_names: list[str],
    *,
    port: int | None = None,
    use_sudo: bool = False,
    keep_temp: bool = False,
    engagement: str = "",
    audit: AuditLogger | NullAuditLogger | None = None,
    approvals: Any = None,
    scan_timeout: int = 300,
) -> list[ScanResult]:
    """Run one or more scanners against a remote host.

    Args:
        ssh_target:     SSH target (``user@host``, ``host``, alias, or
                        ``user@host:port``).
        remote_target:  Path or URL to scan *on the remote box* (e.g.
                        ``/srv/app``, ``192.168.1.1``).
        scanner_names:  List of scanner names to run.
        port:           Optional SSH port override.
        use_sudo:       If True, elevate scanner commands with sudo.
        keep_temp:      If True, leave ``/tmp/koda-<uuid>`` in place.
        engagement:     Engagement tag for audit events.
        audit:          Audit logger (NullAuditLogger if not provided).
        approvals:      ApprovalPolicy instance (skipped if None).
        scan_timeout:   Per-scanner timeout in seconds.

    Returns:
        List of :class:`~koda.security.scanners.registry.ScanResult`.
    """
    if audit is None:
        audit = NullAuditLogger()

    run_id = uuid.uuid4().hex[:8]
    remote_temp_dir = f"/tmp/koda-{run_id}"
    results: list[ScanResult] = []

    session = SSHSession(ssh_target, port=port)
    try:
        # ── Connect ──────────────────────────────────────────────────
        session.connect()
        audit.emit(
            "scan.remote.connect",
            engagement=engagement,
            target=ssh_target,
            control_socket_path=session.socket_path,
        )

        # ── sudo setup ───────────────────────────────────────────────
        sudo_available = False
        if use_sudo:
            sudo_available = _setup_sudo(session, audit=audit, engagement=engagement)

        # ── OS probe (one round-trip) ────────────────────────────────
        remote_host = probe_remote_os(session)
        audit.emit(
            "scan.remote.connect",  # update with OS probe result
            engagement=engagement,
            target=ssh_target,
            control_socket_path=session.socket_path,
            os_probe_result=str(remote_host),
        )

        # ── Create temp dir ──────────────────────────────────────────
        session.exec(f"mkdir -p {remote_temp_dir}/bin")

        # ── Per-scanner loop ─────────────────────────────────────────
        for scanner_name in scanner_names:
            result = _run_one_scanner(
                session=session,
                scanner_name=scanner_name,
                remote_target=remote_target,
                remote_temp_dir=remote_temp_dir,
                use_sudo=use_sudo and sudo_available,
                engagement=engagement,
                audit=audit,
                approvals=approvals,
                scan_timeout=scan_timeout,
            )
            if result is not None:
                results.append(result)

    finally:
        # ── Cleanup ───────────────────────────────────────────────────
        kept = keep_temp
        if not keep_temp:
            try:
                session.exec(f"rm -rf {remote_temp_dir}")
            except Exception:  # noqa: BLE001
                pass

        audit.emit(
            "scan.remote.cleanup",
            engagement=engagement,
            target=ssh_target,
            temp_dir=remote_temp_dir,
            kept=kept,
        )
        session.cleanup()

    return results


# ---------------------------------------------------------------------------
# Per-scanner execution
# ---------------------------------------------------------------------------

def _run_one_scanner(
    *,
    session: SSHSession,
    scanner_name: str,
    remote_target: str,
    remote_temp_dir: str,
    use_sudo: bool,
    engagement: str,
    audit: Any,
    approvals: Any,
    scan_timeout: int,
) -> ScanResult | None:
    """Provision + run a single scanner on the remote host.

    Returns a ScanResult on success, None if the scanner is unavailable.
    """
    # ── Approval gate (local) ────────────────────────────────────────
    if approvals is not None:
        import asyncio

        from ..tools.approval import ApprovalRequest
        from ..tools.registry import RiskLevel

        req = ApprovalRequest(
            tool_name=f"scan.remote.{scanner_name}",
            arguments={"target": remote_target, "ssh_target": session.target},
            risk=RiskLevel.SENSITIVE,
            engagement=engagement,
        )
        try:
            loop = asyncio.get_event_loop()
            allowed = loop.run_until_complete(approvals.decide(req))
        except RuntimeError:
            allowed = asyncio.run(approvals.decide(req))
        if not allowed:
            return ScanResult(
                success=False,
                scanner=scanner_name,
                error=f"Remote scan of {scanner_name!r} denied by approval gate",
            )

    # ── Provision ────────────────────────────────────────────────────
    ref = ensure_scanner(session, scanner_name, remote_temp_dir)
    if ref is None:
        # ensure_scanner already printed a warning.
        return None

    if ref.was_uploaded:
        audit.emit(
            "scan.remote.upload",
            engagement=engagement,
            scanner=scanner_name,
            remote_path=ref.remote_path,
            bytes=ref.size,
            sha256=ref.sha256,
        )

    # ── Build command ────────────────────────────────────────────────
    remote_cmd = _build_remote_cmd(
        scanner_name,
        ref.remote_path,
        remote_target,
        use_sudo=use_sudo,
    )

    # Audit args — never include sudo password
    audit_args = remote_cmd
    if session.has_sudo_password:
        audit_args = audit_args.replace("sudo -S ", "sudo [REDACTED] ")

    t_start = time.monotonic()

    # ── Execute ──────────────────────────────────────────────────────
    stdout, stderr, rc = session.exec(remote_cmd, timeout=scan_timeout)
    duration_ms = int((time.monotonic() - t_start) * 1000)

    audit.emit(
        "scan.remote.run",
        engagement=engagement,
        scanner=scanner_name,
        target=session.target,
        args=audit_args,
        exit_code=rc,
        duration_ms=duration_ms,
    )

    # ── Pull / parse ─────────────────────────────────────────────────
    bytes_pulled = len(stdout.encode("utf-8"))
    audit.emit(
        "scan.remote.pull",
        engagement=engagement,
        scanner=scanner_name,
        bytes=bytes_pulled,
    )

    # ── Delegate parsing to local scanner runner ─────────────────────
    # We inject the remote stdout as if it came from a local invocation
    # by monkey-patching _run_cmd for the duration of one parse call.
    result = _parse_remote_output(scanner_name, stdout, stderr, rc)
    return result


def _parse_remote_output(
    scanner_name: str,
    stdout: str,
    stderr: str,
    exit_code: int,
) -> ScanResult:
    """Parse scanner stdout locally using the existing registry parsers.

    Replays the captured remote output through the same parser a local
    invocation would use, via the registry's :func:`replay_run_cmd`
    ContextVar override. No subprocess is spawned.
    """
    runner = _SCANNER_MAP.get(scanner_name)
    if runner is None:
        return ScanResult(
            success=False,
            scanner=scanner_name,
            error=f"No local parser for scanner {scanner_name!r}",
        )
    with replay_run_cmd(stdout, stderr, exit_code):
        try:
            return runner("/dev/null")  # target arg unused — _run_cmd is overridden
        except Exception as exc:  # noqa: BLE001
            return ScanResult(
                success=False,
                scanner=scanner_name,
                error=f"Parse error: {exc}",
            )


# ---------------------------------------------------------------------------
# sudo setup helper
# ---------------------------------------------------------------------------

def _setup_sudo(
    session: SSHSession,
    *,
    audit: Any,
    engagement: str,
) -> bool:
    """Configure sudo for the session.

    Returns True if sudo will work (passwordless or password supplied).
    Returns False if the operator declined to provide a password.

    Password is never logged or emitted in audit events.
    """
    if session.probe_passwordless_sudo():
        audit.emit(
            "scan.remote.sudo",
            engagement=engagement,
            target=session.target,
            mode="passwordless",
        )
        return True

    # Need a password — prompt once.
    import sys
    print(
        f"sudo -n failed on {session.target!r}. "
        "Enter sudo password (will not be stored):",
        file=sys.stderr,
    )
    try:
        password = getpass.getpass(prompt="sudo password: ")
    except (KeyboardInterrupt, EOFError):
        print("\n[sudo password prompt cancelled]", file=sys.stderr)
        return False

    if not password:
        return False

    session.set_sudo_password(password)
    audit.emit(
        "scan.remote.sudo",
        engagement=engagement,
        target=session.target,
        mode="password_provided",
        # deliberately NOT logging the password — just the mode
    )
    return True
