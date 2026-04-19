"""SSH transport for remote scanning.

Uses the system's ``ssh``/``scp`` binaries via subprocess. Never imports
paramiko, fabric, or pexpect — zero new hard dependencies.

ControlMaster strategy
----------------------
On ``connect()`` we open a single master SSH connection with:

    -o ControlMaster=auto
    -o ControlPath=~/.ssh/cm-<host>-<pid>
    -o ControlPersist=10m    ← keeps the socket alive for 10 min
    -fNT                     ← fork into background, no tty, no command

Every subsequent ``exec()`` / ``upload()`` reuses the same socket via:

    -o ControlMaster=no
    -o ControlPath=<same socket>

ControlPersist=10m was chosen deliberately:
  - Enough headroom so a slow scanner run (Trivy DB pull, large nuclei sweep)
    doesn't disconnect the master mid-scan.
  - Not "yes" (infinite) — the master exits automatically after all clients
    disconnect even without an explicit cleanup call. Belt-and-suspenders.
  - We still call ``cleanup()`` explicitly (``-O exit``) at the end of each
    run so the socket is reaped promptly and doesn't sit around.

Socket path: ``~/.ssh/cm-koda-<hostname>-<pid>`` where ``<pid>`` is the
controlling process's PID so concurrent koda invocations don't share or
race on the same socket.

sudo handling
-------------
If ``sudo=True`` the executor first probes passwordless sudo
(``sudo -n true``).  If that succeeds, every command is prefixed with
``sudo -n``.  If it fails, ``getpass.getpass()`` prompts the operator
once; the password is piped to ``sudo -S`` via stdin only — it is never
written to disk, never emitted in audit or log output, and never included
in the list of args passed to audit events.

Password redaction pattern: any time we format the ``args`` field for an
audit event we replace the actual sudo stdin content with the literal
string ``<REDACTED>``.  The flag ``_has_sudo_password`` on this class
signals callers to apply that redaction.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any


class SSHError(RuntimeError):
    """Raised for unrecoverable SSH transport failures."""


class SSHSession:
    """Multiplexed OpenSSH session using ControlMaster.

    Usage::

        with SSHSession("user@host") as session:
            stdout, stderr, rc = session.exec("uname -a")
            session.upload("/local/bin/trivy", "/tmp/koda-abc/bin/trivy")
    """

    def __init__(
        self,
        target: str,
        *,
        port: int | None = None,
        control_persist: str = "10m",
        ssh_executable: str = "ssh",
        scp_executable: str = "scp",
        connect_timeout: int = 15,
    ) -> None:
        """Initialise session parameters (does NOT connect yet).

        Args:
            target:          SSH target — ``user@host``, ``host``, or
                             a ``~/.ssh/config`` alias.  If the target
                             contains ``user@host:port`` syntax the port
                             is parsed out.
            port:            Explicit port override.
            control_persist: Value for ``ControlPersist``  (default ``10m``).
            ssh_executable:  Path or name of the ``ssh`` binary.
            scp_executable:  Path or name of the ``scp`` binary.
            connect_timeout: Seconds for the initial ``ConnectTimeout``.
        """
        self.target, self._port = _parse_target(target, port)
        self.control_persist = control_persist
        self._ssh_exe = ssh_executable
        self._scp_exe = scp_executable
        self._connect_timeout = connect_timeout

        pid = os.getpid()
        # Extract just the host part for the socket name.
        host_part = self.target.split("@")[-1].split(":")[0]
        self._socket_path = str(
            Path.home() / ".ssh" / f"cm-koda-{host_part}-{pid}"
        )

        self._connected = False
        self._sudo_password: str | None = None  # never logged
        self.has_sudo_password: bool = False      # set by executor after prompt

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> SSHSession:
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.cleanup()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open the ControlMaster background SSH socket.

        Idempotent — calling connect() a second time on an already-connected
        session is a no-op.
        """
        if self._connected:
            return

        cmd = [
            self._ssh_exe,
            *self._port_flags(),
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={self._socket_path}",
            "-o", f"ControlPersist={self.control_persist}",
            "-o", f"ConnectTimeout={self._connect_timeout}",
            "-o", "BatchMode=yes",
            "-fNT",           # fork into background, no tty, no command
            self.target,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SSHError(
                f"SSH ControlMaster connect to {self.target!r} failed "
                f"(rc={result.returncode}): {result.stderr.strip()}"
            )
        self._connected = True

    def cleanup(self) -> None:
        """Close the ControlMaster socket gracefully.

        Never raises — cleanup is always called from a ``finally`` block
        and a crash here would shadow the real exception.
        """
        if not self._connected:
            return
        try:
            subprocess.run(
                [
                    self._ssh_exe,
                    *self._port_flags(),
                    "-o", "ControlMaster=no",
                    "-o", f"ControlPath={self._socket_path}",
                    "-O", "exit",
                    self.target,
                ],
                capture_output=True,
                timeout=10,
            )
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._connected = False
            self._sudo_password = None
            # Best-effort socket file removal.
            try:
                Path(self._socket_path).unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Remote execution
    # ------------------------------------------------------------------

    def exec(
        self,
        cmd: str,
        *,
        timeout: int = 300,
        sudo: bool = False,
    ) -> tuple[str, str, int]:
        """Execute a shell command on the remote host.

        Reuses the existing ControlMaster socket — only ONE SSH handshake
        happens per SSHSession lifetime (in ``connect()``).

        Args:
            cmd:     Shell command string (run via ``sh -c``).
            timeout: Subprocess timeout in seconds.
            sudo:    If True, prepend sudo.  Uses passwordless sudo if
                     available; otherwise pipes the stored password via
                     ``sudo -S``.  Password never appears in return values.

        Returns:
            (stdout, stderr, exit_code)
        """
        remote_cmd = self._wrap_sudo(cmd) if sudo else cmd

        ssh_cmd = [
            self._ssh_exe,
            *self._port_flags(),
            "-o", "ControlMaster=no",
            "-o", f"ControlPath={self._socket_path}",
            "-o", "BatchMode=yes",
            self.target,
            remote_cmd,
        ]

        if sudo and self._sudo_password is not None:
            # Pipe password via stdin to sudo -S
            result = subprocess.run(
                ssh_cmd,
                input=self._sudo_password + "\n",
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        else:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

        return result.stdout, result.stderr, result.returncode

    # ------------------------------------------------------------------
    # File upload
    # ------------------------------------------------------------------

    def upload(
        self,
        local_path: str,
        remote_path: str,
        *,
        mode: str = "0755",
    ) -> None:
        """Upload a local file to the remote host via scp.

        Uses the existing ControlMaster socket for zero-handshake upload.

        Args:
            local_path:  Absolute path to the local file.
            remote_path: Destination path on the remote host.
            mode:        chmod value to apply after upload (octal string).
        """
        # scp reuses the ControlMaster socket when given the same ControlPath.
        scp_cmd = [
            self._scp_exe,
            *self._scp_port_flags(),
            "-o", "ControlMaster=no",
            "-o", f"ControlPath={self._socket_path}",
            local_path,
            f"{self.target}:{remote_path}",
        ]
        result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise SSHError(
                f"scp upload failed for {local_path!r} -> {remote_path!r}: "
                f"{result.stderr.strip()}"
            )
        # Apply permissions.
        self.exec(f"chmod {mode} {remote_path}")

    # ------------------------------------------------------------------
    # sudo password management
    # ------------------------------------------------------------------

    def set_sudo_password(self, password: str) -> None:
        """Store the sudo password in memory only.

        Never written to disk.  Never included in audit event fields.
        Call this ONLY from ``executor.py`` after obtaining via
        ``getpass.getpass()``.
        """
        self._sudo_password = password
        self.has_sudo_password = True

    def probe_passwordless_sudo(self) -> bool:
        """Check if passwordless sudo is available on the remote host.

        Returns True if ``sudo -n true`` succeeds, False otherwise.
        """
        _, _, rc = self.exec("sudo -n true")
        return rc == 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _port_flags(self) -> list[str]:
        if self._port:
            return ["-p", str(self._port)]
        return []

    def _scp_port_flags(self) -> list[str]:
        if self._port:
            return ["-P", str(self._port)]  # scp uses -P (uppercase)
        return []

    def _wrap_sudo(self, cmd: str) -> str:
        """Return sudo-prefixed command string.

        Prefers passwordless sudo (``-n``).  Falls back to ``sudo -S``
        when a password has been stored.  Password is piped via stdin
        in ``exec()`` — never embedded in the command string itself.
        """
        if self._sudo_password is not None:
            # sudo -S reads password from stdin.  We pass it via Popen.stdin.
            return f"sudo -S {cmd}"
        return f"sudo -n {cmd}"

    @property
    def socket_path(self) -> str:
        """Path to the ControlMaster socket (for audit events)."""
        return self._socket_path

    @property
    def connected(self) -> bool:
        return self._connected


# ---------------------------------------------------------------------------
# Target parsing helper
# ---------------------------------------------------------------------------

def _parse_target(target: str, port_override: int | None) -> tuple[str, int | None]:
    """Split ``user@host:port`` into ``(user@host, port)``.

    Returns (target_without_port, port_or_None).
    Handles:
      - ``host``
      - ``user@host``
      - ``user@host:port``
    """
    port: int | None = port_override

    # Check for user@host:port form.
    if ":" in target:
        parts = target.rsplit(":", 1)
        try:
            port_candidate = int(parts[1])
            target = parts[0]
            if port is None:
                port = port_candidate
        except ValueError:
            pass  # Not a port suffix — treat as-is.

    return target, port
