"""Remote OS / capability probing.

Runs a single compound command over the SSH session and parses the result
into a :class:`RemoteHost` dataclass that downstream code can consult for
provisioning and execution decisions.

The probe command is::

    uname -a; echo '---OS-RELEASE---'; cat /etc/os-release 2>/dev/null; \\
    echo '---ARCH---'; arch; echo '---PYTHON---'; command -v python3; \\
    echo '---SUDO---'; sudo -n true 2>/dev/null && echo yes || echo no

This is intentionally a single round-trip to minimise latency — the output
is parsed into named sections by ``---SECTION---`` delimiters.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RemoteHost:
    """Parsed capabilities of the remote box."""

    # Uname + os-release info
    uname: str = ""
    os_family: str = ""       # "debian" | "rhel" | "alpine" | "arch" | "unknown"
    os_id: str = ""           # Value of ID= in /etc/os-release  (e.g. "ubuntu")
    os_version: str = ""      # VERSION_ID from /etc/os-release
    arch: str = ""            # Output of arch(1), e.g. "x86_64" | "aarch64"

    # Available tooling
    has_python3: bool = False
    python3_path: str = ""
    pkg_manager: str = ""     # "apt" | "yum" | "dnf" | "apk" | "pacman" | ""
    has_sudo: bool = False    # True if passwordless sudo -n true succeeds

    # PATH-available scanners (populated by ensure_scanner, not here)
    available_scanners: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return (
            f"RemoteHost(os={self.os_id!r} {self.os_version!r}, "
            f"arch={self.arch!r}, python3={self.has_python3}, "
            f"pkg={self.pkg_manager!r}, sudo={self.has_sudo})"
        )


# ---------------------------------------------------------------------------
# Probe command builder
# ---------------------------------------------------------------------------

_PROBE_SCRIPT = (
    "uname -a; "
    "echo '---OS-RELEASE---'; "
    "cat /etc/os-release 2>/dev/null; "
    "echo '---ARCH---'; "
    "arch 2>/dev/null || uname -m; "
    "echo '---PYTHON---'; "
    "command -v python3 2>/dev/null || true; "
    "echo '---SUDO---'; "
    "sudo -n true 2>/dev/null && echo yes || echo no"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def probe_remote_os(session: object) -> RemoteHost:
    """Run the OS probe and return a :class:`RemoteHost`.

    Args:
        session: A connected :class:`~koda.remote.ssh.SSHSession`.

    Returns:
        Populated :class:`RemoteHost`.  Never raises — on parse failures
        the relevant fields default to empty / False.
    """
    stdout, _stderr, _rc = session.exec(_PROBE_SCRIPT)  # type: ignore[attr-defined]
    return _parse_probe_output(stdout)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_probe_output(output: str) -> RemoteHost:
    """Parse the multi-section probe output into a RemoteHost."""
    sections: dict[str, list[str]] = {
        "uname": [],
        "os_release": [],
        "arch": [],
        "python": [],
        "sudo": [],
    }

    _DELIMITERS = {
        "---OS-RELEASE---": "os_release",
        "---ARCH---": "arch",
        "---PYTHON---": "python",
        "---SUDO---": "sudo",
    }

    current_section = "uname"
    for line in output.splitlines():
        stripped = line.strip()
        if stripped in _DELIMITERS:
            current_section = _DELIMITERS[stripped]
            continue
        sections[current_section].append(stripped)

    host = RemoteHost()

    # uname
    host.uname = " ".join(sections["uname"]).strip()

    # /etc/os-release
    os_vars: dict[str, str] = {}
    for line in sections["os_release"]:
        if "=" in line:
            k, _, v = line.partition("=")
            os_vars[k.strip()] = v.strip().strip('"')

    host.os_id = os_vars.get("ID", "").lower()
    host.os_version = os_vars.get("VERSION_ID", "")
    host.os_family = _infer_os_family(host.os_id, os_vars)
    host.pkg_manager = _infer_pkg_manager(host.os_family, host.os_id)

    # arch
    arch_lines = [ln for ln in sections["arch"] if ln]
    host.arch = arch_lines[0] if arch_lines else ""

    # python3
    python_lines = [ln for ln in sections["python"] if ln]
    if python_lines:
        host.python3_path = python_lines[0]
        host.has_python3 = bool(host.python3_path)

    # sudo
    sudo_lines = [ln for ln in sections["sudo"] if ln]
    host.has_sudo = bool(sudo_lines and sudo_lines[0].lower() == "yes")

    return host


def _infer_os_family(os_id: str, os_vars: dict[str, str]) -> str:
    """Map os-release ID to a broad family name."""
    id_like = os_vars.get("ID_LIKE", "").lower()

    debian_ids = {"debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali"}
    rhel_ids = {"rhel", "centos", "fedora", "rocky", "almalinux", "ol",
                "amzn", "redhat"}
    alpine_ids = {"alpine"}
    arch_ids = {"arch", "manjaro", "endeavouros"}

    if os_id in debian_ids or "debian" in id_like:
        return "debian"
    if os_id in rhel_ids or "rhel" in id_like or "fedora" in id_like:
        return "rhel"
    if os_id in alpine_ids:
        return "alpine"
    if os_id in arch_ids or "arch" in id_like:
        return "arch"
    return "unknown"


def _infer_pkg_manager(os_family: str, os_id: str) -> str:
    """Best-guess primary package manager from OS family."""
    return {
        "debian": "apt",
        "rhel": "dnf" if os_id in {"fedora", "rhel"} else "yum",
        "alpine": "apk",
        "arch": "pacman",
    }.get(os_family, "")
