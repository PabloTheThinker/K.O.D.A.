"""koda.remote — SSH-based remote scanning transport.

Provides the infrastructure for running K.O.D.A. scanners against remote
boxes over standard OpenSSH (system ``ssh``/``scp`` binaries — no paramiko).

Public API
----------
SSHSession   — connect, exec, upload, cleanup (ControlMaster multiplexing)
RemoteHost   — dataclass returned by probe_remote_os()
RemoteScannerRef — dataclass returned by ensure_scanner()
probe_remote_os  — OS / arch / capability detection
ensure_scanner   — bring-your-own or upload-static-binary logic
run_remote_scan  — orchestrate probe + provision + run + pull + parse
"""
from .executor import run_remote_scan
from .probe import RemoteHost, probe_remote_os
from .provision import RemoteScannerRef, ensure_scanner
from .ssh import SSHSession

__all__ = [
    "SSHSession",
    "RemoteHost",
    "probe_remote_os",
    "RemoteScannerRef",
    "ensure_scanner",
    "run_remote_scan",
]
