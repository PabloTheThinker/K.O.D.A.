"""Scanner provisioning for remote execution.

Two modes:

1. **Bring-your-own** — scanner already on remote PATH.  Detected via
   ``command -v <scanner>``.  This is the preferred path: no upload,
   no temp-dir residue, no permissions hassle.

2. **Upload static binary** — scanners that distribute as a single Go
   static binary can be ``scp``'d to ``/tmp/koda-<uuid>/bin/<name>`` and
   run there.  The local install must have the same binary on PATH (we
   copy the operator's own copy).  Deletion is handled by the executor's
   cleanup.

Not shippable (and why)
-----------------------
Some scanners cannot be auto-provisioned without leaving a footprint or
requiring root:

- **semgrep** — Python package, not a static binary.  Can't scp.
- **bandit**  — Python package.  Same reason.
- **nmap**    — C binary that may need root/capabilities; distro package
               is preferable; no universal static build.
- **falco**   — Needs a kernel module or eBPF probe; cannot run without
               kernel support that must already be present.
- **checkov** — Python package.
- **kics**    — Has a single static Go binary *in theory* but the
               official releases bundle a rules directory alongside the
               binary, so the lone binary is useless without it.  We skip
               it here; install via the official install script.
- **dependency_track** — HTTP server, not a CLI binary.

For these we emit a warning and return None.  The executor skips the
scanner with a human-readable message.
"""
from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Shippable scanners: set of tool names we CAN upload as a static binary.
# ---------------------------------------------------------------------------

#: These scanners ship as self-contained static Go binaries.
#: Key = scanner name; value = common binary name on local PATH.
_SHIPPABLE: dict[str, str] = {
    "trivy":       "trivy",
    "gitleaks":    "gitleaks",
    "nuclei":      "nuclei",
    "osv-scanner": "osv-scanner",
    "grype":       "grype",
}

#: Scanners that are NOT shippable — require pre-installation on the remote.
_NOT_SHIPPABLE: frozenset[str] = frozenset({
    "semgrep",
    "bandit",
    "nmap",
    "falco",
    "checkov",
    "kics",
    "dependency_track",
    "sarif",
})


@dataclass
class RemoteScannerRef:
    """Reference to a scanner that is available on the remote host.

    Attributes:
        name:         Scanner name (same key as in registry._SCANNER_MAP).
        remote_path:  Absolute path to the binary on the remote host.
                      May be just the name if it's on the remote PATH.
        was_uploaded: True if we uploaded the binary; False if it was
                      already present.
        sha256:       SHA-256 of the uploaded binary (empty if preinstalled).
        size:         Byte-size of the upload (0 if preinstalled).
    """
    name: str
    remote_path: str
    was_uploaded: bool = False
    sha256: str = ""
    size: int = 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ensure_scanner(
    session: object,
    name: str,
    remote_temp_dir: str,
    *,
    local_binary_path: str | None = None,
) -> RemoteScannerRef | None:
    """Ensure ``name`` is available on the remote host.

    Decision flow:

    1. ``command -v <name>`` — already on remote PATH → return ref (no upload).
    2. Scanner is not shippable (semgrep, bandit, nmap, …) → warn + return None.
    3. Scanner is shippable → locate local binary (``local_binary_path`` or
       ``shutil.which(name)``).  If not found locally → error + return None.
    4. ``scp`` the binary to ``<remote_temp_dir>/bin/<name>``.

    Args:
        session:           A connected :class:`~koda.remote.ssh.SSHSession`.
        name:              Scanner name (e.g. ``"trivy"``).
        remote_temp_dir:   Remote working directory (e.g. ``/tmp/koda-<uuid>``).
        local_binary_path: Override for the local binary path.  If None,
                           resolved via ``shutil.which(name)``.

    Returns:
        :class:`RemoteScannerRef` on success, or None if the scanner is
        unavailable and we couldn't (or chose not to) provision it.
    """
    # Step 1: already on remote PATH?
    stdout, _, rc = session.exec(f"command -v {name} 2>/dev/null")  # type: ignore[attr-defined]
    remote_bin = stdout.strip()
    if rc == 0 and remote_bin:
        return RemoteScannerRef(name=name, remote_path=remote_bin, was_uploaded=False)

    # Step 2: not shippable?
    if name in _NOT_SHIPPABLE:
        _warn_not_installable(name)
        return None

    # Step 3: shippable — find local binary.
    local_name = _SHIPPABLE.get(name, name)
    local_bin = local_binary_path or shutil.which(local_name)
    if not local_bin:
        import sys
        print(
            f"warning: {name}: not installed on remote and local binary "
            f"{local_name!r} not found — cannot auto-provision; "
            f"install {name} on the remote box or locally to enable upload.",
            file=sys.stderr,
        )
        return None

    # Step 4: upload.
    remote_bin_dir = f"{remote_temp_dir}/bin"
    session.exec(f"mkdir -p {remote_bin_dir}")  # type: ignore[attr-defined]
    remote_bin_path = f"{remote_bin_dir}/{name}"

    # Compute SHA-256 of local binary before upload.
    local_path = Path(local_bin)
    sha256, size = _hash_and_size(local_path)

    try:
        session.upload(local_bin, remote_bin_path, mode="0755")  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        import sys
        print(
            f"warning: {name}: upload failed ({exc}); skipping.",
            file=sys.stderr,
        )
        return None

    return RemoteScannerRef(
        name=name,
        remote_path=remote_bin_path,
        was_uploaded=True,
        sha256=sha256,
        size=size,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _warn_not_installable(name: str) -> None:
    import sys
    _reasons: dict[str, str] = {
        "semgrep":          "Python package — cannot scp",
        "bandit":           "Python package — cannot scp",
        "nmap":             "C binary that may need root/capabilities",
        "falco":            "requires kernel module / eBPF — must be pre-installed",
        "checkov":          "Python package — cannot scp",
        "kics":             "requires bundled rules directory alongside binary",
        "dependency_track": "HTTP server — configure via KODA_DTRACK_URL",
        "sarif":            "not a standalone scanner",
    }
    reason = _reasons.get(name, "not shippable")
    print(
        f"warning: {name} not installed on remote and cannot be "
        f"auto-provisioned ({reason}); "
        f"install it manually or use --scanner to select a different scanner.",
        file=sys.stderr,
    )


def _hash_and_size(path: Path) -> tuple[str, int]:
    """Return (sha256_hex, byte_size) for a local file."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size
