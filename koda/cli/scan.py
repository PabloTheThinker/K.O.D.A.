"""``koda scan`` subcommand dispatcher.

Subcommands:
  koda scan local <target> [--scanner NAME]... [--preset NAME]
  koda scan remote <ssh-target> [--target PATH] [--preset NAME]
             [--scanner NAME]... [--sudo] [--keep-temp] [--engagement NAME]
             [--port PORT]

The ``scan remote`` path runs scanners against a remote box over SSH using
ControlMaster multiplexing.  No agent or daemon is installed on the remote;
binaries that ship as static Go binaries are uploaded to a temporary
directory and removed afterwards.

Preset loading
--------------
``--preset`` lazily imports ``koda.missions.get(name)`` so this module
works even when the missions agent hasn't shipped yet.  If the module is
absent, a ``--scanner`` argument is required.
"""
from __future__ import annotations

import sys
from typing import Any

# ---------------------------------------------------------------------------
# Preset loader (lazy, tolerant of missing module)
# ---------------------------------------------------------------------------

def _load_preset(name: str) -> list[str]:
    """Return scanner list from a named mission preset.

    If ``koda.missions`` doesn't exist yet, raises ImportError with a
    human-friendly message so the caller can fall back to ``--scanner``.
    """
    try:
        import importlib
        missions = importlib.import_module("koda.missions")
        get_fn = getattr(missions, "get", None)
        if get_fn is None:
            raise ImportError("koda.missions exists but has no get() function")
        scanners = get_fn(name)
        if not isinstance(scanners, list):
            raise ImportError(
                f"koda.missions.get({name!r}) returned {type(scanners).__name__}, "
                "expected list[str]"
            )
        return scanners
    except ModuleNotFoundError as exc:
        raise ImportError(
            "koda.missions is not available yet; use --scanner to specify scanners."
        ) from exc


# ---------------------------------------------------------------------------
# Argument parsing helpers
# ---------------------------------------------------------------------------

_HELP_SENTINEL: dict[str, Any] = {"_exit_code": 0}
_ERROR_SENTINEL: dict[str, Any] = {"_exit_code": 2}


def _parse_remote_args(argv: list[str]) -> dict[str, Any]:
    """Parse ``koda scan remote`` flags.

    Returns a dict of parsed options, or a sentinel dict with ``_exit_code``
    when help was printed (0) or an error occurred (2).
    """
    if not argv or argv[0] in {"-h", "--help"}:
        _print_remote_help()
        return _HELP_SENTINEL

    parsed: dict[str, Any] = {
        "ssh_target": argv[0],
        "remote_target": ".",
        "scanners": [],
        "preset": None,
        "port": None,
        "sudo": False,
        "keep_temp": False,
        "engagement": None,
    }

    i = 1
    while i < len(argv):
        a = argv[i]

        if a in {"-h", "--help"}:
            _print_remote_help()
            return _HELP_SENTINEL

        if a == "--target" and i + 1 < len(argv):
            parsed["remote_target"] = argv[i + 1]; i += 2; continue
        if a.startswith("--target="):
            parsed["remote_target"] = a.split("=", 1)[1]; i += 1; continue

        if a == "--preset" and i + 1 < len(argv):
            parsed["preset"] = argv[i + 1]; i += 2; continue
        if a.startswith("--preset="):
            parsed["preset"] = a.split("=", 1)[1]; i += 1; continue

        if a == "--scanner" and i + 1 < len(argv):
            parsed["scanners"].append(argv[i + 1]); i += 2; continue
        if a.startswith("--scanner="):
            parsed["scanners"].append(a.split("=", 1)[1]); i += 1; continue

        if a == "--port" and i + 1 < len(argv):
            try:
                parsed["port"] = int(argv[i + 1])
            except ValueError:
                print(f"error: --port requires an integer, got {argv[i+1]!r}", file=sys.stderr)
                return None
            i += 2; continue
        if a.startswith("--port="):
            try:
                parsed["port"] = int(a.split("=", 1)[1])
            except ValueError:
                print(f"error: --port requires an integer, got {a!r}", file=sys.stderr)
                return None
            i += 1; continue

        if a == "--sudo":
            parsed["sudo"] = True; i += 1; continue
        if a == "--keep-temp":
            parsed["keep_temp"] = True; i += 1; continue

        if a == "--engagement" and i + 1 < len(argv):
            parsed["engagement"] = argv[i + 1]; i += 2; continue
        if a.startswith("--engagement="):
            parsed["engagement"] = a.split("=", 1)[1]; i += 1; continue

        print(f"error: unknown flag {a!r}", file=sys.stderr)
        return _ERROR_SENTINEL

    return parsed


def _print_remote_help() -> None:
    print("usage: koda scan remote <ssh-target> [flags]")
    print()
    print("  Run security scanners against a remote host over SSH.")
    print("  Requires that `ssh <ssh-target> 'true'` works without interaction.")
    print()
    print("positional:")
    print("  <ssh-target>        user@host | host | user@host:port | ~/.ssh/config alias")
    print()
    print("flags:")
    print("  --target PATH       Remote path to scan (default: .)")
    print("  --preset NAME       Mission preset name (requires koda.missions)")
    print("  --scanner NAME      Scanner to run (repeatable; combinable with --preset)")
    print("  --port PORT         SSH port override")
    print("  --sudo              Elevate scanner commands with sudo on the remote")
    print("  --keep-temp         Do not delete /tmp/koda-* on the remote after scan")
    print("  --engagement NAME   Tag results under this engagement name")
    print()
    print("auto-provisioned scanners (uploaded if not on remote PATH):")
    print("  trivy, gitleaks, nuclei, osv-scanner, grype")
    print()
    print("require pre-installation on remote:")
    print("  semgrep, bandit, nmap, falco, checkov, kics")
    print()
    print("examples:")
    print("  koda scan remote user@192.168.1.1 --scanner trivy --target /srv/app")
    print("  koda scan remote ops@server --preset server-hardening --sudo")


# ---------------------------------------------------------------------------
# Remote scan entry point
# ---------------------------------------------------------------------------

def _cmd_scan_remote(argv: list[str]) -> int:
    """Execute ``koda scan remote``."""
    parsed = _parse_remote_args(argv)
    if "_exit_code" in parsed:
        return parsed["_exit_code"]

    ssh_target: str = parsed["ssh_target"]
    remote_target: str = parsed["remote_target"]
    preset_name: str | None = parsed["preset"]
    explicit_scanners: list[str] = parsed["scanners"]
    port: int | None = parsed["port"]
    use_sudo: bool = parsed["sudo"]
    keep_temp: bool = parsed["keep_temp"]
    engagement: str | None = parsed["engagement"]

    # Resolve scanner list from preset + explicit flags.
    scanner_names: list[str] = list(explicit_scanners)

    if preset_name:
        try:
            preset_scanners = _load_preset(preset_name)
            scanner_names = list(dict.fromkeys(preset_scanners + scanner_names))
        except ImportError as exc:
            if not explicit_scanners:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            print(f"warning: {exc}  Using --scanner list only.", file=sys.stderr)

    if not scanner_names:
        print(
            "error: no scanners specified. "
            "Use --scanner <name> or --preset <name>.",
            file=sys.stderr,
        )
        return 1

    # Resolve engagement.
    import time as _time
    host_part = ssh_target.split("@")[-1].split(":")[0]
    ts = int(_time.time())
    if engagement is None:
        from ..config import KODA_HOME
        engagement = f"remote-{host_part}-{ts}"
        eng_dir = KODA_HOME / "engagements" / engagement
    else:
        from ..config import KODA_HOME
        eng_dir = KODA_HOME / "engagements" / engagement

    eng_dir.mkdir(parents=True, exist_ok=True)

    from ..audit import AuditLogger

    audit = AuditLogger()

    print("K.O.D.A. remote scan")
    print(f"  target:     {ssh_target}")
    print(f"  path:       {remote_target}")
    print(f"  scanners:   {', '.join(scanner_names)}")
    print(f"  engagement: {engagement}")
    if use_sudo:
        print("  sudo:       enabled")
    if keep_temp:
        print("  keep-temp:  yes")
    print()

    from ..remote.executor import run_remote_scan

    try:
        results = run_remote_scan(
            ssh_target=ssh_target,
            remote_target=remote_target,
            scanner_names=scanner_names,
            port=port,
            use_sudo=use_sudo,
            keep_temp=keep_temp,
            engagement=engagement,
            audit=audit,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"error: remote scan failed: {exc}", file=sys.stderr)
        audit.close()
        return 1

    # ── Summary output ────────────────────────────────────────────────
    total_findings = sum(len(r.findings) for r in results)
    print(f"scan complete — {len(results)} scanner(s) ran, {total_findings} finding(s)")
    print()

    for r in results:
        status = "ok" if r.success else "error"
        n = len(r.findings)
        print(f"  {r.scanner:<16} {status:<8} {n:>4} finding(s)  {r.elapsed:.1f}s")
        if r.error:
            print(f"    error: {r.error}")

    print()
    print(f"engagement: {eng_dir}")

    audit.close()
    return 0


# ---------------------------------------------------------------------------
# Top-level dispatcher for ``koda scan``
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    """Entry point for ``koda scan``."""
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage:")
        print("  koda scan remote <ssh-target> [flags]  — scan a remote host over SSH")
        print()
        print("Run `koda scan remote --help` for full flag reference.")
        return 0

    sub = argv[0]

    if sub == "remote":
        return _cmd_scan_remote(argv[1:])

    print(f"error: unknown scan subcommand {sub!r}", file=sys.stderr)
    print("       run: koda scan --help", file=sys.stderr)
    return 2


__all__ = ["main"]
