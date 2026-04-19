"""``koda remote`` subcommand — push/pull/list evidence bundles via S3-compatible storage.

Config source priority (highest → lowest):
  1. CLI flags (--bucket, --endpoint-url, --region, --prefix)
  2. Env vars: KODA_REMOTE_BUCKET, KODA_REMOTE_ENDPOINT, KODA_REMOTE_REGION,
               KODA_REMOTE_PREFIX  (plus standard AWS_ACCESS_KEY_ID /
               AWS_SECRET_ACCESS_KEY for credentials)
  3. KODA_HOME/remote.toml  [bucket, endpoint_url, region, prefix]

Subcommands:
  koda remote push <engagement> [--dest-key KEY] [--bucket B] [--endpoint-url U] ...
  koda remote pull <key>        [--out DIR]      [--bucket B] [--endpoint-url U] ...
  koda remote list              [--prefix P]     [--bucket B] [--endpoint-url U] ...

Credentials are never printed or included in audit events.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


def _parse_store_flags(argv: list[str]) -> tuple[dict[str, Any], list[str]]:
    """Extract shared --bucket / --endpoint-url / --region / --prefix flags.

    Returns (store_kwargs, remaining_argv).
    """
    kwargs: dict[str, Any] = {}
    rest: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--bucket" and i + 1 < len(argv):
            kwargs["bucket"] = argv[i + 1]; i += 2; continue
        if a.startswith("--bucket="):
            kwargs["bucket"] = a.split("=", 1)[1]; i += 1; continue
        if a == "--endpoint-url" and i + 1 < len(argv):
            kwargs["endpoint_url"] = argv[i + 1]; i += 2; continue
        if a.startswith("--endpoint-url="):
            kwargs["endpoint_url"] = a.split("=", 1)[1]; i += 1; continue
        if a == "--region" and i + 1 < len(argv):
            kwargs["region"] = argv[i + 1]; i += 2; continue
        if a.startswith("--region="):
            kwargs["region"] = a.split("=", 1)[1]; i += 1; continue
        if a == "--prefix" and i + 1 < len(argv):
            kwargs["prefix"] = argv[i + 1]; i += 2; continue
        if a.startswith("--prefix="):
            kwargs["prefix"] = a.split("=", 1)[1]; i += 1; continue
        rest.append(a); i += 1
    return kwargs, rest


def _make_store(store_kwargs: dict[str, Any], audit: Any = None) -> Any:
    from ..evidence.remote import RemoteBundleStore
    return RemoteBundleStore(audit=audit, **store_kwargs)


# ---------------------------------------------------------------------------
# koda remote push
# ---------------------------------------------------------------------------

def _cmd_push(argv: list[str]) -> int:
    """Create a bundle for <engagement> and push it to configured remote."""
    store_kwargs, rest = _parse_store_flags(argv)

    if not rest or rest[0] in {"-h", "--help"}:
        print("usage: koda remote push <engagement> [--dest-key KEY] [store-flags]")
        print()
        print("  Creates an evidence bundle for <engagement> and uploads it.")
        print("  Prints the resulting URL and SHA-256 on success.")
        print()
        _print_store_flags_help()
        return 0

    engagement = rest[0]
    rest = rest[1:]
    dest_key: str | None = None

    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--dest-key" and i + 1 < len(rest):
            dest_key = rest[i + 1]; i += 2; continue
        if a.startswith("--dest-key="):
            dest_key = a.split("=", 1)[1]; i += 1; continue
        print(f"error: unknown flag {a!r}", file=sys.stderr)
        return 2

    import tempfile

    from ..audit import AuditLogger
    from ..evidence.bundle import export_bundle
    from ..evidence.store import EvidenceStore

    audit = AuditLogger()
    evidence = EvidenceStore()

    # Build the bundle into a temp directory first.
    with tempfile.TemporaryDirectory(prefix="koda-remote-push-") as tmp:
        bundle_name = dest_key or f"{engagement}_{int(__import__('time').time())}.tar.gz"
        if not bundle_name.endswith(".tar.gz"):
            bundle_name += ".tar.gz"
        bundle_path = Path(tmp) / bundle_name

        report = export_bundle(evidence, engagement, bundle_path)
        if not report.ok:
            print(
                f"warning: bundle export completed with warnings for {engagement!r}:",
                file=sys.stderr,
            )
            for w in report.warnings:
                print(f"  - {w}", file=sys.stderr)

        if report.artifact_count == 0:
            print(
                f"warning: engagement {engagement!r} has no artifacts — "
                "bundle will be empty",
                file=sys.stderr,
            )

        try:
            store = _make_store(store_kwargs, audit=audit)
        except (ValueError, ImportError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        if dest_key is None:
            dest_key = bundle_name

        try:
            result = store.push(bundle_path, dest_key=dest_key)
        except Exception as exc:  # noqa: BLE001
            print(f"error: push failed: {exc}", file=sys.stderr)
            return 1

    print(f"pushed  {result['bytes']} bytes")
    print(f"sha256  {result['sha256']}")
    print(f"url     {result['url']}")
    return 0


# ---------------------------------------------------------------------------
# koda remote pull
# ---------------------------------------------------------------------------

def _cmd_pull(argv: list[str]) -> int:
    """Download a bundle by key, verify integrity, extract to engagement dir."""
    store_kwargs, rest = _parse_store_flags(argv)

    if not rest or rest[0] in {"-h", "--help"}:
        print("usage: koda remote pull <key> [--out DIR] [store-flags]")
        print()
        print("  Downloads <key> from remote, verifies SHA-256 against the")
        print("  sidecar, then extracts the bundle into")
        print("  KODA_HOME/engagements/<name>/ (or --out DIR).")
        print()
        _print_store_flags_help()
        return 0

    src_key = rest[0]
    rest = rest[1:]
    out_dir: str | None = None

    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--out" and i + 1 < len(rest):
            out_dir = rest[i + 1]; i += 2; continue
        if a.startswith("--out="):
            out_dir = a.split("=", 1)[1]; i += 1; continue
        print(f"error: unknown flag {a!r}", file=sys.stderr)
        return 2

    import tarfile
    import tempfile

    from ..audit import AuditLogger
    from ..config import KODA_HOME

    audit = AuditLogger()

    try:
        store = _make_store(store_kwargs, audit=audit)
    except (ValueError, ImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Determine destination directory.
    if out_dir:
        dest_dir = Path(out_dir)
    else:
        # Derive engagement name from key basename (strip .tar.gz etc).
        key_base = Path(src_key).name
        for suffix in (".tar.gz", ".tgz", ".tar"):
            if key_base.endswith(suffix):
                key_base = key_base[: -len(suffix)]
                break
        # Strip timestamp suffix like engagementname_1700000000 → engagementname
        parts = key_base.rsplit("_", 1)
        eng_name = parts[0] if len(parts) == 2 and parts[1].isdigit() else key_base
        dest_dir = KODA_HOME / "engagements" / eng_name

    dest_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="koda-remote-pull-") as tmp:
        tmp_bundle = Path(tmp) / Path(src_key).name
        try:
            store.pull(src_key, dest_path=tmp_bundle)
        except (ValueError, RuntimeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        # Extract the verified bundle into dest_dir.
        try:
            with tarfile.open(tmp_bundle, "r:gz") as tar:
                _safe_extract(tar, dest_dir)
        except tarfile.TarError as exc:
            print(f"error: could not extract bundle: {exc}", file=sys.stderr)
            return 1

    print(f"pulled and extracted to {dest_dir}")
    return 0


def _safe_extract(tar: Any, dest: Path) -> None:
    """Defend against path traversal in pulled bundles."""
    import tarfile
    base = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(base)):
            raise tarfile.TarError(f"unsafe path in bundle: {member.name}")
    tar.extractall(dest)


# ---------------------------------------------------------------------------
# koda remote list
# ---------------------------------------------------------------------------

def _cmd_list(argv: list[str]) -> int:
    """List available bundles at the configured remote prefix."""
    store_kwargs, rest = _parse_store_flags(argv)

    list_prefix = ""
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in {"-h", "--help"}:
            print("usage: koda remote list [--prefix PREFIX] [store-flags]")
            print()
            print("  Lists bundles stored at the configured (or given) prefix.")
            print()
            _print_store_flags_help()
            return 0
        if a == "--prefix" and i + 1 < len(rest):
            list_prefix = rest[i + 1]; i += 2; continue
        if a.startswith("--prefix="):
            list_prefix = a.split("=", 1)[1]; i += 1; continue
        print(f"error: unknown flag {a!r}", file=sys.stderr)
        return 2

    from ..audit import AuditLogger

    audit = AuditLogger()

    try:
        store = _make_store(store_kwargs, audit=audit)
    except (ValueError, ImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        items = store.list_remote(prefix=list_prefix)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not items:
        print("(no bundles found)")
        return 0

    # Print a simple table.
    col_key = max(len(e["key"]) for e in items)
    col_key = max(col_key, 10)
    header = f"  {'KEY':<{col_key}}  {'SIZE':>12}  {'LAST MODIFIED':<24}  SHA256"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for e in items:
        sha = (e.get("sha256") or "")[:12] or "-"
        size = e.get("size") or 0
        lm = (e.get("last_modified") or "")[:19]
        print(f"  {e['key']:<{col_key}}  {size:>12}  {lm:<24}  {sha}")

    print(f"\n  {len(items)} bundle(s)")
    return 0


# ---------------------------------------------------------------------------
# Top-level dispatch
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    """Entry point for ``koda remote``."""
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage:")
        print("  koda remote push <engagement> [--dest-key KEY] [store-flags]")
        print("  koda remote pull <key>        [--out DIR]      [store-flags]")
        print("  koda remote list              [--prefix PREFIX][store-flags]")
        print()
        _print_store_flags_help()
        return 0

    sub = argv[0]
    rest = argv[1:]

    if sub == "push":
        return _cmd_push(rest)
    if sub == "pull":
        return _cmd_pull(rest)
    if sub in {"list", "ls"}:
        return _cmd_list(rest)

    print(f"error: unknown remote subcommand {sub!r}", file=sys.stderr)
    print("       run: koda remote --help", file=sys.stderr)
    return 2


def _print_store_flags_help() -> None:
    print("  store flags (override env / remote.toml):")
    print("    --bucket BUCKET       required if KODA_REMOTE_BUCKET is not set")
    print("    --endpoint-url URL    set for R2/MinIO; omit for AWS S3")
    print("    --region REGION       default: us-east-1")
    print("    --prefix PREFIX       key prefix, e.g. engagements/")
    print()
    print("  credentials: use AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars,")
    print("               ~/.aws/credentials, or IAM instance roles.")
    print()
    print("  config file: KODA_HOME/remote.toml  (bucket, endpoint_url, region, prefix)")


__all__ = ["main"]
