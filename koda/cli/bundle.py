"""``koda bundle`` subcommand — local evidence bundle export + verification.

Why this exists separately from ``koda remote push``:

  - Some operators want a portable tar.gz to hand a client or legal team
    without ever touching object storage. ``koda remote`` assumes an
    S3-compatible backend; this one doesn't.
  - ``verify`` needs to work on a bundle pulled off a USB stick, possibly
    on a machine that never held the original engagement. The verifier
    reads the bundle alone — no live store required.

Subcommands:
  koda bundle export <engagement> [--out PATH]
  koda bundle verify <bundle.tar.gz>
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


def _timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _print_report(report: object, *, header: str) -> None:
    path = getattr(report, "path", "")
    artifact_count = getattr(report, "artifact_count", 0)
    root_hash = getattr(report, "root_hash", "")
    ok = bool(getattr(report, "ok", False))
    warnings = list(getattr(report, "warnings", ()) or ())

    print(header)
    if path:
        print(f"  path           : {path}")
    print(f"  artifact_count : {artifact_count}")
    print(f"  root_hash      : {root_hash}")
    print(f"  ok             : {ok}")
    if warnings:
        print("  warnings:")
        for w in warnings:
            print(f"    - {w}")


def _cmd_export(args: argparse.Namespace) -> int:
    from ..config import KODA_HOME
    from ..evidence.bundle import export_bundle
    from ..evidence.store import EvidenceStore

    engagement = args.engagement
    if args.out:
        out_path = Path(args.out).expanduser()
    else:
        out_path = (
            KODA_HOME
            / "engagements"
            / engagement
            / "bundles"
            / f"{engagement}-{_timestamp()}.tar.gz"
        )

    evidence = EvidenceStore()
    report = export_bundle(evidence, engagement, out_path)

    if report.artifact_count == 0:
        print(
            f"warning: engagement {engagement!r} has no artifacts — "
            "bundle will be empty",
            file=sys.stderr,
        )

    _print_report(report, header=f"bundle exported for {engagement!r}:")
    return 0 if report.ok else 1


def _cmd_verify(args: argparse.Namespace) -> int:
    from ..evidence.bundle import verify_bundle

    bundle_path = Path(args.bundle).expanduser()
    if not bundle_path.exists():
        print(f"error: bundle not found: {bundle_path}", file=sys.stderr)
        return 1

    report = verify_bundle(bundle_path)
    _print_report(report, header=f"verifying {bundle_path}:")
    return 0 if report.ok else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="koda bundle",
        description="Export and verify portable evidence bundles.",
    )
    sub = parser.add_subparsers(dest="subcommand")

    exp = sub.add_parser("export", help="export an engagement as a portable tar.gz")
    exp.add_argument("engagement", help="engagement name")
    exp.add_argument(
        "--out",
        default="",
        help="output path (default: KODA_HOME/engagements/<name>/bundles/<name>-<ts>.tar.gz)",
    )
    exp.set_defaults(func=_cmd_export)

    ver = sub.add_parser("verify", help="verify a bundle's integrity from the file alone")
    ver.add_argument("bundle", help="path to a bundle .tar.gz")
    ver.set_defaults(func=_cmd_verify)

    return parser


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage:")
        print("  koda bundle export <engagement> [--out PATH]")
        print("  koda bundle verify <bundle.tar.gz>")
        return 0

    parser = _build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
