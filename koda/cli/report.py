"""CLI subcommand: ``koda report generate | stats``.

Reads findings from a JSONL file (one ``UnifiedFinding.to_dict()`` per
line), builds a ``ReportContext`` from flags, and drives
``generate`` + ``write_bundle``.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from ..intel.store import NullThreatIntel, ThreatIntel, default_intel_path
from ..security.findings import Severity, UnifiedFinding
from ..security.report.context import ReportContext
from ..security.report.generate import generate, write_bundle


def _load_findings(path: Path) -> list[UnifiedFinding]:
    findings: list[UnifiedFinding] = []
    text = path.read_text(encoding="utf-8")
    for lineno, raw in enumerate(text.splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"warning: line {lineno} not JSON ({exc})", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            continue
        try:
            findings.append(UnifiedFinding.from_dict(data))
        except Exception as exc:  # noqa: BLE001 — partial files are common
            print(f"warning: line {lineno} parse failed ({exc})", file=sys.stderr)
    return findings


def _get_intel() -> Any:
    """Open the local intel DB if present, else return a NullThreatIntel."""
    try:
        path = default_intel_path()
        if (path / "intel.db").exists():
            return ThreatIntel(path)
    except Exception:
        pass
    return NullThreatIntel()


def _parse_formats(value: str) -> tuple[str, ...]:
    parts = [p.strip().lower() for p in (value or "").split(",") if p.strip()]
    valid = {"executive", "technical", "markdown", "sarif"}
    out = tuple(p for p in parts if p in valid)
    if not out:
        return ("executive", "technical", "markdown", "sarif")
    return out


def _cmd_generate(args: argparse.Namespace) -> int:
    findings_path = Path(args.findings).expanduser()
    if not findings_path.exists():
        print(f"error: findings file not found: {findings_path}", file=sys.stderr)
        return 1

    out_dir = Path(args.out).expanduser()
    findings = _load_findings(findings_path)
    if not findings:
        print("warning: no findings loaded — report will be empty", file=sys.stderr)

    ctx = ReportContext(
        engagement_id=args.engagement_id or "ENG-0001",
        engagement_name=args.engagement_name or "Ad-hoc Engagement",
        scope=args.scope or "(unspecified)",
        operator=args.operator or "operator",
        started_at=args.started_at or "",
        ended_at=args.ended_at or "",
        mode=args.mode or "red",
        targets=tuple(args.target or ()),
        client=args.client or "",
        roe_id=args.roe_id or "",
    )

    intel = _get_intel()
    try:
        outputs = generate(ctx, findings, intel, formats=_parse_formats(args.format))
        paths = write_bundle(outputs, out_dir, basename=args.basename)
    finally:
        close = getattr(intel, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass

    for fmt, path in sorted(paths.items()):
        print(f"{fmt:<10}  {path}")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    findings_path = Path(args.findings).expanduser()
    if not findings_path.exists():
        print(f"error: findings file not found: {findings_path}", file=sys.stderr)
        return 1
    findings = _load_findings(findings_path)

    sev_counter: Counter[str] = Counter()
    for f in findings:
        sev_counter[f.severity.value] += 1
    kev = sum(1 for f in findings if f.cisa_kev)
    cve_counter: Counter[str] = Counter()
    for f in findings:
        for cve in f.cve or []:
            cid = (cve or "").strip().upper()
            if cid:
                cve_counter[cid] += 1

    print(f"total findings : {len(findings)}")
    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
        Severity.UNKNOWN,
    ):
        n = sev_counter.get(sev.value, 0)
        if n:
            print(f"  {sev.value:<9}    : {n}")
    print(f"CISA-KEV       : {kev}")
    if cve_counter:
        print("top CVEs:")
        for cid, n in cve_counter.most_common(10):
            print(f"  {cid}  x{n}")
    return 0


def _cmd_engagement(args: argparse.Namespace) -> int:
    """Generate a report for an existing engagement by name.

    Looks up the engagement under ``KODA_HOME/engagements/<name>/``,
    reads its findings (``findings.jsonl`` by convention), auto-fills
    metadata from ``engagement.toml`` if present, and delegates to the
    same generate path as ``koda report generate``.
    """
    from ..config import KODA_HOME

    name = args.name
    eng_dir = KODA_HOME / "engagements" / name
    if not eng_dir.is_dir():
        print(f"error: engagement '{name}' not found under {KODA_HOME/'engagements'}", file=sys.stderr)
        return 1

    findings_path = eng_dir / "findings.jsonl"
    if not findings_path.exists():
        print(
            f"error: no findings at {findings_path}\n"
            f"       write UnifiedFinding JSONL there, or point --findings at another file.",
            file=sys.stderr,
        )
        return 1

    meta = _read_engagement_meta(eng_dir)
    out_dir = Path(args.out).expanduser() if args.out else (eng_dir / "reports")
    findings = _load_findings(findings_path)
    if not findings:
        print("warning: no findings loaded — report will be empty", file=sys.stderr)

    ctx = ReportContext(
        engagement_id=args.engagement_id or meta.get("id") or f"ENG-{name}",
        engagement_name=args.engagement_name or meta.get("name") or name,
        scope=args.scope or meta.get("scope") or "(unspecified)",
        operator=args.operator or meta.get("operator") or "operator",
        started_at=args.started_at or meta.get("started_at") or "",
        ended_at=args.ended_at or meta.get("ended_at") or "",
        mode=args.mode or meta.get("mode") or "red",
        targets=tuple(args.target or meta.get("targets") or ()),
        client=args.client or meta.get("client") or "",
        roe_id=args.roe_id or meta.get("roe_id") or "",
    )

    intel = _get_intel()
    try:
        outputs = generate(ctx, findings, intel, formats=_parse_formats(args.format))
        paths = write_bundle(outputs, out_dir, basename=args.basename)
    finally:
        close = getattr(intel, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass

    for fmt, path in sorted(paths.items()):
        print(f"{fmt:<10}  {path}")
    return 0


def _read_engagement_meta(eng_dir: Path) -> dict[str, Any]:
    """Best-effort read of engagement.toml; empty dict if absent/invalid."""
    meta_path = eng_dir / "engagement.toml"
    if not meta_path.exists():
        return {}
    try:
        import tomllib
        return tomllib.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"warning: could not parse {meta_path}: {exc}", file=sys.stderr)
        return {}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="koda report", description="Generate security reports.")
    sub = parser.add_subparsers(dest="subcommand")

    eng = sub.add_parser("engagement", help="report for an engagement by name (auto-fills metadata)")
    eng.add_argument("name", help="engagement name under KODA_HOME/engagements/")
    eng.add_argument("--out", default="", help="output directory (default: <engagement>/reports)")
    eng.add_argument("--format", default="executive,technical,markdown,sarif",
                     help="comma-separated subset of: executive,technical,markdown,sarif")
    eng.add_argument("--basename", default="report", help="output filename base (default: report)")
    eng.add_argument("--engagement-id", dest="engagement_id", default="")
    eng.add_argument("--engagement-name", dest="engagement_name", default="")
    eng.add_argument("--scope", default="")
    eng.add_argument("--operator", default="")
    eng.add_argument("--started-at", dest="started_at", default="")
    eng.add_argument("--ended-at", dest="ended_at", default="")
    eng.add_argument("--mode", default="", choices=["", "red", "blue", "purple"])
    eng.add_argument("--client", default="")
    eng.add_argument("--roe-id", dest="roe_id", default="")
    eng.add_argument("--target", action="append", help="repeatable target identifier")
    eng.set_defaults(func=_cmd_engagement)

    gen = sub.add_parser("generate", help="generate executive/technical/markdown/SARIF reports")
    gen.add_argument("--findings", required=True, help="path to JSONL file of UnifiedFindings")
    gen.add_argument("--out", required=True, help="output directory")
    gen.add_argument("--format", default="executive,technical,markdown,sarif",
                     help="comma-separated subset of: executive,technical,markdown,sarif")
    gen.add_argument("--basename", default="report", help="output filename base (default: report)")
    gen.add_argument("--engagement-id", dest="engagement_id", default="")
    gen.add_argument("--engagement-name", dest="engagement_name", default="")
    gen.add_argument("--scope", default="")
    gen.add_argument("--operator", default="")
    gen.add_argument("--started-at", dest="started_at", default="")
    gen.add_argument("--ended-at", dest="ended_at", default="")
    gen.add_argument("--mode", default="red", choices=["red", "blue", "purple"])
    gen.add_argument("--client", default="")
    gen.add_argument("--roe-id", dest="roe_id", default="")
    gen.add_argument("--target", action="append", help="repeatable target identifier")
    gen.set_defaults(func=_cmd_generate)

    stats = sub.add_parser("stats", help="print severity counts, KEV count, top CVEs")
    stats.add_argument("--findings", required=True, help="path to JSONL file of UnifiedFindings")
    stats.set_defaults(func=_cmd_stats)

    return parser


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage:")
        print("  koda report generate --findings FILE --out DIR [options]")
        print("  koda report stats --findings FILE")
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
