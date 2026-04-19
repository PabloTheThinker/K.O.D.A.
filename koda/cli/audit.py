"""``koda audit`` subcommand: run mission presets end-to-end.

Usage::

    koda audit --list-presets
    koda audit --explain <preset>
    koda audit --preset <name> [target] [options]

The command translates a security *outcome* into a scanner composition,
runs each scanner in order, generates a report in the preset's chosen style,
and exits 0 if no CRITICAL/HIGH findings were produced, 1 otherwise.

Subcommand flags
----------------
--list-presets
    Print a table of all available presets and exit 0.
--explain <preset>
    Print the preset's full description, scanner list, success criteria,
    and next-steps guidance, then exit 0.
--preset <name>
    Select a preset to run.  Required for execution.
--dry-run
    Print what would run without executing any scanner.  Exits 0.
--engagement <name>
    Use an existing engagement directory instead of creating a throwaway.
--no-report
    Skip the report-generation step.
--skip-scanner <name>
    Remove a scanner from the preset's list.  Repeatable.
--url <url>
    Supplementary URL target (used by web-app preset for nuclei).
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

_APPROVAL_ORDER: dict[str, int] = {"safe": 0, "sensitive": 1, "dangerous": 2}

# Report-style → writer key accepted by koda.security.report.generate
_STYLE_MAP: dict[str, str] = {
    "executive": "executive",
    "technical": "technical",
    "audit": "markdown",        # audit uses the markdown writer with an audit frame
    "ir-timeline": "technical", # IR timeline uses technical writer with IR framing
}


def _tier_int(tier: str) -> int:
    return _APPROVAL_ORDER.get(tier.lower(), 0)


def _print_table(rows: list[tuple[str, ...]]) -> None:
    """Print a simple fixed-width table without external deps."""
    if not rows:
        return
    col_w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    sep = "  "
    for i, row in enumerate(rows):
        line = sep.join(cell.ljust(col_w[j]) for j, cell in enumerate(row))
        print(line)
        if i == 0:
            print(sep.join("-" * col_w[j] for j in range(len(col_w))))


def _cmd_list_presets() -> int:
    from ..missions import list_presets
    presets = list_presets()
    rows: list[tuple[str, ...]] = [
        ("NAME", "AUDIENCE", "TIER", "SUMMARY"),
    ]
    for p in presets:
        summary = p.summary if len(p.summary) <= 64 else p.summary[:61] + "..."
        rows.append((p.name, p.audience[:32], p.approval_tier, summary))
    _print_table(rows)
    return 0


def _cmd_explain(preset_name: str) -> int:
    from ..missions import get_preset, preset_names
    preset = get_preset(preset_name)
    if preset is None:
        valid = ", ".join(preset_names())
        print(
            f"error: unknown preset {preset_name!r}. "
            f"Available: {valid}",
            file=sys.stderr,
        )
        return 1

    print(f"\n{'=' * 60}")
    print(f"  {preset.title}")
    print(f"{'=' * 60}")
    print(f"\nAudience:    {preset.audience}")
    print(f"Tier:        {preset.approval_tier}")
    print(f"Frameworks:  {', '.join(preset.compliance_frameworks) or 'none'}")
    print(f"Report:      {preset.report_style}")
    print(f"Scanners:    {', '.join(preset.scanners)}")
    print(f"ATT&CK:      {', '.join(preset.attack_phases)}")
    print("\n--- Description ---\n")
    print(preset.description)
    print("\n--- Success Criteria ---\n")
    print(preset.success_criteria)
    print("\n--- Next Steps (if findings appear) ---\n")
    print(preset.next_steps)
    return 0


def _resolve_engagement_dir(
    koda_home: Path,
    preset_name: str,
    engagement_name: str | None,
) -> Path:
    """Return the engagement directory.  Creates a throwaway if needed."""
    if engagement_name:
        eng_dir = koda_home / "engagements" / engagement_name
        if not eng_dir.is_dir():
            print(
                f"error: engagement {engagement_name!r} not found at {eng_dir}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        return eng_dir

    timestamp = time.strftime("%Y%m%dT%H%M%S")
    eng_name = f"audit-{preset_name}-{timestamp}"
    eng_dir = koda_home / "engagements" / eng_name
    (eng_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (eng_dir / "audit.jsonl").touch()
    return eng_dir


def _check_approval_tier(preset_tier: str, config: dict) -> bool:
    """Return True if config permits running at *preset_tier*."""
    config_tier = str(
        config.get("approvals", {}).get("auto_approve", "all")
    ).strip().lower()
    # "all" means the operator has approved up to DANGEROUS
    if config_tier == "all":
        return True
    return _tier_int(preset_tier) <= _tier_int(config_tier)


def _run_scanners(
    preset,
    target: str,
    skip: set[str],
    extra_url: str | None,
    *,
    dry_run: bool,
) -> list:
    """Invoke each scanner in the preset.  Returns list[ScanResult]."""
    from ..security.scanners.registry import ScannerRegistry

    registry = ScannerRegistry()
    results = []

    scanners_to_run = [s for s in preset.scanners if s not in skip]

    for scanner_name in scanners_to_run:
        # dependency_track is URL-based — special dispatch
        if scanner_name == "dependency_track":
            if dry_run:
                dtrack_url = os.environ.get("KODA_DTRACK_URL", "")
                if dtrack_url:
                    print("  [dry-run] would run: dependency_track  (project: $KODA_DTRACK_PROJECT_UUID)")
                else:
                    print("  [dry-run] skip dependency_track — KODA_DTRACK_URL not set")
                continue

            dtrack_url = os.environ.get("KODA_DTRACK_URL", "").strip()
            dtrack_key = os.environ.get("KODA_DTRACK_API_KEY", "").strip()
            dtrack_uuid = os.environ.get("KODA_DTRACK_PROJECT_UUID", "").strip()

            if not (dtrack_url and dtrack_key and dtrack_uuid):
                print(
                    "  skip: dependency_track — set KODA_DTRACK_URL, "
                    "KODA_DTRACK_API_KEY, KODA_DTRACK_PROJECT_UUID to enable"
                )
                continue

            result = registry.run(
                "dependency_track",
                dtrack_uuid,
                base_url=dtrack_url,
                api_key=dtrack_key,
            )
            results.append(result)
            _print_scanner_line(result)
            continue

        # nuclei in web-app preset only runs when --url is provided
        if scanner_name == "nuclei" and not extra_url:
            if dry_run:
                print("  [dry-run] skip nuclei — no --url provided")
            else:
                print("  skip: nuclei — pass --url <staging-url> to enable")
            continue

        # For nuclei, use extra_url as the target instead of path
        effective_target = extra_url if scanner_name == "nuclei" and extra_url else target

        per_scanner_kwargs = dict(preset.scanner_args.get(scanner_name, {}))

        if dry_run:
            args_display = ""
            if per_scanner_kwargs:
                args_display = "  kwargs=" + repr(per_scanner_kwargs)
            print(f"  [dry-run] would run: {scanner_name:<20}  target={effective_target!r}{args_display}")
            continue

        result = registry.run(scanner_name, effective_target, **per_scanner_kwargs)
        results.append(result)
        _print_scanner_line(result)

    return results


def _print_scanner_line(result) -> None:
    status = "ok" if result.success else "err"
    count = len(result.findings)
    elapsed = getattr(result, "elapsed", 0.0)
    print(f"  [{status}] {result.scanner:<20}  {count:>4} finding(s)  {elapsed:.1f}s")


def _severity_summary(results: list) -> dict[str, int]:
    """Aggregate findings by severity across all results."""
    counts: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def _has_high_or_critical(results: list) -> bool:
    for r in results:
        for f in r.findings:
            if f.severity.value in ("critical", "high"):
                return True
    return False


def _save_findings_jsonl(eng_dir: Path, results: list) -> Path:
    path = eng_dir / "findings.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for r in results:
            for f in r.findings:
                fh.write(json.dumps(f.to_dict()) + "\n")
    return path


def _generate_report(
    preset,
    eng_dir: Path,
    target: str,
    results: list,
    started_at: str,
) -> dict[str, Path] | None:
    """Generate the report.  Returns {format: path} dict or None on failure."""
    try:
        from ..security.report.context import ReportContext
        from ..security.report.generate import generate, write_bundle
    except ImportError as exc:
        print(f"  warning: report generation unavailable: {exc}", file=sys.stderr)
        return None

    all_findings = [f for r in results for f in r.findings]

    writer_key = _STYLE_MAP.get(preset.report_style, "technical")

    ctx = ReportContext(
        engagement_id=eng_dir.name,
        engagement_name=eng_dir.name,
        scope=target,
        operator="koda-audit",
        started_at=started_at,
        ended_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        mode=f"audit-preset:{preset.name}",
        targets=(target,) if target else (),
    )

    try:
        outputs = generate(ctx, all_findings, intel=None, formats=(writer_key,))
    except Exception as exc:  # noqa: BLE001
        print(f"  warning: report generation failed: {exc}", file=sys.stderr)
        return None

    report_dir = eng_dir / "reports"
    return write_bundle(outputs, report_dir, basename=f"audit-{preset.name}")


def _cmd_run_preset(
    preset_name: str,
    target: str | None,
    *,
    dry_run: bool,
    engagement_name: str | None,
    no_report: bool,
    skip_scanners: set[str],
    extra_url: str | None,
) -> int:
    from ..config import KODA_HOME, load_config
    from ..missions import get_preset, preset_names

    preset = get_preset(preset_name)
    if preset is None:
        valid = ", ".join(preset_names())
        print(
            f"error: unknown preset {preset_name!r}.\n"
            f"  Available presets: {valid}\n"
            f"  Run `koda audit --list-presets` for details.",
            file=sys.stderr,
        )
        return 1

    # --- target required check ---
    if preset.requires_target and not target:
        print(
            f"error: preset {preset_name!r} requires a target argument "
            f"({preset.default_target_type})",
            file=sys.stderr,
        )
        print(
            f"  usage: koda audit --preset {preset_name} <{preset.default_target_type}>",
            file=sys.stderr,
        )
        return 1

    effective_target = target or "."

    # --- approval tier enforcement ---
    if not dry_run:
        # Use KODA_HOME directly so tests that patch the module attr work correctly.
        _cfg_path = KODA_HOME / "config.yaml"
        config = load_config(_cfg_path) if (_cfg_path.exists() and _cfg_path.stat().st_size > 0) else {}
        if not _check_approval_tier(preset.approval_tier, config):
            config_tier = str(
                config.get("approvals", {}).get("auto_approve", "all")
            ).strip().lower()
            print(
                f"error: preset {preset_name!r} requires approval tier "
                f"{preset.approval_tier!r}, but current config is {config_tier!r}.\n"
                f"  Run `koda setup` to change the approval threshold.",
                file=sys.stderr,
            )
            return 1

    # --- print plan ---
    print(f"\nK.O.D.A. audit — {preset.title}")
    print(f"  preset:   {preset.name}")
    print(f"  target:   {effective_target}")
    print(f"  tier:     {preset.approval_tier}")
    print(f"  scanners: {', '.join(s for s in preset.scanners if s not in skip_scanners)}")
    if skip_scanners:
        print(f"  skipping: {', '.join(skip_scanners)}")
    if extra_url:
        print(f"  url:      {extra_url}")
    if dry_run:
        print("  mode:     DRY RUN — no scanners will execute")
    print()

    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    # --- dry-run ---
    if dry_run:
        _run_scanners(preset, effective_target, skip_scanners, extra_url, dry_run=True)
        print("\ndry-run complete — no scanners were executed.")
        return 0

    # --- engagement directory ---
    KODA_HOME.mkdir(parents=True, exist_ok=True)
    try:
        eng_dir = _resolve_engagement_dir(KODA_HOME, preset_name, engagement_name)
    except SystemExit as exc:
        return int(exc.code or 1)

    print(f"  engagement: {eng_dir}")
    print()

    # --- run scanners ---
    results = _run_scanners(preset, effective_target, skip_scanners, extra_url, dry_run=False)

    # --- persist findings ---
    findings_path = _save_findings_jsonl(eng_dir, results)
    total = sum(len(r.findings) for r in results)

    print(f"\n  findings saved → {findings_path}  ({total} total)")

    # --- report ---
    report_paths: dict[str, Path] | None = None
    if not no_report and results:
        print("  generating report...")
        report_paths = _generate_report(preset, eng_dir, effective_target, results, started_at)
        if report_paths:
            for fmt, path in report_paths.items():
                print(f"  report [{fmt}] → {path}")

    # --- severity summary ---
    summary = _severity_summary(results)
    print()
    print("  severity summary:")
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        n = summary.get(sev, 0)
        if n:
            print(f"    {sev:<10} {n}")
    if not summary:
        print("    (no findings)")

    has_blocker = _has_high_or_critical(results)
    print()
    if has_blocker:
        print("  RESULT: FAIL — HIGH or CRITICAL findings require remediation.")
        print()
        print("  Next steps:")
        for line in preset.next_steps.strip().splitlines():
            if line.strip():
                print(f"  {line}")
        print()
        return 1
    else:
        print("  RESULT: PASS — no HIGH/CRITICAL findings.")
        print()
        print("  Success criteria met:")
        for line in preset.success_criteria.strip().splitlines():
            if line.strip():
                print(f"  {line}")
        print()
        return 0


def main(argv: list[str]) -> int:
    """Entry point for ``koda audit``."""
    from ..missions import preset_names

    if not argv or argv[0] in {"-h", "--help"}:
        _print_usage()
        return 0

    if "--list-presets" in argv:
        return _cmd_list_presets()

    # --explain <preset>
    if "--explain" in argv:
        idx = argv.index("--explain")
        if idx + 1 >= len(argv):
            print("error: --explain requires a preset name", file=sys.stderr)
            return 2
        return _cmd_explain(argv[idx + 1])

    # Parse flags for --preset run
    preset_name: str | None = None
    target: str | None = None
    dry_run = False
    engagement_name: str | None = None
    no_report = False
    skip_scanners: set[str] = set()
    extra_url: str | None = None

    i = 0
    positional: list[str] = []
    while i < len(argv):
        arg = argv[i]
        if arg in {"--preset", "-p"}:
            if i + 1 >= len(argv):
                print("error: --preset requires a value", file=sys.stderr)
                return 2
            preset_name = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--preset="):
            preset_name = arg.split("=", 1)[1]
            i += 1
            continue
        if arg == "--dry-run":
            dry_run = True
            i += 1
            continue
        if arg == "--no-report":
            no_report = True
            i += 1
            continue
        if arg in {"--engagement", "-e"}:
            if i + 1 >= len(argv):
                print("error: --engagement requires a value", file=sys.stderr)
                return 2
            engagement_name = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--engagement="):
            engagement_name = arg.split("=", 1)[1]
            i += 1
            continue
        if arg == "--skip-scanner":
            if i + 1 >= len(argv):
                print("error: --skip-scanner requires a value", file=sys.stderr)
                return 2
            skip_scanners.add(argv[i + 1])
            i += 2
            continue
        if arg.startswith("--skip-scanner="):
            skip_scanners.add(arg.split("=", 1)[1])
            i += 1
            continue
        if arg == "--url":
            if i + 1 >= len(argv):
                print("error: --url requires a value", file=sys.stderr)
                return 2
            extra_url = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--url="):
            extra_url = arg.split("=", 1)[1]
            i += 1
            continue
        if arg.startswith("-"):
            print(f"error: unknown flag {arg!r}", file=sys.stderr)
            _print_usage()
            return 2
        positional.append(arg)
        i += 1

    if not preset_name:
        print(
            "error: --preset is required. "
            f"Available: {', '.join(preset_names())}",
            file=sys.stderr,
        )
        _print_usage()
        return 2

    if positional:
        target = positional[0]
    if len(positional) > 1:
        print(f"error: unexpected positional arguments: {positional[1:]}", file=sys.stderr)
        return 2

    return _cmd_run_preset(
        preset_name,
        target,
        dry_run=dry_run,
        engagement_name=engagement_name,
        no_report=no_report,
        skip_scanners=skip_scanners,
        extra_url=extra_url,
    )


def _print_usage() -> None:
    from ..missions import preset_names
    names = " | ".join(preset_names())
    print("usage:")
    print("  koda audit --list-presets")
    print("  koda audit --explain <preset>")
    print(f"  koda audit --preset <{names}> [target] [options]")
    print()
    print("options:")
    print("  --dry-run              print plan without running any scanner")
    print("  --engagement <name>    use existing engagement instead of throwaway")
    print("  --no-report            skip report generation")
    print("  --skip-scanner <name>  remove a scanner from the preset (repeatable)")
    print("  --url <url>            supplementary URL target (web-app / nuclei)")


__all__ = ["main"]
