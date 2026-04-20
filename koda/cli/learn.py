"""``koda learn`` — promote Helix concepts into reviewable skill drafts.

Subcommands:

    koda learn                     one cycle: consolidate → scan → draft
    koda learn list                show pending and approved learned skills
    koda learn approve <name>      promote pending/<name> → _learned/<name>
    koda learn reject  <name>      archive pending/<name> under _rejected/
    koda learn status              pipeline metrics
    koda learn schedule <action>   manage nightly cron entry
"""
from __future__ import annotations

import sys
from pathlib import Path

from koda.learning import (
    default_store,
    draft_skill_from_concept,
    find_candidates,
    scan_skill_draft,
)
from koda.learning.schedule import (
    get_learn_schedule,
    get_report_schedule,
    install_learn_schedule,
    install_report_schedule,
    remove_learn_schedule,
    remove_report_schedule,
)

_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        _print_help()
        return 0 if argv and argv[0] in {"-h", "--help"} else _cmd_run([])

    cmd = argv[0]
    rest = argv[1:]

    if cmd == "run":
        return _cmd_run(rest)
    if cmd == "list":
        return _cmd_list(rest)
    if cmd == "approve":
        return _cmd_approve(rest)
    if cmd == "reject":
        return _cmd_reject(rest)
    if cmd == "status":
        return _cmd_status(rest)
    if cmd == "schedule":
        return _cmd_schedule(rest)
    if cmd == "report":
        return _cmd_report(rest)

    print(f"error: unknown subcommand {cmd!r}", file=sys.stderr)
    print("run `koda learn --help` for usage", file=sys.stderr)
    return 2


def _print_help() -> None:
    print("usage: koda learn [run] [--dry-run] [--min-confidence F] [--min-evidence N]")
    print("       koda learn list")
    print("       koda learn approve <name>")
    print("       koda learn reject  <name>")
    print("       koda learn status")
    print("       koda learn schedule [<time>|off]")
    print("       koda learn report   [<time>|off|status|--since DUR|--stdout]")
    print()
    print("  run              (default) consolidate Helix, scan for candidates,")
    print("                   write drafts to _pending/")
    print("                   flags: --llm[=provider] --llm-model NAME")
    print("  list             show pending + approved learned skills")
    print("  approve <name>   move _pending/<name> into _learned/<name>")
    print("  reject  <name>   archive draft under _rejected/")
    print("  status           show pipeline counts")
    print("  schedule <time>  install nightly `koda learn run`; bare = status, `off` = remove")
    print("  report           bare = digest now; <time> = schedule it daily; `off` = remove")
    print()
    print("  <time> accepts: 8am, 2:30pm, 14:00, or a raw 5-field cron expression.")


def _cmd_run(argv: list[str]) -> int:
    dry_run = False
    min_confidence = 0.7
    min_evidence = 5
    max_candidates = 10
    skip_consolidate = False
    llm_provider: str | None = None
    llm_model: str | None = None

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--dry-run":
            dry_run = True
        elif arg == "--skip-consolidate":
            skip_consolidate = True
        elif arg == "--min-confidence" and i + 1 < len(argv):
            min_confidence = float(argv[i + 1])
            i += 1
        elif arg == "--min-evidence" and i + 1 < len(argv):
            min_evidence = int(argv[i + 1])
            i += 1
        elif arg == "--limit" and i + 1 < len(argv):
            max_candidates = int(argv[i + 1])
            i += 1
        elif arg == "--llm":
            llm_provider = "ollama"
        elif arg.startswith("--llm="):
            llm_provider = arg.split("=", 1)[1] or "ollama"
        elif arg == "--llm-provider" and i + 1 < len(argv):
            llm_provider = argv[i + 1]
            i += 1
        elif arg == "--llm-model" and i + 1 < len(argv):
            llm_model = argv[i + 1]
            i += 1
        else:
            print(f"error: unknown flag {arg!r}", file=sys.stderr)
            return 2
        i += 1

    synth = _make_synthesizer(llm_provider, llm_model)
    if synth is None:
        return 1

    helix = _open_helix()
    if helix is None:
        print(f"{_YELLOW}⚠ Helix not initialized — nothing to learn from yet.{_RESET}")
        return 0

    try:
        if not skip_consolidate:
            result = helix.consolidate()
            print(
                f"{_DIM}consolidated:{_RESET} "
                f"{result.concepts_created} new · "
                f"{result.concepts_reinforced} reinforced · "
                f"{result.conflicts_detected} conflicts"
            )

        store = default_store()
        already = store.pending_concept_ids()

        candidates = find_candidates(
            helix=helix,
            min_confidence=min_confidence,
            min_evidence=min_evidence,
            limit=max_candidates,
            exclude_concept_ids=already,
        )
        if not candidates:
            print(f"{_GREEN}✓ no new candidates above threshold{_RESET}")
            return 0

        drafted = 0
        blocked = 0
        for cand in candidates:
            draft = synth(cand.concept, cand.episodes)
            report = scan_skill_draft(
                name=draft.name,
                description=draft.description,
                body=draft.body,
            )
            if not report.clean:
                blocked += 1
                print(
                    f"{_RED}✗ blocked {draft.name}{_RESET} "
                    f"{_DIM}({cand.concept_id[:10]}){_RESET}: "
                    f"{report.summary()}"
                )
                continue

            if dry_run:
                drafted += 1
                print(
                    f"{_DIM}would draft{_RESET} {_BOLD}{draft.name}{_RESET} "
                    f"{_DIM}← {cand.concept_id[:10]} "
                    f"conf={cand.confidence:.2f} ep={len(cand.episodes)}{_RESET}"
                )
                continue

            source = {
                "concept_id": cand.concept_id,
                "title": cand.title,
                "confidence": cand.confidence,
                "evidence_count": len(cand.episodes),
            }
            store.save_pending(
                name=draft.name, skill_md=draft.render(), source=source,
            )
            drafted += 1
            print(
                f"{_GREEN}+ drafted{_RESET} {_BOLD}{draft.name}{_RESET} "
                f"{_DIM}← {cand.concept_id[:10]} "
                f"conf={cand.confidence:.2f} ep={len(cand.episodes)}{_RESET}"
            )

        print()
        verb = "would draft" if dry_run else "drafted"
        print(
            f"{_BOLD}{drafted}{_RESET} {verb}, "
            f"{_BOLD}{blocked}{_RESET} blocked by guard."
        )
        if not dry_run and drafted:
            print(f"  review: {_DIM}koda learn list{_RESET}")
        return 0
    finally:
        helix.close()


def _cmd_list(argv: list[str]) -> int:
    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda learn list")
        return 0
    store = default_store()
    pending = store.list_pending()
    approved = store.list_approved()

    print(f"{_BOLD}pending{_RESET} ({len(pending)}):")
    if not pending:
        print(f"  {_DIM}none — run `koda learn` to generate drafts{_RESET}")
    for p in pending:
        cid = p.source.get("concept_id", "?")
        ev = p.source.get("evidence_count", "?")
        conf = p.source.get("confidence")
        conf_str = f"{conf:.2f}" if isinstance(conf, (int, float)) else "?"
        print(f"  • {p.name}  {_DIM}← {cid[:10]} conf={conf_str} ep={ev}{_RESET}")

    print()
    print(f"{_BOLD}approved{_RESET} ({len(approved)}):")
    if not approved:
        print(f"  {_DIM}none yet{_RESET}")
    for path in approved:
        print(f"  • {path.name}  {_DIM}{path}{_RESET}")
    return 0


def _cmd_approve(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage: koda learn approve <name>")
        return 0 if argv else 2
    name = argv[0]
    store = default_store()
    try:
        dest = store.approve(name)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{_GREEN}✓ approved{_RESET} {name} → {dest}")
    print(f"  {_DIM}auto-loaded by SkillLoader on next koda run{_RESET}")
    return 0


def _cmd_reject(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage: koda learn reject <name>")
        return 0 if argv else 2
    name = argv[0]
    store = default_store()
    try:
        dest = store.reject(name)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{_YELLOW}✓ rejected{_RESET} {name} → {dest}")
    return 0


def _cmd_status(argv: list[str]) -> int:
    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda learn status")
        return 0
    store = default_store()
    pending = store.list_pending()
    approved = store.list_approved()

    print(f"  pending   {len(pending)}")
    print(f"  approved  {len(approved)}")

    helix = _open_helix()
    if helix is None:
        print(f"  helix     {_DIM}uninitialized{_RESET}")
        return 0
    try:
        concepts = helix.beta.recall(min_confidence=0.0, limit=10000)
        episodes = helix.alpha.recall_recent(hours=24 * 30, limit=10000)
        promotable = [
            c for c in concepts
            if float(getattr(c, "confidence", 0)) >= 0.7
            and int(getattr(c, "evidence_count", 0)) >= 5
            and str(getattr(c, "category", "")) in {"pattern", "procedure", "rule"}
        ]
        print(f"  helix     {len(episodes)} episodes · {len(concepts)} concepts")
        print(f"  ready     {len(promotable)} concepts above promotion threshold")
    finally:
        helix.close()
    return 0


def _make_synthesizer(provider_name: str | None, model: str | None):
    """Return a callable ``(concept, episodes) -> SkillDraft``.

    Template synthesizer by default. If ``provider_name`` is set, build a
    provider + wrap the async LLM synthesizer in a sync shim. Returns ``None``
    if provider construction fails — caller prints a clean error.
    """
    if not provider_name:
        def template(concept, episodes):
            return draft_skill_from_concept(
                concept=concept, evidence_episodes=episodes,
            )
        return template

    try:
        from koda.adapters import create_provider
        from koda.learning.synthesizer_llm import draft_skill_from_concept_llm_sync
    except ImportError as exc:
        print(f"error: LLM synthesizer unavailable: {exc}", file=sys.stderr)
        return None

    cfg: dict[str, object] = {}
    if model:
        cfg["model"] = model
    try:
        provider = create_provider(provider_name, cfg)
    except Exception as exc:
        print(f"error: could not create provider {provider_name!r}: {exc}", file=sys.stderr)
        return None

    def llm(concept, episodes):
        return draft_skill_from_concept_llm_sync(
            concept=concept,
            evidence_episodes=episodes,
            provider=provider,
        )
    print(f"{_DIM}using LLM synthesizer: {provider_name}"
          f"{f' / {model}' if model else ''}{_RESET}")
    return llm


def _cmd_schedule(argv: list[str]) -> int:
    """Manage the nightly `koda learn run` cron. ``argv`` is a natural time
    spec ("8am", "14:30", raw cron), "off", "status", or empty."""
    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda learn schedule [<time>|off|status]")
        print()
        print("  <time>   e.g. 8am, 2:30pm, 14:00, or `0 8 * * *`")
        print("  off      remove the cron entry")
        print("  (bare)   show current schedule")
        return 0

    if not argv or argv[0] == "status":
        return _print_schedule_status(
            entry=get_learn_schedule(),
            label="nightly learn",
            install_hint="koda learn schedule 2am",
        )

    first = argv[0].lower()
    if first in {"off", "remove", "none"}:
        return _remove_cron(remove_learn_schedule)

    cron_expr = _parse_time_to_cron(" ".join(argv))
    if cron_expr is None:
        print(
            f"error: could not parse time {' '.join(argv)!r}. "
            "Try 8am, 2:30pm, 14:00, or a 5-field cron expression.",
            file=sys.stderr,
        )
        return 2
    try:
        entry = install_learn_schedule(cron_expr=cron_expr)
    except Exception as exc:
        print(f"error: could not install cron entry: {exc}", file=sys.stderr)
        return 1
    print(f"{_GREEN}✓ scheduled{_RESET} {entry.cron_expr}  {_DIM}{entry.command}{_RESET}")
    return 0


def _cmd_report(argv: list[str]) -> int:
    """Either generate a digest now or manage the digest schedule.

    Shape:
      koda learn report                   generate digest, write to disk
      koda learn report --since 7d        generate with custom window
      koda learn report --stdout          print instead of writing
      koda learn report <time>            schedule daily digest at <time>
      koda learn report off               remove schedule
      koda learn report status            show schedule
    """
    if argv and argv[0] in {"-h", "--help"}:
        print("usage: koda learn report                        (generate digest now)")
        print("       koda learn report [--since DUR] [--stdout]")
        print("       koda learn report <time>                 (schedule daily)")
        print("       koda learn report off|status")
        print()
        print("  <time>   e.g. 8am, 2:30pm, 14:00, or `0 8 * * *`")
        print("  DUR      30m / 24h / 7d (default 24h); `all` for lifetime")
        return 0

    # Schedule-management branches.
    if argv and argv[0].lower() == "status":
        return _print_schedule_status(
            entry=get_report_schedule(),
            label="daily digest",
            install_hint="koda learn report 8am",
        )
    if argv and argv[0].lower() in {"off", "remove", "none"}:
        return _remove_cron(remove_report_schedule)

    # If the first token parses cleanly as a time, treat the whole argv as
    # "schedule" rather than "generate now". Flags are never time specs,
    # so `--since`/`--stdout` can't collide here.
    if argv and not argv[0].startswith("-"):
        cron_expr = _parse_time_to_cron(" ".join(argv))
        if cron_expr is not None:
            try:
                entry = install_report_schedule(cron_expr=cron_expr)
            except Exception as exc:
                print(f"error: could not install cron entry: {exc}", file=sys.stderr)
                return 1
            print(
                f"{_GREEN}✓ scheduled{_RESET} {entry.cron_expr}  "
                f"{_DIM}{entry.command}{_RESET}"
            )
            return 0

    # ── Generate-now path ────────────────────────────────────────────
    since_raw = "24h"
    to_stdout = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--since" and i + 1 < len(argv):
            since_raw = argv[i + 1]
            i += 1
        elif arg == "--stdout":
            to_stdout = True
        else:
            print(f"error: unknown flag {arg!r}", file=sys.stderr)
            return 2
        i += 1

    from koda.learning.report import generate_report, write_report

    since = _parse_since(since_raw)
    report = generate_report(since=since)

    if to_stdout:
        md = report.render_markdown()
        sys.stdout.write(md)
        if not md.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    dest = write_report(report)
    window = "lifetime" if since is None else f"since {since.isoformat()}"
    print(
        f"{_GREEN}✓ digest written{_RESET} {dest}  "
        f"{_DIM}({window}): "
        f"pending={len(report.pending)} approved={len(report.approved)} "
        f"rejected={len(report.rejected)}{_RESET}"
    )
    return 0


def _print_schedule_status(*, entry, label: str, install_hint: str) -> int:
    if entry is None:
        print(f"{_DIM}no {label} schedule installed{_RESET}")
        print(f"  install: {_DIM}{install_hint}{_RESET}")
        return 0
    print(f"{_GREEN}✓ installed{_RESET}  {_BOLD}{entry.cron_expr}{_RESET}")
    print(f"  command: {_DIM}{entry.command}{_RESET}")
    return 0


def _remove_cron(remover) -> int:
    try:
        removed = remover()
    except Exception as exc:
        print(f"error: could not remove cron entry: {exc}", file=sys.stderr)
        return 1
    if removed:
        print(f"{_GREEN}✓ removed{_RESET}")
    else:
        print(f"{_DIM}nothing to remove{_RESET}")
    return 0


def _parse_time_to_cron(text: str) -> str | None:
    """Parse a human time into a 5-field cron expression.

    Accepts: ``8am``, ``2:30pm``, ``14:00``, ``0 8 * * *``. Returns ``None``
    if nothing matches so the caller can error gracefully.
    """
    stripped = text.strip()
    if not stripped:
        return None

    # Raw 5-field cron — e.g. "*/15 * * * *" or "0 8 * * 1-5". Pass through
    # without validation; crontab will reject anything malformed.
    parts = stripped.split()
    if len(parts) == 5 and any(c in stripped for c in "*,-/"):
        return stripped
    if len(parts) == 5 and all(
        _looks_like_cron_field(p) for p in parts
    ):
        return stripped

    raw = stripped.lower().replace(" ", "")

    suffix: str | None = None
    if raw.endswith("am"):
        suffix, raw = "am", raw[:-2]
    elif raw.endswith("pm"):
        suffix, raw = "pm", raw[:-2]

    if ":" in raw:
        hh_str, _, mm_str = raw.partition(":")
    else:
        hh_str, mm_str = raw, "0"

    if not (hh_str.isdigit() and mm_str.isdigit()):
        return None
    hour = int(hh_str)
    minute = int(mm_str)

    if suffix == "am":
        if not 1 <= hour <= 12:
            return None
        if hour == 12:
            hour = 0
    elif suffix == "pm":
        if not 1 <= hour <= 12:
            return None
        if hour < 12:
            hour += 12

    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return None

    return f"{minute} {hour} * * *"


def _looks_like_cron_field(field: str) -> bool:
    # Very loose — anything made of digits / commas / dashes / slashes /
    # asterisks / L / W / # counts as a cron field for passthrough.
    return bool(field) and all(c.isdigit() or c in "*,-/LW#" for c in field)


def _parse_since(raw: str):
    """Parse ``--since`` values: ``24h`` / ``7d`` / ``30m`` / ``none|all``."""
    from datetime import UTC, datetime, timedelta

    raw = raw.strip().lower()
    if raw in {"none", "all", "0", ""}:
        return None
    units = {"m": 60, "h": 3600, "d": 86400}
    if raw[-1] in units and raw[:-1].isdigit():
        seconds = int(raw[:-1]) * units[raw[-1]]
        return datetime.now(UTC) - timedelta(seconds=seconds)
    # Fallback: attempt ISO-8601 parse.
    try:
        ts = datetime.fromisoformat(raw.replace("z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts
    except ValueError:
        # Permissive default — 24 h if we can't parse it.
        return datetime.now(UTC) - timedelta(hours=24)


def _open_helix():
    """Open the Helix store at ``$KODA_HOME/memory/``; return None on failure."""
    from koda.config import KODA_HOME
    from koda.memory.helix import Helix

    memory_dir = KODA_HOME / "memory"
    if not memory_dir.is_dir():
        return None
    try:
        return Helix(memory_dir)
    except Exception as exc:  # pragma: no cover — sqlite corruption etc.
        print(f"{_YELLOW}⚠ Helix unavailable: {exc}{_RESET}", file=sys.stderr)
        return None


def _open_helix_for_testing(base_dir: Path):
    """Test helper — open Helix at an explicit path without touching $HOME."""
    from koda.memory.helix import Helix
    return Helix(base_dir)
