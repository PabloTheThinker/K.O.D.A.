"""``koda learn`` — promote Helix concepts into reviewable skill drafts.

Subcommands:

    koda learn                     one cycle: consolidate → scan → draft
    koda learn list                show pending and approved learned skills
    koda learn approve <name>      promote pending/<name> → _learned/<name>
    koda learn reject  <name>      archive pending/<name> under _rejected/
    koda learn status              pipeline metrics
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

    print(f"error: unknown subcommand {cmd!r}", file=sys.stderr)
    print("run `koda learn --help` for usage", file=sys.stderr)
    return 2


def _print_help() -> None:
    print("usage: koda learn [run] [--dry-run] [--min-confidence F] [--min-evidence N]")
    print("       koda learn list")
    print("       koda learn approve <name>")
    print("       koda learn reject  <name>")
    print("       koda learn status")
    print()
    print("  run              (default) consolidate Helix, scan for candidates,")
    print("                   write drafts to _pending/")
    print("  list             show pending + approved learned skills")
    print("  approve <name>   move _pending/<name> into _learned/<name>")
    print("  reject  <name>   archive draft under _rejected/")
    print("  status           show pipeline counts")


def _cmd_run(argv: list[str]) -> int:
    dry_run = False
    min_confidence = 0.7
    min_evidence = 5
    max_candidates = 10
    skip_consolidate = False

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
        else:
            print(f"error: unknown flag {arg!r}", file=sys.stderr)
            return 2
        i += 1

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
            draft = draft_skill_from_concept(
                concept=cand.concept,
                evidence_episodes=cand.episodes,
            )
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
