"""``koda cost`` — aggregate token + USD usage from the audit log.

Why this is separate from ``quota``:

  - Quota gates *block* a request when a cap is hit — it's a runtime
    control.
  - ``koda cost`` is a forensic rollup. It reads ``audit.jsonl`` after
    the fact and answers "what did the last engagement cost me?"
    Pricing is best-effort (see ``koda/providers/pricing.py``); local
    and unpriced models are counted in tokens only.

Usage:
  koda cost                              rollup across the whole log
  koda cost --engagement NAME            filter to one engagement
  koda cost --by model|engagement|session
  koda cost --since YYYY-MM-DD
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


def _iter_turn_events(log_path: Path) -> list[dict[str, Any]]:
    """Yield turn.complete / turn.aborted records, ignoring malformed lines."""
    if not log_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("event") in {"turn.complete", "turn.aborted"}:
                rows.append(rec)
    return rows


def _parse_since(raw: str) -> float | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    # Accept YYYY-MM-DD or a raw unix timestamp.
    try:
        return float(raw)
    except ValueError:
        pass
    import datetime as _dt
    try:
        return _dt.datetime.strptime(raw, "%Y-%m-%d").replace(
            tzinfo=_dt.UTC
        ).timestamp()
    except ValueError:
        print(f"warning: could not parse --since {raw!r}", file=sys.stderr)
        return None


def _key_for(rec: dict[str, Any], group_by: str) -> str:
    if group_by == "model":
        return rec.get("model") or "(unknown)"
    if group_by == "engagement":
        return rec.get("engagement") or "(none)"
    if group_by == "session":
        return rec.get("session_id") or "(none)"
    return "(all)"


def _cmd_cost(args: argparse.Namespace) -> int:
    from ..audit.logger import default_log_path

    log_path = Path(args.log).expanduser() if args.log else default_log_path()
    rows = _iter_turn_events(log_path)

    engagement_filter = (args.engagement or "").strip()
    since_ts = _parse_since(args.since or "")

    totals: dict[str, dict[str, float]] = defaultdict(
        lambda: {"turns": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0, "unpriced": 0}
    )

    for rec in rows:
        if engagement_filter and rec.get("engagement") != engagement_filter:
            continue
        if since_ts is not None:
            ts = rec.get("ts") or rec.get("timestamp")
            try:
                if ts is None or float(ts) < since_ts:
                    continue
            except (TypeError, ValueError):
                continue
        key = _key_for(rec, args.by)
        bucket = totals[key]
        bucket["turns"] += 1
        bucket["tokens_in"] += int(rec.get("tokens_prompt") or 0)
        bucket["tokens_out"] += int(rec.get("tokens_completion") or 0)
        cost = rec.get("cost_usd")
        if cost is None:
            bucket["unpriced"] += 1
        else:
            try:
                bucket["cost_usd"] += float(cost)
            except (TypeError, ValueError):
                bucket["unpriced"] += 1

    if not totals:
        print(f"no turn events found in {log_path}")
        return 0

    # Sorted by total cost desc, then tokens_out desc.
    ordered = sorted(
        totals.items(),
        key=lambda kv: (-kv[1]["cost_usd"], -kv[1]["tokens_out"]),
    )

    col_label = args.by
    print(f"{col_label:<32}  {'turns':>6}  {'tokens_in':>11}  {'tokens_out':>11}  {'USD':>10}  unpriced")
    print("-" * 90)
    grand = {"turns": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0, "unpriced": 0}
    for key, b in ordered:
        print(
            f"{key[:32]:<32}  "
            f"{int(b['turns']):>6}  "
            f"{int(b['tokens_in']):>11,}  "
            f"{int(b['tokens_out']):>11,}  "
            f"${b['cost_usd']:>9.4f}  "
            f"{int(b['unpriced']):>8}"
        )
        grand["turns"] += b["turns"]
        grand["tokens_in"] += b["tokens_in"]
        grand["tokens_out"] += b["tokens_out"]
        grand["cost_usd"] += b["cost_usd"]
        grand["unpriced"] += b["unpriced"]

    print("-" * 90)
    print(
        f"{'TOTAL':<32}  "
        f"{int(grand['turns']):>6}  "
        f"{int(grand['tokens_in']):>11,}  "
        f"{int(grand['tokens_out']):>11,}  "
        f"${grand['cost_usd']:>9.4f}  "
        f"{int(grand['unpriced']):>8}"
    )
    if grand["unpriced"]:
        print(
            f"\nnote: {int(grand['unpriced'])} turn(s) ran on unpriced/local models "
            f"(tokens counted, USD = $0.00)."
        )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="koda cost",
        description="Aggregate token usage and rough USD cost from the audit log.",
    )
    parser.add_argument(
        "--by",
        default="model",
        choices=["model", "engagement", "session"],
        help="group results by this field (default: model)",
    )
    parser.add_argument(
        "--engagement", default="", help="filter to a single engagement name"
    )
    parser.add_argument(
        "--since",
        default="",
        help="only count events after this date (YYYY-MM-DD or unix ts)",
    )
    parser.add_argument(
        "--log",
        default="",
        help="path to audit.jsonl (default: KODA_HOME/logs/audit.jsonl)",
    )
    parser.set_defaults(func=_cmd_cost)
    return parser


def main(argv: list[str]) -> int:
    if argv and argv[0] in {"-h", "--help"}:
        _build_parser().print_help()
        return 0
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
