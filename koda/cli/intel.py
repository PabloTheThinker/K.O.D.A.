"""``koda intel`` subcommand: sync / status / lookup / search.

Thin argparse wrapper over ``koda.intel.store.ThreatIntel`` and
``koda.intel.feeds``. Plain ASCII output, no colors. All network work is
delegated to the sync functions; this module only dispatches and formats.
"""
from __future__ import annotations

import argparse
import re
import sys

from ..intel.feeds import (
    attack_for_cwe,
    extended_counts,
    lookup_attack_technique,
    lookup_capec,
    lookup_exploits_for_cve,
    register_extended_schema,
    sync_attack,
    sync_capec,
    sync_exploitdb,
    sync_nvd,
)
from ..intel.store import ThreatIntel

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_TECH_RE = re.compile(r"^T\d{4}(\.\d+)?$", re.IGNORECASE)
_CAPEC_RE = re.compile(r"^CAPEC-\d+$", re.IGNORECASE)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="koda intel")
    sub = parser.add_subparsers(dest="cmd")

    p_sync = sub.add_parser("sync", help="sync intel feeds")
    p_sync.add_argument("--kev", action="store_true")
    p_sync.add_argument("--epss", action="store_true")
    p_sync.add_argument("--cwe", action="store_true")
    p_sync.add_argument("--nvd", action="store_true")
    p_sync.add_argument("--exploitdb", action="store_true")
    p_sync.add_argument("--attack", action="store_true")
    p_sync.add_argument("--capec", action="store_true")
    p_sync.add_argument("--all", action="store_true")

    sub.add_parser("status", help="show feed freshness + row counts")

    p_lookup = sub.add_parser("lookup", help="lookup an intel ID")
    p_lookup.add_argument("id")

    p_search = sub.add_parser("search", help="substring search CVEs + techniques")
    p_search.add_argument("keyword")

    return parser


def _cmd_sync(args: argparse.Namespace, intel: ThreatIntel) -> int:
    want_kev = args.kev
    want_epss = args.epss
    want_cwe = args.cwe
    want_nvd = args.nvd
    want_exploitdb = args.exploitdb
    want_attack = args.attack
    want_capec = args.capec

    any_flag = any(
        (
            want_kev,
            want_epss,
            want_cwe,
            want_nvd,
            want_exploitdb,
            want_attack,
            want_capec,
            args.all,
        )
    )
    if not any_flag:
        # Default: KEV + EPSS.
        want_kev = True
        want_epss = True

    if args.all:
        want_kev = want_epss = want_cwe = True
        want_nvd = want_exploitdb = want_attack = want_capec = True

    needs_extended = want_nvd or want_exploitdb or want_attack or want_capec
    if needs_extended:
        assert intel._conn is not None
        register_extended_schema(intel._conn)

    # Core feeds via ThreatIntel.sync (returns dict).
    if want_kev or want_epss or want_cwe:
        status = intel.sync(kev=want_kev, epss=want_epss, cwe=want_cwe)
        for feed in ("kev", "epss", "cwe"):
            if feed in status:
                print(f"[{feed}] {status[feed]}")

    if want_nvd:
        print(f"[nvd] {sync_nvd(intel)}")
    if want_exploitdb:
        print(f"[exploitdb] {sync_exploitdb(intel)}")
    if want_attack:
        print(f"[attack] {sync_attack(intel)}")
    if want_capec:
        print(f"[capec] {sync_capec(intel)}")

    return 0


def _cmd_status(intel: ThreatIntel) -> int:
    fresh = intel.freshness()
    assert intel._conn is not None
    register_extended_schema(intel._conn)
    ext = extended_counts(intel)

    print("Freshness")
    print(f"{'kev_last_sync':<20} {fresh.kev_last_sync or '-'}")
    print(f"{'epss_last_sync':<20} {fresh.epss_last_sync or '-'}")
    print(f"{'cwe_last_sync':<20} {fresh.cwe_last_sync or '-'}")
    print(f"{'nvd_last_sync':<20} {fresh.nvd_last_sync or '-'}")
    print()
    print("Row counts")
    for label in ("cves", "kev", "epss", "cwes"):
        print(f"{label:<20} {fresh.counts.get(label, 0)}")
    for label in ("exploits", "attack_techniques", "attack_tactics", "capec"):
        print(f"{label:<20} {ext.get(label, 0)}")
    return 0


def _print_cve_bundle(intel: ThreatIntel, cve_id: str) -> None:
    bundle = intel.lookup_cve(cve_id)
    print(f"CVE: {bundle.cve_id}")
    if bundle.cve is not None:
        print(f"  description: {bundle.cve.description}")
        print(f"  cvss_v3:     {bundle.cve.cvss_v3_score} ({bundle.cve.cvss_v3_vector})")
        print(f"  cwe_ids:     {', '.join(bundle.cve.cwe_ids) or '-'}")
        print(f"  published:   {bundle.cve.published_at}")
        print(f"  modified:    {bundle.cve.last_modified}")
    else:
        print("  (no CVE row; run `koda intel sync --nvd`)")
    if bundle.kev is not None:
        print(
            f"  KEV: vendor={bundle.kev.vendor} product={bundle.kev.product}"
            f" ransomware={bundle.kev.known_ransomware}"
        )
    if bundle.epss is not None:
        print(
            f"  EPSS: score={bundle.epss.score} percentile={bundle.epss.percentile}"
        )
    for cwe in bundle.cwes:
        print(f"  CWE {cwe.cwe_id}: {cwe.name}")

    print()
    print("Exploits")
    exploits = lookup_exploits_for_cve(intel, cve_id)
    if not exploits:
        print("  (none)")
    for exp in exploits:
        print(
            f"  EDB-{exp.edb_id} [{exp.platform}/{exp.type}]"
            f" verified={exp.verified} — {exp.description}"
        )

    print()
    print("ATT&CK chain (via CWE -> CAPEC)")
    shown = False
    if bundle.cve is not None:
        for cwe_id in bundle.cve.cwe_ids:
            capecs = attack_for_cwe(intel, cwe_id)
            for cap in capecs:
                shown = True
                print(
                    f"  {cwe_id} -> {cap.capec_id} {cap.name}"
                    f" (severity={cap.typical_severity or '-'},"
                    f" likelihood={cap.likelihood_of_attack or '-'})"
                )
    if not shown:
        print("  (none)")


def _print_cwe(intel: ThreatIntel, cwe_id: str) -> int:
    assert intel._conn is not None
    with intel._lock:
        row = intel._conn.execute(
            "SELECT cwe_id, name, description, url FROM cwes WHERE cwe_id=?",
            (cwe_id,),
        ).fetchone()
    if row is None:
        print(f"CWE not found: {cwe_id}")
        return 1
    print(f"CWE: {row['cwe_id']}")
    print(f"  name: {row['name']}")
    print(f"  url:  {row['url']}")
    print(f"  description: {row['description']}")
    print()
    print("Related CAPECs")
    capecs = attack_for_cwe(intel, cwe_id)
    if not capecs:
        print("  (none)")
    for cap in capecs:
        print(
            f"  {cap.capec_id} {cap.name}"
            f" (severity={cap.typical_severity or '-'},"
            f" likelihood={cap.likelihood_of_attack or '-'})"
        )
    return 0


def _cmd_lookup(args: argparse.Namespace, intel: ThreatIntel) -> int:
    raw = (args.id or "").strip().upper()
    if not raw:
        print("unrecognized id format", file=sys.stderr)
        return 2

    assert intel._conn is not None
    register_extended_schema(intel._conn)

    if _CVE_RE.match(raw):
        _print_cve_bundle(intel, raw)
        return 0
    if _CWE_RE.match(raw):
        return _print_cwe(intel, raw)
    if _TECH_RE.match(raw):
        tech = lookup_attack_technique(intel, raw)
        if tech is None:
            print(f"technique not found: {raw}")
            return 1
        print(f"Technique: {tech.technique_id}")
        print(f"  name:       {tech.name}")
        print(f"  tactic:     {tech.tactic}")
        print(f"  url:        {tech.url}")
        print(f"  sub:        {tech.is_subtechnique} parent={tech.parent_id or '-'}")
        print(f"  description: {tech.description}")
        return 0
    if _CAPEC_RE.match(raw):
        cap = lookup_capec(intel, raw)
        if cap is None:
            print(f"CAPEC not found: {raw}")
            return 1
        print(f"CAPEC: {cap.capec_id}")
        print(f"  name:       {cap.name}")
        print(f"  severity:   {cap.typical_severity or '-'}")
        print(f"  likelihood: {cap.likelihood_of_attack or '-'}")
        print(f"  url:        {cap.url}")
        print(f"  cwe_ids:    {', '.join(cap.cwe_ids) or '-'}")
        print(f"  description: {cap.description}")
        return 0

    print("unrecognized id format", file=sys.stderr)
    return 2


def _cmd_search(args: argparse.Namespace, intel: ThreatIntel) -> int:
    kw = (args.keyword or "").strip()
    if not kw:
        print("empty keyword", file=sys.stderr)
        return 2
    pattern = f"%{kw}%"

    assert intel._conn is not None
    register_extended_schema(intel._conn)

    with intel._lock:
        cve_rows = intel._conn.execute(
            "SELECT cve_id, description FROM cves WHERE description LIKE ? LIMIT 20",
            (pattern,),
        ).fetchall()
        tech_rows = intel._conn.execute(
            "SELECT technique_id, name FROM attack_techniques WHERE name LIKE ? LIMIT 20",
            (pattern,),
        ).fetchall()

    print(f"CVEs matching '{kw}' ({len(cve_rows)})")
    if not cve_rows:
        print("  (none)")
    for row in cve_rows:
        desc = (row["description"] or "").replace("\n", " ")
        if len(desc) > 100:
            desc = desc[:97] + "..."
        print(f"  {row['cve_id']:<18} {desc}")

    print()
    print(f"ATT&CK techniques matching '{kw}' ({len(tech_rows)})")
    if not tech_rows:
        print("  (none)")
    for row in tech_rows:
        print(f"  {row['technique_id']:<10} {row['name']}")

    return 0


def main(argv: list[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 2

    intel = ThreatIntel()
    try:
        if args.cmd == "sync":
            return _cmd_sync(args, intel)
        if args.cmd == "status":
            return _cmd_status(intel)
        if args.cmd == "lookup":
            return _cmd_lookup(args, intel)
        if args.cmd == "search":
            return _cmd_search(args, intel)
        parser.print_help()
        return 2
    finally:
        intel.close()


__all__ = ["main"]
