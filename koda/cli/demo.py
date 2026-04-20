"""``koda demo`` — self-contained tour of the full KODA loop.

Creates a synthetic engagement on disk, seeds a handful of hand-crafted
findings, and runs the standard report generator. Fully offline — no
scanner shells out, no network egress. The goal is a one-command
smoke-check an analyst can run on a fresh laptop to confirm the
pipeline (engagement → findings → report bundle) is wired up before
they point KODA at anything real.

Usage:
  koda demo [--name NAME] [--keep]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from argparse import Namespace
from pathlib import Path

_DEMO_TOML = """\
id = "ENG-DEMO"
name = "Demo Engagement"
scope = "127.0.0.1"
operator = "demo"
mode = "red"
targets = ["127.0.0.1"]
client = "(none)"
roe_id = "DEMO-ROE"
"""


def _synthetic_findings() -> list[dict]:
    """Hand-crafted findings that exercise CRIT/HIGH/MED severity + CVE + KEV paths."""
    from ..security.findings import FindingStatus, Severity, UnifiedFinding

    specs = [
        dict(
            scanner="demo",
            rule_id="DEMO-001",
            severity=Severity.CRITICAL,
            title="Exposed OpenSSH with known RCE (CVE-2023-38408)",
            description=(
                "Synthetic finding: OpenSSH agent forwarding accepts crafted PKCS#11 "
                "provider paths leading to remote code execution. Shown here to "
                "exercise the CISA-KEV / CVE enrichment path."
            ),
            category="remote-code-execution",
            file_path="demo://127.0.0.1:22",
            cve=["CVE-2023-38408"],
            cwe=["CWE-77"],
            cisa_kev=True,
            cvss_score=9.8,
            epss_score=0.42,
            fix_suggestion="Upgrade OpenSSH to 9.3p2 or later.",
        ),
        dict(
            scanner="demo",
            rule_id="DEMO-002",
            severity=Severity.HIGH,
            title="Hard-coded secret in configuration",
            description=(
                "Synthetic finding: a static API token committed to a config file. "
                "Demonstrates secret-leak categorization."
            ),
            category="secret-leak",
            file_path="demo://config/prod.yaml",
            start_line=42,
            end_line=42,
            snippet='api_token: "sk-demo-XXXXXXXXXXXXXXXXXXXXXXXX"',
            cwe=["CWE-798"],
            cvss_score=7.5,
            fix_suggestion="Move the token to a secret manager and rotate the leaked value.",
        ),
        dict(
            scanner="demo",
            rule_id="DEMO-003",
            severity=Severity.HIGH,
            title="SQL injection via string concatenation",
            description=(
                "Synthetic finding: user-controlled input is concatenated into a SQL "
                "statement. Shown to exercise the technical-report code-snippet path."
            ),
            category="injection",
            file_path="demo://app/handlers/orders.py",
            start_line=118,
            end_line=120,
            snippet='query = "SELECT * FROM orders WHERE id = " + request.args["id"]',
            cwe=["CWE-89"],
            cvss_score=8.1,
            fix_suggestion="Use parameterized queries (e.g., psycopg `execute(sql, (id,))`).",
        ),
        dict(
            scanner="demo",
            rule_id="DEMO-004",
            severity=Severity.MEDIUM,
            title="TLS certificate expires in <30 days",
            description=(
                "Synthetic finding: monitored endpoint serves a cert nearing expiry. "
                "Exercises the non-code / infra-finding path in the report."
            ),
            category="tls-hygiene",
            file_path="demo://127.0.0.1:443",
            cwe=["CWE-295"],
            cvss_score=5.3,
            fix_suggestion="Renew the certificate before expiry; automate via ACME.",
        ),
    ]

    findings: list[dict] = []
    for spec in specs:
        # Deterministic synthetic id so repeat runs are idempotent.
        payload = f"{spec['rule_id']}|{spec.get('file_path','')}|{spec['title']}"
        spec["id"] = hashlib.sha256(payload.encode()).hexdigest()[:16]
        spec["status"] = FindingStatus.NEW
        findings.append(UnifiedFinding(**spec).to_dict())
    return findings


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, default=str) + "\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="koda demo",
        description="Run a self-contained demo of the full KODA loop.",
    )
    parser.add_argument("--name", default="demo", help="engagement name (default: demo)")
    parser.add_argument(
        "--keep",
        action="store_true",
        help="suppress the cleanup hint at the end",
    )
    return parser


def main(argv: list[str]) -> int:
    if argv and argv[0] in {"-h", "--help"}:
        _build_parser().print_help()
        return 0

    args = _build_parser().parse_args(argv)

    from ..config import KODA_HOME
    from .report import _cmd_engagement

    name = args.name
    eng_dir = KODA_HOME / "engagements" / name
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "engagement.toml").write_text(_DEMO_TOML, encoding="utf-8")
    print(f"[ok] engagement created → {eng_dir}")

    findings = _synthetic_findings()
    findings_path = eng_dir / "findings.jsonl"
    _write_jsonl(findings_path, findings)
    print(f"[ok] {len(findings)} synthetic findings written → {findings_path}")

    ns = Namespace(
        name=name,
        out="",
        format="executive,technical,markdown,sarif",
        basename="report",
        engagement_id="",
        engagement_name="",
        scope="",
        operator="",
        started_at="",
        ended_at="",
        mode="",
        client="",
        roe_id="",
        target=None,
    )
    rc = _cmd_engagement(ns)
    if rc != 0:
        print("[err] report generation failed", file=sys.stderr)
        return rc
    print(f"[ok] report generated → {eng_dir / 'reports'}")

    print()
    print(f"Demo complete. Inspect: {eng_dir}")
    if not args.keep:
        print(f"  (remove with: trash {eng_dir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
