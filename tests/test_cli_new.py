"""Tests for ``koda new`` engagement scaffolding command."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from koda.cli.new import _validate_name
from koda.cli.new import main as new_main
from koda.cli.templates import get, names

# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------


def test_template_list_has_three_names():
    assert set(names()) == {"pentest", "ir", "audit"}


def test_template_list_sorted():
    result = names()
    assert result == sorted(result)


def test_get_known_templates():
    for n in ("pentest", "ir", "audit"):
        tmpl = get(n)
        assert tmpl is not None
        assert tmpl.name == n


def test_get_unknown_template_returns_none():
    assert get("does-not-exist") is None


def test_pentest_defaults():
    t = get("pentest")
    assert t is not None
    assert t.approval_tier == "all"
    assert "nmap" in t.scanners
    assert "semgrep" in t.scanners
    assert "nuclei" in t.scanners
    assert "gitleaks" in t.scanners
    assert "trivy" in t.scanners
    assert "osv-scanner" in t.scanners
    assert "recon" in t.attack_phases
    assert "initial_access" in t.attack_phases
    assert "execution" in t.attack_phases
    assert t.report_template == "pentest-markdown"


def test_ir_defaults():
    t = get("ir")
    assert t is not None
    assert t.approval_tier == "safe"
    assert "log-analyzer" in t.scanners
    assert "port-monitor" in t.scanners
    assert "oss-forensics" in t.scanners
    assert "persistence" in t.attack_phases
    assert "exfil" in t.attack_phases
    assert t.report_template == "ir-timeline"


def test_audit_defaults():
    t = get("audit")
    assert t is not None
    assert t.approval_tier == "safe"
    assert "semgrep" in t.scanners
    assert "trivy" in t.scanners
    assert "bandit" in t.scanners
    assert "hardening" in t.attack_phases
    assert t.report_template == "audit-findings"


# ---------------------------------------------------------------------------
# Name validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "myengagement",
    "my-engagement",
    "my_engagement",
    "eng01",
    "a",
    "z" * 32,
])
def test_valid_names(name: str):
    assert _validate_name(name) is None


@pytest.mark.parametrize("bad,fragment", [
    ("",              "must not be empty"),
    ("My-Engagement", "lowercase"),
    ("my engagement", "whitespace"),
    ("../traversal",  "path traversal"),
    ("../../etc",     "path traversal"),
    ("-leading-dash", "starts with"),
    ("_leading",      "starts with"),
    ("has/slash",     "path traversal"),
    ("has\\back",     "path traversal"),
    ("z" * 33,        "1\u201332"),     # 33 chars — one over limit
])
def test_invalid_names(bad: str, fragment: str):
    msg = _validate_name(bad)
    assert msg is not None
    assert fragment.lower() in msg.lower()


# ---------------------------------------------------------------------------
# Scaffold helper: directory layout
# ---------------------------------------------------------------------------


def _run_new(tmp_path: Path, template: str, name: str) -> int:
    """Run ``new_main`` with KODA_HOME pointed at *tmp_path*."""
    old = os.environ.get("KODA_HOME")
    os.environ["KODA_HOME"] = str(tmp_path)
    try:
        import koda.config as cfg_mod
        cfg_mod.KODA_HOME = tmp_path  # type: ignore[assignment]
        rc = new_main(["--template", template, name])
    finally:
        if old is None:
            os.environ.pop("KODA_HOME", None)
        else:
            os.environ["KODA_HOME"] = old
    return rc


def test_pentest_creates_layout(tmp_path: Path):
    rc = _run_new(tmp_path, "pentest", "op-alpha")
    assert rc == 0
    eng_dir = tmp_path / "engagements" / "op-alpha"
    assert eng_dir.is_dir()
    assert (eng_dir / "evidence").is_dir()
    assert (eng_dir / "audit.jsonl").is_file()
    assert (eng_dir / "engagement.toml").is_file()
    assert (eng_dir / "README.md").is_file()


def test_ir_creates_layout(tmp_path: Path):
    rc = _run_new(tmp_path, "ir", "incident-2026")
    assert rc == 0
    eng_dir = tmp_path / "engagements" / "incident-2026"
    assert (eng_dir / "engagement.toml").is_file()
    assert (eng_dir / "evidence").is_dir()


def test_audit_creates_layout(tmp_path: Path):
    rc = _run_new(tmp_path, "audit", "q2-audit")
    assert rc == 0
    eng_dir = tmp_path / "engagements" / "q2-audit"
    assert (eng_dir / "engagement.toml").is_file()


def test_toml_contains_template_fields(tmp_path: Path):
    _run_new(tmp_path, "pentest", "check-toml")
    toml_text = (tmp_path / "engagements" / "check-toml" / "engagement.toml").read_text()
    assert 'template = "pentest"' in toml_text
    assert 'approval_tier = "all"' in toml_text
    assert 'report_template = "pentest-markdown"' in toml_text
    assert "nmap" in toml_text
    assert "recon" in toml_text


def test_readme_contains_scanner_and_phases(tmp_path: Path):
    _run_new(tmp_path, "ir", "readme-check")
    readme = (tmp_path / "engagements" / "readme-check" / "README.md").read_text()
    assert "log-analyzer" in readme
    assert "persistence" in readme
    assert "ir-timeline" in readme


# ---------------------------------------------------------------------------
# Duplicate / conflict guard
# ---------------------------------------------------------------------------


def test_existing_engagement_returns_nonzero(tmp_path: Path, capsys):
    _run_new(tmp_path, "pentest", "dupe-test")
    rc = _run_new(tmp_path, "pentest", "dupe-test")
    assert rc != 0
    captured = capsys.readouterr()
    assert "already exists" in captured.err.lower()


# ---------------------------------------------------------------------------
# Invalid name → non-zero exit + clear error
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_name", [
    "Has Spaces",
    "UPPER",
    "../traversal",
    "../../etc/passwd",
])
def test_invalid_name_returns_nonzero(tmp_path: Path, bad_name: str, capsys):
    old = os.environ.get("KODA_HOME")
    os.environ["KODA_HOME"] = str(tmp_path)
    try:
        rc = new_main(["--template", "pentest", bad_name])
    finally:
        if old is None:
            os.environ.pop("KODA_HOME", None)
        else:
            os.environ["KODA_HOME"] = old
    assert rc != 0
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()


# ---------------------------------------------------------------------------
# --list-templates flag
# ---------------------------------------------------------------------------


def test_list_templates_returns_zero(capsys):
    rc = new_main(["--list-templates"])
    assert rc == 0
    out = capsys.readouterr().out
    for n in ("pentest", "ir", "audit"):
        assert n in out


# ---------------------------------------------------------------------------
# Missing --template flag → non-zero
# ---------------------------------------------------------------------------


def test_no_template_flag_returns_nonzero(tmp_path: Path, capsys):
    old = os.environ.get("KODA_HOME")
    os.environ["KODA_HOME"] = str(tmp_path)
    try:
        rc = new_main(["my-engagement"])
    finally:
        if old is None:
            os.environ.pop("KODA_HOME", None)
        else:
            os.environ["KODA_HOME"] = old
    assert rc != 0
    captured = capsys.readouterr()
    assert "--template" in captured.err


# ---------------------------------------------------------------------------
# Unknown template → non-zero
# ---------------------------------------------------------------------------


def test_unknown_template_returns_nonzero(tmp_path: Path, capsys):
    old = os.environ.get("KODA_HOME")
    os.environ["KODA_HOME"] = str(tmp_path)
    try:
        rc = new_main(["--template", "nonexistent", "my-eng"])
    finally:
        if old is None:
            os.environ.pop("KODA_HOME", None)
        else:
            os.environ["KODA_HOME"] = old
    assert rc != 0
