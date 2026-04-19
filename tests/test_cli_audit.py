"""Tests for ``koda audit`` CLI subcommand."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from koda.cli.audit import main as audit_main
from koda.security.findings import Severity, UnifiedFinding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_audit(argv: list[str], tmp_path: Path, config: dict | None = None) -> int:
    """Run ``audit_main`` with KODA_HOME patched to *tmp_path*."""
    old_home = os.environ.get("KODA_HOME")
    os.environ["KODA_HOME"] = str(tmp_path)
    try:
        import koda.config as cfg_mod
        cfg_mod.KODA_HOME = tmp_path  # type: ignore[assignment]

        if config is not None:
            # Write a minimal config.yaml so config_exists() returns True
            import yaml  # type: ignore[import]
            config_path = tmp_path / "config.yaml"
            config_path.write_text(yaml.dump(config))

        rc = audit_main(argv)
    finally:
        if old_home is None:
            os.environ.pop("KODA_HOME", None)
        else:
            os.environ["KODA_HOME"] = old_home
    return rc


def _make_scan_result(scanner: str, findings: list[UnifiedFinding] | None = None) -> MagicMock:
    result = MagicMock()
    result.success = True
    result.scanner = scanner
    result.findings = findings or []
    result.elapsed = 0.1
    return result


def _make_finding(severity: Severity, scanner: str = "test") -> UnifiedFinding:
    return UnifiedFinding(
        id=UnifiedFinding.make_id(scanner, "test-rule", "/tmp/test.py", 1),
        scanner=scanner,
        rule_id="test-rule",
        severity=severity,
        title="Test finding",
        description="A test finding",
    )


# ---------------------------------------------------------------------------
# --list-presets
# ---------------------------------------------------------------------------


def test_list_presets_exits_zero(tmp_path, capsys):
    rc = _run_audit(["--list-presets"], tmp_path)
    assert rc == 0


def test_list_presets_shows_all_five(tmp_path, capsys):
    rc = _run_audit(["--list-presets"], tmp_path)
    assert rc == 0
    out = capsys.readouterr().out
    for name in ("server-hardening", "web-app", "pci-readiness", "post-breach", "sbom-scan"):
        assert name in out


def test_list_presets_shows_tier(tmp_path, capsys):
    _run_audit(["--list-presets"], tmp_path)
    out = capsys.readouterr().out
    assert "sensitive" in out
    assert "safe" in out


# ---------------------------------------------------------------------------
# --explain
# ---------------------------------------------------------------------------


def test_explain_pci_readiness_contains_pci(tmp_path, capsys):
    rc = _run_audit(["--explain", "pci-readiness"], tmp_path)
    assert rc == 0
    out = capsys.readouterr().out
    assert "PCI" in out


def test_explain_server_hardening_contains_cis(tmp_path, capsys):
    rc = _run_audit(["--explain", "server-hardening"], tmp_path)
    assert rc == 0
    out = capsys.readouterr().out
    assert "CIS" in out


def test_explain_post_breach_contains_forensic(tmp_path, capsys):
    rc = _run_audit(["--explain", "post-breach"], tmp_path)
    assert rc == 0
    out = capsys.readouterr().out
    assert "forensic" in out.lower()


def test_explain_unknown_preset_returns_one(tmp_path, capsys):
    rc = _run_audit(["--explain", "nonexistent-preset"], tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "unknown" in err.lower()


def test_explain_lists_valid_presets_on_error(tmp_path, capsys):
    _run_audit(["--explain", "nonexistent"], tmp_path)
    err = capsys.readouterr().err
    assert "server-hardening" in err


# ---------------------------------------------------------------------------
# --preset unknown → helpful error
# ---------------------------------------------------------------------------


def test_unknown_preset_returns_one(tmp_path, capsys):
    rc = _run_audit(["--preset", "not-a-real-preset", "/tmp"], tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "not-a-real-preset" in err


def test_unknown_preset_lists_valid_names(tmp_path, capsys):
    _run_audit(["--preset", "bogus", "/tmp"], tmp_path)
    err = capsys.readouterr().err
    assert "server-hardening" in err


# ---------------------------------------------------------------------------
# requires_target: preset without a target errors before running anything
# ---------------------------------------------------------------------------


def test_server_hardening_without_target_returns_nonzero(tmp_path, capsys):
    config = {"approvals": {"auto_approve": "all"}}
    rc = _run_audit(["--preset", "server-hardening"], tmp_path, config=config)
    assert rc == 1
    err = capsys.readouterr().err
    assert "target" in err.lower()


def test_web_app_without_target_returns_nonzero(tmp_path, capsys):
    config = {"approvals": {"auto_approve": "all"}}
    rc = _run_audit(["--preset", "web-app"], tmp_path, config=config)
    assert rc == 1


# ---------------------------------------------------------------------------
# --dry-run never invokes scanners
# ---------------------------------------------------------------------------


def test_dry_run_exits_zero(tmp_path, capsys):
    config = {"approvals": {"auto_approve": "all"}}
    rc = _run_audit(["--preset", "server-hardening", "--dry-run", "localhost"], tmp_path, config=config)
    assert rc == 0


def test_dry_run_does_not_invoke_scanner_registry(tmp_path, capsys):
    config = {"approvals": {"auto_approve": "all"}}
    with patch("koda.security.scanners.registry.ScannerRegistry.run") as mock_run:
        _run_audit(["--preset", "server-hardening", "--dry-run", "localhost"], tmp_path, config=config)
        mock_run.assert_not_called()


def test_dry_run_prints_scanner_plan(tmp_path, capsys):
    config = {"approvals": {"auto_approve": "all"}}
    _run_audit(["--preset", "server-hardening", "--dry-run", "localhost"], tmp_path, config=config)
    out = capsys.readouterr().out
    assert "dry-run" in out.lower()


# ---------------------------------------------------------------------------
# --skip-scanner removes scanner from dispatch
# ---------------------------------------------------------------------------


def test_skip_scanner_removes_from_dry_run_output(tmp_path, capsys):
    config = {"approvals": {"auto_approve": "all"}}
    _run_audit(
        ["--preset", "server-hardening", "--dry-run", "--skip-scanner", "trivy", "localhost"],
        tmp_path,
        config=config,
    )
    out = capsys.readouterr().out
    # trivy should not appear in scanner run lines; it should appear in "skipping:"
    assert "trivy" not in out or "skipping" in out


def test_skip_scanner_gitleaks_not_dispatched(tmp_path, capsys):
    """--skip-scanner gitleaks must not result in gitleaks being run."""
    config = {"approvals": {"auto_approve": "all"}}
    with patch("koda.security.scanners.registry.ScannerRegistry.run") as mock_run:
        mock_run.return_value = _make_scan_result("trivy")
        _run_audit(
            [
                "--preset", "server-hardening",
                "--skip-scanner", "gitleaks",
                "--skip-scanner", "grype",
                "--skip-scanner", "trivy",
                "--skip-scanner", "osv-scanner",
                "--skip-scanner", "nmap",
                "localhost",
            ],
            tmp_path,
            config=config,
        )
        # gitleaks must not have been called
        called_scanners = [call.args[0] for call in mock_run.call_args_list]
        assert "gitleaks" not in called_scanners


# ---------------------------------------------------------------------------
# server-hardening dispatches exactly its scanner set
# ---------------------------------------------------------------------------


def test_server_hardening_dispatches_exact_scanner_set(tmp_path, capsys):
    from koda.missions import get_preset
    preset = get_preset("server-hardening")
    assert preset is not None

    config = {"approvals": {"auto_approve": "all"}}
    dispatched: list[str] = []

    def fake_run(scanner: str, target: str, **kwargs):
        dispatched.append(scanner)
        return _make_scan_result(scanner)

    with patch("koda.security.scanners.registry.ScannerRegistry.run", side_effect=fake_run):
        _run_audit(["--preset", "server-hardening", "localhost"], tmp_path, config=config)

    assert set(dispatched) == set(preset.scanners)


# ---------------------------------------------------------------------------
# Approval tier enforcement
# ---------------------------------------------------------------------------


def test_sensitive_preset_blocked_by_safe_config(tmp_path, capsys):
    """server-hardening is 'sensitive'; a safe-only config should block it."""
    config = {"approvals": {"auto_approve": "safe"}}
    rc = _run_audit(["--preset", "server-hardening", "localhost"], tmp_path, config=config)
    assert rc == 1
    err = capsys.readouterr().err
    assert "tier" in err.lower() or "approval" in err.lower()


def test_safe_preset_passes_safe_config(tmp_path, capsys):
    """post-breach is 'safe' — it should not be blocked by a safe-only config."""
    config = {"approvals": {"auto_approve": "safe"}}
    with patch("koda.security.scanners.registry.ScannerRegistry.run") as mock_run:
        mock_run.return_value = _make_scan_result("gitleaks")
        _run_audit(["--preset", "post-breach", "/tmp"], tmp_path, config=config)
    # Should not have returned 1 due to tier (mock results are empty)
    err = capsys.readouterr().err
    assert "approval" not in err.lower()


# ---------------------------------------------------------------------------
# Exit code: 0 on clean, 1 on CRITICAL/HIGH
# ---------------------------------------------------------------------------


def test_exit_code_zero_on_empty_findings(tmp_path):
    config = {"approvals": {"auto_approve": "all"}}

    def fake_run(scanner: str, target: str, **kwargs):
        return _make_scan_result(scanner, findings=[])

    with patch("koda.security.scanners.registry.ScannerRegistry.run", side_effect=fake_run):
        rc = _run_audit(["--preset", "server-hardening", "--no-report", "localhost"],
                        tmp_path, config=config)
    assert rc == 0


def test_exit_code_one_on_critical_finding(tmp_path):
    config = {"approvals": {"auto_approve": "all"}}
    critical_finding = _make_finding(Severity.CRITICAL, scanner="trivy")

    def fake_run(scanner: str, target: str, **kwargs):
        findings = [critical_finding] if scanner == "trivy" else []
        return _make_scan_result(scanner, findings=findings)

    with patch("koda.security.scanners.registry.ScannerRegistry.run", side_effect=fake_run):
        rc = _run_audit(["--preset", "server-hardening", "--no-report", "localhost"],
                        tmp_path, config=config)
    assert rc == 1


def test_exit_code_one_on_high_finding(tmp_path):
    config = {"approvals": {"auto_approve": "all"}}
    high_finding = _make_finding(Severity.HIGH, scanner="gitleaks")

    def fake_run(scanner: str, target: str, **kwargs):
        findings = [high_finding] if scanner == "gitleaks" else []
        return _make_scan_result(scanner, findings=findings)

    with patch("koda.security.scanners.registry.ScannerRegistry.run", side_effect=fake_run):
        rc = _run_audit(["--preset", "server-hardening", "--no-report", "localhost"],
                        tmp_path, config=config)
    assert rc == 1


def test_exit_code_zero_on_medium_only(tmp_path):
    """MEDIUM findings should not cause a non-zero exit."""
    config = {"approvals": {"auto_approve": "all"}}
    med_finding = _make_finding(Severity.MEDIUM, scanner="semgrep")

    def fake_run(scanner: str, target: str, **kwargs):
        findings = [med_finding]
        return _make_scan_result(scanner, findings=findings)

    with patch("koda.security.scanners.registry.ScannerRegistry.run", side_effect=fake_run):
        rc = _run_audit(["--preset", "server-hardening", "--no-report", "localhost"],
                        tmp_path, config=config)
    assert rc == 0


# ---------------------------------------------------------------------------
# findings.jsonl is written
# ---------------------------------------------------------------------------


def test_findings_jsonl_written(tmp_path):
    config = {"approvals": {"auto_approve": "all"}}
    high_finding = _make_finding(Severity.HIGH, scanner="nmap")

    def fake_run(scanner: str, target: str, **kwargs):
        return _make_scan_result(scanner, findings=[high_finding])

    with patch("koda.security.scanners.registry.ScannerRegistry.run", side_effect=fake_run):
        _run_audit(["--preset", "server-hardening", "--no-report", "localhost"],
                   tmp_path, config=config)

    # Find the findings.jsonl in the created engagement dir
    jsonl_files = list(tmp_path.rglob("findings.jsonl"))
    assert jsonl_files, "findings.jsonl not created"
    content = jsonl_files[0].read_text()
    assert content.strip()  # not empty


# ---------------------------------------------------------------------------
# Engagement directory creation
# ---------------------------------------------------------------------------


def test_throwaway_engagement_created(tmp_path):
    config = {"approvals": {"auto_approve": "all"}}

    def fake_run(scanner: str, target: str, **kwargs):
        return _make_scan_result(scanner)

    with patch("koda.security.scanners.registry.ScannerRegistry.run", side_effect=fake_run):
        _run_audit(["--preset", "server-hardening", "--no-report", "localhost"],
                   tmp_path, config=config)

    engagements = list((tmp_path / "engagements").glob("audit-server-hardening-*"))
    assert len(engagements) == 1
    assert (engagements[0] / "findings.jsonl").exists()


def test_existing_engagement_used(tmp_path):
    config = {"approvals": {"auto_approve": "all"}}

    # Pre-create an engagement
    eng_dir = tmp_path / "engagements" / "my-existing"
    (eng_dir / "evidence").mkdir(parents=True)
    (eng_dir / "audit.jsonl").touch()

    def fake_run(scanner: str, target: str, **kwargs):
        return _make_scan_result(scanner)

    with patch("koda.security.scanners.registry.ScannerRegistry.run", side_effect=fake_run):
        _run_audit(
            ["--preset", "server-hardening", "--no-report", "--engagement", "my-existing", "localhost"],
            tmp_path,
            config=config,
        )

    assert (eng_dir / "findings.jsonl").exists()


def test_nonexistent_engagement_returns_nonzero(tmp_path, capsys):
    config = {"approvals": {"auto_approve": "all"}}
    rc = _run_audit(
        ["--preset", "server-hardening", "--engagement", "ghost-engagement", "localhost"],
        tmp_path,
        config=config,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "ghost-engagement" in err
