"""Tests for mission preset schema and registry."""
from __future__ import annotations

import pytest

from koda.missions import (
    PCI_READINESS,
    POST_BREACH,
    PRESET_SCHEMA_VERSION,
    SBOM_SCAN,
    SERVER_HARDENING,
    WEB_APP,
    MissionPreset,
    get_preset,
    list_presets,
    preset_names,
)

# ---------------------------------------------------------------------------
# Schema version constant
# ---------------------------------------------------------------------------


def test_schema_version_is_int():
    assert isinstance(PRESET_SCHEMA_VERSION, int)


def test_schema_version_exported():
    """PRESET_SCHEMA_VERSION must be importable directly."""
    import koda.missions as missions_mod
    assert hasattr(missions_mod, "PRESET_SCHEMA_VERSION")
    assert missions_mod.PRESET_SCHEMA_VERSION == PRESET_SCHEMA_VERSION


def test_schema_version_is_positive():
    assert PRESET_SCHEMA_VERSION >= 1


# ---------------------------------------------------------------------------
# MissionPreset dataclass is frozen
# ---------------------------------------------------------------------------


def test_preset_is_frozen():
    p = get_preset("server-hardening")
    assert p is not None
    with pytest.raises((AttributeError, TypeError)):
        p.name = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# All five presets round-trip through the dataclass without error
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("preset_name", [
    "server-hardening",
    "web-app",
    "pci-readiness",
    "post-breach",
    "sbom-scan",
])
def test_preset_roundtrip(preset_name: str):
    """Every preset is retrievable and has all required fields populated."""
    preset = get_preset(preset_name)
    assert preset is not None
    assert isinstance(preset, MissionPreset)
    assert preset.name == preset_name
    assert preset.title
    assert preset.summary
    assert preset.description
    assert preset.audience
    assert preset.scanners  # at least one scanner
    assert isinstance(preset.scanners, tuple)
    assert preset.scanner_args is not None
    assert isinstance(preset.scanner_args, dict)
    assert preset.approval_tier in ("safe", "sensitive", "dangerous")
    assert isinstance(preset.attack_phases, tuple)
    assert isinstance(preset.compliance_frameworks, tuple)
    assert preset.report_style in ("executive", "technical", "audit", "ir-timeline")
    assert preset.success_criteria
    assert preset.next_steps
    assert isinstance(preset.requires_target, bool)
    assert preset.default_target_type in ("host", "url", "path", "local")
    assert preset.schema_version == PRESET_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Registry: list and names
# ---------------------------------------------------------------------------


def test_list_presets_returns_five():
    assert len(list_presets()) == 5


def test_preset_names_sorted():
    names = preset_names()
    assert names == sorted(names)


def test_preset_names_contains_all():
    names = preset_names()
    for expected in ("server-hardening", "web-app", "pci-readiness", "post-breach", "sbom-scan"):
        assert expected in names


def test_get_unknown_preset_returns_none():
    assert get_preset("does-not-exist") is None


def test_get_known_presets():
    for name in ("server-hardening", "web-app", "pci-readiness", "post-breach", "sbom-scan"):
        p = get_preset(name)
        assert p is not None
        assert p.name == name


# ---------------------------------------------------------------------------
# Per-preset specific checks
# ---------------------------------------------------------------------------


def test_server_hardening_scanner_set():
    p = get_preset("server-hardening")
    assert p is not None
    assert "gitleaks" in p.scanners
    assert "grype" in p.scanners
    assert "trivy" in p.scanners
    assert "osv-scanner" in p.scanners
    assert "nmap" in p.scanners


def test_server_hardening_metadata():
    p = get_preset("server-hardening")
    assert p is not None
    assert p.approval_tier == "sensitive"
    assert "CIS-Ubuntu" in p.compliance_frameworks
    assert "CIS-Linux" in p.compliance_frameworks
    assert p.requires_target is True
    assert p.default_target_type == "host"


def test_web_app_scanner_set():
    p = get_preset("web-app")
    assert p is not None
    assert "semgrep" in p.scanners
    assert "gitleaks" in p.scanners
    assert "osv-scanner" in p.scanners
    assert "trivy" in p.scanners
    assert "nuclei" in p.scanners


def test_web_app_metadata():
    p = get_preset("web-app")
    assert p is not None
    assert "OWASP-Top-10" in p.compliance_frameworks
    assert p.approval_tier == "sensitive"
    assert p.report_style == "technical"
    assert p.requires_target is True
    assert p.default_target_type == "path"


def test_pci_readiness_scanner_set():
    p = get_preset("pci-readiness")
    assert p is not None
    assert "semgrep" in p.scanners
    assert "gitleaks" in p.scanners
    assert "trivy" in p.scanners
    assert "osv-scanner" in p.scanners
    assert "nmap" in p.scanners


def test_pci_readiness_framework():
    p = get_preset("pci-readiness")
    assert p is not None
    assert "PCI-DSS-4.0" in p.compliance_frameworks
    assert p.report_style == "audit"


def test_post_breach_is_safe_tier():
    """post-breach must be safe — it must never run anything intrusive."""
    p = get_preset("post-breach")
    assert p is not None
    assert p.approval_tier == "safe"


def test_post_breach_scanner_set():
    p = get_preset("post-breach")
    assert p is not None
    assert "log-analyzer" in p.scanners
    assert "oss-forensics" in p.scanners
    assert "gitleaks" in p.scanners
    assert "trivy" in p.scanners


def test_post_breach_no_compliance_frameworks():
    p = get_preset("post-breach")
    assert p is not None
    assert p.compliance_frameworks == ()


def test_post_breach_attack_phases():
    p = get_preset("post-breach")
    assert p is not None
    assert "persistence" in p.attack_phases
    assert "defense_evasion" in p.attack_phases
    assert "exfiltration" in p.attack_phases


def test_post_breach_report_style():
    p = get_preset("post-breach")
    assert p is not None
    assert p.report_style == "ir-timeline"


def test_post_breach_next_steps_mentions_counsel():
    p = get_preset("post-breach")
    assert p is not None
    assert "counsel" in p.next_steps.lower()


def test_sbom_scan_scanner_set():
    p = get_preset("sbom-scan")
    assert p is not None
    assert "osv-scanner" in p.scanners
    assert "grype" in p.scanners
    assert "trivy" in p.scanners
    assert "dependency_track" in p.scanners


def test_sbom_scan_is_safe_tier():
    p = get_preset("sbom-scan")
    assert p is not None
    assert p.approval_tier == "safe"


def test_sbom_scan_frameworks():
    p = get_preset("sbom-scan")
    assert p is not None
    assert "SLSA" in p.compliance_frameworks
    assert "CycloneDX" in p.compliance_frameworks


def test_sbom_scan_success_criteria_mentions_kev():
    p = get_preset("sbom-scan")
    assert p is not None
    assert "KEV" in p.success_criteria


# ---------------------------------------------------------------------------
# Direct module-level preset objects
# ---------------------------------------------------------------------------


def test_module_level_presets_are_same_as_registry():
    assert SERVER_HARDENING is get_preset("server-hardening")
    assert WEB_APP is get_preset("web-app")
    assert PCI_READINESS is get_preset("pci-readiness")
    assert POST_BREACH is get_preset("post-breach")
    assert SBOM_SCAN is get_preset("sbom-scan")
