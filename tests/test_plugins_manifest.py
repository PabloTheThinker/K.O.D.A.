"""Tests for the manifest-first plugin control plane.

Keeps the contract honest: manifests parse without importing runtimes,
cold routing works on model_prefixes, discovery shadows correctly,
registry activation is idempotent and importable-aware.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from koda.plugins import (
    ManifestError,
    PluginCandidate,
    PluginDiscovery,
    PluginKind,
    PluginManifest,
    PluginRegistry,
    PluginRegistryError,
)


# ---------- manifest parsing ---------------------------------------------


def test_manifest_minimal_required_fields(tmp_path: Path) -> None:
    path = tmp_path / "koda.plugin.json"
    path.write_text(json.dumps({
        "id": "example",
        "kinds": ["provider"],
        "runtime_entry": "koda",  # any importable module is fine for parse
    }))
    m = PluginManifest.from_path(path)
    assert m.id == "example"
    assert m.kinds == (PluginKind.PROVIDER,)
    assert m.runtime_entry == "koda"
    assert m.version == "0.0.0"


def test_manifest_rejects_missing_id(tmp_path: Path) -> None:
    path = tmp_path / "koda.plugin.json"
    path.write_text(json.dumps({"kinds": ["provider"], "runtime_entry": "koda"}))
    with pytest.raises(ManifestError):
        PluginManifest.from_path(path)


def test_manifest_rejects_uppercase_id(tmp_path: Path) -> None:
    path = tmp_path / "koda.plugin.json"
    path.write_text(json.dumps({
        "id": "Example",
        "kinds": ["provider"],
        "runtime_entry": "koda",
    }))
    with pytest.raises(ManifestError, match="lowercase"):
        PluginManifest.from_path(path)


def test_manifest_rejects_unknown_kind(tmp_path: Path) -> None:
    path = tmp_path / "koda.plugin.json"
    path.write_text(json.dumps({
        "id": "example",
        "kinds": ["not-a-real-kind"],
        "runtime_entry": "koda",
    }))
    with pytest.raises(ManifestError, match="unknown plugin kind"):
        PluginManifest.from_path(path)


def test_manifest_accepts_kind_singular_string(tmp_path: Path) -> None:
    path = tmp_path / "koda.plugin.json"
    path.write_text(json.dumps({
        "id": "example",
        "kind": "channel",
        "runtime_entry": "koda",
    }))
    m = PluginManifest.from_path(path)
    assert m.kinds == (PluginKind.CHANNEL,)


def test_manifest_cold_model_prefix_match() -> None:
    m = PluginManifest.from_dict({
        "id": "anthropic",
        "kinds": ["provider"],
        "runtime_entry": "koda",
        "model_support": {"model_prefixes": ["claude-", "anthropic/"]},
    })
    assert m.matches_model("claude-sonnet-4-6")
    assert m.matches_model("anthropic/claude-opus")
    assert not m.matches_model("gpt-5.4")


def test_manifest_legacy_ids_allow_rename() -> None:
    m = PluginManifest.from_dict({
        "id": "memory-wiki",
        "kinds": ["memory"],
        "runtime_entry": "koda",
        "legacy_ids": ["obsidian-memory"],
    })
    assert m.matches_id("memory-wiki")
    assert m.matches_id("obsidian-memory")
    assert not m.matches_id("memory-lancedb")


# ---------- discovery -----------------------------------------------------


def _write_manifest(dir_: Path, payload: dict) -> Path:
    dir_.mkdir(parents=True, exist_ok=True)
    path = dir_ / "koda.plugin.json"
    path.write_text(json.dumps(payload))
    return path


def test_discovery_walks_search_paths(tmp_path: Path) -> None:
    bundled = tmp_path / "bundled" / "anthropic"
    user = tmp_path / "user" / "slack"
    _write_manifest(bundled, {
        "id": "anthropic",
        "kinds": ["provider"],
        "runtime_entry": "koda",
    })
    _write_manifest(user, {
        "id": "slack",
        "kinds": ["channel"],
        "runtime_entry": "koda",
    })

    disc = PluginDiscovery([
        (tmp_path / "bundled", "bundled"),
        (tmp_path / "user", "user"),
    ])
    candidates, errors = disc.discover()
    assert errors == []
    ids = {c.manifest.id for c in candidates}
    assert ids == {"anthropic", "slack"}


def test_discovery_first_wins_on_shadow(tmp_path: Path) -> None:
    bundled = tmp_path / "bundled" / "anthropic"
    user = tmp_path / "user" / "anthropic"
    _write_manifest(bundled, {
        "id": "anthropic",
        "kinds": ["provider"],
        "runtime_entry": "koda",
        "version": "1.0.0",
    })
    _write_manifest(user, {
        "id": "anthropic",
        "kinds": ["provider"],
        "runtime_entry": "koda",
        "version": "2.0.0",
    })

    disc = PluginDiscovery([
        (tmp_path / "bundled", "bundled"),
        (tmp_path / "user", "user"),
    ])
    candidates, errors = disc.discover()
    assert len(candidates) == 1
    # Bundled wins because it was first in the search path.
    assert candidates[0].manifest.version == "1.0.0"
    assert candidates[0].origin == "bundled"
    # Shadow is surfaced as an error so ``koda doctor`` can show it.
    assert any("shadowed" in msg for _, msg in errors)


def test_discovery_malformed_manifest_isolated(tmp_path: Path) -> None:
    good = tmp_path / "good"
    bad = tmp_path / "bad"
    _write_manifest(good, {
        "id": "good",
        "kinds": ["provider"],
        "runtime_entry": "koda",
    })
    bad.mkdir()
    (bad / "koda.plugin.json").write_text("{not valid json")

    disc = PluginDiscovery([(tmp_path, "bundled")])
    candidates, errors = disc.discover()
    assert [c.manifest.id for c in candidates] == ["good"]
    assert len(errors) == 1


def test_discovery_find_by_model_is_cold(tmp_path: Path) -> None:
    """Cold routing must not import plugin runtime entries.

    We point ``runtime_entry`` at a module that would explode on import,
    and verify discovery + find_by_model still return the candidate.
    """
    mdir = tmp_path / "anthropic"
    _write_manifest(mdir, {
        "id": "anthropic",
        "kinds": ["provider"],
        "runtime_entry": "koda.plugins.__does_not_exist__",
        "model_support": {"model_prefixes": ["claude-"]},
    })
    disc = PluginDiscovery([(tmp_path, "bundled")])
    matches = disc.find_by_model("claude-sonnet-4-6")
    assert len(matches) == 1
    assert matches[0].manifest.id == "anthropic"


# ---------- registry ------------------------------------------------------


def _candidate(tmp_path: Path, plugin_id: str, runtime_entry: str) -> PluginCandidate:
    m = PluginManifest.from_dict({
        "id": plugin_id,
        "kinds": ["provider"],
        "runtime_entry": runtime_entry,
    })
    return PluginCandidate(manifest=m, dir=tmp_path, origin="bundled")


def test_registry_activate_imports_runtime(tmp_path: Path) -> None:
    reg = PluginRegistry()
    cand = _candidate(tmp_path, "example", "json")  # stdlib, safe to import
    reg.activate(cand)
    assert reg.is_active("example")
    mod = reg.module("example")
    assert mod is not None
    assert hasattr(mod, "dumps")


def test_registry_activate_is_idempotent(tmp_path: Path) -> None:
    reg = PluginRegistry()
    cand = _candidate(tmp_path, "example", "json")
    reg.activate(cand)
    reg.activate(cand)  # must not raise
    assert reg.active_ids() == ["example"]


def test_registry_rejects_reactivation_from_different_path(tmp_path: Path) -> None:
    reg = PluginRegistry()
    a = _candidate(tmp_path / "a", "example", "json")
    b = _candidate(tmp_path / "b", "example", "json")
    reg.activate(a)
    with pytest.raises(PluginRegistryError, match="already active"):
        reg.activate(b)


def test_registry_activate_bad_entry_raises(tmp_path: Path) -> None:
    reg = PluginRegistry()
    cand = _candidate(tmp_path, "bad", "koda.plugins.__does_not_exist__")
    with pytest.raises(PluginRegistryError, match="runtime_entry"):
        reg.activate(cand)


def test_registry_deactivate_calls_hook_if_present(tmp_path: Path, monkeypatch) -> None:
    import types

    called = {"count": 0}
    fake_mod = types.ModuleType("fake_plugin_mod")

    def _deactivate() -> None:
        called["count"] += 1

    fake_mod.deactivate = _deactivate

    import sys

    monkeypatch.setitem(sys.modules, "fake_plugin_mod", fake_mod)
    reg = PluginRegistry()
    cand = _candidate(tmp_path, "fake", "fake_plugin_mod")
    reg.activate(cand)
    reg.deactivate("fake")
    assert called["count"] == 1
    assert not reg.is_active("fake")
