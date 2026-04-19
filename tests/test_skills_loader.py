"""Smoke tests for the external SKILL.md pack loader."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from koda.security.modes import SecurityMode
from koda.security.skills.registry import SkillRegistry
from koda.skills.loader import SkillLoader
from koda.skills.pack import SkillPack, SkillPackError


def _write_pack(root: Path, name: str, body: str) -> Path:
    pack = root / name
    pack.mkdir(parents=True, exist_ok=True)
    skill_md = pack / "SKILL.md"
    skill_md.write_text(body, encoding="utf-8")
    return skill_md


def test_pack_parses_minimum_frontmatter(tmp_path: Path) -> None:
    skill_md = _write_pack(
        tmp_path,
        "mini",
        textwrap.dedent(
            """\
            ---
            name: mini
            description: tiny skill
            ---

            body text
            """
        ),
    )
    pack = SkillPack.from_path(skill_md)
    assert pack.name == "mini"
    assert pack.description == "tiny skill"
    assert pack.body == "body text"


def test_pack_rejects_missing_frontmatter(tmp_path: Path) -> None:
    skill_md = tmp_path / "bad" / "SKILL.md"
    skill_md.parent.mkdir(parents=True)
    skill_md.write_text("no frontmatter here", encoding="utf-8")
    with pytest.raises(SkillPackError):
        SkillPack.from_path(skill_md)


def test_pack_rejects_missing_required_fields(tmp_path: Path) -> None:
    skill_md = _write_pack(
        tmp_path,
        "missing-name",
        textwrap.dedent(
            """\
            ---
            description: no name here
            ---

            body
            """
        ),
    )
    with pytest.raises(SkillPackError):
        SkillPack.from_path(skill_md)


def test_pack_to_skill_fills_defaults_and_frontmatter(tmp_path: Path) -> None:
    skill_md = _write_pack(
        tmp_path,
        "recon-pack",
        textwrap.dedent(
            """\
            ---
            name: recon-pack
            description: subdomain enumeration
            mode: red
            phase: recon
            attack_techniques: [T1595.002]
            tools_required: [shell.exec]
            ---

            how to enumerate
            """
        ),
    )
    pack = SkillPack.from_path(skill_md)
    skill = pack.to_skill()
    assert skill.name == "recon-pack"
    assert skill.mode == SecurityMode.RED
    assert skill.phase == "recon"
    assert skill.attack_techniques == ("T1595.002",)
    assert skill.tools_required == ("shell.exec",)
    assert "subdomain enumeration" in skill.prompt_fragment


def test_loader_registers_into_fresh_registry(tmp_path: Path) -> None:
    _write_pack(
        tmp_path,
        "p1",
        textwrap.dedent(
            """\
            ---
            name: p1
            description: pack one
            mode: red
            phase: recon
            ---

            body
            """
        ),
    )
    _write_pack(
        tmp_path,
        "p2",
        textwrap.dedent(
            """\
            ---
            name: p2
            description: pack two
            mode: blue
            phase: ir
            ---

            body
            """
        ),
    )
    registry = SkillRegistry()
    loader = SkillLoader(registry=registry, search_paths=[tmp_path])
    count, errors = loader.register_all()
    assert count == 2
    assert errors == []
    assert registry.skill_by_name("p1") is not None
    assert registry.skill_by_name("p2") is not None


def test_loader_collects_errors_without_raising(tmp_path: Path) -> None:
    _write_pack(tmp_path, "good", "---\nname: good\ndescription: ok\n---\n\nbody")
    _write_pack(tmp_path, "bad", "no frontmatter here")
    registry = SkillRegistry()
    loader = SkillLoader(registry=registry, search_paths=[tmp_path])
    count, errors = loader.register_all()
    assert count == 1
    assert len(errors) == 1
    assert registry.skill_by_name("good") is not None
