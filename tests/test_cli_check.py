"""Tests for ``koda check`` CLI subcommand."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from koda.cli import _cmd_check, _npm_has_script


def test_check_help(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _cmd_check(["--help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "koda check" in out
    assert "--lint-only" in out
    assert "--install-hook" in out


def test_check_rejects_unknown_flag(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _cmd_check(["--bogus"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown flag" in err


def test_check_rejects_conflicting_flags(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _cmd_check(["--lint-only", "--tests-only"])
    assert rc == 2


def test_check_no_project_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _cmd_check(["--dir", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "nothing to check" in err


def test_check_passes_on_clean_python_repo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (tmp_path / "x.py").write_text("print('ok')\n")
    # No tests/ dir so we only run lint; ruff default config passes on this.
    rc = _cmd_check(["--dir", str(tmp_path), "--lint-only"])
    out = capsys.readouterr().out
    # If ruff isn't installed the test is still a pass (skipped lint, no tests).
    assert rc == 0
    assert "check passed" in out


def test_npm_has_script_detects_scripts(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"scripts": {"lint": "eslint .", "test": "jest"}}'
    )
    assert _npm_has_script(tmp_path, "lint") is True
    assert _npm_has_script(tmp_path, "test") is True
    assert _npm_has_script(tmp_path, "build") is False


def test_npm_has_script_missing_file(tmp_path: Path) -> None:
    assert _npm_has_script(tmp_path, "lint") is False


def test_install_hook_writes_pre_push(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    rc = _cmd_check(["--dir", str(tmp_path), "--install-hook"])
    assert rc == 0
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    assert hook.exists()
    body = hook.read_text()
    assert "koda check" in body
    assert hook.stat().st_mode & 0o111  # executable


def test_install_hook_requires_git_repo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _cmd_check(["--dir", str(tmp_path), "--install-hook"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not a git repository" in err


def test_uninstall_hook_removes_koda_hook(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    _cmd_check(["--dir", str(tmp_path), "--install-hook"])
    rc = _cmd_check(["--dir", str(tmp_path), "--uninstall-hook"])
    assert rc == 0
    assert not (tmp_path / ".git" / "hooks" / "pre-push").exists()


def test_uninstall_hook_preserves_foreign_hook(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho custom\n")
    rc = _cmd_check(["--dir", str(tmp_path), "--uninstall-hook"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not created by koda" in err
    assert hook.exists()
