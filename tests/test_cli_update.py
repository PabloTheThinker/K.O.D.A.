"""Tests for ``koda update`` CLI subcommand."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from koda.cli import _cmd_update, _extract_version, _read_version


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_extract_version_happy_path() -> None:
    src = '__version__ = "1.2.3"\n'
    assert _extract_version(src) == "1.2.3"


def test_extract_version_single_quotes() -> None:
    src = "__version__ = '0.6.1'\n"
    assert _extract_version(src) == "0.6.1"


def test_extract_version_missing() -> None:
    assert _extract_version("# no version here\n") is None


def test_read_version_missing_file(tmp_path: Path) -> None:
    assert _read_version(tmp_path / "nope.py") is None


# ---------------------------------------------------------------------------
# Help / flag parsing
# ---------------------------------------------------------------------------


def test_update_help(capsys: pytest.CaptureFixture[str]) -> None:
    rc = _cmd_update(["--help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "koda update" in out
    assert "--check" in out
    assert "--yes" in out
    assert "--installer" in out


def test_update_rejects_unknown_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = _cmd_update(["--bogus"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown flag" in err


# ---------------------------------------------------------------------------
# Fast-path git integration (uses a tiny fixture repo)
# ---------------------------------------------------------------------------


def _init_fixture_repo(
    install_dir: Path,
    *,
    version: str = "0.0.1",
    pyproject: str = '[project]\nname = "koda"\n',
) -> Path:
    """Build an install layout with a .source/ git clone and .venv/.

    Creates an 'origin' bare repo and a working .source/ cloned from it so
    ``git fetch origin`` and ``rev-parse origin/main`` both resolve.
    """
    install_dir.mkdir(parents=True, exist_ok=True)

    origin = install_dir / ".origin.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(origin)], check=True)

    work = install_dir / ".work"
    work.mkdir()
    subprocess.run(["git", "init", "--quiet", "-b", "main", str(work)], check=True)
    subprocess.run(
        ["git", "-C", str(work), "config", "user.email", "t@t"], check=True
    )
    subprocess.run(
        ["git", "-C", str(work), "config", "user.name", "t"], check=True
    )

    (work / "koda").mkdir()
    (work / "koda" / "__init__.py").write_text(f'__version__ = "{version}"\n')
    (work / "pyproject.toml").write_text(pyproject)

    subprocess.run(["git", "-C", str(work), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "--quiet", "-m", "init"], check=True
    )
    subprocess.run(
        ["git", "-C", str(work), "remote", "add", "origin", str(origin)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(work), "push", "--quiet", "-u", "origin", "main"],
        check=True,
    )

    source = install_dir / ".source"
    subprocess.run(
        ["git", "clone", "--quiet", str(origin), str(source)], check=True
    )
    subprocess.run(["git", "-C", str(source), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "t"], check=True)

    # Stub venv so the install-dir detection accepts the layout and any
    # pip-install path we hit is skipped (we only exercise pyproject-unchanged
    # flows in these tests).
    (install_dir / ".venv" / "bin").mkdir(parents=True, exist_ok=True)

    shutil.rmtree(work)
    return source


def _append_remote_commit(
    source: Path, *, version: str, pyproject: str | None = None
) -> None:
    """Add a commit on origin/main by pushing from a second working tree."""
    origin = source.parent / ".origin.git"
    tmp = source.parent / f".tmp-{os.getpid()}"
    subprocess.run(
        ["git", "clone", "--quiet", str(origin), str(tmp)], check=True
    )
    subprocess.run(["git", "-C", str(tmp), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(tmp), "config", "user.name", "t"], check=True)

    (tmp / "koda" / "__init__.py").write_text(f'__version__ = "{version}"\n')
    if pyproject is not None:
        (tmp / "pyproject.toml").write_text(pyproject)

    subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp), "commit", "--quiet", "-m", f"bump {version}"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp), "push", "--quiet", "origin", "main"],
        check=True,
    )
    shutil.rmtree(tmp)


@pytest.fixture
def _git_available() -> None:
    if shutil.which("git") is None:
        pytest.skip("git not available")


def test_update_up_to_date(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    _git_available: None,
) -> None:
    install = tmp_path / "install"
    _init_fixture_repo(install, version="0.1.0")

    rc = _cmd_update(["--dir", str(install), "--check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "already on latest" in out


def test_update_check_reports_available_update(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    _git_available: None,
) -> None:
    install = tmp_path / "install"
    source = _init_fixture_repo(install, version="0.1.0")
    _append_remote_commit(source, version="0.1.1")

    rc = _cmd_update(["--dir", str(install), "--check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "v0.1.0" in out
    assert "v0.1.1" in out
    assert "koda update" in out


def test_update_applies_with_yes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    _git_available: None,
) -> None:
    install = tmp_path / "install"
    source = _init_fixture_repo(install, version="0.1.0")
    _append_remote_commit(source, version="0.1.2")

    rc = _cmd_update(["--dir", str(install), "--yes"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "updated" in out
    # Local checkout advanced
    new_version = (source / "koda" / "__init__.py").read_text()
    assert '"0.1.2"' in new_version


def test_update_refuses_dirty_tree(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    _git_available: None,
) -> None:
    install = tmp_path / "install"
    source = _init_fixture_repo(install, version="0.1.0")
    (source / "koda" / "__init__.py").write_text('__version__ = "0.1.0-dirty"\n')

    rc = _cmd_update(["--dir", str(install), "--yes"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "uncommitted" in err
