"""Integration test for ``koda learn`` against a real Helix store."""
from __future__ import annotations

from pathlib import Path

import pytest

from koda.cli.learn import _cmd_list, _cmd_run
from koda.cli.learn import main as learn_main
from koda.learning import LearnedSkillStore
from koda.memory.helix import Helix


def _seed_helix(helix: Helix) -> None:
    """Encode enough episodes to produce a promotable concept."""
    for i in range(6):
        helix.encode(
            event_type="finding",
            content=f"host-{i} exposes SSH with PermitRootLogin yes",
            severity="high",
            outcome=f"flagged host-{i}",
            metadata={"tool": "nmap"},
        )
    helix.consolidate(min_cluster_size=3, max_age_hours=72)


def test_learn_run_drafts_pending_skill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("KODA_HOME", str(tmp_path))
    # Force a fresh import of koda.config so KODA_HOME rebinds.
    import importlib

    import koda.config
    importlib.reload(koda.config)

    memory_dir = tmp_path / "memory"
    memory_dir.mkdir(parents=True, exist_ok=True)

    with Helix(memory_dir) as helix:
        _seed_helix(helix)

        # Force threshold down so the seeded concept promotes even with modest
        # confidence — the seed above creates a 0.4-0.6 confidence concept.
        rc = _cmd_run(["--min-confidence", "0.3", "--min-evidence", "3"])
        assert rc == 0

    out = capsys.readouterr().out
    assert "drafted" in out

    store = LearnedSkillStore(tmp_path / "skills" / "_learned")
    pending = store.list_pending()
    assert len(pending) >= 1
    md = (pending[0].path / "SKILL.md").read_text()
    assert "status: learned-draft" in md
    assert "## Observations" in md


def test_learn_no_helix_is_graceful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("KODA_HOME", str(tmp_path))
    import importlib

    import koda.config
    importlib.reload(koda.config)

    rc = _cmd_run([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Helix not initialized" in out or "not initialized" in out


def test_learn_list_shows_empty_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("KODA_HOME", str(tmp_path))
    import importlib

    import koda.config
    importlib.reload(koda.config)

    rc = _cmd_list([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pending" in out
    assert "approved" in out


def test_learn_dispatch_help(capsys: pytest.CaptureFixture[str]) -> None:
    rc = learn_main(["--help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "koda learn" in out
    assert "approve" in out
    assert "reject" in out


def test_learn_rejects_unknown_subcommand(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = learn_main(["bogus"])
    assert rc == 2
