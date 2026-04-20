"""On-disk store for learned skill candidates.

Layout under ``$KODA_HOME/skills/_learned/``:

    _learned/
      _pending/               # drafts awaiting human review
        <name>/
          SKILL.md
          .source.json        # which concept generated this
      <name>/                 # approved learned skills (auto-loaded by SkillLoader)
        SKILL.md
        .source.json
      _rejected/              # drafts the reviewer turned down (kept for audit)
        <name>-<timestamp>.md

The approved tier sits directly under ``_learned/`` so the existing
:class:`koda.skills.SkillLoader` picks it up without any configuration
changes — the search path already includes ``~/.koda/skills``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

PENDING_DIRNAME = "_pending"
REJECTED_DIRNAME = "_rejected"
LEARNED_ROOT_DIRNAME = "_learned"


@dataclass
class PendingSkill:
    """A draft waiting for review, rendered from :class:`SkillDraft`."""

    name: str
    path: Path
    skill_md: str
    source: dict


class LearnedSkillStore:
    """Manage pending / approved / rejected learned skills on disk.

    Thin wrapper — no caching, each call re-reads the filesystem so external
    edits (say, the reviewer editing a SKILL.md by hand) take effect
    immediately.
    """

    def __init__(self, root: Path):
        self.root = Path(root)

    # ── Paths ─────────────────────────────────────────────────────

    @property
    def pending_dir(self) -> Path:
        return self.root / PENDING_DIRNAME

    @property
    def rejected_dir(self) -> Path:
        return self.root / REJECTED_DIRNAME

    def pending_path(self, name: str) -> Path:
        return self.pending_dir / name

    def approved_path(self, name: str) -> Path:
        return self.root / name

    # ── Pending ───────────────────────────────────────────────────

    def save_pending(
        self,
        *,
        name: str,
        skill_md: str,
        source: dict,
    ) -> PendingSkill:
        """Write a draft to ``_pending/<name>/SKILL.md`` atomically."""
        dest = self.pending_path(name)
        dest.mkdir(parents=True, exist_ok=True)

        skill_file = dest / "SKILL.md"
        _atomic_write(skill_file, skill_md)

        meta_file = dest / ".source.json"
        _atomic_write(meta_file, json.dumps(source, indent=2, sort_keys=True))

        return PendingSkill(
            name=name, path=dest, skill_md=skill_md, source=source,
        )

    def list_pending(self) -> list[PendingSkill]:
        if not self.pending_dir.is_dir():
            return []
        result: list[PendingSkill] = []
        for entry in sorted(self.pending_dir.iterdir()):
            if not entry.is_dir():
                continue
            skill_file = entry / "SKILL.md"
            if not skill_file.is_file():
                continue
            try:
                skill_md = skill_file.read_text(encoding="utf-8")
            except OSError:
                continue
            source = _load_source(entry / ".source.json")
            result.append(PendingSkill(
                name=entry.name, path=entry, skill_md=skill_md, source=source,
            ))
        return result

    def pending_concept_ids(self) -> set[str]:
        """Concept IDs already drafted — used to avoid re-drafting duplicates."""
        ids: set[str] = set()
        for pending in self.list_pending():
            cid = pending.source.get("concept_id")
            if isinstance(cid, str) and cid:
                ids.add(cid)
        return ids

    # ── Approve / reject ──────────────────────────────────────────

    def approve(self, name: str) -> Path:
        src = self.pending_path(name)
        if not src.is_dir():
            raise FileNotFoundError(f"no pending skill named {name!r}")
        dest = self.approved_path(name)
        if dest.exists():
            raise FileExistsError(
                f"approved skill {name!r} already exists at {dest}"
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        src.rename(dest)
        return dest

    def reject(self, name: str) -> Path:
        src = self.pending_path(name)
        if not src.is_dir():
            raise FileNotFoundError(f"no pending skill named {name!r}")
        self.rejected_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        dest_file = self.rejected_dir / f"{name}-{stamp}.md"
        skill_file = src / "SKILL.md"
        payload = skill_file.read_text(encoding="utf-8") if skill_file.is_file() else ""
        _atomic_write(dest_file, payload)
        # Wipe the pending dir — rejection is final; source.json archived inline.
        _rmtree(src)
        return dest_file

    # ── Approved inventory ────────────────────────────────────────

    def list_approved(self) -> list[Path]:
        if not self.root.is_dir():
            return []
        result: list[Path] = []
        for entry in sorted(self.root.iterdir()):
            if not entry.is_dir() or entry.name.startswith("_"):
                continue
            if (entry / "SKILL.md").is_file():
                result.append(entry)
        return result


def default_store() -> LearnedSkillStore:
    """Return the store rooted at ``$KODA_HOME/skills/_learned/``."""
    from koda.config import KODA_HOME
    return LearnedSkillStore(KODA_HOME / "skills" / LEARNED_ROOT_DIRNAME)


# ── Helpers ─────────────────────────────────────────────────────

def _atomic_write(path: Path, payload: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)


def _load_source(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _rmtree(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        for child in path.iterdir():
            _rmtree(child)
        path.rmdir()
    else:
        path.unlink()
