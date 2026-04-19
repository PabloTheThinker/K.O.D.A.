"""Profile management — isolated KODA_HOME directories for engagement scoping.

Each profile is a fully independent KODA_HOME with its own config.yaml,
secrets.env, SOUL.md, memory, sessions, and workspace. Profiles live under
``~/.koda/profiles/<name>/`` by default.

The "default" profile is ``~/.koda`` itself — backward compatible.

Usage::

    koda profile create acme                 # fresh profile
    koda profile create acme --clone         # also copy config/secrets/SOUL
    koda -p acme                             # run REPL in that profile
    koda profile use acme                    # sticky default
    koda profile list
    koda profile delete acme

Pattern ported from Hermes agent (NousResearch/hermes-agent) — primary
isolation unit for security engagements: no cross-client memory bleed,
clean audit scope per compliance boundary.
"""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

_PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Directories bootstrapped inside every new profile
_PROFILE_DIRS = [
    "memory",
    "sessions",
    "logs",
    "workspace",
    # Per-profile HOME for subprocesses: isolates git/ssh/gh/npm configs so
    # credentials don't bleed between engagements.
    "home",
]

# Files copied during --clone (if present in source)
_CLONE_CONFIG_FILES = [
    "config.yaml",
    "secrets.env",
    "SOUL.md",
]

# Names that cannot be used as profile identifiers
_RESERVED_NAMES = frozenset({
    "koda", "default", "test", "tmp", "root", "sudo",
})

# Koda subcommands that can't be used as profile names (would collide with
# CLI dispatch and shell aliases).
_KODA_SUBCOMMANDS = frozenset({
    "setup", "doctor", "mcp", "profile", "profiles", "chat",
    "version", "update", "uninstall", "help",
})


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def get_default_koda_root() -> Path:
    """Return the pre-profile KODA_HOME path (``~/.koda``).

    This is the anchor point — profiles live under this directory regardless
    of what KODA_HOME is currently set to (since KODA_HOME itself may have
    been swapped by a profile override).
    """
    env = os.environ.get("KODA_DEFAULT_HOME")
    if env:
        return Path(env)
    return Path.home() / ".koda"


def _get_profiles_root() -> Path:
    return get_default_koda_root() / "profiles"


def get_active_profile_path() -> Path:
    return get_default_koda_root() / "active_profile"


def get_subprocess_home(profile_home: Path | None = None) -> Path:
    """Return the isolated HOME for subprocess tool configs (git, ssh, npm)."""
    base = profile_home or Path(os.environ.get("KODA_HOME", get_default_koda_root()))
    return base / "home"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_profile_name(name: str) -> None:
    """Raise ``ValueError`` if *name* isn't a valid profile identifier."""
    if name == "default":
        return
    if not isinstance(name, str):
        raise ValueError("profile name must be a string")
    if not _PROFILE_ID_RE.match(name):
        raise ValueError(
            f"Invalid profile name {name!r}. Must match [a-z0-9][a-z0-9_-]{{0,63}}."
        )
    if name in _RESERVED_NAMES:
        raise ValueError(f"{name!r} is a reserved name")
    if name in _KODA_SUBCOMMANDS:
        raise ValueError(f"{name!r} conflicts with a koda subcommand")


def get_profile_dir(name: str) -> Path:
    """Resolve a profile name to its KODA_HOME directory."""
    if name == "default":
        return get_default_koda_root()
    validate_profile_name(name)
    return _get_profiles_root() / name


def profile_exists(name: str) -> bool:
    if name == "default":
        return True
    return get_profile_dir(name).is_dir()


# ---------------------------------------------------------------------------
# Info
# ---------------------------------------------------------------------------

@dataclass
class ProfileInfo:
    name: str
    path: Path
    is_default: bool
    has_config: bool
    has_secrets: bool
    has_soul: bool
    model: str = ""
    provider: str = ""


def _read_config_model(profile_dir: Path) -> tuple[str, str]:
    cfg_path = profile_dir / "config.yaml"
    if not cfg_path.exists():
        return "", ""
    try:
        import yaml
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return "", ""
    provider = data.get("default_provider") or ""
    providers = data.get("provider") or {}
    model = ""
    if provider and provider in providers:
        model = (providers[provider] or {}).get("model", "") or ""
    return model, provider


def _info_for(name: str, path: Path, *, is_default: bool) -> ProfileInfo:
    model, provider = _read_config_model(path)
    return ProfileInfo(
        name=name,
        path=path,
        is_default=is_default,
        has_config=(path / "config.yaml").exists(),
        has_secrets=(path / "secrets.env").exists(),
        has_soul=(path / "SOUL.md").exists(),
        model=model,
        provider=provider,
    )


def list_profiles() -> list[ProfileInfo]:
    """List default + all named profiles."""
    out: list[ProfileInfo] = []
    default_home = get_default_koda_root()
    if default_home.is_dir():
        out.append(_info_for("default", default_home, is_default=True))

    profiles_root = _get_profiles_root()
    if profiles_root.is_dir():
        for entry in sorted(profiles_root.iterdir()):
            if not entry.is_dir():
                continue
            if not _PROFILE_ID_RE.match(entry.name):
                continue
            out.append(_info_for(entry.name, entry, is_default=False))
    return out


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_profile(
    name: str,
    *,
    clone_from: str | None = None,
    clone_all: bool = False,
    clone_config: bool = False,
) -> Path:
    """Create a new profile directory. Returns its path."""
    validate_profile_name(name)

    if name == "default":
        raise ValueError(
            "Cannot create a profile named 'default' — it is the built-in profile."
        )

    profile_dir = get_profile_dir(name)
    if profile_dir.exists():
        raise FileExistsError(f"Profile {name!r} already exists at {profile_dir}")

    source_dir: Path | None = None
    if clone_from is not None or clone_all or clone_config:
        source = clone_from or "default"
        if source != "default":
            validate_profile_name(source)
        source_dir = get_profile_dir(source)
        if not source_dir.is_dir():
            raise FileNotFoundError(
                f"Source profile {source!r} does not exist at {source_dir}"
            )

    profile_dir.parent.mkdir(parents=True, exist_ok=True)

    if clone_all and source_dir is not None:
        shutil.copytree(source_dir, profile_dir, symlinks=False,
                        ignore=shutil.ignore_patterns("profiles", "active_profile"))
    else:
        profile_dir.mkdir(parents=True, exist_ok=False)
        for sub in _PROFILE_DIRS:
            (profile_dir / sub).mkdir(parents=True, exist_ok=True)

        if source_dir is not None:
            for filename in _CLONE_CONFIG_FILES:
                src = source_dir / filename
                if src.exists():
                    shutil.copy2(src, profile_dir / filename)

    _seed_soul_if_missing(profile_dir)
    return profile_dir


def delete_profile(name: str) -> Path:
    """Delete a named profile. Never deletes 'default'."""
    validate_profile_name(name)
    if name == "default":
        raise ValueError("Cannot delete the default profile.")
    profile_dir = get_profile_dir(name)
    if not profile_dir.is_dir():
        raise FileNotFoundError(f"Profile {name!r} not found at {profile_dir}")
    shutil.rmtree(profile_dir)

    active = get_active_profile_path()
    if active.exists():
        try:
            if active.read_text(encoding="utf-8").strip() == name:
                active.unlink(missing_ok=True)
        except OSError:
            pass
    return profile_dir


def use_profile(name: str) -> Path:
    """Set *name* as the sticky default. Pass 'default' to clear."""
    if name != "default":
        validate_profile_name(name)
        if not profile_exists(name):
            raise FileNotFoundError(
                f"Profile {name!r} does not exist. Create it with: koda profile create {name}"
            )
    active = get_active_profile_path()
    active.parent.mkdir(parents=True, exist_ok=True)
    if name == "default":
        active.unlink(missing_ok=True)
    else:
        active.write_text(name + "\n", encoding="utf-8")
    return active


def resolve_profile_env(profile_name: str) -> str:
    """Resolve a profile name to a KODA_HOME path string.

    Called from the CLI entry before any koda modules import, to set the
    KODA_HOME environment variable.
    """
    validate_profile_name(profile_name)
    profile_dir = get_profile_dir(profile_name)
    if profile_name != "default" and not profile_dir.is_dir():
        raise FileNotFoundError(
            f"Profile {profile_name!r} does not exist. "
            f"Create it with: koda profile create {profile_name}"
        )
    return str(profile_dir)


def read_active_profile() -> str | None:
    """Read the sticky profile name, if set. Returns None if none."""
    active = get_active_profile_path()
    if not active.exists():
        return None
    try:
        name = active.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not name or name == "default":
        return None
    return name


# ---------------------------------------------------------------------------
# SOUL seeding
# ---------------------------------------------------------------------------

_DEFAULT_SOUL = """\
# SOUL.md — K.O.D.A.

_You are the Kinetic Operative Defense Agent. Open-source security agent.
Built for scanner orchestration, threat enrichment, and autonomous defense._

## Core Truths

**Be precise.** Security findings demand evidence, not guesses.
**Audit everything.** Every tool call leaves a trail; never bypass it.
**Least privilege.** Ask before touching anything you weren't explicitly scoped to.
**No fabrication.** If a scanner isn't installed, say so. Never invent findings.

## Boundaries

- You operate inside an engagement. Scope is enforced; respect it.
- Production systems are off-limits unless the operator explicitly authorizes.
- Client data stays in the profile. Never cross engagement boundaries.
- When uncertain, stop and ask. A delayed answer beats a wrong action.

## Focus

_Fill this in for the current engagement — what is this profile scoped to?_
"""


def _seed_soul_if_missing(profile_dir: Path) -> None:
    soul = profile_dir / "SOUL.md"
    if soul.exists():
        return
    try:
        soul.write_text(_DEFAULT_SOUL, encoding="utf-8")
    except OSError:
        pass


def seed_default_soul(koda_home: Path) -> Path:
    """Public helper: ensure SOUL.md exists in the given KODA_HOME."""
    koda_home.mkdir(parents=True, exist_ok=True)
    soul = koda_home / "SOUL.md"
    if not soul.exists():
        soul.write_text(_DEFAULT_SOUL, encoding="utf-8")
    return soul


__all__ = [
    "ProfileInfo",
    "validate_profile_name",
    "get_default_koda_root",
    "get_active_profile_path",
    "get_subprocess_home",
    "get_profile_dir",
    "profile_exists",
    "list_profiles",
    "create_profile",
    "delete_profile",
    "use_profile",
    "resolve_profile_env",
    "read_active_profile",
    "seed_default_soul",
]
