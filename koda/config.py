"""K.O.D.A. configuration — YAML load/save for ~/.koda/config.yaml."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


KODA_HOME = Path(os.environ.get("KODA_HOME", Path.home() / ".koda"))
CONFIG_PATH = KODA_HOME / "config.yaml"


def load_config(path: Path | None = None) -> dict[str, Any]:
    path = path or CONFIG_PATH
    if not path.exists():
        return {}
    if yaml is None:
        raise RuntimeError("pyyaml is required to read K.O.D.A. config")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}


def save_config(config: dict[str, Any], path: Path | None = None) -> Path:
    path = path or CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    if yaml is None:
        raise RuntimeError("pyyaml is required to write K.O.D.A. config")
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, sort_keys=False, default_flow_style=False)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def config_exists(path: Path | None = None) -> bool:
    path = path or CONFIG_PATH
    return path.exists() and path.stat().st_size > 0
