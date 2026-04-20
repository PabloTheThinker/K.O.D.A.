"""Built-in tools. Importing this package triggers registration with the global registry.

Auto-discovery has two scan paths (Hermes pattern):

1. **Package builtins** — every ``*.py`` in this directory is imported on package
   load. Used for tools that ship with KODA.
2. **User plugins** — every ``*.py`` under ``$KODA_HOME/plugins/`` (default
   ``~/.koda/plugins/``) is imported too. Drop a file there and its tools
   self-register at next REPL/CLI start. Nested packages (a directory with
   ``__init__.py``) are also supported.

Plugin modules are loaded under the synthetic package name
``koda_user_plugins.<stem>`` so they don't collide with anything shipped.
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import pkgutil
import sys
import types
from pathlib import Path

logger = logging.getLogger(__name__)

_USER_PLUGIN_PACKAGE = "koda_user_plugins"


def _autoload_builtins() -> list[str]:
    loaded: list[str] = []
    for info in pkgutil.iter_modules(__path__):
        if info.ispkg or info.name.startswith("_"):
            continue
        try:
            importlib.import_module(f"{__name__}.{info.name}")
            loaded.append(info.name)
        except Exception as exc:  # noqa: BLE001 — keep startup resilient
            logger.warning("builtin tool module '%s' failed to load: %s", info.name, exc)
    return loaded


def _ensure_namespace_package() -> types.ModuleType:
    mod = sys.modules.get(_USER_PLUGIN_PACKAGE)
    if mod is None:
        mod = types.ModuleType(_USER_PLUGIN_PACKAGE)
        mod.__path__ = []  # type: ignore[attr-defined]
        mod.__package__ = _USER_PLUGIN_PACKAGE
        sys.modules[_USER_PLUGIN_PACKAGE] = mod
    return mod


def _user_plugin_dir() -> Path:
    # Lazy import so merely importing this package doesn't drag config.py,
    # which binds KODA_HOME at *its* import time and could miss a late
    # KODA_HOME override set by the profile shim.
    env = os.environ.get("KODA_HOME")
    home = Path(env) if env else Path.home() / ".koda"
    return home / "plugins"


def _load_user_plugin(path: Path, stem: str) -> None:
    """Import a single ``.py`` file or package dir under the user namespace."""
    full_name = f"{_USER_PLUGIN_PACKAGE}.{stem}"
    if full_name in sys.modules:
        return  # already loaded this session
    if path.is_dir():
        init_file = path / "__init__.py"
        if not init_file.exists():
            return
        spec = importlib.util.spec_from_file_location(
            full_name, init_file, submodule_search_locations=[str(path)],
        )
    else:
        spec = importlib.util.spec_from_file_location(full_name, path)

    if spec is None or spec.loader is None:
        logger.warning("plugin '%s' at %s: could not build import spec", stem, path)
        return

    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        sys.modules.pop(full_name, None)
        logger.warning("plugin '%s' failed to load: %s", stem, exc)


def _autoload_user_plugins() -> list[str]:
    plugin_dir = _user_plugin_dir()
    if not plugin_dir.is_dir():
        return []

    _ensure_namespace_package()
    loaded: list[str] = []
    for entry in sorted(plugin_dir.iterdir()):
        if entry.name.startswith((".", "_")):
            continue
        if entry.is_file() and entry.suffix == ".py":
            stem = entry.stem
        elif entry.is_dir() and (entry / "__init__.py").exists():
            stem = entry.name
        else:
            continue
        _load_user_plugin(entry, stem)
        loaded.append(stem)
    return loaded


_LOADED: list[str] = _autoload_builtins()
_LOADED_PLUGINS: list[str] = _autoload_user_plugins()
