"""Built-in tools. Importing this package triggers registration with the global registry.

Plugin auto-discovery: every ``*.py`` sibling (except ``_private.py``) is imported
on package load, so dropping a new module into this directory is enough to
register the tools it defines. No edits to this file required.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil

logger = logging.getLogger(__name__)


def _autoload() -> list[str]:
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


_LOADED: list[str] = _autoload()
