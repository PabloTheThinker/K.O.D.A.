"""Persist API keys to ~/.koda/secrets.env with 0600 permissions.

Keys never go into config.yaml or git — always the secrets file. On write,
we rewrite the file so duplicate keys don't stack up.
"""
from __future__ import annotations

import os
from pathlib import Path


def save_secrets(secrets: dict[str, str], path: Path) -> None:
    """Merge `secrets` into the dotenv-style file at `path`. Chmod 0600.

    Existing keys are updated; unrelated keys are preserved. Comment and
    blank lines are preserved. Values are single-quoted if they contain a
    space.
    """
    if not secrets:
        return

    path.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, str] = {}
    preamble: list[str] = []

    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                preamble.append(raw)
                continue
            if "=" not in line:
                preamble.append(raw)
                continue
            k, v = line.split("=", 1)
            existing[k.strip()] = v.strip()

    existing.update({k: _quote(v) for k, v in secrets.items() if v})

    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for line in preamble:
            f.write(line.rstrip() + "\n")
        if preamble and not preamble[-1] == "":
            f.write("\n")
        for k in sorted(existing):
            f.write(f"{k}={existing[k]}\n")

    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _quote(value: str) -> str:
    value = value.strip().strip('"').strip("'")
    if " " in value and not (value.startswith('"') and value.endswith('"')):
        return f'"{value}"'
    return value


__all__ = ["save_secrets"]
