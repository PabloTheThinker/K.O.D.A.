"""Subprocess runner + shell-out helpers.

Thin wrapper around asyncio.create_subprocess_exec with timeout, binary-missing
detection, and cwd validation. Used by every shell-out tool in koda.tools.
"""
from __future__ import annotations

import asyncio
import contextlib
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CmdResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    error: str | None = None

    @property
    def combined(self) -> str:
        parts: list[str] = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(self.stderr)
        return "\n".join(parts).strip()


def which(*binaries: str) -> str | None:
    """First binary on PATH, or None."""
    for b in binaries:
        p = shutil.which(b)
        if p:
            return p
    return None


def trim(text: str, limit: int = 20_000) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n...[trimmed]"


async def run_cmd(args: list[str], timeout: int = 60, cwd: str | None = None) -> CmdResult:
    """Run a subprocess. Never raises — returns CmdResult with error populated."""
    if cwd and not Path(cwd).exists():
        return CmdResult(False, "", "", 1, f"working directory not found: {cwd}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    except FileNotFoundError:
        return CmdResult(False, "", "", 127, f"binary not installed: {args[0]}")
    except OSError as exc:
        return CmdResult(False, "", "", 1, str(exc))

    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        with contextlib.suppress(Exception):
            await proc.communicate()
        return CmdResult(False, "", "", 124, f"command timed out after {timeout}s: {args[0]}")

    return CmdResult(
        ok=(proc.returncode == 0),
        stdout=out_b.decode(errors="ignore"),
        stderr=err_b.decode(errors="ignore"),
        returncode=proc.returncode or 0,
    )
