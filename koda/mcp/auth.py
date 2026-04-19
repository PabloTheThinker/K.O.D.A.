"""MCP SSE transport authentication — bearer token and audit integration.

Token precedence (highest → lowest):
  1. KODA_MCP_TOKEN environment variable
  2. KODA_HOME/mcp.toml  auth.bearer_token field
  3. Auto-generated on first run, written to mcp.toml with 0600 perms

Audit events emitted (unless KODA_MCP_NO_AUDIT=1):
  mcp.auth.denied — fields: remote_addr, path, reason
  mcp.auth.ok     — fields: remote_addr, path, token_fingerprint (first 8 of sha256)
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sys
import tomllib
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

_MCP_TOML_NAME = "mcp.toml"


def _mcp_toml_path(home: Path) -> Path:
    return home / _MCP_TOML_NAME


def load_mcp_config(home: Path) -> dict[str, Any]:
    """Read mcp.toml from *home*. Returns {} if the file does not exist."""
    path = _mcp_toml_path(home)
    if not path.exists():
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _write_mcp_config(home: Path, data: dict[str, Any]) -> None:
    """Write *data* as TOML to mcp.toml with 0600 permissions.

    We produce minimal TOML by hand to avoid pulling in a write-capable
    TOML library (tomllib is stdlib read-only in 3.11+).  The only key we
    ever write is auth.bearer_token, so the manual serialisation is safe.
    """
    home.mkdir(parents=True, exist_ok=True)
    path = _mcp_toml_path(home)

    lines: list[str] = []
    for section, values in data.items():
        lines.append(f"[{section}]")
        if isinstance(values, dict):
            for k, v in values.items():
                if isinstance(v, str):
                    escaped = v.replace("\\", "\\\\").replace('"', '\\"')
                    lines.append(f'{k} = "{escaped}"')
                else:
                    lines.append(f"{k} = {v!r}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def ensure_bearer_token(home: Path) -> str:
    """Return the configured bearer token, generating and persisting one if needed.

    Priority:
      1. KODA_MCP_TOKEN env var
      2. mcp.toml auth.bearer_token
      3. Generate secrets.token_urlsafe(32), persist, print once.

    Idempotent: calling multiple times returns the same token.
    """
    # 1. env var (highest priority — never persisted)
    env_token = os.environ.get("KODA_MCP_TOKEN", "").strip()
    if env_token:
        return env_token

    # 2. existing mcp.toml
    cfg = load_mcp_config(home)
    existing = cfg.get("auth", {}).get("bearer_token", "").strip()
    if existing:
        return existing

    # 3. auto-generate
    token = secrets.token_urlsafe(32)
    cfg.setdefault("auth", {})["bearer_token"] = token
    _write_mcp_config(home, cfg)

    # Print exactly once, prominently
    msg = (
        "\n"
        "  ┌─────────────────────────────────────────────────────────────┐\n"
        "  │  K.O.D.A. MCP — bearer token (save this, shown only once)  │\n"
        f"  │  {token:<61}│\n"
        "  │  Written to: " + str(_mcp_toml_path(home)) + "\n"
        "  └─────────────────────────────────────────────────────────────┘\n"
    )
    print(msg, file=sys.stderr, flush=True)
    return token


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------

def _token_fingerprint(token: str) -> str:
    """Return first 8 hex chars of the SHA-256 of the token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


def verify_bearer(token_header: str | None, expected: str) -> bool:
    """Constant-time comparison of the Authorization header value vs *expected*.

    *token_header* is the raw header value, e.g. ``"Bearer abc123"`` or
    ``"bearer abc123"`` (RFC 6750 prefix is case-insensitive).
    Returns True iff the header is well-formed and the token matches.
    """
    if not token_header:
        return False
    parts = token_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    candidate = parts[1].strip()
    # Constant-time: both sides encoded to bytes of equal length
    # (hmac.compare_digest pads nothing; we must pass same-type args)
    try:
        return hmac.compare_digest(
            candidate.encode("utf-8"),
            expected.encode("utf-8"),
        )
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

def _should_audit() -> bool:
    return os.environ.get("KODA_MCP_NO_AUDIT", "").strip() not in {"1", "true", "yes"}


def emit_auth_event(event: str, **fields: Any) -> None:
    """Emit an audit event for MCP auth decisions.

    Respects KODA_MCP_NO_AUDIT=1 to suppress events in tests.
    Uses the same AuditLogger used everywhere else in K.O.D.A.
    """
    if not _should_audit():
        return
    try:
        from ..audit.logger import AuditLogger
        logger = AuditLogger()
        logger.emit(event, **fields)
        logger.close()
    except Exception:  # noqa: BLE001 — never let audit break the server
        pass


__all__ = [
    "load_mcp_config",
    "ensure_bearer_token",
    "verify_bearer",
    "emit_auth_event",
    "_token_fingerprint",
]
