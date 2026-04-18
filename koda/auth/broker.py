"""Per-engagement credential broker — the auth-health layer.

Why a dedicated subsystem instead of shoving keys into env vars:

  - Engagement isolation. A cred for client A must never be readable
    while the agent is working on client B. Enforced at the read path
    — ``get(cred_id, engagement)`` raises if the requested cred belongs
    to a different engagement.
  - Redaction. Scanners and APIs have a bad habit of echoing the
    credential they used back into stdout. The broker registers the
    literal value on access, and ``redact(text)`` replaces it before
    the bytes land in the session transcript or evidence sidecar.
  - Cooldown. A broken/expired cred retried in a loop will lock out
    the operator's account. When a cred fails auth, ``mark_broken``
    puts it in cooldown for a configurable window.
  - Placeholder detection. Catches obvious "your-api-key-here" values
    before they hit a live endpoint.
  - Audit trail. Every access, addition, and break is emitted so the
    engagement log can answer "which cred was used, when, and did it
    work." The literal value never appears in the audit.

Storage model:

  <KODA_HOME>/credentials/<engagement>.json  (chmod 0o600)

Each file is a JSON object keyed by credential_id. Plaintext on disk
relies on filesystem permissions for confidentiality — the same posture
as ~/.aws/credentials, ~/.kube/config, and ~/.ssh/. If operators want
encryption at rest, set KODA_VAULT_KEYRING to point at an OS keyring
(follow-up) or wrap the whole koda tree with age/gpg.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

# Values that look like placeholders. Rejected at store time.
_PLACEHOLDER_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"^your[_\-]?[\w\-]*key[_\-]?here$", re.I),
    re.compile(r"^(?:x+|0+|-+|\.+)$"),
    re.compile(r"^(?:xxx+|yyy+|zzz+|aaa+)$", re.I),
    re.compile(r"^\s*$"),
    re.compile(r"^(?:replace|insert|todo|tbd|fixme)[:\s].*", re.I),
    re.compile(r"^<.*>$"),
    re.compile(r"^(?:none|null|undefined|placeholder|example)$", re.I),
)

# Minimum plausible length for a real key. Shorter = almost certainly fake.
_MIN_KEY_LENGTH = 16


@dataclass(frozen=True)
class Credential:
    credential_id: str
    name: str
    kind: str  # "api_key" | "bearer" | "basic" | "ssh" | "oauth" | "custom"
    engagement: str
    metadata: dict[str, Any] = field(default_factory=dict)
    added_at: float = 0.0
    # Value is intentionally excluded from the frozen dataclass so accidental
    # stringification never includes the secret. Pull via broker.get_value().

    def redacted_view(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "name": self.name,
            "kind": self.kind,
            "engagement": self.engagement,
            "metadata": dict(self.metadata),
            "added_at": self.added_at,
        }


@dataclass
class CredentialHealth:
    credential_id: str
    healthy: bool
    checked_at: float
    detail: str = ""
    cooldown_until: float = 0.0


class CredentialError(Exception):
    """Raised for placeholder/too-short values, wrong-engagement access,
    and missing creds. Callers should treat any CredentialError as fatal
    for the current invocation — continuing would either burn the cred
    in a loop or leak it across engagements."""


def default_credentials_path() -> Path:
    root = Path(os.environ.get("KODA_HOME", str(Path.home() / ".koda")))
    return root / "credentials"


def looks_like_placeholder(value: str) -> bool:
    v = (value or "").strip()
    if len(v) < _MIN_KEY_LENGTH:
        return True
    for pattern in _PLACEHOLDER_PATTERNS:
        if pattern.match(v):
            return True
    return False


class NullCredentialBroker:
    """No-op broker. Used when credentials are intentionally disabled."""

    def add(self, *_, **__) -> Credential:  # type: ignore[override]
        raise CredentialError("credentials disabled in this profile")

    def get(self, credential_id: str, engagement: str) -> Credential:  # type: ignore[override]
        raise CredentialError(f"credential {credential_id!r} not found")

    def get_value(self, credential_id: str, engagement: str) -> str:
        raise CredentialError(f"credential {credential_id!r} not found")

    def list(self, engagement: str) -> list[Credential]:
        return []

    def remove(self, credential_id: str, engagement: str) -> bool:
        return False

    def mark_broken(self, credential_id: str, engagement: str, *, cooldown_seconds: int = 900, detail: str = "") -> None:
        return None

    def healthy(self, credential_id: str, engagement: str) -> bool:
        return False

    async def check_health(self, *_, **__) -> CredentialHealth:  # type: ignore[override]
        raise CredentialError("credentials disabled in this profile")

    def register_redaction(self, value: str, label: str) -> None:
        return None

    def redact(self, text: str) -> str:
        return text

    def close(self) -> None:
        return None


class CredentialBroker:
    """Engagement-scoped credential vault with redaction and cooldown."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        audit: Any = None,
    ) -> None:
        self.root = Path(path) if path else default_credentials_path()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        self.audit = audit
        self._lock = threading.RLock()
        # In-memory redaction map: literal value -> label to substitute.
        # Populated on every get_value() so tool output can be sanitized
        # before it reaches the transcript / evidence store.
        self._redactions: dict[str, str] = {}
        # Cooldowns are in-memory only — on restart, agents re-check from
        # scratch. Preventing retry-in-a-loop is the point, not durability.
        self._cooldowns: dict[tuple[str, str], float] = {}

    # --- persistence ---

    def _vault_path(self, engagement: str) -> Path:
        safe = engagement or "_unscoped"
        safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in safe)[:64]
        return self.root / f"{safe}.json"

    def _load(self, engagement: str) -> dict[str, dict[str, Any]]:
        path = self._vault_path(engagement)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text() or "{}") or {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, engagement: str, data: dict[str, dict[str, Any]]) -> None:
        path = self._vault_path(engagement)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _emit(self, event: str, **fields: Any) -> None:
        if self.audit is None:
            return
        try:
            self.audit.emit(event, **fields)
        except Exception:
            pass

    # --- write path ---

    def add(
        self,
        *,
        credential_id: str,
        name: str,
        kind: str,
        value: str,
        engagement: str,
        metadata: dict[str, Any] | None = None,
    ) -> Credential:
        if looks_like_placeholder(value):
            raise CredentialError(
                f"value for {credential_id!r} looks like a placeholder; refusing to store."
            )
        with self._lock:
            data = self._load(engagement)
            entry = {
                "credential_id": credential_id,
                "name": name,
                "kind": kind,
                "engagement": engagement,
                "metadata": dict(metadata or {}),
                "added_at": time.time(),
                "value": value,
            }
            data[credential_id] = entry
            self._save(engagement, data)
        cred = Credential(
            credential_id=credential_id,
            name=name,
            kind=kind,
            engagement=engagement,
            metadata=dict(metadata or {}),
            added_at=entry["added_at"],
        )
        self._emit(
            "cred.added",
            engagement=engagement,
            credential_id=credential_id,
            kind=kind,
            name=name,
        )
        return cred

    def remove(self, credential_id: str, engagement: str) -> bool:
        with self._lock:
            data = self._load(engagement)
            if credential_id not in data:
                return False
            del data[credential_id]
            self._save(engagement, data)
        self._emit(
            "cred.removed",
            engagement=engagement,
            credential_id=credential_id,
        )
        return True

    # --- read path ---

    def _read_entry(self, credential_id: str, engagement: str) -> dict[str, Any]:
        data = self._load(engagement)
        entry = data.get(credential_id)
        if entry is None:
            raise CredentialError(
                f"credential {credential_id!r} not found in engagement {engagement!r}"
            )
        stored_eng = str(entry.get("engagement") or "")
        if stored_eng and stored_eng != engagement:
            # Should not happen (per-engagement files) but defense in depth.
            raise CredentialError(
                f"credential {credential_id!r} belongs to a different engagement"
            )
        return entry

    def get(self, credential_id: str, engagement: str) -> Credential:
        with self._lock:
            entry = self._read_entry(credential_id, engagement)
        return Credential(
            credential_id=entry["credential_id"],
            name=entry["name"],
            kind=entry["kind"],
            engagement=entry["engagement"],
            metadata=dict(entry.get("metadata") or {}),
            added_at=float(entry.get("added_at") or 0.0),
        )

    def get_value(self, credential_id: str, engagement: str) -> str:
        """Return the literal secret AND register it for redaction.

        Raises CredentialError if the cred is in cooldown — callers must
        handle this rather than retry blindly.
        """
        with self._lock:
            if not self.healthy(credential_id, engagement):
                until = self._cooldowns.get((engagement, credential_id), 0.0)
                remaining = max(0, int(until - time.time()))
                raise CredentialError(
                    f"credential {credential_id!r} in cooldown for {remaining}s"
                )
            entry = self._read_entry(credential_id, engagement)
            value = str(entry.get("value") or "")
            self._redactions[value] = f"[REDACTED {entry.get('name') or credential_id}]"
        self._emit(
            "cred.access",
            engagement=engagement,
            credential_id=credential_id,
            kind=entry.get("kind"),
        )
        return value

    def list(self, engagement: str) -> list[Credential]:
        with self._lock:
            data = self._load(engagement)
        out: list[Credential] = []
        for entry in data.values():
            out.append(
                Credential(
                    credential_id=entry["credential_id"],
                    name=entry.get("name") or "",
                    kind=entry.get("kind") or "custom",
                    engagement=entry.get("engagement") or engagement,
                    metadata=dict(entry.get("metadata") or {}),
                    added_at=float(entry.get("added_at") or 0.0),
                )
            )
        out.sort(key=lambda c: c.added_at)
        return out

    # --- health + cooldown ---

    def mark_broken(
        self,
        credential_id: str,
        engagement: str,
        *,
        cooldown_seconds: int = 900,
        detail: str = "",
    ) -> None:
        until = time.time() + max(1, int(cooldown_seconds))
        with self._lock:
            self._cooldowns[(engagement, credential_id)] = until
        self._emit(
            "cred.broken",
            engagement=engagement,
            credential_id=credential_id,
            cooldown_seconds=cooldown_seconds,
            detail=detail[:200],
        )

    def healthy(self, credential_id: str, engagement: str) -> bool:
        with self._lock:
            until = self._cooldowns.get((engagement, credential_id), 0.0)
        return time.time() >= until

    async def check_health(
        self,
        credential_id: str,
        engagement: str,
        probe: Callable[[str], Awaitable[bool] | bool],
        *,
        cooldown_seconds: int = 900,
    ) -> CredentialHealth:
        """Run operator-supplied ``probe(value)`` against the cred value.

        If the probe returns False (or raises), mark broken and cool down.
        """
        try:
            value = self.get_value(credential_id, engagement)
        except CredentialError as exc:
            return CredentialHealth(
                credential_id=credential_id,
                healthy=False,
                checked_at=time.time(),
                detail=str(exc),
                cooldown_until=self._cooldowns.get((engagement, credential_id), 0.0),
            )

        ok = False
        detail = ""
        try:
            result = probe(value)
            if hasattr(result, "__await__"):
                result = await result  # type: ignore[assignment]
            ok = bool(result)
        except Exception as exc:  # noqa: BLE001
            detail = f"{type(exc).__name__}: {exc}"

        if not ok:
            self.mark_broken(
                credential_id,
                engagement,
                cooldown_seconds=cooldown_seconds,
                detail=detail or "probe returned False",
            )

        return CredentialHealth(
            credential_id=credential_id,
            healthy=ok,
            checked_at=time.time(),
            detail=detail,
            cooldown_until=self._cooldowns.get((engagement, credential_id), 0.0),
        )

    # --- redaction ---

    def register_redaction(self, value: str, label: str) -> None:
        """Manually register a literal for redaction (e.g. a bearer token
        pulled from env that the broker didn't hand out)."""
        if value and len(value) >= 4:
            with self._lock:
                self._redactions[value] = label

    def redact(self, text: str) -> str:
        if not text:
            return text
        with self._lock:
            items = list(self._redactions.items())
        # Redact longest values first so overlapping secrets don't leave
        # dangling suffixes.
        items.sort(key=lambda kv: len(kv[0]), reverse=True)
        out = text
        for value, label in items:
            if value and value in out:
                out = out.replace(value, label)
        return out

    def close(self) -> None:
        with self._lock:
            self._redactions.clear()
            self._cooldowns.clear()


__all__ = [
    "Credential",
    "CredentialBroker",
    "CredentialError",
    "CredentialHealth",
    "NullCredentialBroker",
    "default_credentials_path",
    "looks_like_placeholder",
]
