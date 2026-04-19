"""Rules of Engagement gate.

The ROE gate is the per-action authorization layer for a live engagement.
It sits between the agent's tool-call intent and the actual tool runner:

  1. ``check_target`` — is this target in the engagement's authorized scope?
  2. ``check_action`` — is this action allowed at all (destruction, DoS),
     and if it needs scope, is the target inside it?
  3. ``log``          — every decision appended to a JSONL audit trail
                        under ``{KODA_HOME}/engagements/{roe_id}/roe.jsonl``.

Decisions carry a severity band:
  - ``pass``  — allow, no extra approval needed.
  - ``warn``  — allowed only if the caller has set an explicit approval
                 flag in the action args (e.g. ``persistence_approved``).
  - ``block`` — hard refusal, no override.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from koda.security.modes import EngagementContext, SecurityMode


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

PASS = "pass"
WARN = "warn"
BLOCK = "block"


@dataclass(frozen=True)
class ROEDecision:
    allow: bool
    reason: str
    severity: str  # "pass" | "warn" | "block"


# ---------------------------------------------------------------------------
# Catalogs
# ---------------------------------------------------------------------------

# Unconditional hard-block actions — destructive beyond pentest needs.
HARD_BLOCK_ACTIONS: frozenset[str] = frozenset(
    {
        "rm",
        "dd",
        "format",
        "mkfs",
        "shutdown",
        "reboot",
        "crontab -r",
        "iptables -F",
    }
)

# DoS / stress patterns — out of scope for standard pentest ROE.
DOS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bslowloris\b", re.IGNORECASE),
    re.compile(r"\bhping3\b[^\n]*--flood", re.IGNORECASE),
    re.compile(r"\bab\b[^\n]*-n\s+\d{7,}", re.IGNORECASE),
    re.compile(r"\bsiege\b[^\n]*-c\s+\d{4,}", re.IGNORECASE),
    re.compile(r"\bsynflood\b", re.IGNORECASE),
)

# Passive recon actions — intel gathering is not the breach.
PASSIVE_ACTIONS: frozenset[str] = frozenset(
    {
        "recon.dns",
        "recon.whois",
        "recon.certtrans",
        "scan.amass",
        "scan.httpx",
        "intel.lookup_cve",
        "intel.lookup_attack",
        "intel.lookup_capec",
    }
)

# Actions that create persistence — require explicit approval.
PERSISTENCE_ACTIONS: frozenset[str] = frozenset(
    {
        "post.persistence",
        "exec.crontab",
        "exec.systemd_install",
        "exec.registry_run",
    }
)

# Argument keys where a target identifier typically lives.
_TARGET_KEYS = (
    "target",
    "targets",
    "host",
    "hosts",
    "url",
    "endpoint",
    "address",
    "ip",
    "cidr",
)

# Secret-shaped keys to redact from the audit log.
_SECRET_KEYS = (
    "password",
    "pass",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
)


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


class ROEGate:
    def __init__(self, ctx: EngagementContext) -> None:
        self.ctx = ctx
        self._log_path = _engagement_log_path(ctx.roe_id)

    # -- target scope ------------------------------------------------------

    def check_target(self, target: str) -> ROEDecision:
        if not target:
            return ROEDecision(False, "Empty target.", BLOCK)
        if not self.ctx.targets:
            return ROEDecision(
                False,
                "No authorized scope declared on this engagement.",
                BLOCK,
            )
        if self.ctx.is_in_scope(target):
            return ROEDecision(True, f"Target {target} is in scope.", PASS)
        return ROEDecision(
            False,
            f"Target {target} is outside authorized scope for ROE {self.ctx.roe_id}.",
            BLOCK,
        )

    # -- action --------------------------------------------------------------

    def check_action(self, action: str, args: dict[str, Any]) -> ROEDecision:
        action_low = (action or "").strip().lower()

        # 1. Hard-block destructive actions — scope does not rescue these.
        for blocked in HARD_BLOCK_ACTIONS:
            if action_low == blocked or action_low.startswith(blocked + " "):
                d = ROEDecision(
                    False,
                    f"Action '{action}' is hard-blocked: destructive beyond pentest needs.",
                    BLOCK,
                )
                self.log(d, action, args)
                return d

        # 2. DoS patterns — evaluate against full action+args blob.
        blob = _args_blob(action, args)
        for pat in DOS_PATTERNS:
            if pat.search(blob):
                d = ROEDecision(
                    False,
                    "DoS out of scope for standard pentest ROE.",
                    BLOCK,
                )
                self.log(d, action, args)
                return d

        # 3. Passive recon — always PASS (no scope required; intel gathering
        # is not the breach).
        if action_low in PASSIVE_ACTIONS:
            d = ROEDecision(
                True,
                f"Passive recon action '{action}' allowed without scope gate.",
                PASS,
            )
            self.log(d, action, args)
            return d

        # 4. Persistence — require explicit approval.
        if action_low in PERSISTENCE_ACTIONS:
            if not args.get("persistence_approved"):
                d = ROEDecision(
                    False,
                    (
                        f"Persistence action '{action}' requires "
                        "'persistence_approved': True in action args."
                    ),
                    WARN,
                )
                self.log(d, action, args)
                return d

        # 5. File mutation outside /tmp.
        path = args.get("path") or args.get("file") or args.get("destination")
        if isinstance(path, str) and path and _is_file_mutation(action_low):
            if not path.startswith("/tmp") and not args.get("target_approved"):
                d = ROEDecision(
                    False,
                    (
                        f"Action '{action}' would modify '{path}' outside /tmp. "
                        "Set 'target_approved': True to proceed."
                    ),
                    WARN,
                )
                self.log(d, action, args)
                return d

        # 6. Scope check — if the action carries a target and we're in RED
        # mode, the target must be in scope.
        if self.ctx.mode == SecurityMode.RED:
            targets = _collect_targets(args)
            for t in targets:
                scope_dec = self.check_target(t)
                if not scope_dec.allow:
                    self.log(scope_dec, action, args)
                    return scope_dec

        d = ROEDecision(True, f"Action '{action}' permitted by ROE.", PASS)
        self.log(d, action, args)
        return d

    # -- audit log ---------------------------------------------------------

    def log(
        self,
        decision: ROEDecision,
        action: str,
        args: dict[str, Any],
    ) -> None:
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
                "roe_id": self.ctx.roe_id,
                "operator": self.ctx.operator,
                "mode": self.ctx.mode.value,
                "phase": self.ctx.phase,
                "action": action,
                "args": _redact(args),
                "allow": decision.allow,
                "severity": decision.severity,
                "reason": decision.reason,
            }
            with self._log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError:
            # Never let logging block the decision path.
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _engagement_log_path(roe_id: str) -> Path:
    home = os.environ.get("KODA_HOME") or str(Path.home() / ".koda")
    return Path(home) / "engagements" / roe_id / "roe.jsonl"


def _is_file_mutation(action: str) -> bool:
    for marker in ("write", "append", "install", "touch", "create", "drop", "chmod", "chown"):
        if marker in action:
            return True
    return False


def _collect_targets(args: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for k in _TARGET_KEYS:
        v = args.get(k)
        if v is None:
            continue
        if isinstance(v, str):
            for tok in re.split(r"[,\s]+", v):
                if tok:
                    out.append(tok)
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, str) and item:
                    out.append(item)
    return out


def _args_blob(action: str, args: dict[str, Any]) -> str:
    parts = [action or ""]
    for k, v in args.items():
        parts.append(f"{k}={_stringify(v)}")
    return " ".join(parts)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return " ".join(_stringify(x) for x in value)
    if isinstance(value, dict):
        return " ".join(f"{k}={_stringify(v)}" for k, v in value.items())
    return str(value)


def _redact(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in args.items():
        kl = k.lower()
        if any(s in kl for s in _SECRET_KEYS):
            out[k] = "[redacted]"
        elif isinstance(v, dict):
            out[k] = _redact(v)
        else:
            out[k] = v
    return out


__all__ = [
    "ROEDecision",
    "ROEGate",
    "HARD_BLOCK_ACTIONS",
    "DOS_PATTERNS",
    "PASSIVE_ACTIONS",
    "PERSISTENCE_ACTIONS",
    "PASS",
    "WARN",
    "BLOCK",
]
