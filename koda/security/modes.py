"""Security-harness operating modes and engagement context.

A ``SecurityMode`` selects which family of skills the harness loads.
An ``EngagementContext`` carries the current engagement's scope,
authorization, operator, and phase — everything the harness and ROE
gate need to decide what the agent is allowed to do *right now*.

Keeping this in its own module (instead of in harness.py) lets other
subsystems import the enum + context without pulling the whole harness
prompt machinery.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum


class SecurityMode(str, Enum):
    DEFAULT = "default"    # no sec harness, normal koda
    RED = "red"            # offensive / pentest
    BLUE = "blue"          # defensive / DFIR (Phase 3 uses this)
    PURPLE = "purple"      # both — correlate offense and defense


# Canonical phase names. Free-form string is accepted at the context
# boundary; this tuple documents the values Phase 2/3/4 code will emit.
KNOWN_PHASES: tuple[str, ...] = (
    "recon",
    "enumeration",
    "initial_access",
    "execution",
    "persistence",
    "privesc",
    "lateral",
    "exfil",
    "defense",
    "hunt",
    "ir",
    "hardening",
)


@dataclass(frozen=True)
class EngagementContext:
    """Read-only engagement context.

    ``targets`` is the authoritative in-scope set (CIDRs, IPs, hostnames,
    or ``*.suffix`` wildcards). ``authorized_scope`` is the human text
    describing the SOW — it goes into the system prompt verbatim so the
    model can cite it when challenged.
    """
    mode: SecurityMode
    phase: str
    targets: tuple[str, ...]
    authorized_scope: str
    roe_id: str
    operator: str

    def is_in_scope(self, target: str) -> bool:
        """Return True iff ``target`` matches one of this context's authorized entries.

        Matching rules:
          - IP / CIDR: if the entry parses as a CIDR and ``target`` parses
            as an IP, membership check; if both parse as IPs, equality.
          - Hostname: case-insensitive exact match, or suffix match when
            the entry is ``*.example.com`` (matches ``a.example.com`` but
            not ``example.com`` itself).
          - Empty ``targets``: no scope declared → returns False. Callers
            that want "no scope = wide open" must check that themselves.
        """
        if not target:
            return False
        token = _normalize_target(target)
        if not token:
            return False

        target_ip = _try_ip(token)

        for entry in self.targets:
            # For CIDR-shaped entries, do NOT strip the /NN — normalize only
            # when the entry has no slash.
            entry_stripped = entry.strip()
            if "/" in entry_stripped and "://" not in entry_stripped:
                entry_norm = entry_stripped
            else:
                entry_norm = _normalize_target(entry_stripped)
            if not entry_norm:
                continue

            # Try CIDR / IP membership when target is an IP.
            if target_ip is not None:
                try:
                    net = ipaddress.ip_network(entry_norm, strict=False)
                except ValueError:
                    net = None
                if net is not None and target_ip in net:
                    return True
                continue

            # Hostname matching.
            entry_low = entry_norm.lower()
            token_low = token.lower()
            if entry_low.startswith("*."):
                suffix = entry_low[1:]  # ".example.com"
                if token_low.endswith(suffix) and token_low != suffix[1:]:
                    return True
            elif entry_low == token_low:
                return True

        return False


def _normalize_target(raw: str) -> str:
    """Strip URL scheme, path, and port from a target token."""
    t = raw.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    # Only strip :port for bare host tokens, not CIDRs.
    if ":" in t and "/" not in t:
        host, _, _ = t.partition(":")
        t = host
    return t


def _try_ip(token: str):
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


__all__ = ["SecurityMode", "KNOWN_PHASES", "EngagementContext"]
