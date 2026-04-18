"""Argument-level guardrails for tool calls.

The ``ApprovalPolicy`` asks: *is this tool allowed?* — binary, coarse.
Guardrails ask: *is this specific invocation, with these specific arguments,
against this specific target, allowed right now, by this profile?*

Two gates:
  1. **Argument patterns** — catalog of regex matchers tagged with an action
     (``BLOCK`` = hard refusal, ``ESCALATE`` = bump to DANGEROUS). Covers
     shell destruction, credential exfiltration, supply-chain tricks, live
     production identifiers, and so on.
  2. **Engagement scope** — when a profile declares an explicit scope
     (``target_cidrs`` / ``target_hosts`` / ``disallow``), any tool call
     that names a target outside scope is refused, even if the tool itself
     is on the allowlist. Keeps an engagement from drifting onto assets
     it wasn't authorized to touch.

Decisions return a reason string so the session transcript records *why*
an action was refused — not just that it was.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class GuardrailAction(str, Enum):
    ALLOW = "allow"
    ESCALATE = "escalate"  # bump risk to DANGEROUS — force human approval
    BLOCK = "block"        # hard refusal, no override


@dataclass(frozen=True)
class GuardrailRule:
    """A single match rule.

    ``tool`` is a tool name or ``"*"`` for any tool.
    ``pattern`` is a regex compiled against either:
      - the value at ``arg_key`` if set, or
      - the concatenation of all string argument values if not.
    """
    name: str
    pattern: str
    action: GuardrailAction
    reason: str
    tool: str = "*"
    arg_key: str | None = None
    category: str = "general"

    def matches(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        if self.tool != "*" and self.tool != tool_name:
            return False
        haystack = _extract_haystack(arguments, self.arg_key)
        if not haystack:
            return False
        return re.search(self.pattern, haystack, re.IGNORECASE) is not None


def _extract_haystack(arguments: dict[str, Any], arg_key: str | None) -> str:
    if arg_key is not None:
        val = arguments.get(arg_key)
        return _stringify(val)
    parts: list[str] = []
    for v in arguments.values():
        s = _stringify(v)
        if s:
            parts.append(s)
    return "\n".join(parts)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return " ".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k}={_stringify(v)}" for k, v in value.items())
    return str(value)


# ---------------------------------------------------------------------------
# Default catalog — patterns Koda refuses or escalates by default.
#
# Phrased conservatively: a rule that misfires only costs a human an
# approval prompt; a rule we didn't write can cost an engagement.
# ---------------------------------------------------------------------------

DEFAULT_RULES: tuple[GuardrailRule, ...] = (
    # --- Shell destruction ---
    GuardrailRule(
        name="shell.rm_rf_root",
        pattern=r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(/|~|\$HOME|\*)\s*($|\s)",
        action=GuardrailAction.BLOCK,
        reason="Recursive delete targeting root, home, or wildcard.",
        category="destruction",
    ),
    GuardrailRule(
        name="shell.dd_block_device",
        pattern=r"\bdd\s+.*of=/dev/(sd[a-z]|nvme|disk|hd[a-z])",
        action=GuardrailAction.BLOCK,
        reason="dd write to a raw block device.",
        category="destruction",
    ),
    GuardrailRule(
        name="shell.mkfs_or_format",
        pattern=r"\b(mkfs(\.[a-z0-9]+)?|format)\b.*\s+/dev/",
        action=GuardrailAction.BLOCK,
        reason="Filesystem format against a device node.",
        category="destruction",
    ),
    GuardrailRule(
        name="shell.fork_bomb",
        pattern=r":\(\)\s*\{\s*:\|:&\s*\}\s*;:",
        action=GuardrailAction.BLOCK,
        reason="Fork bomb.",
        category="destruction",
    ),
    GuardrailRule(
        name="shell.power_off",
        pattern=r"\b(shutdown|poweroff|reboot|halt|init\s+[06])\b",
        action=GuardrailAction.ESCALATE,
        reason="Power-state change on the host.",
        category="destruction",
    ),

    # --- Credential / supply-chain ---
    GuardrailRule(
        name="net.curl_pipe_shell",
        pattern=r"\b(curl|wget|fetch)\b[^|\n]*\|\s*(sh|bash|zsh|python[0-9]*|perl|node)\b",
        action=GuardrailAction.ESCALATE,
        reason="curl|wget piping remote content into an interpreter.",
        category="supply-chain",
    ),
    GuardrailRule(
        name="creds.private_key_exfil",
        pattern=r"(\.ssh/id_(rsa|ed25519|ecdsa)|\.aws/credentials|\.kube/config)\b",
        action=GuardrailAction.ESCALATE,
        reason="Reference to a private credential file.",
        category="credentials",
    ),
    GuardrailRule(
        name="creds.history_scrape",
        pattern=r"\b(\.bash_history|\.zsh_history|\.netrc|/etc/shadow)\b",
        action=GuardrailAction.ESCALATE,
        reason="Reference to credential- or history-bearing file.",
        category="credentials",
    ),

    # --- Data layer ---
    GuardrailRule(
        name="sql.drop_or_truncate",
        pattern=r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b",
        action=GuardrailAction.ESCALATE,
        reason="DDL that drops or truncates structured data.",
        category="data",
    ),
    GuardrailRule(
        name="sql.outfile",
        pattern=r"\bINTO\s+(OUTFILE|DUMPFILE)\b",
        action=GuardrailAction.ESCALATE,
        reason="SQL INTO OUTFILE / DUMPFILE is a classic exfil sink.",
        category="data",
    ),

    # --- Offensive tooling switches that shouldn't fire without intent ---
    GuardrailRule(
        name="scanner.nmap_aggressive",
        pattern=r"(^|\s)-(A|sS|sU|O|T5|-script=[a-z-]*(exploit|brute|dos))",
        action=GuardrailAction.ESCALATE,
        reason="Aggressive nmap flag (stealth SYN, OS-detect, exploit scripts, T5).",
        category="scanner",
    ),
    GuardrailRule(
        name="exploit.metasploit_exploit",
        pattern=r"\b(msfconsole|msfvenom)\b.*\b(exploit|payload)\b",
        action=GuardrailAction.ESCALATE,
        reason="Metasploit exploit / payload generation.",
        category="exploit",
    ),
)


# ---------------------------------------------------------------------------
# Engagement scope
# ---------------------------------------------------------------------------

# Argument keys where a target identifier typically lives.
_TARGET_KEYS = ("target", "targets", "host", "hosts", "url", "endpoint", "address", "ip", "cidr")


@dataclass
class ScopePolicy:
    """Allow/deny targets for this engagement.

    - If ``allow_cidrs`` or ``allow_hosts`` is set, any target not matching
      at least one entry is refused.
    - If ``deny_cidrs`` or ``deny_hosts`` is set, matching targets are
      refused even if also in allow.
    - If both allow lists are empty, scope is unbounded (only deny lists
      apply).
    """
    allow_cidrs: list[str] = field(default_factory=list)
    allow_hosts: list[str] = field(default_factory=list)
    deny_cidrs: list[str] = field(default_factory=list)
    deny_hosts: list[str] = field(default_factory=list)

    def _cidr_objs(self, raw: Iterable[str]) -> list[ipaddress._BaseNetwork]:
        out: list[ipaddress._BaseNetwork] = []
        for item in raw:
            try:
                out.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
        return out

    def check(self, arguments: dict[str, Any]) -> tuple[bool, str]:
        """Return (allowed, reason). reason is '' when allowed."""
        targets = _collect_targets(arguments)
        if not targets:
            return True, ""

        allow_nets = self._cidr_objs(self.allow_cidrs)
        deny_nets = self._cidr_objs(self.deny_cidrs)
        allow_hosts = {h.lower() for h in self.allow_hosts}
        deny_hosts = {h.lower() for h in self.deny_hosts}
        bounded = bool(allow_nets or allow_hosts)

        for raw in targets:
            token = raw.strip().lower()
            if not token:
                continue

            ip_obj = _try_ip(token)
            if ip_obj is not None:
                if any(ip_obj in net for net in deny_nets):
                    return False, f"Target {raw} is in engagement deny list."
                if bounded and allow_nets and not any(ip_obj in net for net in allow_nets):
                    return False, f"Target {raw} is outside engagement CIDR scope."
                continue

            # Treat as hostname
            if token in deny_hosts or any(token.endswith("." + d) for d in deny_hosts):
                return False, f"Target {raw} matches an engagement deny host."
            if bounded and allow_hosts:
                if token in allow_hosts or any(token.endswith("." + a) for a in allow_hosts):
                    continue
                return False, f"Target {raw} is outside engagement host scope."

        return True, ""


def _collect_targets(arguments: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for k in _TARGET_KEYS:
        v = arguments.get(k)
        if v is None:
            continue
        if isinstance(v, str):
            # Split on whitespace + comma — handles "1.2.3.4 5.6.7.8"
            for tok in re.split(r"[,\s]+", v):
                if tok:
                    out.append(tok)
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, str) and item:
                    out.append(item)
    return out


def _try_ip(token: str):
    # Strip :port and URL scheme
    t = token
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/")[0].split(":")[0]
    try:
        return ipaddress.ip_address(t)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@dataclass
class GuardrailDecision:
    action: GuardrailAction
    reason: str = ""
    matched_rule: str = ""


def evaluate(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    rules: Iterable[GuardrailRule] = DEFAULT_RULES,
    scope: ScopePolicy | None = None,
) -> GuardrailDecision:
    """Run all rules + scope check. First BLOCK wins; otherwise highest
    action across all matches is returned."""
    # Scope gate first — a scope violation is a block, full stop.
    if scope is not None:
        ok, reason = scope.check(arguments)
        if not ok:
            return GuardrailDecision(
                action=GuardrailAction.BLOCK,
                reason=reason,
                matched_rule="scope",
            )

    highest: GuardrailDecision = GuardrailDecision(action=GuardrailAction.ALLOW)
    for rule in rules:
        if not rule.matches(tool_name, arguments):
            continue
        if rule.action == GuardrailAction.BLOCK:
            return GuardrailDecision(
                action=GuardrailAction.BLOCK,
                reason=rule.reason,
                matched_rule=rule.name,
            )
        if rule.action == GuardrailAction.ESCALATE and highest.action == GuardrailAction.ALLOW:
            highest = GuardrailDecision(
                action=GuardrailAction.ESCALATE,
                reason=rule.reason,
                matched_rule=rule.name,
            )
    return highest


__all__ = [
    "GuardrailAction",
    "GuardrailRule",
    "GuardrailDecision",
    "ScopePolicy",
    "DEFAULT_RULES",
    "evaluate",
]
