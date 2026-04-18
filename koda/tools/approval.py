"""Approval gate. Decides whether a specific tool invocation is allowed.

Decision pipeline:

  1. **Guardrails** — argument-level rules inspect the call itself.
     BLOCK is terminal; ESCALATE bumps the risk to DANGEROUS so the
     request must clear human approval even if the tool was preapproved.
  2. **Entries** — explicit ``always`` / ``never`` entries for the tool
     name, persisted to disk so operator decisions stick across runs.
  3. **Risk threshold** — tools with risk <= ``auto_approve_threshold``
     pass automatically.
  4. **Callback** — interactive prompt (TUI, CLI, MCP transport).
     If none is configured, unknown requests are denied by default.

Every decision carries a reason so the session transcript records
*why* an action went through or got refused.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Iterable

from ..security.guardrails import (
    DEFAULT_RULES,
    GuardrailAction,
    GuardrailDecision,
    GuardrailRule,
    ScopePolicy,
    evaluate,
)
from .registry import RiskLevel


@dataclass
class ApprovalRequest:
    tool_name: str
    arguments: dict
    risk: RiskLevel
    engagement: str = ""


@dataclass
class ApprovalDecision:
    allowed: bool
    reason: str = ""
    stage: str = ""  # "guardrail" | "entry" | "threshold" | "callback"
    matched_rule: str = ""


ApprovalCallback = Callable[
    [ApprovalRequest, GuardrailDecision],
    Awaitable[bool] | bool,
]


class ApprovalPolicy:
    _RISK_ORDER = {RiskLevel.SAFE: 0, RiskLevel.SENSITIVE: 1, RiskLevel.DANGEROUS: 2}

    def __init__(
        self,
        approvals_path: Path | None = None,
        auto_approve_threshold: RiskLevel = RiskLevel.SAFE,
        callback: ApprovalCallback | None = None,
        *,
        rules: Iterable[GuardrailRule] = DEFAULT_RULES,
        scope: ScopePolicy | None = None,
    ) -> None:
        self.approvals_path = approvals_path
        self.auto_approve_threshold = auto_approve_threshold
        self.callback = callback
        self.rules = tuple(rules)
        self.scope = scope
        self._entries: dict[str, str] = {}
        self._load()

    # --- Persistence of sticky per-tool decisions ---

    def _load(self) -> None:
        if not self.approvals_path or not self.approvals_path.exists():
            return
        try:
            data = json.loads(self.approvals_path.read_text())
            if isinstance(data, dict):
                self._entries = {str(k): str(v).lower() for k, v in data.items()}
        except Exception:
            self._entries = {}

    def set(self, tool_name: str, scope: str) -> None:
        self._entries[tool_name] = scope.lower()
        self._persist()

    def _persist(self) -> None:
        if not self.approvals_path:
            return
        self.approvals_path.parent.mkdir(parents=True, exist_ok=True)
        self.approvals_path.write_text(json.dumps(self._entries, indent=2, sort_keys=True))

    # --- Core decision ---

    async def decide_full(self, request: ApprovalRequest) -> ApprovalDecision:
        guardrail = evaluate(
            request.tool_name,
            request.arguments or {},
            rules=self.rules,
            scope=self.scope,
        )

        if guardrail.action == GuardrailAction.BLOCK:
            return ApprovalDecision(
                allowed=False,
                reason=guardrail.reason,
                stage="guardrail",
                matched_rule=guardrail.matched_rule,
            )

        effective_risk = request.risk
        if guardrail.action == GuardrailAction.ESCALATE:
            effective_risk = RiskLevel.DANGEROUS

        entry = self._entries.get(request.tool_name, "")
        if entry == "never":
            return ApprovalDecision(
                allowed=False,
                reason=f"{request.tool_name!r} is in the deny list.",
                stage="entry",
            )

        if entry == "always" and guardrail.action != GuardrailAction.ESCALATE:
            # A sticky 'always' approval does NOT override an escalation —
            # escalated calls always go to the human. Otherwise a single
            # "always" decision could laminate over every future risky
            # variant of the same tool.
            return ApprovalDecision(
                allowed=True,
                reason=f"{request.tool_name!r} preapproved by operator.",
                stage="entry",
            )

        if self._RISK_ORDER[effective_risk] <= self._RISK_ORDER[self.auto_approve_threshold]:
            return ApprovalDecision(
                allowed=True,
                reason=f"Risk {effective_risk.value} within auto-approve threshold.",
                stage="threshold",
            )

        if self.callback is None:
            return ApprovalDecision(
                allowed=False,
                reason="No interactive approver configured; refused by default.",
                stage="callback",
                matched_rule=guardrail.matched_rule,
            )

        result = self.callback(request, guardrail)
        if hasattr(result, "__await__"):
            result = await result  # type: ignore[assignment]
        allowed = bool(result)
        return ApprovalDecision(
            allowed=allowed,
            reason=(
                guardrail.reason or "Operator approved."
                if allowed
                else "Operator declined."
            ),
            stage="callback",
            matched_rule=guardrail.matched_rule,
        )

    async def decide(self, request: ApprovalRequest) -> bool:
        """Backward-compatible boolean path used by the TurnLoop."""
        decision = await self.decide_full(request)
        return decision.allowed
