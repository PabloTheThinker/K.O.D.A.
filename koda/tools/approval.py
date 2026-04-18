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

from ..audit import AuditLogger, NullAuditLogger, hash_arguments
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


_THRESHOLD_MAP: dict[str, RiskLevel] = {
    "safe": RiskLevel.SAFE,
    "medium": RiskLevel.SENSITIVE,
    "all": RiskLevel.DANGEROUS,
    "none": RiskLevel.SAFE,
}


def threshold_from_config(config: dict, default: str = "all") -> RiskLevel:
    """Map the wizard-level approval tier into the RiskLevel threshold.

    Values: safe | medium | all | none. 'all' auto-approves up to DANGEROUS;
    the BLOCKED guardrail tier always requires explicit approval via the
    callback regardless of threshold.
    """
    tier = str(config.get("approvals", {}).get("auto_approve", default)).strip().lower()
    return _THRESHOLD_MAP.get(tier, _THRESHOLD_MAP[default])


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
        audit: AuditLogger | NullAuditLogger | None = None,
    ) -> None:
        self.approvals_path = approvals_path
        self.auto_approve_threshold = auto_approve_threshold
        self.callback = callback
        self.rules = tuple(rules)
        self.scope = scope
        self.audit = audit or NullAuditLogger()
        self._entries: dict[str, str] = {}
        self._load()

    def _emit(self, request: ApprovalRequest, decision: "ApprovalDecision") -> None:
        # Stage drives event name: allowed stages → approval.allowed,
        # refusals get a narrower category so audit queries stay sharp.
        if decision.allowed:
            event = "approval.allowed"
        elif decision.stage == "guardrail":
            event = "approval.blocked"
        elif decision.stage == "entry":
            event = "approval.denied"
        else:
            event = "approval.refused"
        self.audit.emit(
            event,
            engagement=request.engagement,
            tool=request.tool_name,
            risk=request.risk.value if hasattr(request.risk, "value") else str(request.risk),
            args_hash=hash_arguments(request.arguments),
            stage=decision.stage,
            reason=decision.reason,
            rule=decision.matched_rule,
        )

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
            decision = ApprovalDecision(
                allowed=False,
                reason=guardrail.reason,
                stage="guardrail",
                matched_rule=guardrail.matched_rule,
            )
            self._emit(request, decision)
            return decision

        effective_risk = request.risk
        if guardrail.action == GuardrailAction.ESCALATE:
            effective_risk = RiskLevel.DANGEROUS

        entry = self._entries.get(request.tool_name, "")
        if entry == "never":
            decision = ApprovalDecision(
                allowed=False,
                reason=f"{request.tool_name!r} is in the deny list.",
                stage="entry",
            )
            self._emit(request, decision)
            return decision

        if entry == "always" and guardrail.action != GuardrailAction.ESCALATE:
            # A sticky 'always' approval does NOT override an escalation —
            # escalated calls always go to the human. Otherwise a single
            # "always" decision could laminate over every future risky
            # variant of the same tool.
            decision = ApprovalDecision(
                allowed=True,
                reason=f"{request.tool_name!r} preapproved by operator.",
                stage="entry",
            )
            self._emit(request, decision)
            return decision

        if self._RISK_ORDER[effective_risk] <= self._RISK_ORDER[self.auto_approve_threshold]:
            decision = ApprovalDecision(
                allowed=True,
                reason=f"Risk {effective_risk.value} within auto-approve threshold.",
                stage="threshold",
            )
            self._emit(request, decision)
            return decision

        if self.callback is None:
            decision = ApprovalDecision(
                allowed=False,
                reason="No interactive approver configured; refused by default.",
                stage="callback",
                matched_rule=guardrail.matched_rule,
            )
            self._emit(request, decision)
            return decision

        result = self.callback(request, guardrail)
        if hasattr(result, "__await__"):
            result = await result  # type: ignore[assignment]
        allowed = bool(result)
        decision = ApprovalDecision(
            allowed=allowed,
            reason=(
                guardrail.reason or "Operator approved."
                if allowed
                else "Operator declined."
            ),
            stage="callback",
            matched_rule=guardrail.matched_rule,
        )
        self._emit(request, decision)
        return decision

    async def decide(self, request: ApprovalRequest) -> bool:
        """Backward-compatible boolean path used by the TurnLoop."""
        decision = await self.decide_full(request)
        return decision.allowed
