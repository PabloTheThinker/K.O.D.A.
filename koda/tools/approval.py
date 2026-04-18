"""Approval gate. Controls whether a tool call proceeds based on its RiskLevel."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

from .registry import RiskLevel


@dataclass
class ApprovalRequest:
    tool_name: str
    arguments: dict
    risk: RiskLevel


ApprovalCallback = Callable[[ApprovalRequest], Awaitable[bool] | bool]


class ApprovalPolicy:
    """Decides whether a tool call is allowed.

    Rules applied in order:
    1. Explicit entry in the approvals file with value 'always' -> approved.
    2. Explicit entry with value 'never' -> denied.
    3. Risk <= auto_approve_threshold -> approved automatically.
    4. Fall back to the interactive callback.
    """

    _RISK_ORDER = {RiskLevel.SAFE: 0, RiskLevel.SENSITIVE: 1, RiskLevel.DANGEROUS: 2}

    def __init__(
        self,
        approvals_path: Path | None = None,
        auto_approve_threshold: RiskLevel = RiskLevel.SAFE,
        callback: ApprovalCallback | None = None,
    ) -> None:
        self.approvals_path = approvals_path
        self.auto_approve_threshold = auto_approve_threshold
        self.callback = callback
        self._entries: dict[str, str] = {}
        self._load()

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

    async def decide(self, request: ApprovalRequest) -> bool:
        entry = self._entries.get(request.tool_name, "")
        if entry == "always":
            return True
        if entry == "never":
            return False
        if self._RISK_ORDER[request.risk] <= self._RISK_ORDER[self.auto_approve_threshold]:
            return True
        if self.callback is None:
            return False
        result = self.callback(request)
        if hasattr(result, "__await__"):
            result = await result  # type: ignore[assignment]
        return bool(result)
