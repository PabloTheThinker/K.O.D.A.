"""Turn loop — think/act with the grounding verifier in the inner loop.

Flow per user turn:
  1. Append user message to session.
  2. Call provider with (system + history + tools).
  3. If model emitted tool_use blocks:
       - Approval gate per call (risk-based).
       - Dispatch to registry.
       - Append tool results to session.
       - Loop.
  4. If model emitted text:
       - Run grounding verifier over the draft against the tool transcript.
       - If ungrounded claims present, re-prompt with a rejection message and
         loop (bounded retries).
       - Otherwise, commit as final assistant message and return.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..adapters.base import Message, Provider, Role, ToolCall
from ..audit import AuditLogger, NullAuditLogger, hash_arguments
from ..evidence import EvidenceStore, NullEvidenceStore
from ..security.prompts import build_security_prompt
from ..security.verifier import format_rejection, verify_draft
from ..session.store import SessionStore
from ..tools.approval import ApprovalPolicy, ApprovalRequest
from ..tools.registry import RiskLevel, ToolRegistry, ToolResult


def _usage_meta(usage: dict[str, Any], latency_ms: int) -> dict[str, Any]:
    """Normalize provider usage dicts into store-friendly metadata.

    Providers disagree on key names — Anthropic uses input_tokens/output_tokens,
    OpenAI-shaped APIs use prompt_tokens/completion_tokens. Accept both.
    """
    u = usage or {}
    prompt = u.get("prompt_tokens") or u.get("input_tokens") or 0
    completion = u.get("completion_tokens") or u.get("output_tokens") or 0
    return {
        "tokens_prompt": int(prompt or 0),
        "tokens_completion": int(completion or 0),
        "latency_ms": latency_ms,
    }


@dataclass
class TurnOptions:
    max_tool_iterations: int = 8
    max_verifier_retries: int = 2
    tool_choice: str | dict | None = None
    extra_system_prompt: str = ""


@dataclass
class TurnTrace:
    final_text: str = ""
    tool_calls_made: int = 0
    verifier_rejections: int = 0
    iterations: int = 0
    aborted: bool = False
    abort_reason: str = ""
    tool_transcript: list[str] = field(default_factory=list)


class TurnLoop:
    def __init__(
        self,
        provider: Provider,
        registry: ToolRegistry,
        approvals: ApprovalPolicy,
        session: SessionStore,
        session_id: str,
        engagement: str = "",
        audit: AuditLogger | NullAuditLogger | None = None,
        evidence: EvidenceStore | NullEvidenceStore | None = None,
    ) -> None:
        self.provider = provider
        self.registry = registry
        self.approvals = approvals
        self.session = session
        self.session_id = session_id
        self.engagement = engagement
        self.audit = audit or NullAuditLogger()
        self.evidence = evidence or NullEvidenceStore()

    def _build_messages(self, extra_system_prompt: str) -> list[Message]:
        system = Message(role=Role.SYSTEM, content=build_security_prompt(extra_system_prompt))
        return [system] + self.session.messages(self.session_id)

    async def _run_tool_call(self, tc: ToolCall, trace: TurnTrace) -> Message:
        tool = self.registry.get(tc.name)
        risk = tool.risk if tool else RiskLevel.SENSITIVE
        request = ApprovalRequest(
            tool_name=tc.name,
            arguments=tc.arguments,
            risk=risk,
            engagement=self.engagement,
        )
        decision = await self.approvals.decide_full(request)
        t0 = time.perf_counter()
        if not decision.allowed:
            reason = decision.reason or "refused by approval policy"
            rule = f" [rule={decision.matched_rule}]" if decision.matched_rule else ""
            result = ToolResult(
                content=f"Tool '{tc.name}' refused: {reason}{rule}",
                is_error=True,
            )
        else:
            result = await self.registry.invoke(tc.name, tc.arguments)
        latency_ms = int((time.perf_counter() - t0) * 1000)
        trace.tool_calls_made += 1
        rendered = f"[tool_result {tc.name}]\n{result.content}"
        trace.tool_transcript.append(rendered)

        args_hash = hash_arguments(tc.arguments)
        artifact_id = ""
        if decision.allowed and not result.is_error and tool and tool.should_capture():
            # Best-effort target extraction for the sidecar — ScopePolicy
            # uses the same keys so this stays consistent with how we scope.
            target = ""
            for key in ("target", "host", "url", "endpoint", "address"):
                value = (tc.arguments or {}).get(key)
                if value:
                    target = str(value)[:200]
                    break
            artifact = self.evidence.capture(
                result.content,
                tool=tc.name,
                engagement=self.engagement,
                session_id=self.session_id,
                target=target,
                content_type=tool.content_type_for_capture(),
                tool_args_hash=args_hash,
            )
            artifact_id = artifact.artifact_id

        self.audit.emit(
            "tool.call",
            session_id=self.session_id,
            engagement=self.engagement,
            tool=tc.name,
            args_hash=args_hash,
            approved=decision.allowed,
            stage=decision.stage,
            rule=decision.matched_rule,
            is_error=result.is_error,
            latency_ms=latency_ms,
            artifact_id=artifact_id,
        )
        if result.is_error and not decision.allowed:
            # Refused calls are security-relevant — surface a dedicated
            # event alongside tool.call so ``jq 'select(.event=="tool.error")'``
            # picks them up even if the operator filters tool.call noise.
            self.audit.emit(
                "tool.error",
                session_id=self.session_id,
                engagement=self.engagement,
                tool=tc.name,
                reason=decision.reason,
                rule=decision.matched_rule,
            )
        tool_msg = Message(
            role=Role.TOOL,
            content=result.content,
            tool_call_id=tc.id,
            metadata={
                "tool_name": tc.name,
                "is_error": result.is_error,
                "approved": decision.allowed,
                "approval_stage": decision.stage,
                "approval_reason": decision.reason,
                "approval_rule": decision.matched_rule,
                "latency_ms": latency_ms,
                "artifact_id": artifact_id,
            },
        )
        self.session.append(self.session_id, tool_msg)
        return tool_msg

    async def run(self, user_input: str, options: TurnOptions | None = None) -> TurnTrace:
        options = options or TurnOptions()
        trace = TurnTrace()
        self.session.append(self.session_id, Message(role=Role.USER, content=user_input))
        self.audit.emit(
            "turn.start",
            session_id=self.session_id,
            engagement=self.engagement,
            user_len=len(user_input),
        )

        tools_specs = self.registry.specs()
        verifier_retries = 0
        tokens_prompt = 0
        tokens_completion = 0

        while trace.iterations < options.max_tool_iterations + options.max_verifier_retries + 4:
            trace.iterations += 1
            messages = self._build_messages(options.extra_system_prompt)
            t0 = time.perf_counter()
            resp = await self.provider.chat(messages, tools=tools_specs, tool_choice=options.tool_choice)
            latency_ms = int((time.perf_counter() - t0) * 1000)
            turn_meta = _usage_meta(resp.usage, latency_ms)
            tokens_prompt += turn_meta["tokens_prompt"]
            tokens_completion += turn_meta["tokens_completion"]

            if resp.stop_reason == "error":
                trace.aborted = True
                trace.abort_reason = resp.text[:200]
                self.audit.emit(
                    "provider.error",
                    session_id=self.session_id,
                    engagement=self.engagement,
                    detail=trace.abort_reason,
                )
                self._emit_turn_end(trace, tokens_prompt, tokens_completion)
                return trace

            if resp.tool_calls:
                assistant_msg = Message(
                    role=Role.ASSISTANT,
                    content=resp.text,
                    tool_calls=resp.tool_calls,
                    metadata=turn_meta,
                )
                self.session.append(self.session_id, assistant_msg)
                for tc in resp.tool_calls:
                    await self._run_tool_call(tc, trace)
                if trace.tool_calls_made >= options.max_tool_iterations:
                    trace.aborted = True
                    trace.abort_reason = "tool-iteration budget exhausted"
                    self._emit_turn_end(trace, tokens_prompt, tokens_completion)
                    return trace
                continue

            draft = resp.text
            transcript = "\n\n".join(trace.tool_transcript)
            result = verify_draft(draft, transcript)
            if result.ok or verifier_retries >= options.max_verifier_retries:
                self.session.append(
                    self.session_id,
                    Message(role=Role.ASSISTANT, content=draft, metadata=turn_meta),
                )
                trace.final_text = draft
                self._emit_turn_end(trace, tokens_prompt, tokens_completion)
                return trace

            verifier_retries += 1
            trace.verifier_rejections += 1
            rejection = format_rejection(result)
            self.session.append(
                self.session_id,
                Message(role=Role.ASSISTANT, content=draft, metadata={**turn_meta, "rejected": True}),
            )
            self.session.append(self.session_id, Message(role=Role.USER, content=rejection, metadata={"verifier_rejection": True}))

        trace.aborted = True
        trace.abort_reason = "outer loop budget exhausted"
        self._emit_turn_end(trace, tokens_prompt, tokens_completion)
        return trace

    def _emit_turn_end(self, trace: TurnTrace, tokens_prompt: int, tokens_completion: int) -> None:
        event = "turn.aborted" if trace.aborted else "turn.complete"
        self.audit.emit(
            event,
            session_id=self.session_id,
            engagement=self.engagement,
            iterations=trace.iterations,
            tool_calls=trace.tool_calls_made,
            verifier_rejections=trace.verifier_rejections,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            abort_reason=trace.abort_reason,
            final_len=len(trace.final_text),
        )
