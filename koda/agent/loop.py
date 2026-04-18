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

from dataclasses import dataclass, field
from typing import Any

from ..adapters.base import Message, Provider, Role, ToolCall
from ..security.prompts import build_security_prompt
from ..security.verifier import format_rejection, verify_draft
from ..session.store import SessionStore
from ..tools.approval import ApprovalPolicy, ApprovalRequest
from ..tools.registry import RiskLevel, ToolRegistry, ToolResult


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
    ) -> None:
        self.provider = provider
        self.registry = registry
        self.approvals = approvals
        self.session = session
        self.session_id = session_id

    def _build_messages(self, extra_system_prompt: str) -> list[Message]:
        system = Message(role=Role.SYSTEM, content=build_security_prompt(extra_system_prompt))
        return [system] + self.session.messages(self.session_id)

    async def _run_tool_call(self, tc: ToolCall, trace: TurnTrace) -> Message:
        tool = self.registry.get(tc.name)
        risk = tool.risk if tool else RiskLevel.SENSITIVE
        approved = await self.approvals.decide(ApprovalRequest(tool_name=tc.name, arguments=tc.arguments, risk=risk))
        if not approved:
            result = ToolResult(content=f"Tool '{tc.name}' was denied by the approval policy.", is_error=True)
        else:
            result = await self.registry.invoke(tc.name, tc.arguments)
        trace.tool_calls_made += 1
        rendered = f"[tool_result {tc.name}]\n{result.content}"
        trace.tool_transcript.append(rendered)
        tool_msg = Message(role=Role.TOOL, content=result.content, tool_call_id=tc.id, metadata={"name": tc.name, "is_error": result.is_error})
        self.session.append(self.session_id, tool_msg)
        return tool_msg

    async def run(self, user_input: str, options: TurnOptions | None = None) -> TurnTrace:
        options = options or TurnOptions()
        trace = TurnTrace()
        self.session.append(self.session_id, Message(role=Role.USER, content=user_input))

        tools_specs = self.registry.specs()
        verifier_retries = 0

        while trace.iterations < options.max_tool_iterations + options.max_verifier_retries + 4:
            trace.iterations += 1
            messages = self._build_messages(options.extra_system_prompt)
            resp = await self.provider.chat(messages, tools=tools_specs, tool_choice=options.tool_choice)

            if resp.stop_reason == "error":
                trace.aborted = True
                trace.abort_reason = resp.text[:200]
                return trace

            if resp.tool_calls:
                assistant_msg = Message(role=Role.ASSISTANT, content=resp.text, tool_calls=resp.tool_calls)
                self.session.append(self.session_id, assistant_msg)
                for tc in resp.tool_calls:
                    await self._run_tool_call(tc, trace)
                if trace.tool_calls_made >= options.max_tool_iterations:
                    trace.aborted = True
                    trace.abort_reason = "tool-iteration budget exhausted"
                    return trace
                continue

            draft = resp.text
            transcript = "\n\n".join(trace.tool_transcript)
            result = verify_draft(draft, transcript)
            if result.ok or verifier_retries >= options.max_verifier_retries:
                self.session.append(self.session_id, Message(role=Role.ASSISTANT, content=draft))
                trace.final_text = draft
                return trace

            verifier_retries += 1
            trace.verifier_rejections += 1
            rejection = format_rejection(result)
            self.session.append(self.session_id, Message(role=Role.ASSISTANT, content=draft, metadata={"rejected": True}))
            self.session.append(self.session_id, Message(role=Role.USER, content=rejection, metadata={"verifier_rejection": True}))

        trace.aborted = True
        trace.abort_reason = "outer loop budget exhausted"
        return trace
