"""Context window compression for long-running engagements.

Koda sessions accumulate fast — scanner output, tool results, evidence
references, and operator back-and-forth all share the same context window.
``ContextCompressor`` lets the session keep the system prompt and the most
recent turns at full fidelity while replacing everything in between with a
security-aware summary.

The hot path never calls an LLM — the default ``_summarize`` is a
heuristic that surfaces the anchors that matter for a security agent:

  * the earliest user requests (the goal)
  * which tools were used and how often
  * tool errors and refused approvals
  * ATT&CK technique IDs cited in the conversation
  * CVE IDs cited in the conversation

If ``use_llm`` is true and a ``provider_chat`` callable is supplied at
compress time, ``_llm_summarize`` is used instead, with a Koda-shaped
prompt. Any exception falls back to the heuristic summary — compression
must never fail a session.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable


Message = dict[str, Any]


ATTCK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


SUMMARY_PROMPT = """Summarize the compressed conversation segment below.
Produce a Koda-style security-relevant summary with these exact sections:

Goal: <primary user goal>
Progress: <what was completed, what's pending>
Tools: <tool names + counts>
Findings: <ATT&CK tags, CVE IDs, notable tool outputs>
Open questions: <what is still unresolved>

Be concise. Under 500 words."""


@dataclass
class ContextCompressor:
    preserve_last_n: int = 10
    preserve_first_exchange: int = 2
    max_chars_budget: int = 120_000  # ~30k tokens at 4 char/tok
    use_llm: bool = False

    def should_compress(self, messages: list[Message]) -> bool:
        total = sum(len(str(m.get("content", ""))) for m in messages)
        return total > int(self.max_chars_budget * 0.8)

    def compress(
        self,
        messages: list[Message],
        provider_chat: Callable | None = None,
    ) -> list[Message]:
        system_msgs = [m for m in messages if m.get("role") == "system"]
        non_system = [m for m in messages if m.get("role") != "system"]

        threshold = self.preserve_last_n + self.preserve_first_exchange + 1
        if len(non_system) <= threshold:
            return messages

        first_exchange = non_system[: self.preserve_first_exchange]
        tail = non_system[-self.preserve_last_n :]
        middle = non_system[self.preserve_first_exchange : -self.preserve_last_n]

        if self.use_llm and provider_chat is not None:
            summary = self._llm_summarize(middle, provider_chat)
        else:
            summary = self._summarize(middle)

        marker: Message = {
            "role": "system",
            "content": f"[compressed {len(middle)} turns]\n{summary}",
        }
        return [*system_msgs, *first_exchange, marker, *tail]

    def _summarize(self, middle: list[Message]) -> str:
        user_requests: list[str] = []
        tool_counts: Counter[str] = Counter()
        tool_errors = 0
        refused_approvals = 0
        attck: set[str] = set()
        cves: set[str] = set()

        for m in middle:
            role = m.get("role")
            content = str(m.get("content", ""))
            meta = m.get("metadata") or {}

            if role == "user" and len(user_requests) < 5:
                snippet = content.strip().replace("\n", " ")[:180]
                if snippet:
                    user_requests.append(snippet)

            for call in m.get("tool_calls") or []:
                name = call.get("name") or call.get("tool_name")
                if name:
                    tool_counts[name] += 1

            if role == "tool":
                name = meta.get("tool_name")
                if name:
                    tool_counts[name] += 1
                if meta.get("is_error"):
                    tool_errors += 1
                if meta.get("approved") is False:
                    refused_approvals += 1

            attck.update(ATTCK_RE.findall(content))
            cves.update(c.upper() for c in CVE_RE.findall(content))

        if not any((user_requests, tool_counts, tool_errors, refused_approvals, attck, cves)):
            return "Earlier conversation compressed (no signals extracted)."

        lines: list[str] = []
        if user_requests:
            lines.append("User requests:")
            for req in user_requests:
                lines.append(f"  - {req}")
        if tool_counts:
            parts = ", ".join(f"{n}({c})" for n, c in tool_counts.most_common())
            lines.append(f"Tools used: {parts}")
        if tool_errors or refused_approvals:
            lines.append(
                f"Tool errors: {tool_errors}   Refused approvals: {refused_approvals}"
            )
        if attck:
            lines.append("ATT&CK: " + ", ".join(sorted(attck)))
        if cves:
            lines.append("CVEs: " + ", ".join(sorted(cves)))
        return "\n".join(lines)

    def _llm_summarize(self, middle: list[Message], provider_chat: Callable) -> str:
        try:
            recent = middle[-30:]
            transcript_lines = [
                f"{m.get('role', '?')}: {str(m.get('content', ''))[:300]}"
                for m in recent
            ]
            transcript = "\n".join(transcript_lines)
            reply = provider_chat(
                messages=[
                    {"role": "system", "content": SUMMARY_PROMPT},
                    {"role": "user", "content": transcript},
                ]
            )
            if isinstance(reply, dict):
                return str(reply.get("content") or reply.get("text") or "").strip() or self._summarize(middle)
            return str(reply).strip() or self._summarize(middle)
        except Exception:
            return self._summarize(middle)


__all__ = ["ContextCompressor", "ATTCK_RE", "CVE_RE", "SUMMARY_PROMPT"]
