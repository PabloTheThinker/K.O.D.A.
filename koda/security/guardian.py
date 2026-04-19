"""Guardian — input/output risk detector that sits in front of the LLM.

The Guardian is a cheap pre-filter that runs before the model call and
before any tool dispatch. It is not a replacement for the approval gate or
the ROE; it's the outer wall — cheap regex detections that catch the
obvious injection attempts, destructive command patterns, and sensitive-
data writes, and turn them into auditable incidents.

Detection categories:
  prompt_injection   — user text trying to hijack the system prompt
  destructive_action — known-bad shell commands (rm -rf /, fork bombs, …)
  sensitive_data     — tool calls writing content that looks like a secret

Modes:
  strict     — any match blocks
  balanced   — injection blocks; sensitive-data warns (default)
  permissive — everything warns, nothing blocks (for debugging)

Ported from koda-agent/koda/cognition/guardian.py; stripped of the
cognitive-module base class — this is not a trait-adaptive module, it is
a static pre-filter and should act the same on turn 1 as on turn 1000.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


INJECTION_PATTERNS = (
    r"ignore\s+(all\s+)?previous",
    r"you\s+are\s+now",
    r"forget\s+(everything|all|your)",
    r"new\s+instructions?:",
    r"system\s*:",
    r"override\s+(your|all|safety)",
    r"pretend\s+(you|to\s+be)",
    r"act\s+as\s+(if|though|a)",
    r"disregard\s+(your|all|safety)",
    r"jailbreak",
)

DESTRUCTIVE_PATTERNS = (
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+~",
    r"rm\s+-rf\s+\.\s",
    r"drop\s+table",
    r"drop\s+database",
    r"DELETE\s+FROM\s+\w+\s*;?\s*$",
    r"format\s+[cCdD]:",
    r"mkfs\.",
    r"kill\s+-9\s+-1",
    r":\(\)\{\s*:\|:&\s*\};:",  # fork bomb
    r"dd\s+if=.*of=/dev/",
    r"chmod\s+-R\s+777\s+/",
)

SENSITIVE_KEYS = ("password", "api_key", "secret", "token", "private_key", "credential", "auth")


@dataclass(frozen=True)
class GuardDecision:
    """Outcome of a Guardian review. ``action`` is one of allow/warn/block."""

    action: str
    category: str = ""
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    @property
    def warned(self) -> bool:
        return self.action == "warn"


ALLOW = GuardDecision("allow")


@dataclass
class Guardian:
    """Pre-filter for user input and tool calls.

    Thread-safe per process: the compiled regex lists are immutable, and the
    incident log is append-only with a bounded tail.
    """

    mode: str = "balanced"
    allow_file_write: bool = True
    allow_network: bool = True
    max_incidents: int = 100
    incidents: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in ("strict", "balanced", "permissive"):
            raise ValueError(f"unknown guardian mode: {self.mode!r}")
        self._injection_re = tuple(re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS)
        self._destructive_re = tuple(re.compile(p, re.IGNORECASE) for p in DESTRUCTIVE_PATTERNS)

    def review_input(self, text: str) -> GuardDecision:
        """Scan user text for prompt-injection patterns."""
        if not text:
            return ALLOW
        for pattern in self._injection_re:
            m = pattern.search(text)
            if m is not None:
                if self.mode == "permissive":
                    return GuardDecision("warn", "prompt_injection", f"pattern: {pattern.pattern}")
                self._log_incident("prompt_injection", text[:200])
                return GuardDecision("block", "prompt_injection", f"pattern: {pattern.pattern}")
        return ALLOW

    def review_tool_call(self, name: str, args: dict | None) -> GuardDecision:
        """Scan a tool call for destructive commands or sensitive-data writes.

        Tool names are matched loosely — shell-like tools are checked for
        destructive patterns against the ``command`` / ``cmd`` argument,
        file-write tools are checked for secret-shaped content in
        ``content`` / ``data`` / ``body``.
        """
        args = args or {}
        if _looks_like_shell_tool(name):
            cmd = str(args.get("command") or args.get("cmd") or "")
            for pattern in self._destructive_re:
                if pattern.search(cmd):
                    self._log_incident("destructive_action", cmd[:200])
                    if self.mode == "permissive":
                        return GuardDecision("warn", "destructive_action", f"dangerous command: {cmd[:80]}")
                    return GuardDecision("block", "destructive_action", f"dangerous command: {cmd[:80]}")

        if _looks_like_write_tool(name):
            if not self.allow_file_write:
                return GuardDecision("block", "scope_break", "file writes are disabled for this engagement")
            content = str(args.get("content") or args.get("data") or args.get("body") or "")
            for key in SENSITIVE_KEYS:
                if re.search(rf"{key}\s*[=:]\s*[\"']?[\w\-]{{8,}}", content, re.IGNORECASE):
                    if self.mode == "strict":
                        self._log_incident("sensitive_data", f"{name} with potential {key}")
                        return GuardDecision("block", "sensitive_data", f"write contains potential {key}")
                    return GuardDecision("warn", "sensitive_data", f"write may contain {key}")

        if _looks_like_network_tool(name) and not self.allow_network:
            return GuardDecision("block", "scope_break", "network tools are disabled for this engagement")

        return ALLOW

    def _log_incident(self, category: str, detail: str) -> None:
        self.incidents.append(
            {
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "category": category,
                "detail": detail[:300],
            }
        )
        if len(self.incidents) > self.max_incidents:
            self.incidents = self.incidents[-self.max_incidents :]

    def save_state(self, path: Path) -> None:
        data = {"mode": self.mode, "incidents": self.incidents[-50:]}
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load_state(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        self.mode = data.get("mode", self.mode)
        self.incidents = data.get("incidents", [])


_SHELL_TOOL_HINTS = ("shell", "run_command", "exec", "bash", "sh.")
_WRITE_TOOL_HINTS = ("fs.write", "write_file", "file.write", "write.")
_NETWORK_TOOL_HINTS = ("net.", "http.", "fetch.", "curl", "wget", "nmap", "nuclei")


def _looks_like_shell_tool(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _SHELL_TOOL_HINTS)


def _looks_like_write_tool(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _WRITE_TOOL_HINTS)


def _looks_like_network_tool(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _NETWORK_TOOL_HINTS)


__all__ = [
    "Guardian",
    "GuardDecision",
    "INJECTION_PATTERNS",
    "DESTRUCTIVE_PATTERNS",
    "SENSITIVE_KEYS",
]
