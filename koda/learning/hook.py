"""Live, in-session learning hook.

The nightly ``koda learn`` cron keeps running as a safety net, but the real
feedback loop is during work: after a turn finishes (TurnLoop) or after
enough MCP tool calls have accumulated (MCP server), we spawn a daemon
thread that runs the Helix consolidate → promote → draft pipeline against
the current store. The user never waits on it.

Design points:

  * Counter-based. Fires when EITHER the turn counter reaches
    ``turn_threshold`` OR the tool-call counter reaches ``tool_threshold``,
    whichever comes first.
  * Debounced. ``min_interval_seconds`` prevents bursty sessions from
    flooding Helix with concurrent consolidation jobs.
  * Daemon thread. Always ``daemon=True`` so the process can exit cleanly.
  * Singleton-friendly. MCP's per-tool-call handler uses the global hook
    so it survives across tool invocations.
  * Swappable runner. Tests inject a fake ``runner`` callable so we don't
    need a real Helix on disk.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class LearningHookStats:
    """Snapshot of the hook's internal counters — useful for metrics."""

    fires: int
    turns_since_fire: int
    tools_since_fire: int
    is_running: bool


class LearningHook:
    """Threshold-triggered, debounced, async-spawning learning trigger."""

    def __init__(
        self,
        *,
        turn_threshold: int = 10,
        tool_threshold: int = 10,
        min_interval_seconds: float = 60.0,
        runner: Callable[[], None] | None = None,
    ) -> None:
        self.turn_threshold = max(1, int(turn_threshold))
        self.tool_threshold = max(1, int(tool_threshold))
        self.min_interval_seconds = float(min_interval_seconds)
        self._runner = runner or _default_runner

        self._lock = threading.Lock()
        self._turns_since_fire = 0
        self._tools_since_fire = 0
        self._last_fire_ts = -float("inf")
        self._running = False
        self._fires = 0

    # ── Public API ─────────────────────────────────────────────────────

    def record_turn(
        self, *, tool_calls: int = 0, aborted: bool = False,
    ) -> threading.Thread | None:
        """Called by TurnLoop after a turn completes.

        ``aborted`` turns are dropped — Helix should not learn from failed
        flows. Returns the spawned thread (for tests) or ``None`` if no fire.
        """
        if aborted:
            return None
        with self._lock:
            self._turns_since_fire += 1
            self._tools_since_fire += max(0, int(tool_calls))
            if not self._should_fire_locked():
                return None
            self._arm_fire_locked()
        return self._spawn()

    def record_tool_call(self) -> threading.Thread | None:
        """Called by the MCP server after each tool invocation.

        Only the tool-count threshold matters here; MCP has no concept of a
        "turn." Returns the spawned thread or ``None``.
        """
        with self._lock:
            self._tools_since_fire += 1
            if self._running:
                return None
            if (time.monotonic() - self._last_fire_ts) < self.min_interval_seconds:
                return None
            if self._tools_since_fire < self.tool_threshold:
                return None
            self._arm_fire_locked()
        return self._spawn()

    def stats(self) -> LearningHookStats:
        with self._lock:
            return LearningHookStats(
                fires=self._fires,
                turns_since_fire=self._turns_since_fire,
                tools_since_fire=self._tools_since_fire,
                is_running=self._running,
            )

    # ── Internals ──────────────────────────────────────────────────────

    def _should_fire_locked(self) -> bool:
        if self._running:
            return False
        if (time.monotonic() - self._last_fire_ts) < self.min_interval_seconds:
            return False
        return (
            self._turns_since_fire >= self.turn_threshold
            or self._tools_since_fire >= self.tool_threshold
        )

    def _arm_fire_locked(self) -> None:
        self._running = True
        self._turns_since_fire = 0
        self._tools_since_fire = 0
        self._last_fire_ts = time.monotonic()
        self._fires += 1

    def _spawn(self) -> threading.Thread:
        thread = threading.Thread(
            target=self._run_safe,
            daemon=True,
            name="koda-learning-hook",
        )
        thread.start()
        return thread

    def _run_safe(self) -> None:
        try:
            self._runner()
        except Exception:
            # Learning is best-effort. A crash in a daemon thread must never
            # leak into the user's session.
            pass
        finally:
            with self._lock:
                self._running = False


# ── Default runner — swappable via tests ───────────────────────────────

def _default_runner() -> None:
    """Run one full learning cycle against ``$KODA_HOME``.

    Imports are local so the hook module itself stays cheap to import.
    """
    from koda.config import KODA_HOME
    from koda.learning import (
        default_store,
        draft_skill_from_concept,
        find_candidates,
        scan_skill_draft,
    )
    from koda.memory.helix import Helix

    memory_dir = KODA_HOME / "memory"
    if not memory_dir.is_dir():
        return

    with Helix(memory_dir) as helix:
        helix.consolidate()
        store = default_store()
        already = store.pending_concept_ids()
        candidates = find_candidates(helix=helix, exclude_concept_ids=already)
        for cand in candidates:
            draft = draft_skill_from_concept(
                concept=cand.concept, evidence_episodes=cand.episodes,
            )
            report = scan_skill_draft(
                name=draft.name,
                description=draft.description,
                body=draft.body,
            )
            if not report.clean:
                continue
            store.save_pending(
                name=draft.name,
                skill_md=draft.render(),
                source={
                    "concept_id": cand.concept_id,
                    "confidence": cand.confidence,
                    "evidence_count": len(cand.episodes),
                    "trigger": "live-hook",
                },
            )


# ── Global (process-wide) hook for surfaces that can't inject ──────────

_GLOBAL_HOOK: LearningHook | None = None
_GLOBAL_LOCK = threading.Lock()


def install_global_hook(
    *,
    turn_threshold: int = 10,
    tool_threshold: int = 10,
    min_interval_seconds: float = 60.0,
    runner: Callable[[], None] | None = None,
    force: bool = False,
) -> LearningHook:
    """Create-or-reuse the process-wide hook.

    The MCP server installs this on startup (env-gated). Tests pass
    ``force=True`` to reset between cases.
    """
    global _GLOBAL_HOOK
    with _GLOBAL_LOCK:
        if _GLOBAL_HOOK is None or force:
            _GLOBAL_HOOK = LearningHook(
                turn_threshold=turn_threshold,
                tool_threshold=tool_threshold,
                min_interval_seconds=min_interval_seconds,
                runner=runner,
            )
    return _GLOBAL_HOOK


def get_global_hook() -> LearningHook | None:
    return _GLOBAL_HOOK


def disable_global_hook() -> None:
    global _GLOBAL_HOOK
    with _GLOBAL_LOCK:
        _GLOBAL_HOOK = None
