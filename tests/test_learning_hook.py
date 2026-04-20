"""Tests for the live learning hook — thresholds, debouncing, thread safety."""
from __future__ import annotations

import threading
import time

from koda.learning.hook import (
    LearningHook,
    disable_global_hook,
    get_global_hook,
    install_global_hook,
)


class _Counter:
    """Runner stand-in: bumps a counter, optionally blocks on an event."""

    def __init__(self, *, block: threading.Event | None = None) -> None:
        self.calls = 0
        self.lock = threading.Lock()
        self.block = block

    def __call__(self) -> None:
        if self.block is not None:
            self.block.wait(timeout=2.0)
        with self.lock:
            self.calls += 1


def _join(thread: threading.Thread | None) -> None:
    if thread is not None:
        thread.join(timeout=2.0)


def test_turn_threshold_fires_after_n_turns() -> None:
    runner = _Counter()
    hook = LearningHook(
        turn_threshold=3,
        tool_threshold=999,
        min_interval_seconds=0,
        runner=runner,
    )
    _join(hook.record_turn())
    _join(hook.record_turn())
    assert runner.calls == 0
    _join(hook.record_turn())
    assert runner.calls == 1


def test_tool_threshold_fires_independently() -> None:
    runner = _Counter()
    hook = LearningHook(
        turn_threshold=999,
        tool_threshold=5,
        min_interval_seconds=0,
        runner=runner,
    )
    _join(hook.record_turn(tool_calls=4))
    assert runner.calls == 0
    _join(hook.record_turn(tool_calls=1))
    assert runner.calls == 1


def test_aborted_turns_are_dropped() -> None:
    runner = _Counter()
    hook = LearningHook(
        turn_threshold=1, tool_threshold=999,
        min_interval_seconds=0, runner=runner,
    )
    assert hook.record_turn(aborted=True) is None
    assert runner.calls == 0


def test_debounce_blocks_back_to_back_fires() -> None:
    runner = _Counter()
    hook = LearningHook(
        turn_threshold=1, tool_threshold=999,
        min_interval_seconds=10.0, runner=runner,
    )
    _join(hook.record_turn())
    assert runner.calls == 1
    # Second turn should not fire because the interval hasn't elapsed.
    assert hook.record_turn() is None
    assert runner.calls == 1


def test_running_flag_prevents_concurrent_fires() -> None:
    gate = threading.Event()
    runner = _Counter(block=gate)
    hook = LearningHook(
        turn_threshold=1, tool_threshold=999,
        min_interval_seconds=0, runner=runner,
    )
    first = hook.record_turn()
    assert first is not None
    # While runner is blocked, another record_turn must NOT spawn.
    # Give the thread a moment to flip _running.
    time.sleep(0.05)
    assert hook.record_turn() is None
    gate.set()
    first.join(timeout=2.0)
    assert runner.calls == 1


def test_record_tool_call_path() -> None:
    runner = _Counter()
    hook = LearningHook(
        turn_threshold=999, tool_threshold=3,
        min_interval_seconds=0, runner=runner,
    )
    _join(hook.record_tool_call())
    _join(hook.record_tool_call())
    assert runner.calls == 0
    _join(hook.record_tool_call())
    assert runner.calls == 1


def test_runner_exception_does_not_leak() -> None:
    def boom() -> None:
        raise RuntimeError("kaboom")

    hook = LearningHook(
        turn_threshold=1, tool_threshold=999,
        min_interval_seconds=0, runner=boom,
    )
    thread = hook.record_turn()
    assert thread is not None
    thread.join(timeout=2.0)
    # Hook must be able to fire again after a crashed runner.
    assert hook.stats().is_running is False


def test_stats_snapshot_is_consistent() -> None:
    runner = _Counter()
    hook = LearningHook(
        turn_threshold=5, tool_threshold=5,
        min_interval_seconds=0, runner=runner,
    )
    hook.record_turn(tool_calls=2)
    hook.record_turn(tool_calls=1)
    s = hook.stats()
    assert s.turns_since_fire == 2
    assert s.tools_since_fire == 3
    assert s.fires == 0


def test_global_hook_install_and_reset() -> None:
    disable_global_hook()
    assert get_global_hook() is None
    runner = _Counter()
    hook = install_global_hook(
        turn_threshold=1, tool_threshold=1,
        min_interval_seconds=0, runner=runner,
    )
    assert get_global_hook() is hook
    # Without force, second install returns the same instance.
    again = install_global_hook(turn_threshold=999, runner=runner)
    assert again is hook
    # With force, a new one replaces it.
    forced = install_global_hook(turn_threshold=2, runner=runner, force=True)
    assert forced is not hook
    disable_global_hook()
    assert get_global_hook() is None


def test_turn_loop_integration(monkeypatch) -> None:
    """TurnLoop.__init__ accepts learning_hook and _emit_turn_end calls it."""
    from koda.agent.loop import TurnLoop, TurnTrace

    runner = _Counter()
    hook = LearningHook(
        turn_threshold=1, tool_threshold=999,
        min_interval_seconds=0, runner=runner,
    )

    # Construct a minimal TurnLoop with placeholders — we only exercise
    # _emit_turn_end, not the full async run() path.
    loop = TurnLoop.__new__(TurnLoop)
    loop.learning_hook = hook
    loop.audit = type("A", (), {"emit": lambda self, *a, **k: None})()
    loop.session_id = "s"
    loop.engagement = "e"

    trace = TurnTrace(iterations=1, tool_calls_made=0, aborted=False)
    loop._emit_turn_end(trace, 0, 0)
    # Wait briefly for the daemon thread to finish.
    for _ in range(20):
        if runner.calls >= 1:
            break
        time.sleep(0.05)
    assert runner.calls == 1
