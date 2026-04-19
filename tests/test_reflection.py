"""Tests for the ReflectionEngine."""
from __future__ import annotations

import json

from koda.agent.reflection import ReflectionEngine


def test_record_and_bound():
    r = ReflectionEngine(max_entries=3)
    for i in range(10):
        r.record(success=True, tools=["nmap"], iteration=i)
    assert len(r.journal) == 3


def test_recent_hint_low_success():
    r = ReflectionEngine()
    for _ in range(6):
        r.record(success=False, tools=["nmap"])
    hint = r.recent_hint()
    assert "low success" in hint
    assert "nmap" in hint


def test_recent_hint_high_success():
    r = ReflectionEngine()
    for _ in range(10):
        r.record(success=True, tools=["semgrep", "nuclei"])
    hint = r.recent_hint()
    assert "high success" in hint


def test_recent_hint_empty_before_threshold():
    r = ReflectionEngine()
    r.record(success=True)
    assert r.recent_hint() == ""


def test_get_patterns_shape():
    r = ReflectionEngine()
    r.record(success=True, tools=["nmap"])
    r.record(success=False, tools=["nmap"], error="timeout")
    r.record(success=True, tools=["nuclei"], correction="user redirected")
    p = r.get_patterns()
    assert p["entries"] == 3
    assert p["success_rate"] == round(2 / 3, 3)
    assert p["error_rate"] == round(1 / 3, 3)
    assert p["correction_rate"] == round(1 / 3, 3)
    assert p["top_tools"][0][0] == "nmap"
    assert p["top_errors"][0][0] == "timeout"


def test_save_and_load_state(tmp_path):
    r = ReflectionEngine()
    r.record(success=True, tools=["nmap"], engagement="eng-1")
    path = tmp_path / "journal.json"
    r.save_state(path)

    r2 = ReflectionEngine()
    r2.load_state(path)
    assert len(r2.journal) == 1
    assert r2.journal[0]["engagement"] == "eng-1"
    # roundtrip is JSON-safe
    json.loads(path.read_text())
