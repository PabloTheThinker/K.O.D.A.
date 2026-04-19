"""Tests for the context compressor."""
from __future__ import annotations

from koda.session.compressor import ContextCompressor, ATTCK_RE, CVE_RE


def test_regexes_extract_anchors():
    txt = "exploited via T1595.001 and cve-2024-12345 alongside T1059"
    assert set(ATTCK_RE.findall(txt)) == {"T1595.001", "T1059"}
    assert [c.upper() for c in CVE_RE.findall(txt)] == ["CVE-2024-12345"]


def test_short_session_not_compressed():
    c = ContextCompressor(preserve_last_n=5, preserve_first_exchange=2)
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]
    assert c.compress(msgs) == msgs


def test_compression_inserts_marker():
    c = ContextCompressor(preserve_last_n=2, preserve_first_exchange=1)
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "start engagement"},
        {"role": "assistant", "content": "ready"},
        {"role": "tool", "content": "ok", "metadata": {"tool_name": "nmap"}},
        {"role": "assistant", "content": "found CVE-2024-0001 and T1595 reconnaissance"},
        {"role": "tool", "content": "err", "metadata": {"tool_name": "nuclei", "is_error": True}},
        {"role": "user", "content": "report"},
        {"role": "assistant", "content": "done"},
    ]
    out = c.compress(msgs)
    markers = [m for m in out if m["role"] == "system" and m["content"].startswith("[compressed")]
    assert len(markers) == 1
    body = markers[0]["content"]
    assert "nmap" in body
    assert "T1595" in body
    assert "CVE-2024-0001" in body


def test_should_compress_threshold():
    c = ContextCompressor(max_chars_budget=100)
    small = [{"role": "user", "content": "x" * 10}]
    big = [{"role": "user", "content": "x" * 200}]
    assert not c.should_compress(small)
    assert c.should_compress(big)


def test_summary_empty_fallback():
    c = ContextCompressor()
    msgs = [{"role": "assistant", "content": "nothing notable"}]
    assert "no signals extracted" in c._summarize(msgs)


def test_llm_summarize_fallback_on_exception():
    c = ContextCompressor(preserve_last_n=1, preserve_first_exchange=1, use_llm=True)

    def broken(**_kw):
        raise RuntimeError("provider down")

    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "scan"},
        {"role": "assistant", "content": "T1059 detected"},
        {"role": "tool", "content": "ok", "metadata": {"tool_name": "nmap"}},
        {"role": "assistant", "content": "done"},
    ]
    out = c.compress(msgs, provider_chat=broken)
    marker = [m for m in out if "[compressed" in m["content"]][0]
    assert "T1059" in marker["content"]
