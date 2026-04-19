"""Unit tests for koda.evidence.store and koda.evidence.bundle."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from koda.evidence.bundle import export_bundle, verify_bundle
from koda.evidence.store import (
    EvidenceStore,
    compute_chain_hash,
)

_GENESIS = "0" * 64


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store(tmp_path):
    """Fresh EvidenceStore backed by a temp directory."""
    s = EvidenceStore(path=tmp_path / "evidence")
    yield s
    s.close()


# ---------------------------------------------------------------------------
# SHA-256 content addressing
# ---------------------------------------------------------------------------


def test_capture_yields_stable_hash(store):
    """Capturing the same bytes twice produces the same sha256."""
    payload = b"hello koda"
    a1 = store.capture(payload, tool="t", engagement="eng", session_id="s1")
    a2 = store.capture(payload, tool="t", engagement="eng", session_id="s1")
    assert a1.sha256 == a2.sha256
    assert a1.sha256 == hashlib.sha256(payload).hexdigest()


def test_artifact_size_is_byte_length(store):
    payload = b"x" * 256
    a = store.capture(payload, tool="t", engagement="eng", session_id="s1")
    assert a.size == 256


def test_different_content_different_hash(store):
    a = store.capture(b"alpha", tool="t", engagement="eng", session_id="s1")
    b = store.capture(b"beta", tool="t", engagement="eng", session_id="s1")
    assert a.sha256 != b.sha256


# ---------------------------------------------------------------------------
# Merkle chain — forward linking
# ---------------------------------------------------------------------------


def test_first_artifact_starts_from_genesis(store):
    """The first artifact in an engagement links back to the all-zeros genesis."""
    a = store.capture(b"first", tool="t", engagement="eng", session_id="s1")
    assert a.prev_hash == _GENESIS


def test_chain_links_sequentially(store):
    """Each subsequent artifact's prev_hash equals the prior artifact's chain_hash."""
    a1 = store.capture(b"one", tool="t", engagement="eng", session_id="s1")
    a2 = store.capture(b"two", tool="t", engagement="eng", session_id="s1")
    a3 = store.capture(b"three", tool="t", engagement="eng", session_id="s1")
    assert a2.prev_hash == a1.chain_hash
    assert a3.prev_hash == a2.chain_hash


def test_verify_chain_passes_clean(store):
    """verify_chain returns ok=True on an untampered engagement."""
    for i in range(3):
        store.capture(f"artifact {i}".encode(), tool="t", engagement="eng", session_id="s")
    result = store.verify_chain(engagement="eng")
    assert result.ok is True
    assert result.checked == 3


def test_verify_chain_empty_engagement(store):
    """An engagement with no artifacts is trivially valid."""
    result = store.verify_chain(engagement="empty-eng")
    assert result.ok is True
    assert result.checked == 0


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_tamper_detected_on_disk_mutation(store):
    """Mutating the artifact file on disk causes verify_chain to fail."""
    a = store.capture(b"sensitive output", tool="t", engagement="eng", session_id="s")
    # The artifact file is written chmod 0o400 — temporarily make it writable.
    p = Path(a.path)
    p.chmod(0o600)
    p.write_bytes(b"TAMPERED")

    result = store.verify_chain(engagement="eng")
    assert result.ok is False
    assert "sha256 mismatch" in result.reason.lower() or result.first_divergence


# ---------------------------------------------------------------------------
# compute_chain_hash is deterministic
# ---------------------------------------------------------------------------


def test_compute_chain_hash_deterministic():
    """Same inputs always produce the same output (PYTHONHASHSEED-independent)."""
    h1 = compute_chain_hash("0" * 64, "abc123", "artifact-id-xyz", 1700000000.0)
    h2 = compute_chain_hash("0" * 64, "abc123", "artifact-id-xyz", 1700000000.0)
    assert h1 == h2
    assert len(h1) == 64


# ---------------------------------------------------------------------------
# Bundle export / import roundtrip
# ---------------------------------------------------------------------------


def test_bundle_export_import_roundtrip(store, tmp_path):
    """Exported bundle passes verify_bundle without warnings."""
    for i in range(3):
        store.capture(f"tool output #{i}".encode(), tool="scanner", engagement="eng", session_id="s")

    out = tmp_path / "bundle.tar.gz"
    report = export_bundle(store, "eng", out)
    assert report.ok is True
    assert report.artifact_count == 3
    assert not report.warnings

    verification = verify_bundle(out)
    assert verification.ok is True
    assert verification.artifact_count == 3
    assert not verification.warnings


def test_bundle_empty_engagement(store, tmp_path):
    """An empty engagement produces a valid (zero-artifact) bundle."""
    out = tmp_path / "empty.tar.gz"
    report = export_bundle(store, "no-artifacts", out)
    assert report.ok is True
    assert report.artifact_count == 0

    verification = verify_bundle(out)
    assert verification.ok is True


def test_bundle_tampered_file_fails_verify(store, tmp_path):
    """Mutating a bundled artifact causes verify_bundle to report a failure."""
    store.capture(b"original output data here", tool="nmap", engagement="eng", session_id="s")
    out = tmp_path / "bundle.tar.gz"
    export_bundle(store, "eng", out)

    # Unpack, corrupt, repack.
    import io
    import tarfile

    modified_buf = io.BytesIO()
    with tarfile.open(out, "r:gz") as src_tar, tarfile.open(fileobj=modified_buf, mode="w:gz") as dst_tar:
        for member in src_tar.getmembers():
            fobj = src_tar.extractfile(member)
            if fobj is not None and member.name.startswith("artifacts/") and member.name.endswith(".txt"):
                # Replace with corrupted bytes.
                data = b"TAMPERED CONTENT"
                info = tarfile.TarInfo(name=member.name)
                info.size = len(data)
                info.mode = member.mode
                info.mtime = member.mtime
                dst_tar.addfile(info, io.BytesIO(data))
            else:
                if fobj is not None:
                    dst_tar.addfile(member, fobj)
                else:
                    dst_tar.addfile(member)

    tampered_path = tmp_path / "tampered.tar.gz"
    tampered_path.write_bytes(modified_buf.getvalue())

    result = verify_bundle(tampered_path)
    assert result.ok is False
