"""Tests for koda.evidence.remote — RemoteBundleStore and CLI wiring.

We use a hand-rolled boto3 mock (monkeypatch) rather than moto because:
  - moto is not in the project's dev-deps (pyproject.toml lists only
    pytest / pytest-asyncio / ruff).
  - Adding an optional heavy mock library just for transport tests conflicts
    with the local-first / minimal-deps philosophy.
  - A minimal fake s3 client lets us exercise every code path including
    sidecar format, hash-mismatch cleanup, and credential redaction without
    the moto service-startup overhead.

The fake client stores objects in a plain dict keyed by (bucket, key).
"""
from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import warnings
from pathlib import Path
from typing import Any
from unittest.mock import (
    MagicMock,
    patch,
)

import pytest

# ---------------------------------------------------------------------------
# Fake S3 client
# ---------------------------------------------------------------------------

class _FakePaginator:
    """Minimal paginator that returns one page per call."""

    def __init__(self, store: dict, bucket: str, prefix: str) -> None:
        self._store = store
        self._bucket = bucket
        self._prefix = prefix

    def paginate(self, Bucket: str, Prefix: str = "") -> list[dict]:
        # Re-run the filter every time paginate() is called so callers see
        # consistent results even if the store was mutated in between.
        contents = [
            {
                "Key": k,
                "Size": len(v["body"]),
                "LastModified": "2026-01-01T00:00:00+00:00",
            }
            for (b, k), v in self._store.items()
            if b == Bucket and k.startswith(Prefix)
        ]
        return [{"Contents": contents}]


class _FakeS3Client:
    """In-memory S3 substitute — stores objects as {(bucket, key): {body, metadata}}."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], dict[str, Any]] = {}

    def put_object(self, *, Bucket: str, Key: str, Body: Any, ContentType: str = "") -> dict:
        if hasattr(Body, "read"):
            data = Body.read()
        elif isinstance(Body, (bytes, bytearray)):
            data = bytes(Body)
        else:
            data = Body
        self._store[(Bucket, Key)] = {"body": data, "content_type": ContentType}
        digest = hashlib.md5(data).hexdigest()  # noqa: S324 — test only
        return {"ETag": f'"{digest}"'}

    def get_object(self, *, Bucket: str, Key: str) -> dict:
        entry = self._store.get((Bucket, Key))
        if entry is None:
            raise KeyError(f"NoSuchKey: {Key}")
        return {"Body": io.BytesIO(entry["body"])}

    def get_paginator(self, operation_name: str) -> _FakePaginator:
        return _FakePaginator(self._store, "", "")


def _make_store(fake_client: _FakeS3Client, **kwargs: Any) -> Any:
    """Build a RemoteBundleStore backed by fake_client."""
    from koda.evidence.remote import RemoteBundleStore

    store = RemoteBundleStore(bucket="test-bucket", **kwargs)
    store._client = fake_client  # bypass lazy init
    return store


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def fake_s3() -> _FakeS3Client:
    return _FakeS3Client()


@pytest.fixture()
def bundle(tmp_path: Path) -> Path:
    """A minimal but valid .tar.gz bundle."""
    p = tmp_path / "test_eng_1700000000.tar.gz"
    with tarfile.open(p, "w:gz") as tar:
        content = b"tool output from scanner"
        info = tarfile.TarInfo(name="bundle.json")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return p


@pytest.fixture()
def audit_mock() -> MagicMock:
    m = MagicMock()
    m.emit = MagicMock()
    return m


# ---------------------------------------------------------------------------
# 1. Push creates a sidecar
# ---------------------------------------------------------------------------

def test_push_creates_sidecar(fake_s3: _FakeS3Client, bundle: Path) -> None:
    store = _make_store(fake_s3)
    result = store.push(bundle, dest_key="eng/bundle.tar.gz")

    # Main object written.
    assert ("test-bucket", "eng/bundle.tar.gz") in fake_s3._store
    # Sidecar written.
    assert ("test-bucket", "eng/bundle.tar.gz.sha256") in fake_s3._store

    sidecar_body = fake_s3._store[("test-bucket", "eng/bundle.tar.gz.sha256")]["body"]
    sidecar_hex = sidecar_body.decode().strip()
    assert len(sidecar_hex) == 64  # hex SHA-256
    assert sidecar_hex == result["sha256"]


def test_push_sidecar_matches_bundle_content(fake_s3: _FakeS3Client, bundle: Path) -> None:
    store = _make_store(fake_s3)
    result = store.push(bundle, dest_key="test.tar.gz")

    expected = hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert result["sha256"] == expected

    sidecar = fake_s3._store[("test-bucket", "test.tar.gz.sha256")]["body"]
    assert sidecar.decode().strip() == expected


# ---------------------------------------------------------------------------
# 2. Pull verifies sidecar; hash mismatch raises and deletes partial file
# ---------------------------------------------------------------------------

def test_pull_verifies_correctly(fake_s3: _FakeS3Client, bundle: Path, tmp_path: Path) -> None:
    store = _make_store(fake_s3)
    store.push(bundle, dest_key="bundle.tar.gz")

    dest = tmp_path / "pulled.tar.gz"
    returned = store.pull("bundle.tar.gz", dest_path=dest)
    assert returned == dest
    assert dest.exists()
    # Content must match what was uploaded.
    assert dest.read_bytes() == bundle.read_bytes()


def test_pull_mismatch_raises_and_cleans_up(fake_s3: _FakeS3Client, bundle: Path, tmp_path: Path) -> None:
    store = _make_store(fake_s3)
    store.push(bundle, dest_key="bundle.tar.gz")

    # Corrupt the sidecar to simulate an attacker or bit-flip.
    fake_s3._store[("test-bucket", "bundle.tar.gz.sha256")]["body"] = b"deadbeef" * 8 + b"\n"

    dest = tmp_path / "pulled.tar.gz"
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        store.pull("bundle.tar.gz", dest_path=dest)

    # Partial file must NOT exist after a failed pull.
    assert not dest.exists()


def test_pull_missing_sidecar_raises(fake_s3: _FakeS3Client, bundle: Path, tmp_path: Path) -> None:
    """If the sidecar is absent the pull should abort before downloading."""
    store = _make_store(fake_s3)
    # Upload only the bundle; skip the sidecar.
    with open(bundle, "rb") as fh:
        fake_s3.put_object(Bucket="test-bucket", Key="bundle.tar.gz", Body=fh)

    with pytest.raises(RuntimeError, match="sidecar"):
        store.pull("bundle.tar.gz", dest_path=tmp_path / "pulled.tar.gz")


# ---------------------------------------------------------------------------
# 3. Missing boto3 raises ImportError with install hint
# ---------------------------------------------------------------------------

def test_missing_boto3_raises_clean_error(bundle: Path) -> None:
    with patch.dict(sys.modules, {"boto3": None}):
        from importlib import reload

        import koda.evidence.remote as rem_mod
        reload(rem_mod)

        store = rem_mod.RemoteBundleStore(bucket="b")
        with pytest.raises(ImportError, match="pip install boto3"):
            store.push(bundle, dest_key="x.tar.gz")


# ---------------------------------------------------------------------------
# 4. Env-var config loads correctly
# ---------------------------------------------------------------------------

def test_env_var_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KODA_REMOTE_BUCKET", "env-bucket")
    from koda.evidence.remote import RemoteBundleStore
    store = RemoteBundleStore()
    assert store.bucket == "env-bucket"


def test_env_var_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KODA_REMOTE_BUCKET", "b")
    monkeypatch.setenv("KODA_REMOTE_ENDPOINT", "http://localhost:9000")
    from koda.evidence.remote import RemoteBundleStore
    store = RemoteBundleStore()
    assert store.endpoint_url == "http://localhost:9000"


def test_env_var_region(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KODA_REMOTE_BUCKET", "b")
    monkeypatch.setenv("KODA_REMOTE_REGION", "eu-west-1")
    from koda.evidence.remote import RemoteBundleStore
    store = RemoteBundleStore()
    assert store.region == "eu-west-1"


def test_env_var_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KODA_REMOTE_BUCKET", "b")
    monkeypatch.setenv("KODA_REMOTE_PREFIX", "engagements/")
    from koda.evidence.remote import RemoteBundleStore
    store = RemoteBundleStore()
    assert store.prefix == "engagements/"


def test_kwarg_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KODA_REMOTE_BUCKET", "env-bucket")
    from koda.evidence.remote import RemoteBundleStore
    store = RemoteBundleStore(bucket="kwarg-bucket")
    assert store.bucket == "kwarg-bucket"


def test_missing_bucket_raises() -> None:
    import os

    from koda.evidence.remote import RemoteBundleStore
    # Ensure no env var leaks from test runner.
    env_backup = os.environ.pop("KODA_REMOTE_BUCKET", None)
    try:
        with pytest.raises(ValueError, match="bucket is required"):
            RemoteBundleStore()
    finally:
        if env_backup is not None:
            os.environ["KODA_REMOTE_BUCKET"] = env_backup


# ---------------------------------------------------------------------------
# 5. remote.toml parsing
# ---------------------------------------------------------------------------

def test_remote_toml_parsed(tmp_path: Path) -> None:
    (tmp_path / "remote.toml").write_text('bucket = "toml-bucket"\nregion = "us-west-2"\n')

    from koda.evidence.remote import RemoteBundleStore
    store = RemoteBundleStore(koda_home=tmp_path)
    assert store.bucket == "toml-bucket"
    assert store.region == "us-west-2"


def test_remote_toml_kwarg_overrides_toml(tmp_path: Path) -> None:
    (tmp_path / "remote.toml").write_text('bucket = "toml-bucket"\n')
    from koda.evidence.remote import RemoteBundleStore
    store = RemoteBundleStore(bucket="override-bucket", koda_home=tmp_path)
    assert store.bucket == "override-bucket"


def test_remote_toml_malformed_warns_but_does_not_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "remote.toml").write_text("this is not valid toml ][")
    monkeypatch.setenv("KODA_REMOTE_BUCKET", "fallback-bucket")

    from koda.evidence.remote import RemoteBundleStore
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        store = RemoteBundleStore(koda_home=tmp_path)
    assert store.bucket == "fallback-bucket"
    assert any("remote.toml" in str(warning.message) for warning in w)


def test_remote_toml_missing_is_silent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing remote.toml must not raise or warn."""
    monkeypatch.setenv("KODA_REMOTE_BUCKET", "b")
    from koda.evidence.remote import RemoteBundleStore
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        RemoteBundleStore(koda_home=tmp_path)
    assert not any("remote.toml" in str(warning.message) for warning in w)


# ---------------------------------------------------------------------------
# 6. Credentials never appear in output
# ---------------------------------------------------------------------------

def test_credentials_not_in_error_message(fake_s3: _FakeS3Client) -> None:
    """ValueError from a missing bucket must not contain the secret key."""
    secret = "super-secret-key-12345"
    from koda.evidence.remote import RemoteBundleStore
    store = RemoteBundleStore(bucket="b", secret_access_key=secret)
    store._client = fake_s3

    # Trigger a "missing sidecar" error path and capture the message.
    with pytest.raises(RuntimeError) as exc_info:
        store.pull("nonexistent.tar.gz")

    assert secret not in str(exc_info.value)


def test_credentials_not_in_push_result(fake_s3: _FakeS3Client, bundle: Path) -> None:
    secret = "access-secret-xyz"
    store = _make_store(fake_s3, secret_access_key=secret)
    result = store.push(bundle)
    result_str = str(result)
    assert secret not in result_str


# ---------------------------------------------------------------------------
# 7. Audit events emitted with correct fields
# ---------------------------------------------------------------------------

def test_push_emits_audit_event(fake_s3: _FakeS3Client, bundle: Path, audit_mock: MagicMock) -> None:
    store = _make_store(fake_s3, audit=audit_mock)
    store.push(bundle, dest_key="eng/bundle.tar.gz")

    audit_mock.emit.assert_called_once()
    call_kwargs = audit_mock.emit.call_args
    assert call_kwargs[0][0] == "evidence.remote.push"
    kw = call_kwargs[1]
    assert "bundle_sha256" in kw
    assert "bucket" in kw
    assert "key" in kw
    assert "bytes" in kw


def test_pull_emits_audit_event(fake_s3: _FakeS3Client, bundle: Path, tmp_path: Path, audit_mock: MagicMock) -> None:
    store = _make_store(fake_s3)
    store.push(bundle, dest_key="bundle.tar.gz")

    store2 = _make_store(fake_s3, audit=audit_mock)
    store2.pull("bundle.tar.gz", dest_path=tmp_path / "out.tar.gz")

    audit_mock.emit.assert_called_once()
    call_kwargs = audit_mock.emit.call_args
    assert call_kwargs[0][0] == "evidence.remote.pull"
    kw = call_kwargs[1]
    assert kw.get("verified") is True
    assert "bundle_sha256" in kw
    assert "bucket" in kw


def test_pull_mismatch_audit_event_has_verified_false(
    fake_s3: _FakeS3Client, bundle: Path, tmp_path: Path, audit_mock: MagicMock
) -> None:
    store = _make_store(fake_s3, audit=audit_mock)
    store.push(bundle, dest_key="bundle.tar.gz")
    # Corrupt sidecar.
    fake_s3._store[("test-bucket", "bundle.tar.gz.sha256")]["body"] = b"bad" * 22 + b"\n"

    with pytest.raises(ValueError):
        store.pull("bundle.tar.gz", dest_path=tmp_path / "out.tar.gz")

    # The last emit call should be the pull event (push emit happened first).
    last_call = audit_mock.emit.call_args_list[-1]
    assert last_call[0][0] == "evidence.remote.pull"
    assert last_call[1].get("verified") is False


def test_list_emits_audit_event(fake_s3: _FakeS3Client, audit_mock: MagicMock) -> None:
    store = _make_store(fake_s3, audit=audit_mock)
    store.list_remote()

    audit_mock.emit.assert_called_once()
    call_kwargs = audit_mock.emit.call_args
    assert call_kwargs[0][0] == "evidence.remote.list"
    kw = call_kwargs[1]
    assert "bucket" in kw
    assert "prefix" in kw
    assert "count" in kw


# ---------------------------------------------------------------------------
# 8. Key prefix applied correctly
# ---------------------------------------------------------------------------

def test_prefix_applied_on_push(fake_s3: _FakeS3Client, bundle: Path) -> None:
    store = _make_store(fake_s3, prefix="ops/")
    store.push(bundle, dest_key="bundle.tar.gz")

    assert ("test-bucket", "ops/bundle.tar.gz") in fake_s3._store
    assert ("test-bucket", "ops/bundle.tar.gz.sha256") in fake_s3._store


def test_prefix_applied_on_pull(fake_s3: _FakeS3Client, bundle: Path, tmp_path: Path) -> None:
    store = _make_store(fake_s3, prefix="ops/")
    store.push(bundle, dest_key="bundle.tar.gz")

    dest = tmp_path / "pulled.tar.gz"
    store.pull("bundle.tar.gz", dest_path=dest)
    assert dest.exists()
    assert dest.read_bytes() == bundle.read_bytes()


def test_prefix_applied_on_list(fake_s3: _FakeS3Client, bundle: Path) -> None:
    store = _make_store(fake_s3, prefix="ops/")
    store.push(bundle, dest_key="bundle.tar.gz")

    items = store.list_remote()
    # Should see the key through the prefix filter.
    keys = [i["key"] for i in items]
    assert "ops/bundle.tar.gz" in keys
    # Sidecar should NOT appear in list results.
    assert not any(k.endswith(".sha256") for k in keys)


def test_push_default_key_is_filename(fake_s3: _FakeS3Client, bundle: Path) -> None:
    """When dest_key is omitted the bundle's filename is used as the key."""
    store = _make_store(fake_s3)
    store.push(bundle)
    assert ("test-bucket", bundle.name) in fake_s3._store
