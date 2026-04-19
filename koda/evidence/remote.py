"""Remote bundle storage — S3-compatible push/pull/list.

Design rationale:
  - ``boto3`` is lazy-imported so the dependency stays optional.  Operators
    who never push off-box don't need it in their venv.
  - Every upload writes a sidecar ``<key>.sha256`` object (plain-text hex
    digest, newline-terminated).  This means a fresh machine — with no sqlite
    store — can still verify a download without trusting the bundle metadata
    alone.
  - Pull fetches the sidecar FIRST, computes the SHA-256 of the downloaded
    bytes, then asserts equality before returning the path.  If the assert
    fails the partial file is unlinked immediately.
  - Credentials are never printed or logged.  All audit fields and error
    messages redact the access key.
  - Concurrent pushes to the same key silently overwrite (last-writer-wins).
    S3 / R2 / MinIO are all eventually consistent on PUTs so there is no
    safe "refuse-if-exists" without extra HEAD overhead.  Operators who need
    versioning should enable bucket versioning at the provider level.

Config priority (highest → lowest):
  1. Constructor kwargs (passed by CLI after flag parsing)
  2. Env vars: KODA_REMOTE_BUCKET, KODA_REMOTE_ENDPOINT, KODA_REMOTE_REGION,
               KODA_REMOTE_PREFIX — plus standard AWS_* creds vars
  3. KODA_HOME/remote.toml  [bucket, endpoint_url, region, prefix]
"""
from __future__ import annotations

import hashlib
import os
import warnings
from pathlib import Path
from typing import Any

# Sidecar format: plain UTF-8 text — one line, the SHA-256 hex digest.
# Why text instead of JSON?  verify_bundle already works from stdlib only.
# A ".sha256" sidecar keeps the same spirit: any operator can read it with
# `curl … | sha256sum -c` or just `cat`.  JSON would add no structural
# benefit here.
_SIDECAR_SUFFIX = ".sha256"


# ---------------------------------------------------------------------------
# Lazy boto3 import
# ---------------------------------------------------------------------------

def _require_boto3() -> Any:
    try:
        import boto3  # type: ignore[import]
        return boto3
    except ImportError:
        raise ImportError(
            "boto3 is required for remote bundle operations.\n"
            "Install it with:  pip install boto3\n"
            "Or add the optional extra:  pip install 'koda-security[remote]'"
        ) from None


# ---------------------------------------------------------------------------
# TOML config reader (stdlib tomllib / tomli fallback)
# ---------------------------------------------------------------------------

def _parse_toml(path: Path) -> dict[str, Any]:
    """Read a TOML file using stdlib tomllib (Python 3.11+) or tomli."""
    try:
        import tomllib  # stdlib — Python 3.11+
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except ImportError:
        pass
    try:
        import tomli  # type: ignore[import]
        with open(path, "rb") as fh:
            return tomli.load(fh)
    except ImportError:
        return {}


def _load_remote_toml(koda_home: Path | None = None) -> dict[str, Any]:
    """Parse KODA_HOME/remote.toml; return {} on any error (warn only)."""
    if koda_home is None:
        koda_home = Path(os.environ.get("KODA_HOME", Path.home() / ".koda"))
    toml_path = koda_home / "remote.toml"
    if not toml_path.exists():
        return {}
    try:
        data = _parse_toml(toml_path)
        if not isinstance(data, dict):
            raise ValueError("remote.toml top level must be a TOML table")
        return data
    except Exception as exc:  # noqa: BLE001
        warnings.warn(
            f"koda: could not parse {toml_path}: {exc} — remote config ignored",
            stacklevel=3,
        )
        return {}


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# RemoteBundleStore
# ---------------------------------------------------------------------------

class RemoteBundleStore:
    """S3-compatible remote store for K.O.D.A. evidence bundles.

    Parameters (all optional — fall back to env vars then remote.toml):
        endpoint_url   — set for Cloudflare R2, MinIO, localstack; omit for AWS
        region         — default "us-east-1"
        bucket         — required (env: KODA_REMOTE_BUCKET)
        access_key_id  — if omitted, boto3 credential chain applies
        secret_access_key — if omitted, boto3 credential chain applies
        prefix         — optional key prefix, e.g. "engagements/"
        audit          — AuditLogger-compatible object (must have .emit())
        koda_home      — path to resolve remote.toml from (default: KODA_HOME)
    """

    def __init__(
        self,
        *,
        endpoint_url: str | None = None,
        region: str | None = None,
        bucket: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        prefix: str | None = None,
        audit: Any = None,
        koda_home: Path | None = None,
    ) -> None:
        # Build config: kwargs > env vars > remote.toml
        toml = _load_remote_toml(koda_home)

        self.endpoint_url: str | None = (
            endpoint_url
            or os.environ.get("KODA_REMOTE_ENDPOINT")
            or toml.get("endpoint_url")
            or None
        )
        self.region: str = (
            region
            or os.environ.get("KODA_REMOTE_REGION")
            or str(toml.get("region") or "")
            or "us-east-1"
        )
        self.bucket: str = (
            bucket
            or os.environ.get("KODA_REMOTE_BUCKET")
            or str(toml.get("bucket") or "")
        )
        if not self.bucket:
            raise ValueError(
                "bucket is required. Set --bucket, KODA_REMOTE_BUCKET, "
                "or bucket= in KODA_HOME/remote.toml"
            )

        self.prefix: str = (
            prefix
            if prefix is not None
            else (
                os.environ.get("KODA_REMOTE_PREFIX")
                or str(toml.get("prefix") or "")
                or ""
            )
        )

        # Credentials: passed kwargs win; else boto3 chain (AWS_*, ~/.aws/…)
        self._access_key_id: str | None = (
            access_key_id or os.environ.get("AWS_ACCESS_KEY_ID") or None
        )
        self._secret_access_key: str | None = (
            secret_access_key or os.environ.get("AWS_SECRET_ACCESS_KEY") or None
        )

        self.audit = audit
        self._client: Any = None  # lazy

    # --- internal ---

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        boto3 = _require_boto3()
        kwargs: dict[str, Any] = {
            "region_name": self.region,
        }
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        if self._access_key_id and self._secret_access_key:
            kwargs["aws_access_key_id"] = self._access_key_id
            kwargs["aws_secret_access_key"] = self._secret_access_key
        self._client = boto3.client("s3", **kwargs)
        return self._client

    def _full_key(self, key: str) -> str:
        """Apply the configured prefix to a user-supplied key."""
        if self.prefix:
            # Avoid double slashes.
            return self.prefix.rstrip("/") + "/" + key.lstrip("/")
        return key

    def _emit(self, event: str, **fields: Any) -> None:
        if self.audit is None:
            return
        try:
            self.audit.emit(event, **fields)
        except Exception:  # noqa: BLE001
            pass

    # --- public API ---

    def push(self, bundle_path: Path | str, *, dest_key: str | None = None) -> dict[str, Any]:
        """Upload a bundle to remote storage.

        Args:
            bundle_path: local path to the .tar.gz bundle
            dest_key: remote object key (default: basename of bundle_path)

        Returns:
            dict with keys: url, etag, bytes, sha256
        """
        bundle_path = Path(bundle_path)
        if not bundle_path.exists():
            raise FileNotFoundError(f"bundle not found: {bundle_path}")

        if dest_key is None:
            dest_key = bundle_path.name

        full_key = self._full_key(dest_key)
        sidecar_key = full_key + _SIDECAR_SUFFIX

        # Compute SHA-256 before uploading so we can write the sidecar.
        digest = _sha256_path(bundle_path)
        file_size = bundle_path.stat().st_size

        client = self._get_client()

        # Upload the bundle.
        with open(bundle_path, "rb") as fh:
            response = client.put_object(
                Bucket=self.bucket,
                Key=full_key,
                Body=fh,
                ContentType="application/gzip",
            )
        etag: str = (response.get("ETag") or "").strip('"')

        # Upload the sidecar (.sha256 file — plain hex digest + newline).
        sidecar_data = (digest + "\n").encode()
        client.put_object(
            Bucket=self.bucket,
            Key=sidecar_key,
            Body=sidecar_data,
            ContentType="text/plain",
        )

        # Build a public-style URL (works for all backends; not presigned).
        if self.endpoint_url:
            url = f"{self.endpoint_url.rstrip('/')}/{self.bucket}/{full_key}"
        else:
            url = f"https://{self.bucket}.s3.{self.region}.amazonaws.com/{full_key}"

        self._emit(
            "evidence.remote.push",
            engagement=bundle_path.stem.split("_")[0],
            bundle_sha256=digest,
            bucket=self.bucket,
            key=full_key,
            bytes=file_size,
        )

        return {
            "url": url,
            "etag": etag,
            "bytes": file_size,
            "sha256": digest,
        }

    def pull(self, src_key: str, *, dest_path: Path | str | None = None) -> Path:
        """Download a bundle and verify its integrity.

        The sidecar (.sha256) is fetched first.  The bundle bytes are then
        hashed locally and compared.  If they don't match the downloaded file
        is deleted and an exception is raised — a partial/corrupt download
        never reaches the operator's engagement directory.

        Args:
            src_key:   remote object key (without the prefix — it will be added)
            dest_path: local path to write the bundle to; defaults to cwd/<basename>

        Returns:
            Path to the verified bundle file
        """
        full_key = self._full_key(src_key)
        sidecar_key = full_key + _SIDECAR_SUFFIX

        if dest_path is None:
            dest_path = Path.cwd() / Path(src_key).name
        dest_path = Path(dest_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        client = self._get_client()

        # Fetch the sidecar before touching the bundle.
        try:
            sidecar_resp = client.get_object(Bucket=self.bucket, Key=sidecar_key)
            expected_digest = sidecar_resp["Body"].read().decode().strip()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"could not fetch sidecar {sidecar_key!r}: {exc}\n"
                "Bundle integrity cannot be verified; aborting download."
            ) from exc

        # Download the bundle.
        try:
            bundle_resp = client.get_object(Bucket=self.bucket, Key=full_key)
            bundle_data = bundle_resp["Body"].read()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"could not download bundle {full_key!r}: {exc}") from exc

        # Verify before writing — never write a bad file to disk.
        actual_digest = _sha256_bytes(bundle_data)
        verified = actual_digest == expected_digest

        if not verified:
            self._emit(
                "evidence.remote.pull",
                requested_key=src_key,
                bundle_sha256=actual_digest,
                verified=False,
                bucket=self.bucket,
            )
            raise ValueError(
                f"SHA-256 mismatch for {full_key!r}:\n"
                f"  sidecar says: {expected_digest}\n"
                f"  downloaded:   {actual_digest}\n"
                "File not written to disk."
            )

        # Write only after verification passes.
        dest_path.write_bytes(bundle_data)

        self._emit(
            "evidence.remote.pull",
            requested_key=src_key,
            bundle_sha256=actual_digest,
            verified=True,
            bucket=self.bucket,
        )
        return dest_path

    def list_remote(self, prefix: str = "") -> list[dict[str, Any]]:
        """List bundle objects at the configured prefix + optional sub-prefix.

        Returns a list of dicts:
            key           — object key (without the store prefix)
            size          — bytes
            last_modified — ISO-8601 string
            sha256        — hex digest if the .sha256 sidecar exists, else None
        """
        combined_prefix = self._full_key(prefix) if prefix else self.prefix
        client = self._get_client()

        paginator = client.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=self.bucket, Prefix=combined_prefix)

        all_objects: list[dict[str, Any]] = []
        try:
            for page in pages:
                for obj in page.get("Contents") or []:
                    key: str = obj["Key"]
                    # Skip sidecar files from listing results.
                    if key.endswith(_SIDECAR_SUFFIX):
                        continue
                    last_mod = obj.get("LastModified")
                    if hasattr(last_mod, "isoformat"):
                        last_mod = last_mod.isoformat()
                    all_objects.append({
                        "key": key,
                        "size": obj.get("Size", 0),
                        "last_modified": str(last_mod or ""),
                        "sha256": None,  # Populated below if sidecar present
                    })
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"list_objects failed: {exc}") from exc

        # Attempt to hydrate sha256 from sidecars (best-effort, no crash).
        sidecar_keys: set[str] = set()
        try:
            sidecar_pages = paginator.paginate(
                Bucket=self.bucket,
                Prefix=combined_prefix,
            )
            for page in sidecar_pages:
                for obj in page.get("Contents") or []:
                    if obj["Key"].endswith(_SIDECAR_SUFFIX):
                        sidecar_keys.add(obj["Key"])
        except Exception:  # noqa: BLE001
            pass

        for entry in all_objects:
            candidate = entry["key"] + _SIDECAR_SUFFIX
            if candidate in sidecar_keys:
                try:
                    resp = client.get_object(Bucket=self.bucket, Key=candidate)
                    entry["sha256"] = resp["Body"].read().decode().strip()
                except Exception:  # noqa: BLE001
                    pass

        self._emit(
            "evidence.remote.list",
            bucket=self.bucket,
            prefix=combined_prefix,
            count=len(all_objects),
        )
        return all_objects


__all__ = ["RemoteBundleStore"]
