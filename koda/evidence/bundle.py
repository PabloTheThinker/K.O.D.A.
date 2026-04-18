"""Engagement bundle export + offline verification.

Why:

  - At the end of an engagement the operator needs a single portable
    artifact to hand to the client (or legal). A tar.gz that contains
    every captured file plus a ``bundle.json`` and ``chain.txt`` is
    self-describing: anyone with Python stdlib can reverify it years
    later without reinstalling K.O.D.A.
  - ``verify_bundle`` deliberately avoids importing the live store —
    the whole point is to prove integrity from the bundle alone.
"""
from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .store import (
    Artifact,
    EvidenceStore,
    compute_chain_hash,
)

try:
    from koda import __version__ as _KODA_VERSION
except Exception:  # pragma: no cover
    _KODA_VERSION = "unknown"

_GENESIS = "0" * 64


@dataclass
class BundleReport:
    path: str
    artifact_count: int
    root_hash: str
    ok: bool
    warnings: list[str] = field(default_factory=list)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def export_bundle(store: EvidenceStore, engagement: str, out_path: Path | str) -> BundleReport:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    artifacts: list[Artifact] = store.query(engagement=engagement)
    warnings: list[str] = []
    rows: list[dict[str, Any]] = []
    chain_lines: list[str] = []
    root_hash = _GENESIS

    with tarfile.open(out_path, "w:gz") as tar:
        for a in artifacts:
            src = Path(a.path)
            if not src.exists():
                warnings.append(f"missing artifact on disk: {a.artifact_id}")
                continue
            arcname = f"artifacts/{a.artifact_id}{Path(a.path).suffix}"
            tar.add(src, arcname=arcname)
            meta = src.with_suffix(src.suffix + "")  # placeholder, replaced below
            sidecar = src.parent / f"{a.artifact_id}.meta.json"
            if sidecar.exists():
                tar.add(sidecar, arcname=f"artifacts/{a.artifact_id}.meta.json")
            else:
                warnings.append(f"missing sidecar: {a.artifact_id}")
            rows.append(a.to_row())
            chain_lines.append(f"{a.artifact_id}  {a.sha256}  {a.prev_hash}  {a.chain_hash}")
            root_hash = a.chain_hash

        bundle_meta = {
            "engagement": engagement,
            "created_at": time.time(),
            "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            "artifact_count": len(rows),
            "root_hash": root_hash,
            "koda_version": _KODA_VERSION,
            "artifacts": rows,
        }
        _add_bytes(tar, "bundle.json", json.dumps(bundle_meta, indent=2, sort_keys=True).encode())
        _add_bytes(tar, "chain.txt", ("\n".join(chain_lines) + "\n").encode())

    verification = store.verify_chain(engagement=engagement)
    ok = verification.ok and not warnings
    if not verification.ok:
        warnings.append(f"chain verification failed: {verification.reason}")

    return BundleReport(
        path=str(out_path),
        artifact_count=len(rows),
        root_hash=root_hash,
        ok=ok,
        warnings=warnings,
    )


def _add_bytes(tar: tarfile.TarFile, arcname: str, data: bytes) -> None:
    import io

    info = tarfile.TarInfo(name=arcname)
    info.size = len(data)
    info.mtime = int(time.time())
    info.mode = 0o400
    tar.addfile(info, io.BytesIO(data))


def verify_bundle(bundle_path: Path | str) -> BundleReport:
    bundle_path = Path(bundle_path)
    warnings: list[str] = []

    with tempfile.TemporaryDirectory(prefix="koda-bundle-") as tmp:
        tmp_root = Path(tmp)
        try:
            with tarfile.open(bundle_path, "r:gz") as tar:
                _safe_extract(tar, tmp_root)
        except (tarfile.TarError, OSError) as exc:
            return BundleReport(
                path=str(bundle_path),
                artifact_count=0,
                root_hash="",
                ok=False,
                warnings=[f"tar extract failed: {exc}"],
            )

        meta_path = tmp_root / "bundle.json"
        if not meta_path.exists():
            return BundleReport(
                path=str(bundle_path),
                artifact_count=0,
                root_hash="",
                ok=False,
                warnings=["bundle.json missing"],
            )
        try:
            meta = json.loads(meta_path.read_text())
        except json.JSONDecodeError as exc:
            return BundleReport(
                path=str(bundle_path),
                artifact_count=0,
                root_hash="",
                ok=False,
                warnings=[f"bundle.json invalid: {exc}"],
            )

        rows: list[dict[str, Any]] = list(meta.get("artifacts") or [])
        claimed_root = str(meta.get("root_hash") or "")

        prev = _GENESIS
        for row in rows:
            artifact_id = str(row.get("artifact_id") or "")
            sha_expected = str(row.get("sha256") or "")
            prev_hash = str(row.get("prev_hash") or "")
            chain_hash = str(row.get("chain_hash") or "")
            captured_at = float(row.get("captured_at") or 0.0)

            if prev_hash != prev:
                warnings.append(f"prev_hash mismatch at {artifact_id}")
                break

            recomputed = compute_chain_hash(prev_hash, sha_expected, artifact_id, captured_at)
            if recomputed != chain_hash:
                warnings.append(f"chain_hash mismatch at {artifact_id}")
                break

            # Recompute file sha.
            suffix = Path(row.get("path", "")).suffix or ".bin"
            candidate = tmp_root / "artifacts" / f"{artifact_id}{suffix}"
            if not candidate.exists():
                # Fall back: find any file starting with the artifact_id.
                matches = list((tmp_root / "artifacts").glob(f"{artifact_id}*"))
                artifact_files = [m for m in matches if not m.name.endswith(".meta.json")]
                if not artifact_files:
                    warnings.append(f"artifact file missing: {artifact_id}")
                    break
                candidate = artifact_files[0]
            actual_sha = _sha256_file(candidate)
            if actual_sha != sha_expected:
                warnings.append(f"sha256 mismatch at {artifact_id}")
                break

            prev = chain_hash

        actual_root = prev
        if rows and actual_root != claimed_root:
            warnings.append(
                f"root_hash mismatch: bundle claims {claimed_root[:12]}, recomputed {actual_root[:12]}"
            )

    return BundleReport(
        path=str(bundle_path),
        artifact_count=len(rows),
        root_hash=claimed_root,
        ok=not warnings,
        warnings=warnings,
    )


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Defend against path traversal before extracting untrusted tars."""
    base = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(base)):
            raise tarfile.TarError(f"unsafe path in bundle: {member.name}")
    tar.extractall(dest)


__all__ = ["BundleReport", "export_bundle", "verify_bundle"]
