"""Evidence store — tamper-evident artifacts with exportable case bundles."""
from .bundle import BundleReport, export_bundle, verify_bundle
from .store import (
    Artifact,
    ChainVerification,
    EvidenceStore,
    NullEvidenceStore,
    compute_chain_hash,
    default_evidence_path,
)

__all__ = [
    "Artifact",
    "BundleReport",
    "ChainVerification",
    "EvidenceStore",
    "NullEvidenceStore",
    "compute_chain_hash",
    "default_evidence_path",
    "export_bundle",
    "verify_bundle",
]
