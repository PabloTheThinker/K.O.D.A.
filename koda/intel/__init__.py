"""Threat intelligence — local SQLite cache of CVE/KEV/EPSS/CWE.

Queries never touch the network. Sync pulls fresh data from public feeds
and replaces rows atomically. Used by security/findings to enrich raw
scanner output with CVSS, exploitability, and known-exploited status.
"""
from .store import (
    CVEInfo,
    CWEInfo,
    EnrichmentBundle,
    EPSSInfo,
    Freshness,
    KEVInfo,
    NullThreatIntel,
    ThreatIntel,
    default_intel_path,
)

__all__ = [
    "CVEInfo",
    "CWEInfo",
    "EPSSInfo",
    "EnrichmentBundle",
    "Freshness",
    "KEVInfo",
    "NullThreatIntel",
    "ThreatIntel",
    "default_intel_path",
]
