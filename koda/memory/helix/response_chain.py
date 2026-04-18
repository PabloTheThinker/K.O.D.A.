"""Response Chain — Detect, Confirm, Contain, Report.

When a hot finding enters Helix, the Response Chain fires before
memory consolidation. Proactive layer — acts before remembering.

Pipeline: VERIFY → ENRICH → CONTAIN → REPORT

Each stage runs with a timeout. Failed hooks don't block the pipeline.
SQLite-backed incident persistence.
"""
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .storage import HelixDB

logger = logging.getLogger("helix.response")

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="helix-rc")
HOOK_TIMEOUT_SECONDS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Response Stages ────────────────────────────────────────────────

class Stage(str, Enum):
    VERIFY = "verify"
    ENRICH = "enrich"
    CONTAIN = "contain"
    REPORT = "report"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    ESCALATE = "escalate"


# ── Enrichment Data ────────────────────────────────────────────────

@dataclass
class ThreatEnrichment:
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    epss_score: float = 0.0
    cisa_kev: bool = False
    cvss_score: float = 0.0
    known_exploits: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    advisory: str = ""

    @property
    def threat_level(self) -> str:
        if self.cisa_kev or self.epss_score > 0.7 or self.cvss_score >= 9.0:
            return "critical"
        if self.epss_score > 0.3 or self.cvss_score >= 7.0:
            return "high"
        if self.cvss_score >= 4.0:
            return "medium"
        return "low"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["threat_level"] = self.threat_level
        return d


# ── Containment Action ─────────────────────────────────────────────

@dataclass
class ContainmentAction:
    action_type: str
    target: str
    executed: bool = False
    requires_approval: bool = False
    result: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = _now().isoformat()

    def to_dict(self) -> dict:
        return asdict(self)


# ── Incident Record ────────────────────────────────────────────────

@dataclass
class Incident:
    id: str
    episode_id: str
    finding: str
    severity: str
    detected_at: str = ""
    verdict: str = ""
    verified_at: str = ""
    enrichment: Optional[ThreatEnrichment] = None
    enriched_at: str = ""
    containment_actions: list[ContainmentAction] = field(default_factory=list)
    contained_at: str = ""
    reported: bool = False
    reported_at: str = ""
    report_channels: list[str] = field(default_factory=list)
    total_response_ms: int = 0
    status: str = "detected"
    closed_reason: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = _now().isoformat()

    def to_storage_dict(self) -> dict:
        d = {
            "id": self.id,
            "episode_id": self.episode_id,
            "finding": self.finding,
            "severity": self.severity,
            "detected_at": self.detected_at,
            "verdict": self.verdict,
            "verified_at": self.verified_at,
            "enrichment": json.dumps(self.enrichment.to_dict()) if self.enrichment else "",
            "enriched_at": self.enriched_at,
            "containment_actions": json.dumps([a.to_dict() for a in self.containment_actions]),
            "contained_at": self.contained_at,
            "reported": int(self.reported),
            "reported_at": self.reported_at,
            "report_channels": json.dumps(self.report_channels),
            "total_response_ms": self.total_response_ms,
            "status": self.status,
            "closed_reason": self.closed_reason,
            "metadata": json.dumps(self.metadata),
        }
        return d

    @classmethod
    def from_storage_dict(cls, d: dict) -> Incident:
        enrichment = None
        enr_raw = d.get("enrichment", "")
        if enr_raw and enr_raw != "":
            try:
                ed = json.loads(enr_raw)
                ed.pop("threat_level", None)
                enrichment = ThreatEnrichment(**ed)
            except Exception:
                pass

        actions_raw = d.get("containment_actions", "[]")
        try:
            actions = [ContainmentAction(**a) for a in json.loads(actions_raw)]
        except Exception:
            actions = []

        channels_raw = d.get("report_channels", "[]")
        try:
            channels = json.loads(channels_raw)
        except Exception:
            channels = []

        meta_raw = d.get("metadata", "{}")
        try:
            metadata = json.loads(meta_raw)
        except Exception:
            metadata = {}

        return cls(
            id=d["id"],
            episode_id=d["episode_id"],
            finding=d["finding"],
            severity=d["severity"],
            detected_at=d.get("detected_at", ""),
            verdict=d.get("verdict", ""),
            verified_at=d.get("verified_at", ""),
            enrichment=enrichment,
            enriched_at=d.get("enriched_at", ""),
            containment_actions=actions,
            contained_at=d.get("contained_at", ""),
            reported=bool(d.get("reported", 0)),
            reported_at=d.get("reported_at", ""),
            report_channels=channels,
            total_response_ms=d.get("total_response_ms", 0),
            status=d.get("status", "detected"),
            closed_reason=d.get("closed_reason", ""),
            metadata=metadata,
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.enrichment:
            d["enrichment"] = self.enrichment.to_dict()
        d["containment_actions"] = [a.to_dict() for a in self.containment_actions]
        return d


# ── Hook Types ─────────────────────────────────────────────────────

VerifyHook = Callable[[str, str, dict], Verdict]
EnrichHook = Callable[[str, dict], ThreatEnrichment]
ContainHook = Callable[[str, ThreatEnrichment, str], list[ContainmentAction]]
ReportHook = Callable[["Incident"], list[str]]


def _run_with_timeout(fn, args, timeout: float, stage: str):
    """Run a hook function with a timeout via thread pool."""
    future = _executor.submit(fn, *args)
    try:
        return future.result(timeout=timeout)
    except FutureTimeout:
        logger.error("%s hook timed out after %.1fs", stage, timeout)
        future.cancel()
        return None
    except Exception as e:
        logger.error("%s hook failed: %s", stage, e)
        return None


# ── Response Chain ─────────────────────────────────────────────────

class ResponseChain:
    """Proactive response pipeline with async hooks and SQLite persistence."""

    AUTO_CONTAIN_EPSS_THRESHOLD = 0.5
    AUTO_CONTAIN_CVSS_THRESHOLD = 8.0

    def __init__(
        self,
        db: HelixDB,
        verify_hook: Optional[VerifyHook] = None,
        enrich_hook: Optional[EnrichHook] = None,
        contain_hook: Optional[ContainHook] = None,
        report_hook: Optional[ReportHook] = None,
        auto_contain: bool = False,
        hook_timeout: float = HOOK_TIMEOUT_SECONDS,
    ):
        self.db = db
        self._verify = verify_hook
        self._enrich = enrich_hook
        self._contain = contain_hook
        self._report = report_hook
        self._auto_contain = auto_contain
        self._hook_timeout = hook_timeout

    def respond(
        self,
        incident_id: str,
        episode_id: str,
        finding: str,
        severity: str,
        metadata: dict | None = None,
    ) -> Incident:
        start_ms = time.monotonic_ns() // 1_000_000
        meta = metadata or {}

        incident = Incident(
            id=incident_id,
            episode_id=episode_id,
            finding=finding,
            severity=severity,
            metadata=meta,
        )

        incident = self._run_verify(incident, meta)
        if incident.verdict == Verdict.FALSE_POSITIVE.value:
            incident.status = "closed"
            incident.closed_reason = "false_positive"
            self._finalize(incident, start_ms)
            return incident

        incident = self._run_enrich(incident, meta)

        if incident.verdict in (Verdict.CONFIRMED.value, Verdict.ESCALATE.value):
            incident = self._run_contain(incident)

        incident = self._run_report(incident)

        self._finalize(incident, start_ms)
        return incident

    def _run_verify(self, incident: Incident, meta: dict) -> Incident:
        if self._verify:
            result = _run_with_timeout(
                self._verify,
                (incident.finding, incident.severity, meta),
                self._hook_timeout, "Verify",
            )
            if result is not None:
                incident.verdict = result.value
                incident.verified_at = _now().isoformat()
                incident.status = "verified"
            else:
                incident.verdict = Verdict.ESCALATE.value
        else:
            incident.verdict = (
                Verdict.CONFIRMED.value if incident.severity == "critical"
                else Verdict.ESCALATE.value
            )
            incident.status = "verified"
        return incident

    def _run_enrich(self, incident: Incident, meta: dict) -> Incident:
        if self._enrich:
            result = _run_with_timeout(
                self._enrich,
                (incident.finding, meta),
                self._hook_timeout, "Enrich",
            )
            if result is not None:
                incident.enrichment = result
                incident.enriched_at = _now().isoformat()
                incident.status = "enriched"
                if result.threat_level == "critical" and incident.severity != "critical":
                    incident.severity = "critical"
        return incident

    def _run_contain(self, incident: Incident) -> Incident:
        if not self._contain:
            logger.warning("No containment hook — escalating [%s]", incident.id[:8])
            return incident

        enrichment = incident.enrichment or ThreatEnrichment()

        can_auto = self._auto_contain and (
            enrichment.cisa_kev
            or enrichment.epss_score >= self.AUTO_CONTAIN_EPSS_THRESHOLD
            or enrichment.cvss_score >= self.AUTO_CONTAIN_CVSS_THRESHOLD
            or incident.severity == "critical"
        )

        result = _run_with_timeout(
            self._contain,
            (incident.finding, enrichment, incident.severity),
            self._hook_timeout, "Contain",
        )

        if result is not None:
            for action in result:
                if can_auto or not action.requires_approval:
                    action.executed = True
                incident.containment_actions.append(action)
            incident.contained_at = _now().isoformat()
            incident.status = "contained"

        return incident

    def _run_report(self, incident: Incident) -> Incident:
        if self._report:
            result = _run_with_timeout(
                self._report,
                (incident,),
                self._hook_timeout, "Report",
            )
            if result is not None:
                incident.reported = True
                incident.reported_at = _now().isoformat()
                incident.report_channels = result
                incident.status = "reported"
        else:
            logger.warning(
                "INCIDENT [%s] %s: %s (verdict=%s, severity=%s) — no report hook configured",
                incident.id[:8], incident.severity.upper(),
                incident.finding[:80], incident.verdict, incident.severity,
            )
        return incident

    def _finalize(self, incident: Incident, start_ms: int) -> None:
        elapsed = (time.monotonic_ns() // 1_000_000) - start_ms
        incident.total_response_ms = elapsed
        self.db.update_incident(incident.to_storage_dict())

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        row = self.db.get_incident(incident_id)
        return Incident.from_storage_dict(row) if row else None

    def active_incidents(self) -> list[Incident]:
        rows = self.db.active_incidents()
        return [Incident.from_storage_dict(r) for r in rows]

    def close_incident(self, incident_id: str, reason: str) -> bool:
        row = self.db.get_incident(incident_id)
        if not row:
            return False
        inc = Incident.from_storage_dict(row)
        inc.status = "closed"
        inc.closed_reason = reason
        self.db.update_incident(inc.to_storage_dict())
        return True

    def stats(self) -> dict:
        return self.db.incident_stats()
