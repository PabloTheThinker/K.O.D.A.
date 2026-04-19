"""Incident-response playbook runner.

Implements a NIST SP 800-61r2-shaped playbook model. A playbook is an
ordered set of ``IRStep`` entries across six phases. Each step is an
executable-adjacent checklist — it names an action verb, a short set of
sub-items a human or agent walks through, and the internal Koda tools
the step expects to use.

This module stores only the playbook data; the actual tool dispatch
lives in Phase 3/4 tool handlers keyed on ``IRStep.tools``.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IRPhase(str, Enum):
    PREP = "preparation"
    IDENT = "identification"
    CONTAIN = "containment"
    ERADICATE = "eradication"
    RECOVER = "recovery"
    LESSONS = "lessons"


@dataclass(frozen=True)
class IRStep:
    """A single step in an IR playbook."""
    phase: IRPhase
    order: int
    action: str
    checklist: tuple[str, ...]
    tools: tuple[str, ...]


@dataclass(frozen=True)
class IRPlaybook:
    """A scenario-specific IR playbook."""
    id: str
    name: str
    scenario: str
    attack_techniques: tuple[str, ...]
    steps: tuple[IRStep, ...]


# ---------------------------------------------------------------------------
# Ransomware
# ---------------------------------------------------------------------------

PLAYBOOK_RANSOMWARE = IRPlaybook(
    id="pb-ransomware-001",
    name="Ransomware response",
    scenario="ransomware",
    attack_techniques=("T1486", "T1059", "T1021", "T1003", "T1053"),
    steps=(
        IRStep(
            phase=IRPhase.PREP,
            order=1,
            action="verify backup integrity for likely targets",
            checklist=(
                "list crown-jewel hosts",
                "confirm last successful backup per host",
                "test-restore one random sample to an isolated host",
                "record backup hashes in the case file",
            ),
            tools=("ir.timeline",),
        ),
        IRStep(
            phase=IRPhase.PREP,
            order=2,
            action="stage clean IR workstation and credentials",
            checklist=(
                "pull out-of-band creds from the vault",
                "verify EDR console access",
                "open the case file and start the timeline",
            ),
            tools=("ir.timeline",),
        ),
        IRStep(
            phase=IRPhase.IDENT,
            order=3,
            action="confirm ransomware event and scope hosts",
            checklist=(
                "collect ransom note filename and content hash",
                "query EDR for the encryption binary across the fleet",
                "list hosts with encrypted file extensions or new .locked/.encrypted files",
                "tag each hit with T1486",
            ),
            tools=("log.query", "detect.yara", "ir.timeline"),
        ),
        IRStep(
            phase=IRPhase.IDENT,
            order=4,
            action="identify initial-access vector",
            checklist=(
                "pull first-seen telemetry for the binary",
                "correlate with phishing, RDP exposure, or vuln exploit logs",
                "name the T1566/T1190/T1078 technique that applies",
            ),
            tools=("log.query", "ir.timeline"),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=5,
            action="isolate compromised host from network",
            checklist=(
                "disable wired port at the switch",
                "disable wifi radio on the host",
                "record MAC and last-seen IP for the timeline",
                "verify isolation with ping from a peer",
            ),
            tools=("ir.contain", "log.query"),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=6,
            action="disable compromised accounts",
            checklist=(
                "list accounts seen on compromised hosts",
                "disable (do not delete) in the directory",
                "kill active sessions",
                "record disable times in the timeline",
            ),
            tools=("ir.contain", "log.query"),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=7,
            action="block C2 indicators at the perimeter",
            checklist=(
                "extract C2 IPs and domains from EDR telemetry",
                "push blocks to firewall and DNS sinkhole",
                "monitor for continued callbacks",
            ),
            tools=("ir.contain", "log.query"),
        ),
        IRStep(
            phase=IRPhase.ERADICATE,
            order=8,
            action="remove ransomware binary and persistence",
            checklist=(
                "remove identified scheduled tasks / cron entries (T1053)",
                "remove autostart registry entries or systemd units (T1547)",
                "delete the encryption binary and stage copies for forensics",
                "hash every removed artifact",
            ),
            tools=("ir.eradicate", "forensics.artifacts"),
        ),
        IRStep(
            phase=IRPhase.ERADICATE,
            order=9,
            action="rotate credentials touched by the incident",
            checklist=(
                "rotate all service accounts seen on compromised hosts",
                "force-rotate admin credentials regardless of observation",
                "rotate kerberos krbtgt twice",
                "invalidate active tokens",
            ),
            tools=("ir.eradicate",),
        ),
        IRStep(
            phase=IRPhase.RECOVER,
            order=10,
            action="rebuild from clean backups",
            checklist=(
                "verify backup hashes against pre-incident values",
                "rebuild host from a known-good image",
                "restore data from the verified backup",
                "re-join to the domain with new credentials",
            ),
            tools=("ir.recover",),
        ),
        IRStep(
            phase=IRPhase.RECOVER,
            order=11,
            action="monitor restored hosts for recurrence",
            checklist=(
                "enable enhanced EDR collection for 14 days",
                "add a Sigma rule for the specific ransomware family",
                "watch for lateral-movement attempts from restored hosts",
            ),
            tools=("ir.recover", "log.query", "detect.sigma"),
        ),
        IRStep(
            phase=IRPhase.LESSONS,
            order=12,
            action="run post-incident review",
            checklist=(
                "build the final timeline",
                "name the gap that let the adversary in",
                "file at least one new detection rule",
                "update the runbook with what worked and what didn't",
            ),
            tools=("ir.timeline",),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Phishing
# ---------------------------------------------------------------------------

PLAYBOOK_PHISHING = IRPlaybook(
    id="pb-phishing-001",
    name="Phishing response",
    scenario="phishing",
    attack_techniques=("T1566", "T1078", "T1059", "T1071"),
    steps=(
        IRStep(
            phase=IRPhase.PREP,
            order=1,
            action="confirm phishing ingest pipeline is healthy",
            checklist=(
                "verify the report-phish mailbox is reachable",
                "confirm the email gateway is sending headers to the SIEM",
            ),
            tools=("ir.timeline",),
        ),
        IRStep(
            phase=IRPhase.IDENT,
            order=2,
            action="triage the reported email",
            checklist=(
                "pull full headers and attachments",
                "detonate any attachment in the sandbox",
                "extract links and classify against URL intel",
                "tag T1566.001 (attachment) or T1566.002 (link)",
            ),
            tools=("log.query", "detect.yara"),
        ),
        IRStep(
            phase=IRPhase.IDENT,
            order=3,
            action="identify who else received the message",
            checklist=(
                "query gateway logs for the sender and subject",
                "list all recipients and whether they interacted",
                "tag interactions: open / click / credential submit",
            ),
            tools=("log.query", "ir.timeline"),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=4,
            action="purge remaining copies from mailboxes",
            checklist=(
                "issue bulk mail-delete across affected mailboxes",
                "confirm with a spot-check query",
            ),
            tools=("ir.contain",),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=5,
            action="block sender and infrastructure",
            checklist=(
                "block sender domain at the gateway",
                "sinkhole or block linked domains",
                "update URL intel with the IOCs",
            ),
            tools=("ir.contain",),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=6,
            action="disable credentials of users who submitted",
            checklist=(
                "list submit events from the gateway",
                "force password reset and revoke active sessions",
                "enable MFA enforcement if not already",
            ),
            tools=("ir.contain",),
        ),
        IRStep(
            phase=IRPhase.ERADICATE,
            order=7,
            action="scan endpoints of clickers for follow-on payloads",
            checklist=(
                "EDR full scan on each clicker host",
                "check for new scheduled tasks (T1053)",
                "check for new outbound connections (T1071)",
            ),
            tools=("ir.eradicate", "detect.yara", "log.query"),
        ),
        IRStep(
            phase=IRPhase.RECOVER,
            order=8,
            action="return affected users to service",
            checklist=(
                "verify password reset completion",
                "confirm MFA enrollment",
                "release the account from the watchlist after 14 days",
            ),
            tools=("ir.recover",),
        ),
        IRStep(
            phase=IRPhase.LESSONS,
            order=9,
            action="deliver targeted user training",
            checklist=(
                "send a non-punitive debrief to clickers",
                "add the lure pattern to the awareness curriculum",
                "file a detection rule for the lure family",
            ),
            tools=("ir.timeline", "detect.sigma"),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Data exfiltration
# ---------------------------------------------------------------------------

PLAYBOOK_DATA_EXFIL = IRPlaybook(
    id="pb-dataexfil-001",
    name="Data exfiltration response",
    scenario="data_exfil",
    attack_techniques=("T1041", "T1048", "T1567", "T1003", "T1078"),
    steps=(
        IRStep(
            phase=IRPhase.PREP,
            order=1,
            action="confirm DLP and netflow collection is healthy",
            checklist=(
                "verify egress netflow is arriving in the SIEM",
                "verify DLP rules are active",
            ),
            tools=("ir.timeline",),
        ),
        IRStep(
            phase=IRPhase.IDENT,
            order=2,
            action="quantify the suspected exfil",
            checklist=(
                "pull netflow for the source host over the incident window",
                "identify destination IPs and byte counts",
                "tag technique: T1041 (C2), T1048 (alt proto), or T1567 (web service)",
            ),
            tools=("log.query", "ir.timeline"),
        ),
        IRStep(
            phase=IRPhase.IDENT,
            order=3,
            action="determine what data was taken",
            checklist=(
                "correlate file-access logs on the source host",
                "classify data sensitivity (PII, PHI, source, secrets)",
                "build a preliminary impact estimate",
            ),
            tools=("log.query", "forensics.artifacts"),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=4,
            action="cut the egress channel",
            checklist=(
                "block destination at the egress firewall",
                "sinkhole any DNS used for exfil",
                "confirm no callbacks in the next 15 minutes",
            ),
            tools=("ir.contain", "log.query"),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=5,
            action="disable the compromised account",
            checklist=(
                "disable in the directory",
                "revoke all active tokens and API keys",
                "rotate any shared service credentials",
            ),
            tools=("ir.contain",),
        ),
        IRStep(
            phase=IRPhase.ERADICATE,
            order=6,
            action="remove the exfil tooling",
            checklist=(
                "locate and hash the exfil binary or script",
                "remove scheduled tasks / cron entries that invoke it",
                "rotate any credentials exposed on the host",
            ),
            tools=("ir.eradicate", "forensics.artifacts"),
        ),
        IRStep(
            phase=IRPhase.RECOVER,
            order=7,
            action="restore service on the source host",
            checklist=(
                "rebuild from image if the host was privileged",
                "re-grant access only after credential rotation",
                "enable enhanced monitoring for 30 days",
            ),
            tools=("ir.recover",),
        ),
        IRStep(
            phase=IRPhase.LESSONS,
            order=8,
            action="notify legal and file the incident",
            checklist=(
                "brief legal on data classes and volumes",
                "produce the disclosure timeline for regulators",
                "add a DLP rule for the observed exfil signature",
            ),
            tools=("ir.timeline",),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Web application compromise
# ---------------------------------------------------------------------------

PLAYBOOK_WEBAPP = IRPlaybook(
    id="pb-webapp-001",
    name="Web application compromise response",
    scenario="web_app_compromise",
    attack_techniques=("T1190", "T1505", "T1059", "T1071", "T1078"),
    steps=(
        IRStep(
            phase=IRPhase.PREP,
            order=1,
            action="verify web-tier telemetry",
            checklist=(
                "confirm access logs, WAF logs, and app logs are shipping",
                "confirm a clean deploy snapshot exists",
            ),
            tools=("ir.timeline",),
        ),
        IRStep(
            phase=IRPhase.IDENT,
            order=2,
            action="confirm compromise vector",
            checklist=(
                "review WAF logs for exploit signatures (SQLi, RCE, deserialization)",
                "correlate with the alert that fired",
                "tag T1190 and the relevant CVE if known",
            ),
            tools=("log.query", "ir.timeline"),
        ),
        IRStep(
            phase=IRPhase.IDENT,
            order=3,
            action="hunt for webshells and implants",
            checklist=(
                "scan the webroot with YARA webshell rules",
                "diff the webroot against the known-good deploy",
                "list any files modified after the deploy timestamp",
            ),
            tools=("detect.yara", "forensics.artifacts", "log.query"),
        ),
        IRStep(
            phase=IRPhase.CONTAIN,
            order=4,
            action="cut the attacker's access",
            checklist=(
                "WAF-block source IPs and observed payload patterns",
                "rotate any API keys exposed in the app env",
                "revoke active sessions if session hijack is suspected",
            ),
            tools=("ir.contain", "log.query"),
        ),
        IRStep(
            phase=IRPhase.ERADICATE,
            order=5,
            action="remove implants and patch the vuln",
            checklist=(
                "delete webshells (stage copies first)",
                "apply the vendor patch or code fix for the exploited bug",
                "rebuild the application image from source",
            ),
            tools=("ir.eradicate", "harden.patch"),
        ),
        IRStep(
            phase=IRPhase.RECOVER,
            order=6,
            action="redeploy from clean source",
            checklist=(
                "deploy the patched image",
                "run smoke tests",
                "re-enable traffic in stages",
            ),
            tools=("ir.recover",),
        ),
        IRStep(
            phase=IRPhase.LESSONS,
            order=7,
            action="post-incident hardening",
            checklist=(
                "file a WAF rule for the payload family",
                "add the CVE to the patch-watch list",
                "file the timeline and the root cause",
            ),
            tools=("ir.timeline", "harden.patch"),
        ),
    ),
)


ALL_PLAYBOOKS: tuple[IRPlaybook, ...] = (
    PLAYBOOK_RANSOMWARE,
    PLAYBOOK_PHISHING,
    PLAYBOOK_DATA_EXFIL,
    PLAYBOOK_WEBAPP,
)


def playbook_for(scenario: str) -> IRPlaybook | None:
    """Return the playbook whose ``scenario`` matches (case-insensitive)."""
    if not scenario:
        return None
    key = scenario.strip().lower()
    for pb in ALL_PLAYBOOKS:
        if pb.scenario.lower() == key:
            return pb
    return None


__all__ = [
    "IRPhase",
    "IRStep",
    "IRPlaybook",
    "PLAYBOOK_RANSOMWARE",
    "PLAYBOOK_PHISHING",
    "PLAYBOOK_DATA_EXFIL",
    "PLAYBOOK_WEBAPP",
    "ALL_PLAYBOOKS",
    "playbook_for",
]
