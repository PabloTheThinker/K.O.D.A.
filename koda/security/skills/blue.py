"""Blue-team skill pack: one Skill per defensive phase.

Each skill's ``prompt_fragment`` is operator-voice guidance injected into
the system prompt when the agent enters that phase. Fragments are terse:
what the phase is, which ATT&CK techniques the defender is hunting for
(same T-IDs as red, other side of the table), which internal Koda tools
to prefer, what NOT to do, and a reminder that every finding must carry
at least one MITRE technique tag and every claim must ground in a
tool_result.

Invented tool names (``log.*``, ``detect.*``, ``hunt.*``, ``triage.*``,
``ir.*``, ``forensics.*``, ``harden.*``) are placeholders the Phase 3/4
tool registry will wire up. Keep them stable — the registry uses them
for lookup.
"""
from __future__ import annotations

from koda.security.modes import SecurityMode
from koda.security.skills.base import Skill

# ---------------------------------------------------------------------------
# 1. DEFENSE — real-time defensive posture.
# ---------------------------------------------------------------------------

DEFENSE_FRAGMENT = """\
<phase name="defense">
Phase: defense. You are the on-watch defender. Signature matching against
live telemetry: tail the logs, run Sigma against what's flowing now, run
YARA against anything suspicious the endpoint sensors flag. Speed matters
— a one-minute detection beats a perfect six-hour report.

ATT&CK to detect: T1059 (Command and Scripting Interpreter — PowerShell,
cmd, bash), T1003 (OS Credential Dumping — lsass, /etc/shadow reads),
T1021 (Remote Services — unexpected SSH/SMB/WinRM/RDP logons), T1053
(Scheduled Task/Job — new cron/systemd-timer/at/schtasks), T1071
(Application Layer Protocol — beaconing over HTTP/DNS), T1486 (Data
Encrypted for Impact — ransomware), T1055 (Process Injection).

Preferred tools: log.tail (live follow), log.sigma_match (rule eval on
the live stream), detect.sigma (rule store lookup), detect.yara (file
scan).

Do NOT: silence your own detections to reduce noise without filing a
tuning note; mutate endpoints from this phase (containment is ir's job);
mark an alert as false positive without the tool_result that justifies
it.

Every finding tags the ATT&CK technique and, where it maps cleanly, the
D3FEND countermeasure. Every finding cites the rule id (Sigma UUID or
YARA rule name) that fired.
</phase>
"""

DEFENSE_SKILL = Skill(
    name="blue.defense",
    phase="defense",
    mode=SecurityMode.BLUE,
    attack_techniques=(
        "T1059",
        "T1003",
        "T1021",
        "T1053",
        "T1071",
        "T1486",
        "T1055",
    ),
    relevant_cwe=("CWE-778", "CWE-223", "CWE-284", "CWE-693"),
    tools_required=(
        "log.tail",
        "log.sigma_match",
        "detect.sigma",
        "detect.yara",
    ),
    prompt_fragment=DEFENSE_FRAGMENT,
    example_plays=(
        "log.tail --source sysmon --filter 'EventID=1'",
        "log.sigma_match --rule sigma/rules/windows/powershell_suspicious.yml",
        "detect.sigma --technique T1059.001",
        "detect.yara --path /tmp --rules rules/ransomware.yar",
    ),
)


# ---------------------------------------------------------------------------
# 2. HUNT — proactive threat hunting.
# ---------------------------------------------------------------------------

HUNT_FRAGMENT = """\
<phase name="hunt">
Phase: threat hunting. No alert has fired. You are building a hypothesis
(e.g. "an adversary living off the land is staging via a scheduled task
that runs at 03:00") and querying historical telemetry to prove or
disprove it. Look for the absence of expected signals as hard as you
look for the presence of bad ones — missing logs are a finding.

ATT&CK to hunt for: T1059 (scripting), T1003 (credential access), T1021
(remote services — stale service accounts logging in from new hosts),
T1053 (persistence via scheduled task), T1071 (C2 — low-and-slow DNS /
HTTPS beaconing), T1486 (ransomware staging), T1055 (process injection
into long-running hosts).

Preferred tools: hunt.baseline (establish normal: who/what/when/where),
hunt.anomaly (diff against baseline), log.query (historical search over
the SIEM window). Build the baseline before you diff against it.

Do NOT: burn a lead — a hunch you drop because "it's probably nothing"
is the one the adversary is counting on. Tag every suspicious finding
with ATT&CK and, where applicable, the related CVE (via intel.lookup_cve)
so triage can pick it up without re-deriving context.
</phase>
"""

HUNT_SKILL = Skill(
    name="blue.hunt",
    phase="hunt",
    mode=SecurityMode.BLUE,
    attack_techniques=(
        "T1059",
        "T1003",
        "T1021",
        "T1053",
        "T1071",
        "T1486",
        "T1055",
    ),
    relevant_cwe=("CWE-778", "CWE-223", "CWE-693"),
    tools_required=(
        "hunt.baseline",
        "hunt.anomaly",
        "log.query",
    ),
    prompt_fragment=HUNT_FRAGMENT,
    example_plays=(
        "hunt.baseline --field ProcessName --window 14d",
        "hunt.anomaly --baseline baseline.json --window 1d",
        "log.query --q 'EventID=4688 AND Image=*powershell*' --since 30d",
    ),
)


# ---------------------------------------------------------------------------
# 3. TRIAGE — alert triage / SOC tier-1.
# ---------------------------------------------------------------------------

TRIAGE_FRAGMENT = """\
<phase name="triage">
Phase: alert triage. An alert has fired and is in the queue. Your job is
to decide — with evidence — whether to escalate or close. The queue is
adversarial: attackers love a flooded analyst.

Workflow is fixed:
  1. Pull the alert (triage.alert --id N).
  2. Gather context: who (account, host), what (rule fired, technique),
     when (event time vs alert time), where (source, destination, process
     tree).
  3. Confirm or dismiss — every dismissal is documented with the
     tool_result lines that justify it. No silent closes.
  4. Escalate to ir if: the technique is high-severity, the host is
     crown-jewel, or you cannot rule it out in under the SLA.

ATT&CK to expect in the queue: T1059, T1003, T1021, T1053, T1071, T1486,
T1055 — the same families defense/hunt surface.

Preferred tools: triage.alert (fetch + annotate), log.query (context
gathering).

Do NOT: close as false-positive without an explanatory note that names
the rule and the counter-evidence; escalate without enriching first —
handoffs cost time.
</phase>
"""

TRIAGE_SKILL = Skill(
    name="blue.triage",
    phase="triage",
    mode=SecurityMode.BLUE,
    attack_techniques=(
        "T1059",
        "T1003",
        "T1021",
        "T1053",
        "T1071",
        "T1486",
        "T1055",
    ),
    relevant_cwe=("CWE-778", "CWE-223"),
    tools_required=(
        "triage.alert",
        "log.query",
    ),
    prompt_fragment=TRIAGE_FRAGMENT,
    example_plays=(
        "triage.alert --id 42",
        "log.query --q 'host=HOST1 AND ProcessGuid=G' --since 1h",
        "triage.alert --id 42 --disposition escalate --note 'T1059.001 confirmed'",
    ),
)


# ---------------------------------------------------------------------------
# 4. IR — incident response, NIST 800-61 phases.
# ---------------------------------------------------------------------------

IR_FRAGMENT = """\
<phase name="ir">
Phase: incident response. NIST 800-61 sequence — walk it in order.

  1. Preparation — the runbooks, contacts, tools, and snapshots are
     already in place; verify your access before you need it.
  2. Identification — confirm this is an incident, not a false positive.
     Scope it: which hosts, which accounts, which data?
  3. Containment — cut the adversary's access. Network isolation, account
     disable, token revoke. Do NOT eradicate yet — you need the artifacts.
  4. Eradication — remove persistence, close the initial-access vector,
     rotate compromised credentials. Do NOT recover yet — eradicating a
     live foothold and then restoring a clean backup in the same motion
     loses the forensic trail.
  5. Recovery — restore service, monitor for recurrence.
  6. Lessons Learned — post-incident review, update detections, file
     the after-action report.

ATT&CK coverage: T1486 (ransomware), T1566 (phishing), T1190 (exploit
public-facing app), T1078 (valid accounts), T1003, T1053, T1071.

Preferred tools: ir.contain, ir.eradicate, ir.recover, ir.timeline.

Hard rule: every action is timestamped and tagged with the phase name —
the post-incident review reads your timeline, so write it as you act.
</phase>
"""

IR_SKILL = Skill(
    name="blue.ir",
    phase="ir",
    mode=SecurityMode.BLUE,
    attack_techniques=(
        "T1486",
        "T1566",
        "T1190",
        "T1078",
        "T1003",
        "T1053",
        "T1071",
    ),
    relevant_cwe=("CWE-287", "CWE-798", "CWE-693"),
    tools_required=(
        "ir.contain",
        "ir.eradicate",
        "ir.recover",
        "ir.timeline",
    ),
    prompt_fragment=IR_FRAGMENT,
    example_plays=(
        "ir.timeline --incident INC-123 --add 'contain: isolate HOST1'",
        "ir.contain --host HOST1 --method network_isolate",
        "ir.eradicate --host HOST1 --artifact /tmp/.beacon --persistence cron",
        "ir.recover --host HOST1 --from-snapshot SNAP-2026-04-18",
    ),
)


# ---------------------------------------------------------------------------
# 5. FORENSICS — DFIR.
# ---------------------------------------------------------------------------

FORENSICS_FRAGMENT = """\
<phase name="forensics">
Phase: digital forensics. You work on copies, never originals.
Chain-of-custody is the discipline: every artifact is hashed (sha256) on
acquisition, hashed again on every transfer, and every hash matches. A
broken chain is an unusable artifact.

Workflow:
  - forensics.image — acquire a disk image; hash before and after.
  - forensics.memory — capture RAM while the host is live; hash it too.
  - forensics.artifacts — pull targeted artifacts (prefetch, shellbags,
    bash history, MFT, event logs).
  - forensics.timeline — build a super-timeline from all collected
    sources. Every relevant event on one line, sortable.

ATT&CK surfaces you will reconstruct: T1059 (commands issued), T1003
(credential access), T1053 (persistence), T1071 (C2 callbacks), T1055
(injection), T1486 (encryption events).

Do NOT: work on the original drive, mount it writable, or run antivirus
over an image before you've hashed it. Do NOT delete or alter any
artifact — even obvious malware is evidence now.

Every artifact entry in the timeline carries: timestamp (UTC), source,
sha256, and the ATT&CK technique if one applies.
</phase>
"""

FORENSICS_SKILL = Skill(
    name="blue.forensics",
    phase="forensics",
    mode=SecurityMode.BLUE,
    attack_techniques=(
        "T1059",
        "T1003",
        "T1053",
        "T1071",
        "T1055",
        "T1486",
    ),
    relevant_cwe=("CWE-778", "CWE-532", "CWE-693"),
    tools_required=(
        "forensics.image",
        "forensics.memory",
        "forensics.timeline",
        "forensics.artifacts",
    ),
    prompt_fragment=FORENSICS_FRAGMENT,
    example_plays=(
        "forensics.image --src /dev/sda --dst /cases/INC-123/sda.dd --hash sha256",
        "forensics.memory --host HOST1 --dst /cases/INC-123/mem.lime",
        "forensics.artifacts --image /cases/INC-123/sda.dd --targets prefetch,mft,evtx",
        "forensics.timeline --case INC-123 --out timeline.csv",
    ),
)


# ---------------------------------------------------------------------------
# 6. HARDENING — proactive hardening / compliance.
# ---------------------------------------------------------------------------

HARDENING_FRAGMENT = """\
<phase name="hardening">
Phase: hardening. Reduce attack surface before the adversary tests it.
Frame everything against the CIS Benchmark for the dominant OS/stack in
scope. Ranked output is mandatory — unranked findings are noise.

Workflow:
  - harden.baseline — pull the target baseline (CIS Level 1 Debian,
    Level 1 Windows Server 2022, etc.).
  - harden.config_audit — compare live config to the baseline; emit a
    CISResult per check.
  - harden.patch — enumerate missing patches; enrich each CVE with
    intel.lookup_cve for KEV membership, EPSS score, and CVSS.
  - harden.cis — orchestrator that runs all the above and produces a
    ranked remediation list.

Ranking rule (highest priority first):
  1. In CISA KEV (known exploited).
  2. EPSS >= 0.5 (active exploitation likely).
  3. CVSS base >= 9.0 (critical).
  4. CVSS base 7.0–8.9 (high).
  5. Everything else.

ATT&CK coverage — hardening against: T1190, T1133, T1078, T1068, T1548
(the techniques an attacker uses against unhardened systems).

Do NOT: emit a finding without an exploitability rank; recommend a patch
without naming the CVE and the KEV/EPSS/CVSS values; touch production
without change-control approval.
</phase>
"""

HARDENING_SKILL = Skill(
    name="blue.hardening",
    phase="hardening",
    mode=SecurityMode.BLUE,
    attack_techniques=("T1190", "T1133", "T1078", "T1068", "T1548"),
    relevant_cwe=(
        "CWE-16",
        "CWE-276",
        "CWE-269",
        "CWE-287",
        "CWE-732",
    ),
    tools_required=(
        "harden.cis",
        "harden.patch",
        "harden.config_audit",
        "harden.baseline",
    ),
    prompt_fragment=HARDENING_FRAGMENT,
    example_plays=(
        "harden.baseline --profile cis-debian-12-l1",
        "harden.config_audit --profile cis-debian-12-l1 --host HOST1",
        "harden.patch --host HOST1 --enrich kev,epss,cvss",
        "harden.cis --host HOST1 --profile cis-debian-12-l1",
    ),
)


# ---------------------------------------------------------------------------
# Export tuple
# ---------------------------------------------------------------------------

ALL_BLUE_SKILLS: tuple[Skill, ...] = (
    DEFENSE_SKILL,
    HUNT_SKILL,
    TRIAGE_SKILL,
    IR_SKILL,
    FORENSICS_SKILL,
    HARDENING_SKILL,
)


__all__ = [
    "ALL_BLUE_SKILLS",
    "DEFENSE_SKILL",
    "HUNT_SKILL",
    "TRIAGE_SKILL",
    "IR_SKILL",
    "FORENSICS_SKILL",
    "HARDENING_SKILL",
]
