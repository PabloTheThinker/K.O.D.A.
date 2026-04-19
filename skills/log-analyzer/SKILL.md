---
name: log-analyzer
description: Analyze system logs for security-relevant patterns — failed logins, privilege escalations, and recent errors. Surfaces attacker footprints and operator mistakes before they compound.
version: 0.2.0
author: Vektra Industries
license: MIT
mode: blue
phase: hunt
attack_techniques: [T1078, T1110, T1098]
tools_required: [shell.exec]
prerequisites:
  commands: [journalctl]
metadata:
  tags: [logs, hunt, auth, ssh, pam, forensics]
  category: security
  ported_from: koda-cli-legacy/skills/log_analyzer
---

# System Log Analysis

Triage system logs for credential abuse, privilege escalation, and unexplained errors. This is a fast first-pass skill — use it at the start of an incident investigation to spot whether authentication or privilege patterns look wrong before you open a full DFIR workflow.

## When to Use

- An incident is suspected and you need a baseline of recent auth activity
- The operator asks about failed logins, brute force, or account lockouts
- A user asks "has anyone tried to log in as root" or similar
- You are establishing whether a host is in a pre-compromise, active, or post-compromise state

## Procedure

### 1. Confirm Log Access

Before querying, confirm you can read system logs. On systemd hosts:

```bash
journalctl --no-pager -n 1
```

If this fails with a permissions error, tell the operator: either run Koda as root (not recommended) or add the current user to the `systemd-journal` group.

### 2. Failed Authentications (last 24h)

```bash
journalctl --since "24 hours ago" --no-pager | grep -Ei "fail(ed)? password|authentication failure|invalid user" | tail -200
```

Report counts by source IP and username. Cluster of failures from a single IP → brute force (T1110). Many usernames from one IP → user enumeration (T1078).

### 3. Privilege Escalation Attempts

```bash
journalctl --since "24 hours ago" --no-pager | grep -E "sudo|su\[|pkexec" | tail -100
```

Look for: unexpected `sudo` by non-admin users, `su -` to root outside maintenance windows, `pkexec` invocations.

### 4. Account Changes

```bash
journalctl --since "7 days ago" --no-pager | grep -E "useradd|usermod|groupmod|passwd\[" | tail -50
```

New accounts, group changes, or password resets during the incident window are ATT&CK T1098 indicators.

### 5. Recent Kernel & Service Errors

```bash
journalctl --since "24 hours ago" --no-pager -p err..emerg | tail -100
```

OOM kills, segfaults, panic traces — correlate with suspected compromise timing.

## Output Format

Return a single structured finding per category, each mapped to its ATT&CK technique. Example:

> **Failed Authentications — T1110.001 (brute force)**
> 1,243 failed logins in the last 24h. Top sources: `45.33.12.7` (812 attempts, targeting `root`), `172.16.2.9` (431 attempts, targeting `admin`, `git`, `ubuntu`).
>
> **Recommendation:** Block `45.33.12.7` at the perimeter; confirm `admin`/`git` accounts are locked down with key-only SSH.

## Pitfalls

- Journalctl without `--no-pager` can hang inside a tool call. Always set the flag.
- `--since "24 hours ago"` is the minimum — too narrow misses slow-roll brute force.
- Syslog format differs across distros; on Debian/Ubuntu/Kali the PAM line format is stable, on Alpine/busybox the format is terser. Adjust the grep.

## Ethical Use

Only analyze logs on systems within the declared engagement scope. Host log contents are evidence — preserve them (copy to the engagement evidence store) before running any remediation that might truncate or rotate them.
