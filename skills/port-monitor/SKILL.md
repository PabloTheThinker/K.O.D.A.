---
name: port-monitor
description: Detect unexpected open ports — establish a listener baseline and flag new or removed services. Used for drift detection, beacon detection, and post-compromise service installs.
version: 0.2.0
author: Vektra Industries
license: MIT
mode: blue
phase: hunt
attack_techniques: [T1571, T1021, T1090]
tools_required: [shell.exec]
prerequisites:
  commands: [ss]
metadata:
  tags: [ports, listeners, drift, baseline, hunt]
  category: security
  ported_from: koda-cli-legacy/skills/port_monitor
---

# Listening Port Monitor

Track what services are listening on the host, compare against a known-good baseline, and surface drift. A backdoor is a new listener; a successful lateral pivot usually stands up a new one too. This skill makes that cheap to detect.

## When to Use

- After establishing a foothold during a red engagement, to capture a pre-change baseline
- At the start of an IR case, to catch C2 callbacks / reverse shells (T1571)
- During a routine hardening audit, to flag unnecessary exposed services
- When the operator asks "what's listening on this box?"

## Procedure

### 1. Capture the Baseline

```bash
ss -tulpnH | sort
```

Parse into a stable canonical form — one line per listener, keyed by `(proto, local_addr, port, process)`. Store this as the baseline for the engagement. If the engagement directory supports it, write to `<KODA_HOME>/engagements/<roe_id>/port-baseline.txt`.

### 2. Check Against Baseline

After the baseline exists, diff each new capture against it:

```bash
ss -tulpnH | sort > /tmp/koda.ports.current
diff <baseline> /tmp/koda.ports.current
```

Report:
- **New listeners** — lines present in current but not baseline. Treat as suspect until the operator names the cause (legitimate config change vs. unauthorized install).
- **Removed listeners** — service crashes, evasion, or expected shutdowns.
- **Process rebinds** — same port, different PID or process name. Common for malware replacing a legitimate service.

### 3. Enrich Each Change

For every new listener, report:

- Protocol + port
- Bound address (0.0.0.0 / ::  = internet-facing; 127.0.0.1 = local-only)
- Process name + PID
- Whether the port is in the well-known range (<1024) → required root to bind
- ATT&CK mapping:
  - External-facing new listener → T1571 (non-standard port C2) candidate
  - New SMB/RDP/SSH listener on unusual interface → T1021 (remote services)
  - Reverse tunnel / proxy process → T1090 (proxy)

### 4. Correlate With Process Tree

For each suspect listener:

```bash
ps -ef --forest | grep -E "^[[:alnum:]]+ +<PID>"
```

If the parent process is `init`, `systemd`, or a known package-managed service, lower suspicion. If the parent is a shell (`bash`, `sh`), a cron job, or an interpreter in a temp directory, raise suspicion.

## Output Format

> **New listener — T1571**
> `tcp 0.0.0.0:4444  python3 (pid 12934, parent bash in /tmp/xmr/)`
> First seen after baseline captured at 2026-04-18T14:22Z. Process tree indicates a shell-spawned Python binary in a tmp directory — high suspicion of operator-placed or attacker-placed reverse shell / backdoor.

## Pitfalls

- `ss` fields change across versions. Always pass `-H` (no header) and parse by column position.
- Ephemeral outbound connections are not listeners — only lines with `LISTEN` state are baseline candidates.
- Some legitimate agents open short-lived ports (package managers, updaters). Re-run twice before escalating.

## Ethical Use

Scope this to the declared engagement host(s). Do not run the baseline sweep against systems outside the ROE even if they are on the same subnet.
