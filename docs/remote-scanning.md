# Remote Scanning

## When you'd use this

A consultant needs to run K.O.D.A.'s scanner suite against a client's server without installing anything permanently on it. `koda scan remote user@client-server --preset server-hardening` connects over standard SSH, runs the selected scanners inside a temporary directory, pulls results back to the operator's machine, and cleans up — all in one command.

---

## Setup

**Requirement:** `ssh user@host 'true'` must succeed before running `koda scan remote`. That means your key is in `~/.ssh/authorized_keys` on the target, your `~/.ssh/config` alias resolves, or whatever auth your environment uses is already working. K.O.D.A. reuses all of that transparently.

```bash
# Verify SSH access works first:
ssh user@client-server 'true' && echo "ready"

# Basic scan:
koda scan remote user@client-server --scanner trivy --target /srv/app

# Multiple scanners with an explicit engagement name:
koda scan remote user@client-server \
  --scanner trivy --scanner gitleaks \
  --target /opt/app \
  --engagement client-acme-2026-q2

# With a mission preset (requires koda.missions to be installed):
koda scan remote user@client-server --preset server-hardening

# Non-standard SSH port:
koda scan remote user@client-server:2222 --scanner grype

# Keep temp dir for debugging:
koda scan remote user@client-server --scanner trivy --keep-temp
```

### Optional: `--sudo`

Some scanners need elevated privileges (reading `/etc/shadow`, scanning privileged paths). Pass `--sudo` to elevate scanner invocations on the remote:

```bash
koda scan remote root@server --scanner trivy --target / --sudo
```

K.O.D.A. first probes for passwordless sudo (`sudo -n true`). If that succeeds, no prompt appears. If passwordless sudo is not available, you are prompted **once** on your local terminal — the password is piped directly to `sudo -S` on the remote and is never written to disk, never logged, and never appears in audit events.

### SSH ControlMaster

K.O.D.A. opens one ControlMaster background socket per run with `ControlPersist=10m`. All subsequent commands (OS probe, binary uploads, scanner invocations, cleanup) reuse the same socket — only one SSH handshake occurs per `koda scan remote` invocation.

The socket lives at `~/.ssh/cm-koda-<host>-<pid>` and is explicitly closed with `ssh -O exit` at the end of each run.

---

## Auto-provisioning

K.O.D.A. checks for each scanner on the remote's PATH before uploading. If it's already there, no upload happens. If it's not there but we can provision it, we `scp` the operator's local copy to `/tmp/koda-<uuid>/bin/` and delete it at the end of the run (unless `--keep-temp` is set).

| Scanner | Strategy | Notes |
|---|---|---|
| `trivy` | Auto-upload static binary | Single Go binary; no dependencies |
| `gitleaks` | Auto-upload static binary | Single Go binary |
| `nuclei` | Auto-upload static binary | Single Go binary |
| `osv-scanner` | Auto-upload static binary | Single Go binary |
| `grype` | Auto-upload static binary | Single Go binary |
| `semgrep` | Must be pre-installed | Python package; cannot `scp` |
| `bandit` | Must be pre-installed | Python package; cannot `scp` |
| `nmap` | Must be pre-installed | May need root/capabilities; distro package preferred |
| `falco` | Must be pre-installed | Requires kernel module or eBPF; cannot ship |
| `checkov` | Must be pre-installed | Python package; cannot `scp` |
| `kics` | Must be pre-installed | Requires bundled rules directory alongside binary |

If a scanner is not installed on the remote and cannot be auto-provisioned, K.O.D.A. prints a warning and skips it — the remaining scanners still run.

**Upload requirement:** for auto-upload to work, the scanner binary must be installed locally (on the operator's machine). K.O.D.A. copies the operator's own binary to the remote. If the local binary is not found, the scanner is skipped with a clear error message.

---

## Flags reference

```
koda scan remote <ssh-target> [flags]

positional:
  <ssh-target>        user@host | host | user@host:port | ~/.ssh/config alias

flags:
  --target PATH       Remote path to scan (default: .)
  --preset NAME       Mission preset name
  --scanner NAME      Scanner to run (repeatable; combinable with --preset)
  --port PORT         SSH port override (alternative to user@host:port)
  --sudo              Elevate scanner commands with sudo on the remote
  --keep-temp         Leave /tmp/koda-* in place after scan (debug)
  --engagement NAME   Tag results under this engagement
```

Results are stored in `KODA_HOME/engagements/<name>/` using the standard engagement layout. The full audit trail (connect, upload, run, pull, cleanup events) lands in the same engagement audit log as local scans.
