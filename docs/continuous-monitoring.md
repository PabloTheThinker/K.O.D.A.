# Continuous Monitoring

## What this does

`koda schedule` registers a periodic security scan via the OS scheduler (systemd user timer
or crontab — no long-running daemon) and sends you a diff-based alert each morning listing
**only the new findings** since the last run.

## Quick start

```bash
koda schedule add \
  --preset server-hardening \
  --target localhost \
  --cron "0 2 * * *" \
  --alert telegram
```

This creates a schedule that:

1. Runs the `server-hardening` preset against `localhost` every night at 02:00.
2. Computes a diff against the previous run.
3. Sends a Telegram message listing any **new** findings (CRITICAL/HIGH first).

To force-run immediately:

```bash
koda schedule run <id>
```

To see all schedules:

```bash
koda schedule list
```

To remove:

```bash
koda schedule remove <id|name>
```

## Alert channels

| Channel | Example | Setup required |
|---|---|---|
| `file:<path>` | `--alert file:~/alerts.jsonl` | None — always works. Default if no other channel is given. |
| `telegram` | `--alert telegram` | Telegram bridge configured (`koda telegram`). |
| `email:<addr>` | `--alert email:ops@example.com` | `KODA_HOME/smtp.toml` with `host`, `port`, `user`, `pass`, `from_addr`. |
| `webhook:<url>` | `--alert webhook:https://hooks.example.com/x` | None. POST JSON; 5s timeout; retries once on failure. |

Multiple `--alert` flags are accepted and all fire on each run:

```bash
koda schedule add --target localhost --preset server-hardening \
  --cron "0 2 * * *" \
  --alert telegram \
  --alert file:~/koda-alerts.jsonl
```

### SMTP config (`KODA_HOME/smtp.toml`)

```toml
host      = "smtp.example.com"
port      = 587
user      = "alerts@example.com"
pass      = "app-password-here"
from_addr = "alerts@example.com"
```

## Alert-on policy

The `--alert-on` flag controls when alerts fire:

| Value | When alerts fire |
|---|---|
| `findings` *(default)* | Only when there are **new** findings since the last run. |
| `change` | When there are new **or** resolved findings (either direction). |
| `empty` | Every run, even with zero findings. Useful for health-check receipts. |

## Diff semantics

Each finding carries a **fingerprint** — a SHA-256 hash over `rule_id`, `file_path`, and
the first 200 bytes of `snippet`. Two findings with the same fingerprint are the same issue.

| Category | Meaning |
|---|---|
| **New** | Fingerprint appears in the current run but not the previous one. |
| **Resolved** | Fingerprint was in the previous run but is gone now. |
| **Persistent** | Fingerprint in both runs — known, unfixed issue. |

On the **first run** every finding is classified as new.

Alert payloads redact credential-shaped strings from finding titles and descriptions
before sending, using the same redactor as the rest of K.O.D.A.

## Manual diff

Compare any two runs explicitly:

```bash
koda schedule diff <id>                          # latest vs previous
koda schedule diff <id> --from run-2026-04-18    # specific baseline
koda schedule diff <id> --from run-001 --to run-003
```

## Run history

```bash
koda schedule history <id> --limit 10
```

## Under the hood

K.O.D.A. never starts a background daemon.  When you run `koda schedule add`:

1. The schedule is written to `KODA_HOME/schedules/<id>.toml`.
2. K.O.D.A. checks whether **systemd --user** is running (Ubuntu 24.04: yes by default).
   - If yes: writes `~/.config/systemd/user/koda-schedule-<id>.{service,timer}` and enables
     the timer with `systemctl --user enable --now`.
   - If no (macOS, headless server without a user session): appends a line to your **crontab**
     via `crontab -l; crontab -`, tagged with `# koda-schedule:<id>` for safe removal.
3. The OS fires `koda schedule _tick <id>` at the scheduled time.
4. `_tick` runs the scanners, writes `KODA_HOME/schedules/<id>/runs/<run_id>/`, computes the
   diff, fires alerts, and updates the `latest` symlink.  It always exits 0 so cron does not
   retry.

Each run directory contains:
- `findings.jsonl` — one `UnifiedFinding` per line
- `meta.toml` — `started_at`, `ended_at`, `exit_code`, `scanner_durations`, `finding_count_by_severity`

### macOS vs Ubuntu

On **Ubuntu 24.04** with a live desktop or `loginctl enable-linger <user>`:
`systemctl --user is-system-running` returns `running` → systemd timer backend chosen.

On **macOS** or a headless Linux server without a user systemd session:
`systemctl` is absent or returns non-zero → crontab backend chosen.

The backend choice is cached to `KODA_HOME/schedule-backend.toml` after first detection
so subsequent calls are consistent even if systemd is momentarily unavailable.
