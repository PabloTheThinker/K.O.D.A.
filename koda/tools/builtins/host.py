"""Host-side tools — auth log triage, file integrity, dependency CVE audit, fail2ban status.

These touch the local system. Output is grounded: either a command ran and we
report what it said, or it didn't and we say so. No inferred "you're fine."
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ...security.runner import run_cmd, trim
from ..registry import RiskLevel, Tool, ToolResult, register


_FAILED_RE   = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
_INVALID_RE  = re.compile(r"Invalid user (\S+) from (\S+)")
_OPENED_BY_RE = re.compile(r"session opened for user (\S+) by (\S+)\(uid=")
_OPENED_RE   = re.compile(r"session opened for user (\S+)")
_SUDO_TTY_RE = re.compile(r"\s([A-Za-z0-9_.-]+)\s*:\sTTY=")
_CVE_RE      = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_SEV_RANK    = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1, "info": 0, "unknown": -1}


# ── auth log triage ───────────────────────────────────────────────────────

def _tail_text(path: str, limit: int) -> str:
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        start = max(size - limit, 0)
        fh.seek(start)
        if start:
            fh.readline()
        return fh.read().decode(errors="ignore")


def _parse_syslog_time(line: str, now: datetime) -> datetime | None:
    if len(line) < 15:
        return None
    try:
        stamp = datetime.strptime(f"{line[:15]} {now.year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return stamp.replace(year=now.year - 1) if stamp - now > timedelta(days=1) else stamp


def _rank_lines(title: str, items: list[tuple[Any, int]], render, limit: int) -> list[str]:
    lines = [title]
    if not items:
        return lines + ["  none"]
    for idx, (key, count) in enumerate(items[:limit], 1):
        lines.append(f"  {idx}. {render(key)} — {count}")
    return lines


async def _auth_log_triage(path: str = "/var/log/auth.log", hours: int = 24) -> ToolResult:
    try:
        text = await asyncio.to_thread(_tail_text, path, 2 * 1024 * 1024)
    except FileNotFoundError:
        return ToolResult(content=f"file not found: {path}", is_error=True)
    except OSError as exc:
        return ToolResult(content=f"failed reading log: {exc}", is_error=True)

    now = datetime.now()
    cutoff = now - timedelta(hours=max(0, int(hours)))
    stats: Counter = Counter()
    attackers: Counter = Counter()
    openers: Counter = Counter()
    sudoers: Counter = Counter()

    for line in text.splitlines():
        ts = _parse_syslog_time(line, now)
        if ts and ts < cutoff:
            continue
        if "Failed password" in line:
            stats["failed_password"] += 1
            if (m := _FAILED_RE.search(line)):
                attackers[(m.group(2), m.group(1))] += 1
        if "Invalid user" in line:
            stats["invalid_user"] += 1
            if (m := _INVALID_RE.search(line)):
                attackers[(m.group(2), m.group(1))] += 1
        if "session opened" in line:
            stats["session_opened"] += 1
            if (m := _OPENED_BY_RE.search(line)):
                openers[m.group(2)] += 1
            elif (m := _OPENED_RE.search(line)):
                openers[m.group(1)] += 1
        if "sudo:" in line:
            stats["sudo"] += 1
            if (m := re.search(r"\bby (\S+)\(uid=", line)) or (m := _SUDO_TTY_RE.search(line)):
                sudoers[m.group(1)] += 1

    lines = [
        f"log: {path}",
        f"window_hours: {max(0, int(hours))}",
        f"summary: failed_password={stats['failed_password']} invalid_user={stats['invalid_user']} "
        f"sudo={stats['sudo']} session_opened={stats['session_opened']}",
        "",
        *_rank_lines("Top attackers (host / user):", attackers.most_common(10), lambda k: f"{k[0]} / {k[1]}", 10),
        "",
        *_rank_lines("Top session openers:", openers.most_common(5), str, 5),
    ]
    if sudoers:
        lines += ["", *_rank_lines("Top sudo actors:", sudoers.most_common(5), str, 5)]

    return ToolResult(
        content="\n".join(lines),
        metadata={
            "summary": dict(stats),
            "top_attackers": attackers.most_common(10),
            "top_session_openers": openers.most_common(5),
        },
    )


# ── file integrity ────────────────────────────────────────────────────────

def _hash_file(path: str) -> tuple[str, int, int]:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    st = os.stat(path)
    return h.hexdigest(), st.st_size, int(st.st_mtime)


async def _file_integrity(path: str, baseline_hash: str = "") -> ToolResult:
    try:
        digest, size, mtime = await asyncio.to_thread(_hash_file, path)
    except FileNotFoundError:
        return ToolResult(content=f"file not found: {path}", is_error=True)
    except OSError as exc:
        return ToolResult(content=f"hash failed: {exc}", is_error=True)

    when = datetime.fromtimestamp(mtime).isoformat()
    metadata: dict[str, Any] = {"path": path, "sha256": digest, "size": size, "mtime": mtime}

    if baseline_hash.strip():
        match = digest.lower() == baseline_hash.strip().lower()
        metadata["match"] = match
        status = "MATCH" if match else "DRIFT"
        content = f"status: {status}\nsha256: {digest}\nsize: {size}\nmtime: {when}"
        return ToolResult(content=content, metadata=metadata)

    return ToolResult(content=f"sha256: {digest}\nsize: {size}\nmtime: {when}", metadata=metadata)


# ── dependency CVE audit ──────────────────────────────────────────────────

def _find_cve(text: str) -> str | None:
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


def _parse_pip_audit(data: Any) -> list[dict[str, str]]:
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    out: list[dict[str, str]] = []
    for dep in deps or []:
        for vuln in dep.get("vulns") or dep.get("vulnerabilities") or []:
            aliases = vuln.get("aliases") or vuln.get("cves") or []
            ident = next((_find_cve(str(a)) for a in aliases if _find_cve(str(a))), None)
            ident = ident or _find_cve(json.dumps(vuln)) or str(vuln.get("id") or "UNKNOWN")
            sev = str(vuln.get("severity") or vuln.get("cvss_severity") or "unknown").lower()
            fix = ", ".join(vuln.get("fix_versions") or []) or "none"
            out.append({
                "id": ident,
                "severity": sev,
                "package": str(dep.get("name") or "unknown"),
                "version": str(dep.get("version") or "?"),
                "fix": fix,
            })
    return out


def _parse_npm_audit(data: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), dict):
        for pkg, info in data["vulnerabilities"].items():
            sev = str(info.get("severity") or "unknown").lower()
            fix = info.get("fixAvailable")
            fix_text = "available" if fix is True else str((fix or {}).get("name") or (fix or {}).get("version") or "none")
            via = info.get("via") if isinstance(info.get("via"), list) else [info.get("via")]
            added = False
            for item in via:
                blob = json.dumps(item) if isinstance(item, dict) else str(item)
                ident = _find_cve(blob) or (str(item.get("source") or item.get("name")) if isinstance(item, dict) else str(item or ""))
                if ident:
                    out.append({"id": ident, "severity": sev, "package": str(pkg), "version": "?", "fix": fix_text})
                    added = True
            if not added and sev != "unknown":
                out.append({"id": str(pkg), "severity": sev, "package": str(pkg), "version": "?", "fix": fix_text})
    return out


def _detect_ecosystem(project_dir: Path, ecosystem: str) -> tuple[str | None, str | None]:
    has_py = (project_dir / "requirements.txt").exists() or (project_dir / "pyproject.toml").exists()
    has_node = (project_dir / "package.json").exists()
    if ecosystem == "python":
        return ("python", None) if has_py else (None, "no python dependency manifest found")
    if ecosystem == "node":
        return ("node", None) if has_node else (None, "no node dependency manifest found")
    if has_py:
        return "python", None
    if has_node:
        return "node", None
    return None, "no supported dependency manifest found"


async def _dep_cve_check(project_dir: str, ecosystem: str = "auto") -> ToolResult:
    project_path = Path(project_dir).expanduser()
    if not project_path.is_dir():
        return ToolResult(content=f"not a directory: {project_dir}", is_error=True)

    eco, err = _detect_ecosystem(project_path, ecosystem)
    if err:
        return ToolResult(content=err, is_error=True)

    args = ["pip-audit", "--format", "json"] if eco == "python" else ["npm", "audit", "--json"]
    cmd = await run_cmd(args, timeout=120, cwd=str(project_path))
    if cmd.error:
        return ToolResult(content=cmd.error, is_error=True)

    raw = (cmd.stdout or cmd.stderr).strip()
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return ToolResult(content=trim(cmd.stderr or cmd.stdout or "failed to parse audit output", 2048), is_error=True)

    findings = _parse_pip_audit(data) if eco == "python" else _parse_npm_audit(data)
    if cmd.returncode not in (0, 1) and not findings:
        return ToolResult(content=trim(cmd.stderr or "dependency audit failed", 2048), is_error=True)

    uniq: dict[tuple[str, str], dict[str, str]] = {}
    for item in findings:
        uniq[(item["id"], item["package"])] = item
    ordered = sorted(uniq.values(), key=lambda x: (_SEV_RANK.get(x["severity"], -1), x["id"]), reverse=True)

    if not ordered:
        return ToolResult(
            content=f"ecosystem: {eco}\nNo CVE findings detected.",
            metadata={"ecosystem": eco, "count": 0},
        )

    lines = [f"ecosystem: {eco}", f"findings: {len(ordered)}", ""]
    for idx, item in enumerate(ordered[:10], 1):
        lines.append(f"{idx}. {item['severity'].upper():<8} {item['id']}  {item['package']}@{item['version']}  fix:{item['fix']}")
    if len(ordered) > 10:
        lines.append(f"... and {len(ordered) - 10} more")

    return ToolResult(
        content="\n".join(lines),
        metadata={"ecosystem": eco, "count": len(ordered), "top": ordered[:10]},
    )


# ── fail2ban status ───────────────────────────────────────────────────────

async def _fail2ban_status(jail: str = "") -> ToolResult:
    args = ["fail2ban-client", "status"] + ([jail.strip()] if jail.strip() else [])
    cmd = await run_cmd(args, timeout=10)
    if cmd.error:
        return ToolResult(content=cmd.error, is_error=True)
    if cmd.returncode != 0:
        return ToolResult(content=trim(cmd.stderr or cmd.stdout, 1024), is_error=True)
    return ToolResult(content=trim(cmd.stdout, 4096) or "no output", metadata={"jail": jail.strip() or "all"})


# ── registration ──────────────────────────────────────────────────────────

register(Tool(
    name="host.auth_log_triage",
    description=(
        "Parse /var/log/auth.log (or equivalent) within a time window and report failed "
        "logins, invalid-user attempts, session opens, and sudo actors. Useful for rapid "
        "SSH brute-force detection. Does NOT infer — only counts what the log actually says."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path":  {"type": "string", "description": "Path to auth log (default /var/log/auth.log)."},
            "hours": {"type": "integer", "description": "Only consider entries within the last N hours (default 24)."},
        },
        "required": [],
    },
    handler=_auth_log_triage,
    risk=RiskLevel.SAFE,
    category="host",
))


register(Tool(
    name="host.file_integrity",
    description=(
        "Compute SHA-256 + size + mtime of a file. If a baseline hash is supplied, report "
        "MATCH or DRIFT. Use for tripwire-style integrity checks."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path."},
            "baseline_hash": {"type": "string", "description": "Optional SHA-256 to compare against."},
        },
        "required": ["path"],
    },
    handler=_file_integrity,
    risk=RiskLevel.SAFE,
    category="host",
))


register(Tool(
    name="host.dep_cve_check",
    description=(
        "Run the appropriate dependency auditor (pip-audit or npm audit) against a project "
        "directory and summarize CVE findings. Auto-detects Python vs Node from manifests."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "project_dir": {"type": "string", "description": "Project root with requirements.txt / pyproject.toml / package.json."},
            "ecosystem":   {"type": "string", "description": "auto|python|node (default auto)."},
        },
        "required": ["project_dir"],
    },
    handler=_dep_cve_check,
    risk=RiskLevel.SAFE,
    category="host",
))


register(Tool(
    name="host.fail2ban_status",
    description="Report fail2ban status (optionally for a specific jail). Requires fail2ban-client on PATH.",
    input_schema={
        "type": "object",
        "properties": {
            "jail": {"type": "string", "description": "Optional jail name (default: overall status)."},
        },
        "required": [],
    },
    handler=_fail2ban_status,
    risk=RiskLevel.SAFE,
    category="host",
))
