"""Network and TLS inspection tools — no external binaries required for most.

port_scan    — async TCP connect scan against a host (stdlib)
ssl_audit    — fetch + decode X.509 cert, report expiry and protocol (stdlib)
http_headers — fetch a URL and score security-relevant response headers (stdlib)
nmap_recon   — shell out to nmap for deeper reconnaissance
whois_lookup — shell out to whois
dig_lookup   — shell out to dig
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import ssl
import tempfile
from datetime import UTC, datetime
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from ...security.runner import run_cmd, trim
from ..registry import RiskLevel, Tool, ToolResult, register

_NMAP_MODES = {
    "fast":    ["-T4", "-F"],
    "full":    ["-T4", "-p-"],
    "service": ["-sV", "-sC"],
    "vuln":    ["-sV", "--script=vuln"],
}
_NMAP_TIMEOUTS = {"fast": 30, "full": 120, "service": 60, "vuln": 90}
_HEADER_NAMES = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "Server",
]


def _parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            left, right = (x.strip() for x in part.split("-", 1))
            if left.isdigit() and right.isdigit():
                start, end = sorted((int(left), int(right)))
                for port in range(start, min(end, 65535) + 1):
                    if 1 <= port <= 65535:
                        ports.add(port)
        elif part.isdigit():
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


async def _scan_one_port(host: str, port: int, timeout: int) -> tuple[int, str]:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return port, "OPEN"
    except TimeoutError:
        return port, "FILTERED"
    except (ConnectionRefusedError, OSError):
        return port, "CLOSED"


async def _port_scan(host: str, ports: str = "22,80,443,3306,5432,6379,7654,8080,8443,11434", timeout: int = 2) -> ToolResult:
    try:
        await asyncio.get_running_loop().getaddrinfo(host, None)
    except socket.gaierror as exc:
        return ToolResult(content=f"host resolution failed: {exc}", is_error=True)

    port_list = _parse_ports(ports)
    if not port_list:
        return ToolResult(content="no valid ports provided", is_error=True)

    timeout = max(1, int(timeout))
    sem = asyncio.Semaphore(100)

    async def _run(port: int) -> tuple[int, str]:
        async with sem:
            return await _scan_one_port(host, port, timeout)

    results = sorted(await asyncio.gather(*(_run(p) for p in port_list)))
    lines = [f"host: {host}", "PORT     STATE", "---------------"]
    lines += [f"{port:<8} {state}" for port, state in results]
    counts = {state: sum(1 for _, s in results if s == state) for state in ("OPEN", "CLOSED", "FILTERED")}
    open_ports = [p for p, s in results if s == "OPEN"]
    return ToolResult(
        content="\n".join(lines),
        metadata={"host": host, "open_ports": open_ports, "counts": counts},
    )


def _fetch_cert(host: str, port: int) -> tuple[dict[str, Any], str, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            protocol = ssock.version() or "unknown"
            cipher = (ssock.cipher() or ("unknown", "", 0))[0]
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write(pem)
        temp_path = fh.name
    try:
        cert = ssl._ssl._test_decode_cert(temp_path)  # type: ignore[attr-defined]
    finally:
        with contextlib.suppress(Exception):
            os.unlink(temp_path)
    return cert, protocol, cipher


def _name_value(name: Any, wanted: str) -> str:
    for rdn in name or []:
        for key, value in rdn:
            if key == wanted:
                return str(value)
    return ""


def _name_text(name: Any) -> str:
    parts = [f"{key}={value}" for rdn in name or [] for key, value in rdn]
    return ", ".join(parts) or "unknown"


async def _ssl_audit(host: str, port: int = 443) -> ToolResult:
    try:
        cert, protocol, cipher = await asyncio.to_thread(_fetch_cert, host, int(port))
    except Exception as exc:  # noqa: BLE001
        return ToolResult(content=f"ssl audit failed: {exc}", is_error=True)

    not_before = str(cert.get("notBefore") or "")
    not_after = str(cert.get("notAfter") or "")
    expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC) if not_after else None
    days = int((expiry - datetime.now(UTC)).total_seconds() // 86400) if expiry else None
    sans = [value for _, value in cert.get("subjectAltName", [])]

    lines = [
        f"host: {host}:{port}",
        f"subject_cn: {_name_value(cert.get('subject'), 'commonName') or 'unknown'}",
        f"issuer: {_name_text(cert.get('issuer'))}",
        f"not_before: {not_before or 'unknown'}",
        f"not_after: {not_after or 'unknown'}",
        f"days_until_expiry: {days if days is not None else 'unknown'}",
        f"sans: {', '.join(sans) if sans else 'none'}",
        f"protocol: {protocol}",
        f"cipher: {cipher}",
    ]
    if days is not None and days < 30:
        lines.append(f"WARNING: certificate expires in {days} days")
    return ToolResult(
        content="\n".join(lines),
        metadata={"days_until_expiry": days, "sans": sans, "host": host, "port": int(port)},
    )


def _fetch_headers(url: str) -> tuple[str, int, dict[str, str]]:
    req = urlrequest.Request(url, headers={"User-Agent": "K.O.D.A./1.0"})
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            return resp.geturl(), getattr(resp, "status", 200), dict(resp.headers.items())
    except urlerror.HTTPError as e:
        return e.geturl(), e.code, dict(e.headers.items())


async def _http_headers(url: str) -> ToolResult:
    if not urlparse.urlparse(url).scheme:
        url = f"https://{url}"
    try:
        final_url, status, headers = await asyncio.to_thread(_fetch_headers, url)
    except Exception as exc:  # noqa: BLE001
        return ToolResult(content=f"http fetch failed: {exc}", is_error=True)

    lower = {k.lower(): " ".join(v.split()) for k, v in headers.items()}
    present, missing = 0, []
    lines = [f"url: {final_url}", f"status: {status}", ""]
    for name in _HEADER_NAMES:
        value = lower.get(name.lower())
        if value is None:
            missing.append(name)
            lines.append(f"  {name}: MISSING")
        else:
            present += 1
            lines.append(f"  {name}: {value}")
    score = round((present / len(_HEADER_NAMES)) * 100, 1)
    lines.append("")
    lines.append(f"security_header_score: {score}/100 ({present}/{len(_HEADER_NAMES)} present)")
    return ToolResult(
        content="\n".join(lines),
        metadata={"score": score, "missing": missing, "status": status, "url": final_url},
    )


async def _nmap_recon(target: str, mode: str = "fast") -> ToolResult:
    mode = mode if mode in _NMAP_MODES else "fast"
    result = await run_cmd(["nmap", *_NMAP_MODES[mode], target], _NMAP_TIMEOUTS[mode])
    if result.error:
        return ToolResult(content=result.error, is_error=True)
    if result.returncode != 0:
        return ToolResult(content=trim(result.stderr or result.stdout, 2048), is_error=True)
    return ToolResult(
        content=trim(result.stdout, 8192) or "no output",
        metadata={"target": target, "mode": mode},
    )


async def _whois_lookup(domain: str) -> ToolResult:
    result = await run_cmd(["whois", domain], 10)
    if result.error:
        return ToolResult(content=result.error, is_error=True)
    if result.returncode != 0:
        return ToolResult(content=trim(result.stderr or result.stdout, 1024), is_error=True)
    return ToolResult(content=trim(result.stdout, 4096) or "no whois data", metadata={"domain": domain})


async def _dig_lookup(domain: str, record_type: str = "A") -> ToolResult:
    rt = (record_type or "A").upper()
    result = await run_cmd(["dig", "+short", domain, rt], 5)
    if result.error:
        return ToolResult(content=result.error, is_error=True)
    if result.returncode != 0:
        return ToolResult(content=trim(result.stderr or result.stdout, 1024), is_error=True)
    out = trim(result.stdout, 2048) or "no records"
    return ToolResult(content=out, metadata={"domain": domain, "record_type": rt})


register(Tool(
    name="net.port_scan",
    description=(
        "Async TCP connect scan against a host. No privileges or external binaries needed. "
        "Default ports cover common services. Reports OPEN/CLOSED/FILTERED per port."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Hostname or IP."},
            "ports": {"type": "string", "description": "Comma/range list, e.g. '22,80,443,8000-8100'."},
            "timeout": {"type": "integer", "description": "Per-port timeout seconds (default 2)."},
        },
        "required": ["host"],
    },
    handler=_port_scan,
    risk=RiskLevel.SENSITIVE,
    category="network",
))


register(Tool(
    name="net.ssl_audit",
    description=(
        "Fetch and decode an X.509 server certificate. Reports subject, issuer, SANs, "
        "expiry in days, negotiated protocol and cipher. Does NOT invent weaknesses."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Hostname."},
            "port": {"type": "integer", "description": "Port (default 443)."},
        },
        "required": ["host"],
    },
    handler=_ssl_audit,
    risk=RiskLevel.SAFE,
    category="network",
))


register(Tool(
    name="net.http_headers",
    description=(
        "Fetch a URL and score the presence of security-relevant response headers "
        "(HSTS, CSP, X-Frame-Options, etc.). Returns the raw values plus a score."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL (scheme optional, defaults to https://)."},
        },
        "required": ["url"],
    },
    handler=_http_headers,
    risk=RiskLevel.SAFE,
    category="network",
))


register(Tool(
    name="net.nmap_recon",
    description=(
        "Shell out to nmap for richer reconnaissance. Modes: fast (top 100 ports), full "
        "(all 65535), service (-sV -sC), vuln (NSE vuln scripts). Requires nmap installed."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host, IP, or CIDR."},
            "mode":   {"type": "string", "description": "fast|full|service|vuln (default fast)."},
        },
        "required": ["target"],
    },
    handler=_nmap_recon,
    risk=RiskLevel.SENSITIVE,
    category="network",
))


register(Tool(
    name="net.whois",
    description="Look up WHOIS registration data for a domain. Shells out to the `whois` binary.",
    input_schema={
        "type": "object",
        "properties": {"domain": {"type": "string", "description": "Domain name."}},
        "required": ["domain"],
    },
    handler=_whois_lookup,
    risk=RiskLevel.SAFE,
    category="network",
))


register(Tool(
    name="net.dig",
    description="DNS lookup via dig. Record types: A, AAAA, MX, TXT, NS, CNAME, etc.",
    input_schema={
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain name."},
            "record_type": {"type": "string", "description": "DNS record type (default A)."},
        },
        "required": ["domain"],
    },
    handler=_dig_lookup,
    risk=RiskLevel.SAFE,
    category="network",
))
