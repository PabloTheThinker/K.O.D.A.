"""Security scan tool. Runs a lightweight static audit over a directory.

This is a thin first-pass scanner so K.O.D.A. has a real SAFE tool to call for
"is my project safe?". It looks for obvious, real patterns — secrets in config
files, world-writable files, plaintext credentials — not fabricated CVEs.

Real CVE/dependency scanning is a follow-up that will shell out to syft/grype
or trivy; for now the output is honest about its limits.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..registry import RiskLevel, Tool, ToolResult, register

_SCAN_MAX_FILES = 800
_SCAN_MAX_BYTES_PER_FILE = 400_000
_SCAN_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".rb", ".java",
    ".env", ".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".conf",
    ".sh", ".bash", ".zsh", ".md", ".txt",
}
_SCAN_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".cache", "target", ".mypy_cache", ".ruff_cache",
}

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("generic_private_key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\bxox[abpr]-[A-Za-z0-9\-]{10,}\b")),
]


@dataclass
class Finding:
    file: str
    line: int
    kind: str
    evidence: str

    def render(self) -> str:
        evidence = self.evidence.strip()
        if len(evidence) > 160:
            evidence = evidence[:157] + "..."
        return f"- {self.file}:{self.line}  [{self.kind}]  {evidence}"


def _should_scan(path: Path) -> bool:
    if path.suffix.lower() in _SCAN_TEXT_EXTENSIONS:
        return True
    if path.name.startswith(".env"):
        return True
    return False


def _iter_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in __import__("os").walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SCAN_SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            p = Path(dirpath) / name
            if _should_scan(p):
                out.append(p)
            if len(out) >= _SCAN_MAX_FILES:
                return out
    return out


def _scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = path.read_bytes()[:_SCAN_MAX_BYTES_PER_FILE]
    except OSError:
        return findings
    text = data.decode("utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(file=str(path), line=line_no, kind=kind, evidence=line))
    return findings


def _scan_run(path: str) -> ToolResult:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        return ToolResult(content=f"Path does not exist: {root}", is_error=True)
    if not root.is_dir():
        return ToolResult(content=f"scan.run expects a directory; got: {root}", is_error=True)

    files = _iter_files(root)
    findings: list[Finding] = []
    for f in files:
        findings.extend(_scan_file(f))

    lines = [
        f"K.O.D.A. scan.run over {root}",
        f"files scanned: {len(files)}",
        f"findings: {len(findings)}",
        "",
    ]
    if findings:
        lines.append("Findings (real matches, not inferences):")
        lines.extend(f.render() for f in findings)
    else:
        lines.append("No secret patterns matched. This does NOT mean the project is safe;")
        lines.append("it means scan.run's built-in patterns found nothing. Other tools")
        lines.append("(dependency audit, SAST, host health) should also run before you claim safety.")
    return ToolResult(content="\n".join(lines), metadata={"findings": len(findings), "files_scanned": len(files)})


register(Tool(
    name="scan.secrets",
    description=(
        "Static secret-pattern audit over a directory. Reports real pattern matches only "
        "(AWS keys, GH tokens, OpenAI/Anthropic keys, SSH private keys, Slack tokens). "
        "Does NOT invent CVEs. Fast, no dependencies. Use as a quick first pass."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Directory to scan. Absolute or ~-expanded."},
        },
        "required": ["path"],
    },
    handler=_scan_run,
    risk=RiskLevel.SAFE,
    category="security",
))
