"""Top-level report-generation entry points.

``generate`` builds the bundle once and fans out to the selected writers.
``write_bundle`` persists the result to disk with conventional filenames.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..findings import UnifiedFinding
from .bundle import build_bundle
from .context import ReportContext
from .writers import (
    executive_summary,
    markdown_report,
    sarif_report,
    technical_report,
)


_FORMATS: tuple[str, ...] = ("executive", "technical", "markdown", "sarif")


_EXTENSIONS: dict[str, str] = {
    "executive": "executive.txt",
    "technical": "technical.txt",
    "markdown": "md",
    "sarif": "sarif.json",
}


def generate(
    ctx: ReportContext,
    findings: list[UnifiedFinding],
    intel: Any,
    *,
    formats: tuple[str, ...] = _FORMATS,
) -> dict[str, str]:
    """Produce the requested report formats. Unknown formats are ignored."""
    bundle = build_bundle(ctx, findings, intel)
    # Attach the intel handle so writers can enrich without re-plumbing.
    # object.__setattr__ because the dataclass is frozen.
    try:
        object.__setattr__(bundle, "_intel", intel)
    except Exception:
        pass

    out: dict[str, str] = {}
    if "executive" in formats:
        out["executive"] = executive_summary(bundle)
    if "technical" in formats:
        out["technical"] = technical_report(bundle)
    if "markdown" in formats:
        out["markdown"] = markdown_report(bundle)
    if "sarif" in formats:
        out["sarif"] = sarif_report(bundle)
    return out


def write_bundle(
    outputs: dict[str, str],
    out_dir: Path,
    *,
    basename: str = "report",
) -> dict[str, Path]:
    """Persist generated outputs to ``out_dir``. Returns {format: path}."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for fmt, content in outputs.items():
        ext = _EXTENSIONS.get(fmt, "txt")
        path = out_dir / f"{basename}.{ext}"
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        paths[fmt] = path
    return paths
