"""``koda new`` subcommand: scaffold a pre-configured engagement from a template.

Usage::

    koda new --template pentest <name>
    koda new --template ir <name>
    koda new --template audit <name>
    koda new --list-templates

The command creates the engagement directory layout under
``KODA_HOME/engagements/<name>/`` and writes ``engagement.toml``,
``evidence/``, ``audit.jsonl``, and a ``README.md`` — but does NOT
activate the engagement.  Print ``koda use <name>`` at the end so the
operator can choose when to switch.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

_TOML_TEMPLATE = """\
[engagement]
name = "{name}"
template = "{template}"
approval_tier = "{approval_tier}"
report_template = "{report_template}"

[scope]
targets = []
attack_phases = {attack_phases_toml}

[scanners]
preferred = {scanners_toml}
"""

_README_TEMPLATE = """\
# Engagement: {name}

**Template:** `{template}`
**Approval tier:** `{approval_tier}`
**Report template:** `{report_template}`

## Scanner Set

{scanners_list}

## ATT&CK Phase Focus

{phases_list}

## Next Steps

{next_steps_list}

---
*Created by `koda new --template {template} {name}`*
"""


def _toml_list(items: tuple[str, ...]) -> str:
    """Render a tuple as a TOML inline array string."""
    quoted = ", ".join(f'"{item}"' for item in items)
    return f"[{quoted}]"


def _md_list(items: tuple[str, ...]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _validate_name(name: str) -> str | None:
    """Return an error message if *name* is invalid, else None."""
    if not name:
        return "engagement name must not be empty"
    if "\x00" in name or "/" in name or "\\" in name or ".." in name:
        return f"invalid name {name!r}: path traversal characters are not allowed"
    if name != name.lower():
        return f"invalid name {name!r}: must be lowercase"
    if " " in name or "\t" in name:
        return f"invalid name {name!r}: whitespace not allowed"
    if not _NAME_RE.match(name):
        return (
            f"invalid name {name!r}: use lowercase a-z, 0-9, _ or - "
            "(1–32 chars, starts with letter/digit)"
        )
    return None


def _scaffold(engagements_dir: Path, name: str, template_name: str) -> int:
    """Create the engagement directory tree.  Returns 0 on success, 1 on error."""
    from .templates import get as get_template

    tmpl = get_template(template_name)
    if tmpl is None:
        from .templates import names
        print(
            f"error: unknown template {template_name!r}. "
            f"Available: {', '.join(names())}",
            file=sys.stderr,
        )
        return 1

    eng_dir = engagements_dir / name

    if eng_dir.exists():
        print(
            f"error: engagement {name!r} already exists at {eng_dir}",
            file=sys.stderr,
        )
        return 1

    # --- create directory tree ---
    (eng_dir / "evidence").mkdir(parents=True, exist_ok=False)
    (eng_dir / "audit.jsonl").touch()

    # --- engagement.toml ---
    toml_content = _TOML_TEMPLATE.format(
        name=name,
        template=tmpl.name,
        approval_tier=tmpl.approval_tier,
        report_template=tmpl.report_template,
        attack_phases_toml=_toml_list(tmpl.attack_phases),
        scanners_toml=_toml_list(tmpl.scanners),
    )
    (eng_dir / "engagement.toml").write_text(toml_content, encoding="utf-8")

    # --- README.md ---
    readme_content = _README_TEMPLATE.format(
        name=name,
        template=tmpl.name,
        approval_tier=tmpl.approval_tier,
        report_template=tmpl.report_template,
        scanners_list=_md_list(tmpl.scanners),
        phases_list=_md_list(tmpl.attack_phases),
        next_steps_list=_md_list(tmpl.next_steps),
    )
    (eng_dir / "README.md").write_text(readme_content, encoding="utf-8")

    print(f"created engagement {name!r} at {eng_dir}")
    print(f"  template:  {tmpl.name}")
    print(f"  approvals: {tmpl.approval_tier}")
    print(f"  scanners:  {', '.join(tmpl.scanners)}")
    print(f"  phases:    {', '.join(tmpl.attack_phases)}")
    print()
    print(f"next: koda use {name}")
    return 0


def main(argv: list[str]) -> int:
    """Entry point for ``koda new``."""
    from .templates import names as template_names

    if not argv or argv[0] in {"-h", "--help"}:
        _print_usage()
        return 0

    if "--list-templates" in argv:
        for n in template_names():
            from .templates import get as get_template
            tmpl = get_template(n)
            assert tmpl is not None
            print(f"  {n:<10}  {tmpl.description}")
        return 0

    # Parse --template <name> <engagement-name>
    template_name: str | None = None
    positional: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in {"--template", "-t"}:
            if i + 1 >= len(argv):
                print("error: --template requires a value", file=sys.stderr)
                return 2
            template_name = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--template="):
            template_name = arg.split("=", 1)[1]
            i += 1
            continue
        if arg.startswith("-"):
            print(f"error: unknown flag {arg!r}", file=sys.stderr)
            _print_usage()
            return 2
        positional.append(arg)
        i += 1

    if not positional:
        if template_name:
            print("error: engagement <name> is required", file=sys.stderr)
        else:
            print(
                "error: --template is required. "
                f"Available: {', '.join(template_names())}",
                file=sys.stderr,
            )
            _print_usage()
        return 2

    if len(positional) > 1:
        print(f"error: unexpected arguments: {positional[1:]}", file=sys.stderr)
        return 2

    if template_name is None:
        print(
            "error: --template is required. "
            f"Available: {', '.join(template_names())}",
            file=sys.stderr,
        )
        _print_usage()
        return 2

    eng_name = positional[0]
    err = _validate_name(eng_name)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    # Resolve KODA_HOME lazily so profile override in __init__.py fires first.
    from ..config import KODA_HOME
    engagements_dir = KODA_HOME / "engagements"
    engagements_dir.mkdir(parents=True, exist_ok=True)

    return _scaffold(engagements_dir, eng_name, template_name)


def _print_usage() -> None:
    from .templates import names as template_names
    available = " | ".join(template_names())
    print("usage:")
    print(f"  koda new --template <{available}> <name>")
    print("  koda new --list-templates")
    print()
    print("  <name>  lowercase a-z/0-9/_/- (1–32 chars, starts with letter/digit)")


__all__ = ["main"]
