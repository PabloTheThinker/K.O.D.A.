"""K.O.D.A. first-run setup wizard.

Multi-stage onboarding for a security-specialist agent harness. The wizard
walks the operator through risk acknowledgement, provider setup, engagement
scoping, approval tier, scanner probing, and a live self-test.

Stages:
    1. Banner + risk acknowledgement (bypass via KODA_ACCEPT_RISK=1)
    2. Welcome-back branch (if config already exists)
    3. Quick vs Full fork
    4. Provider selection + configuration
    5. Engagement naming
    6. Approval tier (safe / medium / all / none)
    7. Scanner probe with install hints
    8. Alert channels (Telegram opt-in)
    9. Scope targets (optional)
   10. Write config, self-test, launch

The wizard reflects K.O.D.A.'s harness model: mount on any engine, scope to
one engagement at a time, audit everything, ground every claim.
"""
from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..adapters import create_provider
from ..adapters.base import Message, Role
from ..config import CONFIG_PATH, KODA_HOME, load_config, save_config
from ..notify import TelegramNotifier
from ..security.scanners.registry import detect_installed_scanners
from ..wizard import (
    Prompter,
    ProviderSetupResult,
    SelectOption,
    WizardCancelled,
    detect_anthropic_env_key,
    detect_azure_openai_env_key,
    detect_gemini_env_key,
    detect_ollama_models,
    save_secrets,
    setup_anthropic,
    setup_azure_openai,
    setup_bedrock,
    setup_gemini,
    setup_llamacpp,
    setup_ollama,
    setup_openai_compat,
    setup_vertex_ai,
)

SECRETS_PATH = KODA_HOME / "secrets.env"
ACTIVE_ENGAGEMENT_FILE = KODA_HOME / "active_engagement"

_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_SCOPE_TARGET_CAP = 50
_TELEGRAM_TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")
_TELEGRAM_CHAT_RE = re.compile(r"^-?\d{4,}$")


# Install hints for scanners that K.O.D.A. wraps. Shown in Stage 7 when the
# binary is missing from PATH.
_SCANNER_INSTALL_HINTS: dict[str, str] = {
    "semgrep":     "pip install semgrep",
    "trivy":       "brew install trivy  |  https://trivy.dev/getting-started/installation/",
    "gitleaks":    "brew install gitleaks  |  https://github.com/gitleaks/gitleaks",
    "nuclei":      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "bandit":      "pip install bandit",
    "osv-scanner": "brew install osv-scanner  |  go install github.com/google/osv-scanner/cmd/osv-scanner@v1",
    "nmap":        "apt install nmap  |  brew install nmap",
    "grype":       "brew install grype  |  https://github.com/anchore/grype",
}


@dataclass(frozen=True)
class _ProviderOption:
    value: str
    label: str
    base_hint: str
    detector: Callable[[], Any] | None
    detail_fn: Callable[[Any], str] | None = None


def _env_detector(env_keys: tuple[str, ...]) -> Callable[[], str | None]:
    def _detect() -> str | None:
        for name in env_keys:
            val = os.environ.get(name, "").strip()
            if val:
                return val
        return None
    return _detect


def _option_from_entry(entry: Any) -> _ProviderOption:
    if entry.id == "ollama":
        return _ProviderOption(
            value=entry.id, label=entry.label,
            base_hint=entry.hint,
            detector=detect_ollama_models,
            detail_fn=lambda v: f"{len(v)} model(s) available" if v else "not reachable",
        )
    if entry.id == "gemini":
        return _ProviderOption(
            value=entry.id, label=entry.label,
            base_hint=entry.hint,
            detector=detect_gemini_env_key,
            detail_fn=lambda v: "key detected" if v else "no key",
        )
    if entry.env_keys:
        return _ProviderOption(
            value=entry.id, label=entry.label,
            base_hint=entry.hint,
            detector=_env_detector(entry.env_keys),
            detail_fn=lambda v: "key detected" if v else "no key",
        )
    return _ProviderOption(
        value=entry.id, label=entry.label,
        base_hint=entry.hint,
        detector=None, detail_fn=None,
    )


def _build_provider_options() -> tuple[_ProviderOption, ...]:
    """Derive the wizard menu from the provider catalog.

    Local tier renders before cloud; Ollama gets a live-model probe,
    Gemini keeps its filesystem-fallback detection, everything else
    uses a generic env-var probe built from the catalog entry.
    """
    from ..providers.catalog import PROVIDER_CATALOG

    local: list[_ProviderOption] = []
    cloud: list[_ProviderOption] = []
    for entry in PROVIDER_CATALOG:
        bucket = local if entry.tier == "local" else cloud
        bucket.append(_option_from_entry(entry))
    return tuple(local + cloud)


def _build_recommended_options() -> tuple[_ProviderOption, ...]:
    """Catalog subset flagged ``recommended=True`` — powers the short picker."""
    from ..providers.catalog import PROVIDER_CATALOG

    local: list[_ProviderOption] = []
    cloud: list[_ProviderOption] = []
    for entry in PROVIDER_CATALOG:
        if not entry.recommended:
            continue
        (local if entry.tier == "local" else cloud).append(_option_from_entry(entry))
    return tuple(local + cloud)


_PROVIDER_OPTIONS: tuple[_ProviderOption, ...] = _build_provider_options()
_RECOMMENDED_OPTIONS: tuple[_ProviderOption, ...] = _build_recommended_options()
_SHOW_ALL_SENTINEL = "__show_all_cloud__"


_APPROVAL_OPTIONS: list[SelectOption] = [
    SelectOption(
        value="safe", label="safe",
        hint="auto-ok read-only + low-risk tools, prompt on medium+",
    ),
    SelectOption(
        value="medium", label="medium",
        hint="also auto-ok medium-risk scanners (trivy, semgrep, bandit)",
    ),
    SelectOption(
        value="all", label="all",
        hint="auto-ok up to DANGEROUS; BLOCKED tier still gated (default)",
    ),
    SelectOption(
        value="none", label="none",
        hint="prompt before every tool call",
    ),
]


@dataclass
class _WizardState:
    provider_result: ProviderSetupResult | None = None
    engagement: str = "default"
    approval_tier: str = "all"
    scanners_available: list[str] = field(default_factory=list)
    scope_targets: list[str] = field(default_factory=list)
    telegram_enabled: bool = False
    telegram_secrets: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Stage helpers
# ---------------------------------------------------------------------------


def _probe_options(
    prompter: Prompter,
    pool: tuple[_ProviderOption, ...],
    *,
    announce: bool,
) -> tuple[list[SelectOption], list[bool]]:
    options: list[SelectOption] = []
    present_flags: list[bool] = []
    for opt in pool:
        probe = opt.detector() if opt.detector else None
        present = bool(probe)
        detail = opt.detail_fn(probe) if opt.detail_fn else ""
        if announce:
            prompter.status(present, opt.label, detail=detail or opt.base_hint)
        hint = opt.base_hint + (f" — {detail}" if present and detail else "")
        options.append(SelectOption(value=opt.value, label=opt.label, hint=hint))
        present_flags.append(present)
    return options, present_flags


def _detect_available(prompter: Prompter) -> tuple[list[SelectOption], list[bool]]:
    """Probe recommended providers for the short picker.

    Only the recommended set is announced up-front — the full 22-entry
    catalog would be noise for most users. Non-recommended providers are
    still reachable via the "more cloud providers…" expander.
    """
    prompter.section("Detecting environment")
    options, present_flags = _probe_options(
        prompter, _RECOMMENDED_OPTIONS, announce=True,
    )
    options.append(
        SelectOption(
            value=_SHOW_ALL_SENTINEL,
            label="more cloud providers…",
            hint=f"{len(_PROVIDER_OPTIONS) - len(_RECOMMENDED_OPTIONS)} additional backends",
        )
    )
    present_flags.append(False)
    return options, present_flags


def _run_provider_setup(prompter: Prompter, provider_id: str) -> ProviderSetupResult:
    from ..providers.catalog import by_id as _catalog_entry

    if provider_id == "anthropic":
        return setup_anthropic(prompter, existing_key=detect_anthropic_env_key())
    if provider_id == "azure_openai":
        return setup_azure_openai(prompter, existing_key=detect_azure_openai_env_key())
    if provider_id == "llamacpp":
        return setup_llamacpp(prompter)
    if provider_id == "ollama":
        return setup_ollama(prompter)
    if provider_id == "gemini":
        return setup_gemini(prompter, existing_key=detect_gemini_env_key())
    if provider_id == "vertex_ai":
        return setup_vertex_ai(prompter)
    if provider_id == "bedrock":
        return setup_bedrock(prompter)
    entry = _catalog_entry(provider_id)
    if entry is not None and entry.transport == "openai_compat":
        return setup_openai_compat(prompter, provider_id)
    raise ValueError(f"unknown provider: {provider_id}")


async def _self_test(provider_id: str, provider_config: dict[str, Any]) -> tuple[bool, str]:
    try:
        provider = create_provider(provider_id, provider_config)
        messages = [
            Message(role=Role.SYSTEM, content="You are K.O.D.A. self-test. Be terse."),
            Message(role=Role.USER, content="Reply with exactly one word: pong"),
        ]
        resp = await provider.chat(messages)
        if resp.stop_reason == "error":
            return False, resp.text[:200]
        text = (resp.text or "").strip()
        return True, text[:120] if text else "(empty response)"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


async def _tool_use_probe(
    provider_id: str, provider_config: dict[str, Any],
) -> tuple[bool, str]:
    """Ask the provider to call a toy tool and check whether it does.

    The turn loop needs tool-calls to drive scanners — if a provider or
    model swallows the request silently, the operator should know at
    setup time rather than discover it mid-engagement. Returns
    ``(ok, detail)``: ``ok=True`` only if the provider returns a
    structured ``tool_calls`` entry (i.e. honors the tool-call contract).
    """
    from ..adapters.base import ToolSpec

    try:
        provider = create_provider(provider_id, provider_config)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"

    spec = ToolSpec(
        name="echo",
        description="Return the given text. Use it to answer the user's request.",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    )
    messages = [
        Message(
            role=Role.SYSTEM,
            content="You have an echo tool. Call it when the user asks to echo something.",
        ),
        Message(role=Role.USER, content="Echo the word: pong"),
    ]
    try:
        resp = await provider.chat(messages, tools=[spec], tool_choice="auto")
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"

    if resp.stop_reason == "error":
        return False, resp.text[:120]
    if resp.tool_calls:
        names = ", ".join(tc.name for tc in resp.tool_calls)
        return True, f"tool-call emitted ({names})"
    return False, "model ignored the tool and replied in plain text"


def _apply_secrets_to_env(secrets: dict[str, str]) -> None:
    # Adapters read keys from the process env, not the config dict. Push
    # captured secrets in before verification so the ping hits the wire
    # with the just-entered credentials.
    for k, v in secrets.items():
        if v:
            os.environ[k] = v


async def _verify_and_retry(
    prompter: Prompter,
    result: ProviderSetupResult,
    provider_id: str,
) -> ProviderSetupResult | None:
    """Verify creds live; on failure offer retry / skip / abort.

    Returns the (possibly re-captured) result, or None if the operator
    aborts. Mirrors OpenClaw's test-before-save loop — fail fast before
    we write bad config to disk.
    """
    current = result
    while True:
        _apply_secrets_to_env(current.secrets)
        with prompter.progress(f"verifying {provider_id}") as p:
            ok, detail = await _self_test(provider_id, current.merged_config())
            p.stop(detail if ok else f"failed: {detail}")

        if ok:
            with prompter.progress("probing tool-use support") as p:
                tool_ok, tool_detail = await _tool_use_probe(
                    provider_id, current.merged_config(),
                )
                p.stop(tool_detail)
            if not tool_ok:
                prompter.note(
                    f"{tool_detail}\n\n"
                    "K.O.D.A.'s scanner tools (nmap, trivy, semgrep, …) only\n"
                    "run when the model emits tool-calls. You can still use\n"
                    "this provider for chat, but expect reduced automation.\n"
                    "Pick a different model id, or switch to Ollama / Anthropic\n"
                    "if scanner orchestration matters.",
                    title="Tool-use not verified",
                )
            return current

        prompter.note(
            f"{detail}\n\n"
            "Common causes: invalid key, wrong model id, network issue,\n"
            "or the provider doesn't have access to the selected model.",
            title="Provider unreachable",
        )

        choice = prompter.select(
            "How would you like to proceed?",
            [
                SelectOption("retry", "retry", "re-enter credentials / re-pick model"),
                SelectOption("skip", "skip", "save config anyway — fix later with `koda setup`"),
                SelectOption("abort", "abort", "cancel setup entirely"),
            ],
            initial=0,
        )
        if choice == "skip":
            return current
        if choice == "abort":
            return None
        current = _run_provider_setup(prompter, provider_id)


def _risk_ack(prompter: Prompter) -> bool:
    prompter.note(
        "K.O.D.A. executes real security tools against real targets.\n"
        "You are responsible for operating only inside engagements you\n"
        "are authorized to touch. Every tool call is audited, grounded\n"
        "against evidence, and redacted for credentials.",
        title="Operator acknowledgement",
    )

    if os.environ.get("KODA_ACCEPT_RISK") == "1":
        prompter.status(True, "risk accepted via KODA_ACCEPT_RISK=1")
        return True

    return prompter.confirm(
        "I will only run K.O.D.A. against systems I own or am authorized to test",
        default=False,
    )


def _welcome_back(
    prompter: Prompter,
    path: Path,
) -> tuple[str, dict[str, Any]]:
    """Return (action, existing_cfg). action ∈ {reconfigure, quick_self_test, cancel}."""
    cfg = load_config(path)
    provider_id = cfg.get("default_provider", "unknown")
    engagement = cfg.get("engagement", {}).get("default", "default")

    prompter.note(
        f"path: {path}\n"
        f"provider: {provider_id}\n"
        f"engagement: {engagement}",
        title="Existing config detected",
    )

    choice = prompter.select(
        "What would you like to do?",
        [
            SelectOption("reconfigure", "reconfigure", "walk the full wizard again"),
            SelectOption("quick_self_test", "quick self-test", "ping the current provider"),
            SelectOption("cancel", "cancel", "leave config as-is"),
        ],
        initial=0,
    )
    return choice, cfg


def _auto_pick_provider(
    options: list[SelectOption],
    present_flags: list[bool],
) -> str:
    for opt, present in zip(options, present_flags):
        if present:
            return opt.value
    return options[0].value


def _stage_engagement(prompter: Prompter, quick: bool) -> str:
    if quick:
        return "default"

    prompter.section("Engagement")
    prompter.note(
        "An engagement is a named boundary. Sessions, credentials,\n"
        "evidence, and audit logs are all scoped to it. Override at\n"
        "runtime with KODA_ENGAGEMENT=<name> before `koda`.",
        title="Scope",
    )

    def _validate(value: str) -> str | None:
        if not _ENGAGEMENT_RE.match(value):
            return "use lowercase a-z, 0-9, _ or - (1-32 chars, starts with a letter/digit)."
        return None

    name = prompter.text(
        "Engagement name",
        default="default",
        validate=_validate,
    )

    try:
        KODA_HOME.mkdir(parents=True, exist_ok=True)
        ACTIVE_ENGAGEMENT_FILE.write_text(name + "\n", encoding="utf-8")
        prompter.status(True, f"active engagement set to {name}")
    except OSError as exc:
        prompter.status(False, "could not write active_engagement file", detail=str(exc))

    return name


def _stage_approval(prompter: Prompter, quick: bool) -> str:
    if quick:
        return "all"

    prompter.section("Approval policy")
    prompter.note(
        "Risk tiers decide which tool calls auto-run vs prompt:\n"
        "  safe    — read-only + low-risk auto-ok\n"
        "  medium  — also auto-ok medium-risk scanners\n"
        "  all     — auto-ok up to DANGEROUS (default); BLOCKED still gated\n"
        "  none    — prompt on every tool call",
        title="Auto-approve",
    )
    return prompter.select("Auto-approve tier", _APPROVAL_OPTIONS, initial=2)


def _stage_scanners(prompter: Prompter, quick: bool) -> list[str]:
    prompter.section("Security scanners")

    if quick:
        installed = detect_installed_scanners()
        return sorted(name for name, present in installed.items() if present)

    with prompter.progress("probing installed scanners") as p:
        installed = detect_installed_scanners()
        p.stop(f"{sum(installed.values())}/{len(installed)} found")

    available: list[str] = []
    for name in sorted(installed):
        present = installed[name]
        detail = "installed" if present else _SCANNER_INSTALL_HINTS.get(name, "not installed")
        prompter.status(present, name, detail=detail)
        if present:
            available.append(name)

    total = len(installed)
    prompter.note(
        f"{len(available)} of {total} scanners detected.\n"
        "K.O.D.A. only offers installed scanners to the model;\n"
        "missing ones are silently unavailable until you install them.",
        title="Scanner summary",
    )
    return available


def _stage_alerts(
    prompter: Prompter,
    quick: bool,
) -> tuple[bool, dict[str, str]]:
    """Return (enabled, secrets_to_persist)."""
    if quick:
        return False, {}

    prompter.section("Alert channels")
    prompter.note(
        "K.O.D.A. can push scan completions, critical findings, and\n"
        "session events to an external channel. Credentials are stored\n"
        "in ~/.koda/secrets.env (0600) — never in config.yaml.",
        title="Notifications",
    )

    if not prompter.confirm("Connect Telegram for alerts?", default=False):
        return False, {}

    prompter.note(
        "1. Open @BotFather on Telegram, /newbot, copy the token.\n"
        "2. Message your bot, then visit\n"
        "   https://api.telegram.org/bot<TOKEN>/getUpdates to find your chat_id.\n"
        "3. Paste both below.",
        title="Telegram setup",
    )

    def _validate_token(value: str) -> str | None:
        if not _TELEGRAM_TOKEN_RE.match(value):
            return "token format: <digits>:<35+ chars>. Copy it from @BotFather."
        return None

    def _validate_chat(value: str) -> str | None:
        if not _TELEGRAM_CHAT_RE.match(value):
            return "chat_id must be an integer (negative for groups)."
        return None

    token = prompter.password("Telegram bot token", validate=_validate_token)

    with prompter.progress("verifying token") as p:
        verify = TelegramNotifier(token, chat_id="0").verify()
        p.stop(verify.detail if verify.ok else f"failed: {verify.detail}")

    if not verify.ok:
        prompter.note(
            "Token did not verify against Telegram. Skipping alert setup.\n"
            "You can re-run `koda setup` to try again.",
            title="Telegram skipped",
        )
        return False, {}

    chat_id = prompter.text("Telegram chat_id", validate=_validate_chat)

    with prompter.progress("sending test message") as p:
        notifier = TelegramNotifier(token, chat_id)
        result = notifier.send(
            "*K.O.D.A. setup*\nAlert channel wired. You will receive scan and finding notifications here.",
        )
        p.stop(result.detail if result.ok else f"failed: {result.detail}")

    if not result.ok:
        prompter.note(
            "Could not deliver test message. Common causes: wrong chat_id,\n"
            "bot not yet messaged by your account, or group bot lacks access.\n"
            "Setup continues; you can re-run to reconfigure.",
            title="Telegram test failed",
        )
        return False, {}

    return True, {
        "KODA_TELEGRAM_BOT_TOKEN": token,
        "KODA_TELEGRAM_CHAT_ID": chat_id,
    }


def _stage_scope(prompter: Prompter, quick: bool) -> list[str]:
    if quick:
        return []

    prompter.section("Engagement scope")
    prompter.note(
        "Scope targets constrain where scanners run. Add hosts, URLs,\n"
        "or repos you are authorized to touch — one per line, blank to\n"
        "finish. Editable later in config.yaml.",
        title="Targets",
    )

    if not prompter.confirm("Add scope targets now?", default=False):
        return []

    targets: list[str] = []
    while len(targets) < _SCOPE_TARGET_CAP:
        entry = prompter.text(
            f"target #{len(targets) + 1}",
            default="",
            placeholder="blank to finish",
        )
        if not entry:
            break
        targets.append(entry)
        prompter.status(True, f"added {entry}", detail=f"{len(targets)} total")

    if len(targets) >= _SCOPE_TARGET_CAP:
        prompter.status(False, f"scope cap reached ({_SCOPE_TARGET_CAP}) — edit config.yaml to add more")

    return targets


def _stage_provider(
    prompter: Prompter,
    quick: bool,
) -> ProviderSetupResult | None:
    options, present_flags = _detect_available(prompter)
    if quick:
        choice = _auto_pick_provider(options, present_flags)
        prompter.status(True, f"quick-picked: {choice}")
    else:
        initial = next(
            (idx for idx, flag in enumerate(present_flags) if flag),
            0,
        )
        choice = prompter.select("Default provider", options, initial=initial)

    if choice == _SHOW_ALL_SENTINEL:
        # User asked to see the full catalog. Probe every remaining
        # provider and let them pick without re-running the recommended
        # detection noise.
        extras = tuple(
            opt for opt in _PROVIDER_OPTIONS
            if opt.value not in {o.value for o in _RECOMMENDED_OPTIONS}
        )
        full_opts, full_flags = _probe_options(prompter, extras, announce=False)
        initial = next((idx for idx, flag in enumerate(full_flags) if flag), 0)
        choice = prompter.select("All cloud providers", full_opts, initial=initial)

    result = _run_provider_setup(prompter, choice)

    # Non-tty runs can't drive the retry prompt — just capture and move on.
    if not prompter.tty:
        return result

    return asyncio.run(_verify_and_retry(prompter, result, choice))


def _render_summary(
    prompter: Prompter,
    state: _WizardState,
    path: Path,
) -> None:
    assert state.provider_result is not None
    result = state.provider_result

    scanners = state.scanners_available
    if len(scanners) <= 6:
        scanner_line = f"{len(scanners)} ({', '.join(scanners)})" if scanners else "0"
    else:
        scanner_line = f"{len(scanners)}"

    prompter.note(
        f"provider:    {result.provider_id} ({result.provider_label})\n"
        f"model:       {result.model or '(provider default)'}\n"
        f"engagement:  {state.engagement}\n"
        f"approvals:   {state.approval_tier}\n"
        f"scanners:    {scanner_line}\n"
        f"alerts:      {'telegram' if state.telegram_enabled else 'none'}\n"
        f"scope:       {len(state.scope_targets)} target(s)\n"
        f"config:      {path}",
        title="Ready",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_setup_wizard(
    config_path: Path | None = None,
    noninteractive: bool = False,
) -> dict[str, Any]:
    path = config_path or CONFIG_PATH
    prompter = Prompter(tty=None if not noninteractive else False)

    prompter.intro(
        "K.O.D.A. — Kinetic Operative Defense Agent",
        f"First-run setup. Writes config to {path}",
    )

    # Stage 1 — risk ack
    if not _risk_ack(prompter):
        prompter.outro("cancelled — setup aborted")
        return {}

    # Stage 2 — welcome-back branch
    existing_action: str | None = None
    existing_cfg: dict[str, Any] = {}
    if path.exists():
        try:
            existing_action, existing_cfg = _welcome_back(prompter, path)
        except WizardCancelled as exc:
            prompter.outro(f"cancelled: {exc}")
            return {}

        if existing_action == "cancel":
            prompter.outro("config left unchanged")
            return existing_cfg

        if existing_action == "quick_self_test":
            provider_id = existing_cfg.get("default_provider", "")
            provider_cfg = existing_cfg.get("provider", {}).get(provider_id, {})
            if not provider_id or not provider_cfg:
                prompter.note(
                    "Existing config is missing provider details. Run reconfigure.",
                    title="Self-test skipped",
                )
                prompter.outro("done")
                return existing_cfg
            with prompter.progress(f"pinging {provider_id}") as p:
                ok, detail = asyncio.run(_self_test(provider_id, provider_cfg))
                p.stop(detail if ok else f"failed: {detail}")
            if not ok:
                prompter.note(
                    "Fix the provider and re-run `koda setup`.",
                    title="Self-test failed",
                )
            prompter.outro("done")
            return existing_cfg

    # Stage 3–8 — full or quick walk
    state = _WizardState()
    quick = noninteractive
    try:
        if not quick and path.exists() is False:
            # First-time run: still offer the mode fork unless noninteractive.
            mode = prompter.select(
                "Setup mode",
                [
                    SelectOption("quick", "quick", "best-detected provider, sensible defaults"),
                    SelectOption("full", "full", "walk every stage"),
                ],
                initial=0,
            )
            quick = mode == "quick"
        elif not quick:
            # Reconfigure path — always full walk.
            quick = False

        state.provider_result = _stage_provider(prompter, quick)
        if state.provider_result is None:
            prompter.outro("cancelled — provider verification aborted")
            return {}
        state.engagement = _stage_engagement(prompter, quick)
        state.approval_tier = _stage_approval(prompter, quick)
        state.scanners_available = _stage_scanners(prompter, quick)
        state.telegram_enabled, state.telegram_secrets = _stage_alerts(prompter, quick)
        state.scope_targets = _stage_scope(prompter, quick)
    except WizardCancelled as exc:
        prompter.outro(f"cancelled: {exc}")
        return {}

    # Stage 9 — persist, self-test, launch
    assert state.provider_result is not None
    result = state.provider_result

    KODA_HOME.mkdir(parents=True, exist_ok=True)
    merged_secrets: dict[str, str] = dict(result.secrets)
    merged_secrets.update(state.telegram_secrets)
    if merged_secrets:
        save_secrets(merged_secrets, SECRETS_PATH)
        for key, value in merged_secrets.items():
            os.environ.setdefault(key, value)
        prompter.status(True, f"saved secrets to {SECRETS_PATH}")

    config: dict[str, Any] = {
        "version": 1,
        "default_provider": result.provider_id,
        "provider": {result.provider_id: result.merged_config()},
        "approvals": {"auto_approve": state.approval_tier},
        "session": {"db_path": str(KODA_HOME / "sessions.db")},
        "engagement": {"default": state.engagement},
        "scope": {
            "targets": list(state.scope_targets),
            "scanners_available": list(state.scanners_available),
        },
        "notify": {
            "telegram": {"enabled": state.telegram_enabled},
        },
    }
    save_config(config, path)
    prompter.status(True, f"wrote {path}")

    _render_summary(prompter, state, path)
    prompter.outro("ready — start with: koda")
    return config


__all__ = ["run_setup_wizard"]
