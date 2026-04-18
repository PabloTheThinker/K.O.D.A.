"""Shared terminal wizard primitives for K.O.D.A.

Modeled on OpenClaw's WizardPrompter API, but self-contained and dependency
free. Uses raw termios input for arrow-key navigation when available, with
plain numbered fallbacks otherwise.
"""
from __future__ import annotations

import re
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator


GOLD = "\033[38;5;178m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"
CLEAR_LINE = "\033[2K"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class SelectOption:
    value: str
    label: str
    hint: str = ""


class WizardCancelled(Exception):
    """Raised when the user aborts or input cannot be completed."""


class ProgressHandle:
    def __init__(self, label: str, *, tty: bool) -> None:
        self.label = label
        self.tty = tty
        self._message = ""
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._stopped = False

    @property
    def closed(self) -> bool:
        return self._closed

    def update(self, msg: str) -> None:
        if self._closed:
            return
        with self._lock:
            self._message = msg

    def stop(self, msg: str = "") -> None:
        if self._closed:
            return
        if msg:
            self.update(msg)
        self._closed = True
        self._stopped = True
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=0.25)

        message = self._current_message()
        if self.tty:
            final = self._compose_text(message)
            sys.stdout.write(f"\r{CLEAR_LINE}{GREEN}✓{RESET} {final}\n")
        else:
            sys.stdout.write(f" {GREEN}✓{RESET}")
            if message:
                sys.stdout.write(f" {message}")
            sys.stdout.write("\n")
        sys.stdout.flush()

    def abort(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=0.25)
        if self.tty:
            sys.stdout.write(f"\r{CLEAR_LINE}")
        else:
            sys.stdout.write("\n")
        sys.stdout.flush()

    def start(self) -> None:
        if self.tty:
            self._thread = threading.Thread(target=self._spin_tty, daemon=True)
            self._thread.start()
        else:
            sys.stdout.write(f"{DIM}{self.label}{RESET}")
            sys.stdout.flush()
            self._thread = threading.Thread(target=self._spin_plain, daemon=True)
            self._thread.start()

    def _current_message(self) -> str:
        with self._lock:
            return self._message

    def _compose_text(self, message: str) -> str:
        return self.label if not message else f"{self.label} — {message}"

    def _spin_tty(self) -> None:
        frames = "|/-\\"
        idx = 0
        while not self._stop_event.is_set():
            text = self._compose_text(self._current_message())
            frame = frames[idx % len(frames)]
            sys.stdout.write(f"\r{CLEAR_LINE}{DIM}{frame}{RESET} {text}")
            sys.stdout.flush()
            idx += 1
            if self._stop_event.wait(0.1):
                break

    def _spin_plain(self) -> None:
        while not self._stop_event.is_set():
            sys.stdout.write(".")
            sys.stdout.flush()
            if self._stop_event.wait(0.1):
                break


class Prompter:
    def __init__(self, *, tty: bool | None = None) -> None:
        self.tty = (sys.stdin.isatty() and sys.stdout.isatty()) if tty is None else tty

    # --- Banners / notes ---
    def intro(self, title: str, subtitle: str = "") -> None:
        width = max(24, _visible_len(title) + 6)
        bar = "━" * width
        self._out("\n")
        self._out(f"{GOLD}{BOLD}{bar}{RESET}\n")
        self._out(f"{GOLD}{BOLD}{title}{RESET}\n")
        if subtitle:
            self._out(f"{DIM}{subtitle}{RESET}\n")
        self._out(f"{GOLD}{DIM}{bar}{RESET}\n\n")

    def outro(self, message: str) -> None:
        width = max(20, _visible_len(message) + 6)
        bar = "─" * width
        self._out("\n")
        self._out(f"{GREEN}{DIM}{bar}{RESET}\n")
        self._out(f"{GREEN}{DIM}{message}{RESET}\n")
        self._out(f"{GREEN}{DIM}{bar}{RESET}\n")

    def note(self, message: str, title: str = "") -> None:
        body_lines = message.splitlines() or [""]
        content_lines: list[str] = []
        if title:
            content_lines.append(f"{BOLD}{title}{RESET}")
        content_lines.extend(body_lines)

        width = max((_visible_len(line) for line in content_lines), default=0)
        border = "─" * (width + 4)

        self._out(f"┌{border}┐\n")
        for line in content_lines:
            self._out(f"│  {_pad_ansi(line, width)}  │\n")
        self._out(f"└{border}┘\n")

    def status(self, ok: bool, name: str, detail: str = "") -> None:
        mark = f"{GREEN}✓{RESET}" if ok else f"{DIM}○{RESET}"
        line = f"  {mark} {name}"
        if detail:
            line += f" {DIM}— {detail}{RESET}"
        self._out(f"{line}\n")

    def section(self, title: str) -> None:
        self._out(f"\n{GOLD}━━━ {title}{RESET}\n")

    # --- Input ---
    def text(
        self,
        message: str,
        *,
        default: str = "",
        placeholder: str = "",
        validate: Callable[[str], str | None] | None = None,
    ) -> str:
        prompt = self._text_prompt(message, default=default, placeholder=placeholder)

        for _ in range(5):
            try:
                raw = self._read_line(prompt)
            except KeyboardInterrupt as exc:
                raise WizardCancelled("user aborted") from exc

            value = raw.strip()
            if not value:
                if default:
                    value = default
                elif not self.tty:
                    raise WizardCancelled("no input available")

            if validate is not None:
                error = validate(value)
                if error:
                    self._err(f"{RED}{error}{RESET}\n")
                    continue
            return value

        raise WizardCancelled("too many invalid attempts")

    def password(
        self,
        message: str,
        *,
        validate: Callable[[str], str | None] | None = None,
    ) -> str:
        import getpass

        prompt = f"{CYAN}{message}{RESET}: "

        for _ in range(5):
            try:
                value = getpass.getpass(prompt, stream=sys.stdout).strip()
            except KeyboardInterrupt as exc:
                raise WizardCancelled("user aborted") from exc
            except EOFError as exc:
                raise WizardCancelled("no input available") from exc

            if not value and not self.tty:
                raise WizardCancelled("no input available")

            if validate is not None:
                error = validate(value)
                if error:
                    self._err(f"{RED}{error}{RESET}\n")
                    continue
            return value

        raise WizardCancelled("too many invalid attempts")

    def confirm(self, message: str, *, default: bool = True) -> bool:
        hint = "Y/n" if default else "y/N"
        prompt = f"{CYAN}{message} [{hint}]{RESET}: "

        if not self.tty:
            answer = "yes" if default else "no"
            self._out(f"{CYAN}{message} [{hint}]{RESET}: {DIM}{answer}{RESET}\n")
            return default

        for _ in range(5):
            try:
                raw = input(prompt)
            except KeyboardInterrupt as exc:
                raise WizardCancelled("user aborted") from exc
            except EOFError:
                return default

            value = raw.strip().lower()
            if not value:
                return default
            if value in {"y", "yes"}:
                return True
            if value in {"n", "no"}:
                return False
            self._err(f"{YELLOW}Please enter yes or no.{RESET}\n")

        raise WizardCancelled("too many invalid attempts")

    def select(
        self,
        message: str,
        options: list[SelectOption],
        *,
        initial: int = 0,
    ) -> str:
        if not options:
            raise ValueError("select() requires at least one option")

        initial = max(0, min(initial, len(options) - 1))

        if not self.tty:
            chosen = options[initial]
            self._out(f"{BOLD}{message}{RESET} {DIM}{chosen.label}{RESET}\n")
            return chosen.value

        if _can_raw(self.tty):
            return self._select_raw(message, options, initial)
        return self._select_fallback(message, options, initial)

    def multiselect(
        self,
        message: str,
        options: list[SelectOption],
        *,
        initial: list[str] | None = None,
        min_choices: int = 1,
    ) -> list[str]:
        if not options:
            raise ValueError("multiselect() requires at least one option")
        if min_choices < 0:
            raise ValueError("min_choices must be >= 0")
        if min_choices > len(options):
            raise ValueError("min_choices cannot exceed number of options")

        initial_values = _initial_values(options, initial or [])
        default_values = _default_multiselect_values(options, initial_values, min_choices)

        if not self.tty:
            labels = _labels_for_values(options, default_values)
            summary = ", ".join(labels)
            self._out(f"{BOLD}{message}{RESET} {DIM}{summary}{RESET}\n")
            return default_values

        if _can_raw(self.tty):
            return self._multiselect_raw(message, options, initial_values, min_choices)
        return self._multiselect_fallback(message, options, default_values, min_choices)

    # --- Progress ---
    @contextmanager
    def progress(self, label: str) -> Iterator[ProgressHandle]:
        handle = ProgressHandle(label, tty=self.tty)
        handle.start()
        try:
            yield handle
        except BaseException:
            handle.abort()
            raise
        else:
            if not handle.closed:
                handle.stop()

    # --- Internal helpers ---
    def _out(self, text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()

    def _err(self, text: str) -> None:
        sys.stderr.write(text)
        sys.stderr.flush()

    def _text_prompt(self, message: str, *, default: str, placeholder: str) -> str:
        suffix = ""
        if default:
            suffix = f" {DIM}[{default}]{RESET}"
        elif placeholder:
            suffix = f" {DIM}({placeholder}){RESET}"
        return f"{CYAN}{message}{RESET}{suffix}: "

    def _read_line(self, prompt: str) -> str:
        if self.tty:
            return input(prompt)
        self._out(prompt)
        line = sys.stdin.readline()
        if line == "":
            return ""
        return line.rstrip("\r\n")

    def _select_raw(
        self,
        message: str,
        options: list[SelectOption],
        initial: int,
    ) -> str:
        cursor = initial
        count = len(options)

        def render_lines() -> list[str]:
            lines = [f"{BOLD}{message}{RESET}"]
            for idx, opt in enumerate(options):
                if idx == cursor:
                    lines.append(f"  {GREEN}› {opt.label}{RESET}")
                else:
                    lines.append(f"  {DIM}  {opt.label}{RESET}")
                if opt.hint:
                    lines.append(f"    {DIM}{opt.hint}{RESET}")
            return lines

        def draw() -> int:
            lines = render_lines()
            for line in lines:
                self._out(f"{line}\n")
            return len(lines)

        drawn = draw()
        try:
            while True:
                key = _read_key()
                if key in ("up", "k"):
                    cursor = (cursor - 1) % count
                elif key in ("down", "j"):
                    cursor = (cursor + 1) % count
                elif key == "enter":
                    _clear_rendered_lines(drawn)
                    choice = options[cursor]
                    self._out(f"{BOLD}{message}{RESET} {GREEN}{choice.label}{RESET}\n")
                    return choice.value
                elif key == "esc":
                    _clear_rendered_lines(drawn)
                    choice = options[initial]
                    self._out(f"{BOLD}{message}{RESET} {DIM}{choice.label}{RESET}\n")
                    return choice.value
                else:
                    continue

                _clear_rendered_lines(drawn)
                drawn = draw()
        except KeyboardInterrupt as exc:
            _clear_rendered_lines(drawn)
            raise WizardCancelled("user aborted") from exc

    def _select_fallback(
        self,
        message: str,
        options: list[SelectOption],
        initial: int,
    ) -> str:
        self._out(f"{BOLD}{message}{RESET}\n")
        for idx, opt in enumerate(options):
            marker = f"{GOLD}*{RESET}" if idx == initial else " "
            self._out(f"  {marker} {idx + 1}) {opt.label}\n")
            if opt.hint:
                self._out(f"      {DIM}{opt.hint}{RESET}\n")

        prompt = f"{CYAN}choice [{initial + 1}]{RESET}: "

        for _ in range(5):
            try:
                raw = input(prompt)
            except KeyboardInterrupt as exc:
                raise WizardCancelled("user aborted") from exc
            except EOFError:
                raw = ""

            value = raw.strip()
            if not value:
                chosen = options[initial]
                self._out(f"{BOLD}{message}{RESET} {GREEN}{chosen.label}{RESET}\n")
                return chosen.value

            try:
                idx = int(value) - 1
            except ValueError:
                self._err(f"{YELLOW}Please enter a valid option number.{RESET}\n")
                continue

            if 0 <= idx < len(options):
                chosen = options[idx]
                self._out(f"{BOLD}{message}{RESET} {GREEN}{chosen.label}{RESET}\n")
                return chosen.value

            self._err(f"{YELLOW}Choice out of range.{RESET}\n")

        raise WizardCancelled("too many invalid attempts")

    def _multiselect_raw(
        self,
        message: str,
        options: list[SelectOption],
        initial_values: list[str],
        min_choices: int,
    ) -> list[str]:
        cursor = 0
        selected = set(initial_values)

        def ordered_selection() -> list[str]:
            return [opt.value for opt in options if opt.value in selected]

        def render_lines() -> list[str]:
            lines = [
                f"{BOLD}{message}{RESET}",
                f"{DIM}space/tab to toggle · enter to continue{RESET}",
            ]
            for idx, opt in enumerate(options):
                checked = "[x]" if opt.value in selected else "[ ]"
                if idx == cursor:
                    lines.append(f"  {GREEN}› {checked} {opt.label}{RESET}")
                else:
                    lines.append(f"  {DIM}  {checked} {opt.label}{RESET}")
                if opt.hint:
                    lines.append(f"    {DIM}{opt.hint}{RESET}")
            return lines

        def draw() -> int:
            lines = render_lines()
            for line in lines:
                self._out(f"{line}\n")
            return len(lines)

        drawn = draw()
        try:
            while True:
                key = _read_key()
                if key in ("up", "k"):
                    cursor = (cursor - 1) % len(options)
                elif key in ("down", "j"):
                    cursor = (cursor + 1) % len(options)
                elif key in ("space", "tab"):
                    value = options[cursor].value
                    if value in selected:
                        selected.remove(value)
                    else:
                        selected.add(value)
                elif key == "enter":
                    chosen = ordered_selection()
                    if len(chosen) < min_choices:
                        need = "choice" if min_choices == 1 else "choices"
                        self._err(
                            f"{YELLOW}Please select at least {min_choices} {need}.{RESET}\n"
                        )
                        continue
                    _clear_rendered_lines(drawn)
                    labels = ", ".join(_labels_for_values(options, chosen))
                    self._out(f"{BOLD}{message}{RESET} {GREEN}{labels}{RESET}\n")
                    return chosen
                else:
                    continue

                _clear_rendered_lines(drawn)
                drawn = draw()
        except KeyboardInterrupt as exc:
            _clear_rendered_lines(drawn)
            raise WizardCancelled("user aborted") from exc

    def _multiselect_fallback(
        self,
        message: str,
        options: list[SelectOption],
        default_values: list[str],
        min_choices: int,
    ) -> list[str]:
        self._out(f"{BOLD}{message}{RESET}\n")
        for idx, opt in enumerate(options):
            marker = "[x]" if opt.value in default_values else "[ ]"
            self._out(f"  {idx + 1}) {marker} {opt.label}\n")
            if opt.hint:
                self._out(f"      {DIM}{opt.hint}{RESET}\n")

        default_indices = [
            str(idx + 1) for idx, opt in enumerate(options) if opt.value in default_values
        ]
        default_text = ",".join(default_indices)
        prompt = f"{CYAN}pick [{default_text}]{RESET}: "

        for _ in range(5):
            try:
                raw = input(prompt)
            except KeyboardInterrupt as exc:
                raise WizardCancelled("user aborted") from exc
            except EOFError:
                raw = ""

            value = raw.strip()
            if not value:
                chosen = default_values
            else:
                try:
                    chosen = _parse_multiselect_input(value, options)
                except ValueError as exc:
                    self._err(f"{YELLOW}{exc}{RESET}\n")
                    continue

            if not chosen and min_choices > 0:
                self._err(f"{YELLOW}Please select at least {min_choices}.{RESET}\n")
                continue

            if len(chosen) < min_choices:
                need = "choice" if min_choices == 1 else "choices"
                self._err(f"{YELLOW}Please select at least {min_choices} {need}.{RESET}\n")
                continue

            labels = ", ".join(_labels_for_values(options, chosen))
            self._out(f"{BOLD}{message}{RESET} {GREEN}{labels}{RESET}\n")
            return chosen

        raise WizardCancelled("too many invalid attempts")


def _can_raw(tty_enabled: bool) -> bool:
    if not tty_enabled:
        return False
    try:
        import termios  # noqa: F401
        import tty  # noqa: F401
        return True
    except ImportError:
        return False


def _read_key() -> str:
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            seq = sys.stdin.read(2)
            if seq == "[A":
                return "up"
            if seq == "[B":
                return "down"
            return "esc"
        if ch in ("\r", "\n"):
            return "enter"
        if ch == "\t":
            return "tab"
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == " ":
            return "space"
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _clear_rendered_lines(count: int) -> None:
    for _ in range(count):
        sys.stdout.write("\033[A" + CLEAR_LINE)
    sys.stdout.flush()


def _visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def _pad_ansi(text: str, width: int) -> str:
    return text + (" " * max(0, width - _visible_len(text)))


def _initial_values(options: list[SelectOption], initial: list[str]) -> list[str]:
    allowed = {opt.value for opt in options}
    seen: set[str] = set()
    values: list[str] = []
    for value in initial:
        if value in allowed and value not in seen:
            values.append(value)
            seen.add(value)
    return values


def _default_multiselect_values(
    options: list[SelectOption],
    initial_values: list[str],
    min_choices: int,
) -> list[str]:
    chosen = list(initial_values)
    seen = set(chosen)
    if len(chosen) >= min_choices:
        return chosen
    for opt in options:
        if opt.value not in seen:
            chosen.append(opt.value)
            seen.add(opt.value)
            if len(chosen) >= min_choices:
                break
    return chosen


def _labels_for_values(options: list[SelectOption], values: list[str]) -> list[str]:
    selected = set(values)
    return [opt.label for opt in options if opt.value in selected]


def _parse_multiselect_input(raw: str, options: list[SelectOption]) -> list[str]:
    value = raw.strip()
    if value.lower().startswith("pick "):
        value = value[5:].strip()

    if not value:
        return []

    tokens = [token for token in re.split(r"[\s,]+", value) if token]
    chosen: list[str] = []
    seen: set[str] = set()

    for token in tokens:
        try:
            idx = int(token) - 1
        except ValueError as exc:
            raise ValueError(f"not a number: {token!r}") from exc
        if idx < 0 or idx >= len(options):
            raise ValueError(f"choice out of range: {token}")
        option_value = options[idx].value
        if option_value not in seen:
            chosen.append(option_value)
            seen.add(option_value)

    return chosen


__all__ = ["Prompter", "SelectOption", "WizardCancelled", "ProgressHandle"]
