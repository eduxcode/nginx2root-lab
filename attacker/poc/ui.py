"""Terminal output for the lab: stages, colors and formatting."""

from __future__ import annotations

import os
import sys

ENABLED = not os.environ.get("NO_COLOR") and (
    sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))
)

RESET = "\033[0m"


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}{RESET}" if ENABLED else text


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def red(t: str) -> str:
    return _c("38;5;203", t)


def green(t: str) -> str:
    return _c("38;5;114", t)


def yellow(t: str) -> str:
    return _c("38;5;221", t)


def blue(t: str) -> str:
    return _c("38;5;75", t)


def magenta(t: str) -> str:
    return _c("38;5;213", t)


def cyan(t: str) -> str:
    return _c("38;5;80", t)


def grey(t: str) -> str:
    return _c("38;5;245", t)


def fmt(n: int) -> str:
    return f"{n:,}"


def human(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{n} B"


def stage(number: int, title: str, detail: str = "") -> None:
    tag = bold(magenta(f"[{number:02d}]"))
    name = bold(title.ljust(12))
    line = f"{tag} {name} {detail}"
    print()
    print(line)
    print(grey("     " + "─" * min(len(detail) + 18, 72)))


def ok(text: str) -> None:
    print(f"     {green('✓')} {text}")


def warn(text: str) -> None:
    print(f"     {yellow('!')} {text}")


def bad(text: str) -> None:
    print(f"     {red('✗')} {text}")


def arrow(text: str) -> None:
    print(f"     {blue('→')} {text}")


def note(text: str) -> None:
    print(f"       {grey(text)}")
