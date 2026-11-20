"""Banner ASCII colorido do laboratorio nginx2root."""

from __future__ import annotations

import os
import sys

ART = r"""
 _   _  _____ _____ _   ___   _____  _____   ____   ____ _______
| \ | |/ ____|_   _| \ | \ \ / /__ \|  __ \ / __ \ / __ \__   __|
|  \| | |  __  | | |  \| |\ V /   ) | |__) | |  | | |  | | | |
| . ` | | |_ | | | | . ` | > <   / /|  _  /| |  | | |  | | | |
| |\  | |__| |_| |_| |\  |/ . \ / /_| | \ \| |__| | |__| | | |
|_| \_|\_____|_____|_| \_/_/ \_\____|_|  \_\\____/ \____/  |_|
"""

SUB = "CVE-2026-123007  ·  HTTP/2 flow-control underflow  ·  by eduxcode"


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def _rgb(r: int, g: int, b: int, text: str) -> str:
    return f"\033[38;2;{r};{g};{b}m{text}\033[0m"


def _gradient(text: str, row: int, rows: int) -> str:
    # do vermelho (topo) ao ambar (base)
    t = row / max(rows - 1, 1)
    r = 255
    g = int(40 + t * 165)
    b = int(60 + (1 - t) * 20)
    return _rgb(r, g, b, text)


def render(stream=sys.stdout) -> None:
    color = _supports_color()
    lines = ART.strip("\n").splitlines()
    width = max(len(line) for line in lines)

    stream.write("\n")
    for i, line in enumerate(lines):
        pad = line.ljust(width)
        stream.write((_gradient(pad, i, len(lines)) if color else pad) + "\n")

    rule = "─" * width
    if color:
        stream.write(_rgb(90, 90, 100, rule) + "\n")
        stream.write(_rgb(180, 200, 220, SUB.center(width)) + "\n")
        stream.write(_rgb(90, 90, 100, rule) + "\n\n")
    else:
        stream.write(rule + "\n" + SUB.center(width) + "\n" + rule + "\n\n")
    stream.flush()


if __name__ == "__main__":
    render()
