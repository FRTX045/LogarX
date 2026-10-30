"""What every `zodiarc` command shares: the consoles, and how a command fails.

Its own module so the command groups can be split across files without one
importing the other for a print function.
"""

from __future__ import annotations

import os
import sys

import typer
from rich.console import Console

__all__ = ["console", "errors", "fail", "path_line", "safe_output"]

console = Console()
errors = Console(stderr=True)


def safe_output() -> None:
    """Let output sent to a file, a pipe or `NUL` hold any character a log can.

    On Windows Python encodes redirected output in the locale's code page —
    cp1252 here — and refuses everything outside it. A log line is whatever the
    client sent, so evidence redirected to a file stopped half way on a
    User-Agent in Chinese; and `NUL` reports itself as a terminal, so Rich drew
    its braille spinner into cp1252 and every command with progress failed on
    `> NUL`.

    Redirected output becomes UTF-8, which loses nothing and is what the log
    itself is. A console is left alone — Python already writes to it through
    the wide-character API — and so is an encoding somebody chose with
    `PYTHONIOENCODING`, except that what it cannot hold is written as an escape
    rather than failing the command.
    """
    chosen = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if reconfigure is None or encoding == "utf8":
            continue
        if chosen:
            reconfigure(errors="backslashreplace")
        else:
            reconfigure(encoding="utf-8", errors="backslashreplace")


def fail(message: str) -> typer.Exit:
    """Report a user error on stderr and return the exit to raise."""
    errors.print(f"[red]error:[/red] {message}", soft_wrap=True)
    return typer.Exit(code=1)


def path_line(message: str) -> None:
    """Print a line carrying a path, without breaking the path.

    Rich wraps to the console width, and a path offers no spaces to break at, so
    a long one is cut mid-word: `...Desktop-BlackHa` on one line and `t\\...` on
    the next. Every path this tool prints is the argument to the next command,
    and one that cannot be copied out of the terminal is one the reader has to
    retype. `soft_wrap` leaves the line whole and lets the terminal fold it,
    which is the difference between a display that wraps and text that has had
    newlines put through it.
    """
    console.print(message, soft_wrap=True)
