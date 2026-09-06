"""What every `logarc` command shares: the consoles, and how a command fails.

Its own module so the command groups can be split across files without one
importing the other for a print function.
"""

from __future__ import annotations

import typer
from rich.console import Console

__all__ = ["console", "errors", "fail", "path_line"]

console = Console()
errors = Console(stderr=True)


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
