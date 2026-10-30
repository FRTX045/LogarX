"""The net under the interface.

A mistake anywhere in the window used to end the process. Qt calls its own
handler for an exception that escapes a slot, and that handler aborts: no
traceback, no dialog, not even an exit status a person could read. Measured
while writing this: exit code -1073740791 and zero bytes of output. The window
simply vanished, and finding the cause took a line-by-line trace of the handler
it happened in.

That is the wrong failure for a forensic tool. An investigator who loses the
window mid-case cannot tell a bug from a crashed machine, cannot say what they
were doing when it went, and has nothing to report.

Replacing `sys.excepthook` is the whole fix. Qt only aborts once the exception
reaches *its* handler, so a hook of our own keeps it away: the slot returns, the
window carries on, and the reader is told what happened. Free of Qt, so what it
decides can be checked without a display — and checked it is, against real
signals, because what has to hold is precisely that Qt never gets the chance.
"""

from __future__ import annotations

import sys
import traceback
from contextlib import suppress
from types import TracebackType
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["install", "write_down"]

#: How many times the reader is shown the same trouble before the net falls
#: silent. A slot that raises on every repaint raises hundreds of times, and a
#: dialog per repaint cannot be dismissed faster than it returns — a net that
#: made the window less usable than the crash did. Nothing is lost by the limit:
#: everything past it is still written down.
_ENOUGH = 3

#: Not caught. These are the reader leaving, not the tool breaking, and a net
#: that swallowed them would print a message and carry on running.
_LEAVING = (KeyboardInterrupt, SystemExit)


def write_down(detail: str, stream: TextIO | None) -> None:
    """Write `detail` to `stream` without ever failing.

    The window writes a failure down before it shows it, and the writing must
    not be what fails. Redirected on Windows, stderr is the code page, which has
    no bytes for a user folder named in Chinese: printing raised, and the dialog
    after it never came up. What the stream cannot encode is escaped instead.
    The packaged application has no console, so no stream at all.
    """
    if stream is None:
        return
    encoding = getattr(stream, "encoding", None) or "utf-8"
    text = detail.encode(encoding, "backslashreplace").decode(encoding)
    # A stream closed or gone under us leaves nowhere to write, and that too
    # must not stop the dialog.
    with suppress(OSError, ValueError):
        print(text, file=stream, end="" if text.endswith("\n") else "\n")


def install(
    report: Callable[[str, str], None],
    *,
    limit: int = _ENOUGH,
    stream: TextIO | None = None,
) -> Callable[
    [type[BaseException], BaseException, TracebackType | None],
    None,
]:
    """Send unhandled exceptions to `report` instead of letting Qt abort.

    `report` is given a sentence for the reader and the traceback behind it —
    the same pair a failed job already hands the window, and worded the same
    way, because two wordings for one kind of trouble read as two kinds.

    Returns the hook it replaced, so a caller can put it back.
    """
    previous = sys.excepthook
    seen = 0

    def net(
        kind: type[BaseException],
        value: BaseException,
        tb: TracebackType | None,
    ) -> None:
        nonlocal seen
        if issubclass(kind, _LEAVING):
            previous(kind, value, tb)
            return
        detail = "".join(traceback.format_exception(kind, value, tb))
        seen += 1
        if seen <= limit:
            # `report` writes the traceback down itself, so it is not repeated
            # here. Past the limit nobody is doing that any more, and the line
            # below takes it over.
            report(f"{kind.__name__}: {value}", detail)
            return
        write_down(detail, stream or sys.stderr)

    sys.excepthook = net
    return previous
