"""What the window says about the stretch of time it is showing.

No Qt, for the same reason `gui.arrangement` and `gui.recent` have none: the
words a control puts on screen are a decision, and a decision should be
checkable without a display.

One idea runs through all of it. A filter that is not set is the ordinary state
and should read as ordinary — `whole case`, not `9,910 of 9,910 clients`, which
is a program telling you it has done nothing. And a filter that leaves nothing
has still answered the question; `0 of 9,910` reads as a failure, so it says
what it looked at instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from zodiarc.style import plural

if TYPE_CHECKING:
    from datetime import datetime

    from zodiarc.core.window import TimeWindow

__all__ = ["nobody_here", "spoken", "summary"]

#: How the far end of a stretch is written when both ends sit inside one day:
#: the time alone, so a window inside an afternoon does not say the date twice
#: for no reason. The other end goes through `_moment`, which writes the date.
_TIME_ONLY = "%H:%M"


def summary(
    window: TimeWindow,
    *,
    clients: int,
    all_clients: int,
    requests: int | None = None,
    all_requests: int | None = None,
) -> str:
    """How much of the case is left, in the words beside the control.

    The request counts join in once a client is selected, so one line can carry
    both numbers that have to agree: what the filter did to the list, and what
    it did to the graph. Those two disagreeing on one screen is the failure this
    whole feature was shaped to avoid, and this is where a reader would see it.
    """
    if window.is_open:
        return "All time"
    said = _of(clients, all_clients, "client")
    if requests is None or all_requests is None:
        return said
    return f"{said} · {_of(requests, all_requests, 'request')}"


def _of(some: int, every: int, noun: str) -> str:
    """`155 of 9,910 clients`.

    The noun agrees with the total, not with the part: it is the total the
    phrase is really about, and "1 of 9,910 client" is not English.
    """
    return f"{some:,} of {plural(every, noun)}"


def nobody_here(window: TimeWindow) -> str:
    """What the client list says when the stretch holds no one.

    Names the stretch rather than counting to zero. Nothing was found, but
    something was answered — often the thing that was being asked.
    """
    if window.is_open:
        return "No clients in this case."
    return f"No client was active {spoken(window)}."


def spoken(window: TimeWindow) -> str:
    """A stretch of time as someone would say it."""
    if window.is_open:
        return "All time"
    if window.start is None:
        return f"up to {_moment(window.end)}"
    if window.end is None:
        return f"{_moment(window.start)} onwards"
    if window.start.date() == window.end.date():
        return f"{_moment(window.start)} → {window.end.strftime(_TIME_ONLY)}"
    return f"{_moment(window.start)} → {_moment(window.end)}"


def _moment(when: datetime | None) -> str:
    assert when is not None
    # `%-d` is not portable; the day is trimmed here so one format string serves
    # both platforms rather than two that can drift apart.
    return when.strftime("%d %b %H:%M").lstrip("0")
