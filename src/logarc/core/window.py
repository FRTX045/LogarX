"""A slice of time, and the name it gives whatever is reconstructed inside it.

A reconstruction is only meaningful together with the stretch of time it covers.
Filtering a case to one window does not hide part of an answer — it asks a
different question, and gets a different answer: fewer requests, possibly fewer
sessions, activities cut where the window cuts.

That is why a window carries a `tag` and identifiers carry it with them. Two
reports for one client over two windows describe different things, and without
the window in the name they would say so using the same identifiers. A folder of
evidence holding both would have nothing in it to tell them apart.

An **open** window is the one exception, and it is deliberate: it means "the
whole case", it names nothing, and it leaves every identifier exactly as it was
before this module existed. Every case and report already on disk stays valid.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

__all__ = ["EVERYTHING", "TimeWindow"]

#: How an end is written into an identifier. Seconds are always present:
#: truncated to minutes, two windows a second apart would produce identical
#: identifiers for different content, which is the failure the tag exists to
#: prevent.
_STAMP: Final = "%Y%m%dT%H%M%S"

#: What separates the two ends. Not a character that can occur in a stamp, so a
#: tag can be split before either half is read.
_BETWEEN: Final = "-"


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """The stretch of time a reconstruction covers.

    Either end may be absent, which is how "everything since 3am" and
    "everything up to the reboot" are said. Both absent is the whole case.
    """

    start: datetime | None = None
    end: datetime | None = None

    def __post_init__(self) -> None:
        if self.start is not None and self.end is not None and self.end < self.start:
            raise ValueError(f"a window that ends before it starts: {self.start} to {self.end}")

    @property
    def is_open(self) -> bool:
        """Whether this is the whole case.

        The value everything else branches on: an open window must leave
        identifiers alone and let the store take the path it already had.
        """
        return self.start is None and self.end is None

    def contains(self, when: datetime) -> bool:
        """Whether an instant falls inside, counting both ends.

        Inclusive because a window typed as 01:25:30 to 02:57:00 reads as
        covering both of those seconds. A reader who names the second an attack
        started should not have to add one to see it.
        """
        if self.start is not None and when < self.start:
            return False
        return not (self.end is not None and when > self.end)

    @property
    def tag(self) -> str:
        """This window as a fragment of an identifier, or `""` if it is open."""
        if self.is_open:
            return ""
        first = self.start.strftime(_STAMP) if self.start is not None else ""
        last = self.end.strftime(_STAMP) if self.end is not None else ""
        return f"{first}{_BETWEEN}{last}"

    @classmethod
    def from_tag(cls, text: str) -> TimeWindow:
        """The window a `tag` was written from.

        Raises rather than guessing. This string arrives as part of something
        claiming to be evidence, and a window inferred from a name that could
        not be read would put the wrong stretch of time on a real finding.
        """
        if not text:
            return EVERYTHING
        first, found, last = text.partition(_BETWEEN)
        if not found or (not first and not last):
            raise ValueError(f"not a time range: {text!r}")
        return cls(start=_read(first, text), end=_read(last, text))

    def clamped_to(self, first: datetime, last: datetime) -> TimeWindow:
        """This window, held inside the stretch a case actually covers.

        An open end takes the case's own, so the result always names both ends —
        which is what the fields in the window need to show, and what the band
        needs to draw a selection against.
        """
        start = first if self.start is None else max(self.start, first)
        end = last if self.end is None else min(self.end, last)
        return TimeWindow(start=start, end=max(end, start))


def _read(stamp: str, whole: str) -> datetime | None:
    if not stamp:
        return None
    try:
        return datetime.strptime(stamp, _STAMP).replace(tzinfo=UTC)
    except ValueError:
        raise ValueError(f"not a time range: {whole!r}") from None


#: The whole case: no ends, no name, nothing changed.
EVERYTHING: Final = TimeWindow()
