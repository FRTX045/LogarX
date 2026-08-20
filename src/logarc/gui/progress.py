"""How far a long ingest has got, and what it may claim about that.

Free of Qt, for the reason the other seams are: the numbers here are the part
that can misinform, and they should be checkable without starting a window.

The percentage and the rate are statements about what has already happened. The
estimate is a prediction, and this project treats a number that looks like a
result and is not as the worst thing it can emit — so the estimate is withheld
until the read has been going long enough for the rate to mean anything, and it
never appears without the word `about`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = ["SETTLE_SECONDS", "Progress"]

#: How long a read must have been going before it may say what is left.
#:
#: The first seconds are the least representative — the file cache is cold, the
#: format has just been sniffed from the opening lines, and one batch has been
#: written. An estimate drawn from that is confidently wrong, and it is the
#: first number anybody sees.
SETTLE_SECONDS: Final = 3.0


@dataclass(frozen=True, slots=True)
class Progress:
    """One report of how a read is going.

    Covers the whole ingest rather than one file: `Case.ingest` restarts its
    counts at each log, and a reader watching the window is waiting for all of
    them.
    """

    file_name: str
    file_index: int
    file_count: int
    lines: int
    bytes_done: int
    bytes_total: int
    seconds: float

    @property
    def subject(self) -> str:
        """Which log this is, and which of how many when that is worth saying."""
        if self.file_count <= 1:
            return self.file_name
        return f"{self.file_name} ({self.file_index} of {self.file_count})"

    @property
    def fraction(self) -> float | None:
        """How much of the read is done, or None when the size is unknown.

        Capped at one. The final batch reads past the size the file reported,
        and a compressed stream's accounting is not exact either; a bar drawn
        at 104% says the tool cannot count.
        """
        if self.bytes_total <= 0:
            return None
        return min(1.0, self.bytes_done / self.bytes_total)

    @property
    def percent(self) -> str | None:
        fraction = self.fraction
        return None if fraction is None else f"{fraction * 100:.0f}%"

    @property
    def rate(self) -> str | None:
        """Lines a second so far. A measurement, not a prediction."""
        if self.seconds <= 0:
            return None
        return f"{round(self.lines / self.seconds):,} lines/s"

    @property
    def remaining(self) -> str | None:
        """Roughly how much longer, once that can be said honestly.

        None until the read has settled, and None again once it is finished —
        "about 0s" beside a full bar is noise, and a reader who sees it wonders
        what is still running.
        """
        if self.seconds < SETTLE_SECONDS or self.bytes_done <= 0:
            return None
        if self.bytes_total <= 0 or self.bytes_done >= self.bytes_total:
            return None
        per_second = self.bytes_done / self.seconds
        return f"about {_span((self.bytes_total - self.bytes_done) / per_second)}"


def _span(seconds: float) -> str:
    """A duration in the largest unit that keeps it readable."""
    whole = round(seconds)
    if whole < 60:
        return f"{whole}s"
    minutes, rest = divmod(whole, 60)
    if minutes < 60:
        return f"{minutes}m {rest}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"
