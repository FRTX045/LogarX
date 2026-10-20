"""How finely the traffic band is counted.

One decision, kept away from Qt so it can be checked without a display: how
many buckets to ask the store for, given how wide the band is on screen.

Why the band's width and not a fixed number. A histogram is only readable at
the size it is drawn: 200 buckets is a proper histogram on a 900px band and a
row of hairlines on a 600px one, which is the width the panel actually gets.
A fixed count cannot know that, so it was wrong on every window but the one it
was chosen for.

Why it is a setting at all. Because it is nearly free: measured on two million
events, 100 buckets came back in 0.165s and 3,200 in 0.235s. The query is one
full scan and a `GROUP BY`, and the scan is what costs — so the reader can have
whichever reading they prefer without paying for it.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["DEFAULT", "Density", "buckets_for", "named"]


class Density(Enum):
    """How many pixels of band one bucket is meant to occupy."""

    COARSE = 8
    MEDIUM = 4
    FINE = 1

    @property
    def per_bucket(self) -> int:
        """Pixels per bucket. The enum's value, named for what it means."""
        return int(self.value)

    @property
    def label(self) -> str:
        """The choice as Preferences offers it."""
        return self.name.title()

    @property
    def stored(self) -> str:
        """The settings value, as it has always been written."""
        return self.name.lower()


#: The finest setting is one bucket to a pixel, and there is deliberately no
#: finer one: two buckets sharing a pixel draw as a single bar, so the second is
#: a row in a result nobody can ever see.
DEFAULT = Density.FINE

#: The narrowest band worth reckoning with. Qt reports a width of zero until the
#: window has been laid out, and a case can be opened before that has happened —
#: without a floor the first band of every session is drawn from no buckets.
_FLOOR = 160


def buckets_for(width: int, density: Density) -> int:
    """How many buckets a band `width` pixels across should ask for."""
    return max(max(width, _FLOOR) // density.per_bucket, 1)


def named(text: str) -> Density:
    """The setting a remembered name stands for.

    Anything unrecognised is the default rather than an error: settings outlive
    the code that wrote them, and a name from some other version of this
    application is not a reason to refuse to draw a band.
    """
    try:
        return Density[text.strip().upper()]
    except KeyError:
        return DEFAULT
