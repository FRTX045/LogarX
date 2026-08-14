"""Helpers shared across the suite.

Here rather than in a module beside it because a `conftest.py` puts its own
directory on the import path, which is what lets `tests/gui` and `tests/report`
share one copy of the same arithmetic. Two copies of a contrast formula is two
places for a threshold to drift.
"""

from __future__ import annotations

import math


def relative_luminance(colour: str) -> float:
    """WCAG relative luminance of a `#rrggbb` colour."""
    channels = [int(colour.lstrip("#")[at : at + 2], 16) / 255 for at in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(one: str, other: str) -> float:
    """WCAG contrast ratio between two hex colours."""
    first, second = relative_luminance(one), relative_luminance(other)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


def _oklab(colour: str) -> tuple[float, float, float]:
    """A `#rrggbb` colour in OKLab."""
    channels = [int(colour.lstrip("#")[at : at + 2], 16) / 255 for at in (0, 2, 4)]
    red, green, blue = (
        c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels
    )
    long = (0.4122214708 * red + 0.5363325363 * green + 0.0514459929 * blue) ** (1 / 3)
    medium = (0.2119034982 * red + 0.6806995451 * green + 0.1073969566 * blue) ** (1 / 3)
    short = (0.0883024619 * red + 0.2817188376 * green + 0.6299787005 * blue) ** (1 / 3)
    return (
        0.2104542553 * long + 0.7936177850 * medium - 0.0040720468 * short,
        1.9779984951 * long - 2.4285922050 * medium + 0.4505937099 * short,
        0.0259040371 * long + 0.7827717662 * medium - 0.8086757660 * short,
    )


def apart(one: str, other: str) -> float:
    """How far apart two colours look, as a distance in OKLab.

    Contrast is the wrong tool for "can these two be told apart": it compares
    luminance only, so an amber and a green of the same brightness score 1.0 —
    identical — while being obviously different colours. That matters here
    because severity is encoded in hue as much as in lightness, and the question
    the canvas asks is whether two findings can be confused, not whether one is
    brighter.

    OKLab is near enough perceptually uniform that a plain Euclidean distance in
    it tracks how different two colours look.
    """
    first, second = _oklab(one), _oklab(other)
    return math.dist(first, second)


def chroma(colour: str) -> float:
    """How saturated a colour is, in OKLab.

    Needed to know whether a colour's *hue* means anything. A near-grey has a
    hue in the arithmetic sense and none in the perceptual one — logarc's `Info`
    grey computes to a blue hue three degrees off the selection blue, while
    being obviously not blue.
    """
    _, a, b = _oklab(colour)
    return math.hypot(a, b)


def hue_apart(one: str, other: str) -> float:
    """The angle between two colours' hues, in degrees, the short way round.

    Only meaningful above some chroma — see `chroma`.
    """
    _, a1, b1 = _oklab(one)
    _, a2, b2 = _oklab(other)
    first = math.degrees(math.atan2(b1, a1)) % 360
    second = math.degrees(math.atan2(b2, a2)) % 360
    gap = abs(first - second) % 360
    return min(gap, 360 - gap)
