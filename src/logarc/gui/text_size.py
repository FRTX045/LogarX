"""The interface text zoom: its range, its steps and its default size."""

import math
from typing import Final

#: The zoom range, in whole points. The roles in `gui.theme` sit up to 1.5 pt
#: below the body size, and stay unclamped across this whole range.
MIN_POINTS: Final = 8
MAX_POINTS: Final = 16

_LEGACY_POINTS: Final = {"compact": 11, "comfortable": 12, "large": 14}


def automatic_points(*, width: int, height: int, system_points: float) -> float:
    """The default zoom for this workspace, kept inside the zoom range.

    A laptop-sized workspace starts at 12pt, short or scaled desktops at 11pt,
    and large workspaces at 14pt. A larger system font wins.
    """
    return clamped(_automatic(width=width, height=height, system_points=system_points))


def clamped(points: float) -> float:
    """`points` as a whole size inside the zoom range."""
    return float(min(max(round(points), MIN_POINTS), MAX_POINTS))


def stepped(points: float, by: int) -> float:
    """The size `by` whole points away from `points`, stopping at the range ends."""
    return clamped(round(points) + by)


def remembered(points: object, legacy: object, *, automatic: float) -> float:
    """The zoom to start with, from what the settings store hands back.

    A stored zoom wins. Without one, a size picked in the old restart-only
    Text size setting carries over, and anything else is the automatic size.
    """
    if isinstance(points, int | float | str) and not isinstance(points, bool):
        try:
            number = float(points)
        except ValueError:
            number = math.nan
        # Read before the crash net is up, so an unreadable value such as
        # `inf` must fall through rather than stop logarc from starting.
        if math.isfinite(number):
            return clamped(number)
    if isinstance(legacy, str) and legacy.strip().lower() in _LEGACY_POINTS:
        return float(_LEGACY_POINTS[legacy.strip().lower()])
    return automatic


def _automatic(*, width: int, height: int, system_points: float) -> float:
    if width <= 0 or height <= 0:
        automatic = 12.0
    elif width < 1440 or height < 900:
        automatic = 11.0
    elif width < 2200 or height < 1200:
        automatic = 12.0
    else:
        automatic = 14.0
    return max(automatic, system_points)
