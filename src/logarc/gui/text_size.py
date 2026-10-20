"""Text-size choices based on the desktop's available logical workspace."""

from enum import Enum
from typing import Final

#: The zoom range, in whole points. The roles in `gui.theme` sit up to 1.5 pt
#: below the body size, and stay unclamped across this whole range.
MIN_POINTS: Final = 8
MAX_POINTS: Final = 16

_LEGACY_POINTS: Final = {"compact": 11, "comfortable": 12, "large": 14}


class TextSize(Enum):
    """An automatic default or an explicit per-machine text size."""

    AUTOMATIC = 0
    COMPACT = 11
    COMFORTABLE = 12
    LARGE = 14

    @property
    def label(self) -> str:
        return (
            "Automatic" if self is TextSize.AUTOMATIC else f"{self.name.title()} ({self.value} pt)"
        )

    @property
    def stored(self) -> str:
        return self.name.lower()


def named(value: str) -> TextSize:
    """Unknown saved values return to automatic sizing."""
    try:
        return TextSize[value.strip().upper()]
    except KeyError:
        return TextSize.AUTOMATIC


def points_for(size: TextSize, *, width: int, height: int, system_points: float) -> float:
    """Respect OS scaling; choose from the workspace Qt already scaled for us.

    Automatic keeps a larger system font. Explicit sizes allow the reader to
    override it. A laptop-sized workspace starts at 12pt, short/scaled desktops
    at 11pt, and large workspaces retain the previous 14pt presentation.
    """
    if size is not TextSize.AUTOMATIC:
        return float(size.value)
    return _automatic(width=width, height=height, system_points=system_points)


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
            return clamped(float(points))
        except ValueError:
            pass
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
