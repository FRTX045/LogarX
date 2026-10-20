"""Text-size choices based on the desktop's available logical workspace."""

from enum import Enum


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
    if width <= 0 or height <= 0:
        automatic = 12.0
    elif width < 1440 or height < 900:
        automatic = 11.0
    elif width < 2200 or height < 1200:
        automatic = 12.0
    else:
        automatic = 14.0
    return max(automatic, system_points)
