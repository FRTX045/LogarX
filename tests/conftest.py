"""Helpers shared across the suite.

Here rather than in a module beside it because a `conftest.py` puts its own
directory on the import path, which is what lets `tests/gui` and `tests/report`
share one copy of the same arithmetic. Two copies of a contrast formula is two
places for a threshold to drift.
"""

from __future__ import annotations


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
