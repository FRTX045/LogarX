"""Dressing the window in the theme `gui.style` decides.

The Qt half of a split `gui.style` makes on purpose: what a colour *means* is
plain data and testable without a display, while handing those colours to
`QPalette` needs a running `QApplication`. This file is the second half and
holds no judgements of its own — every value here comes from `style.THEME`.

Two things live here that are not colours, because they are the same kind of
decision and had the same problem — being made independently at every call site:

* **Type.** Nothing in the GUI set a UI font at all. The whole window ran on
  whatever Qt defaulted to, at one size and one weight, so a heading naming the
  client under investigation carried exactly as much emphasis as the sentence
  telling you to pick one.
* **Spacing.** Margins were chosen per widget — `(8, 4, 6, 4)` here, `(6, 4, 6,
  4)` there, `(4, 2, 4, 2)` in the legend — numbers close enough to look like a
  system and different enough not to be one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtGui import QColor, QFont, QPalette

from logarc.gui.style import THEME

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

__all__ = [
    "GAP",
    "MONO_FAMILIES",
    "PAD",
    "ROOM",
    "STEP",
    "TIGHT",
    "UI_FAMILIES",
    "apply_theme",
    "caption_font",
    "heading_font",
    "title_font",
]

#: The spacing ladder. Four steps is enough for a window of this shape, and
#: naming them stops the next margin from being invented.
TIGHT: Final = 4
PAD: Final = 8
GAP: Final = 12
ROOM: Final = 16
STEP: Final = 24

#: The interface font, in preference order.
#:
#: `Segoe UI Variable Text` is the Windows 11 UI face and is optically sized for
#: body copy — the `Display` cut of the same family is drawn for headlines and
#: is noticeably too tight at 9pt. Everything after it is a fallback for a
#: machine that does not have it; the final `sans-serif` is what Qt resolves on
#: a bare Linux CI box, where these tests also run.
UI_FAMILIES: Final = ("Segoe UI Variable Text", "Segoe UI", "Inter", "sans-serif")

#: The evidence font. Monospace is not decoration here: a log line is columnar,
#: and `100.66.1.152` only lines up under `100.66.2.9` if the digits are.
MONO_FAMILIES: Final = ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "monospace")

#: The type scale, as offsets from whatever the platform's base UI size is.
#:
#: Relative rather than absolute because the base size is a system accessibility
#: setting, and a window that pins 9pt overrides someone who asked for larger
#: text everywhere else. What is fixed is the *ratio* between the roles, which
#: is the part that carries the hierarchy.
_TITLE_STEP: Final = 3.0
_HEADING_STEP: Final = 1.0
_CAPTION_STEP: Final = -1.0
#: No smaller than this, whatever the arithmetic says. A caption on a machine
#: set to a small base font was arriving at 6pt, which is not a quiet label but
#: an unreadable one.
_FLOOR: Final = 7.5


def _sized(base: QFont, step: float, *, weight: QFont.Weight | None = None) -> QFont:
    """`base` moved one role up or down the scale."""
    font = QFont(base)
    font.setPointSizeF(max(base.pointSizeF() + step, _FLOOR))
    if weight is not None:
        font.setWeight(weight)
    return font


def title_font(base: QFont) -> QFont:
    """The one thing on a panel that should be read first."""
    return _sized(base, _TITLE_STEP, weight=QFont.Weight.DemiBold)


def heading_font(base: QFont) -> QFont:
    """A panel's subject — the activity being read, the client selected."""
    return _sized(base, _HEADING_STEP, weight=QFont.Weight.DemiBold)


def caption_font(base: QFont) -> QFont:
    """Column headings and legend labels: structure, not content."""
    return _sized(base, _CAPTION_STEP)


def ui_font(base: QFont | None = None) -> QFont:
    """The interface face, at the platform's own size."""
    font = QFont(base) if base is not None else QFont()
    font.setFamilies(list(UI_FAMILIES))
    return font


def mono_font(point_size: float) -> QFont:
    """The evidence face. Sized absolutely — this one is a column, not prose."""
    font = QFont()
    font.setFamilies(list(MONO_FAMILIES))
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSizeF(point_size)
    return font


def palette() -> QPalette:
    """`style.THEME` as something Qt will draw with.

    `Base` is the document surface and `Window` the chrome around it, which is
    the same distinction the theme draws. `Disabled` is set explicitly because
    Fusion derives it by blending toward the window colour, and on a ground this
    dark that lands a disabled menu item almost exactly on its own background —
    the `Wrap long traces` entry, greyed out on the behaviour map, disappeared
    rather than reading as unavailable.
    """
    colours = QPalette()
    surface, ink = QColor(THEME.surface), QColor(THEME.ink)

    for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
        colours.setColor(group, QPalette.ColorRole.Window, QColor(THEME.chrome))
        colours.setColor(group, QPalette.ColorRole.WindowText, ink)
        colours.setColor(group, QPalette.ColorRole.Base, surface)
        colours.setColor(group, QPalette.ColorRole.AlternateBase, QColor(THEME.stripe))
        colours.setColor(group, QPalette.ColorRole.Text, ink)
        colours.setColor(group, QPalette.ColorRole.Button, QColor(THEME.raised))
        colours.setColor(group, QPalette.ColorRole.ButtonText, ink)
        colours.setColor(group, QPalette.ColorRole.ToolTipBase, QColor(THEME.raised))
        colours.setColor(group, QPalette.ColorRole.ToolTipText, ink)
        colours.setColor(group, QPalette.ColorRole.PlaceholderText, QColor(THEME.faint))
        colours.setColor(group, QPalette.ColorRole.Link, QColor(THEME.accent))
        colours.setColor(group, QPalette.ColorRole.Highlight, QColor(THEME.tint))
        colours.setColor(group, QPalette.ColorRole.HighlightedText, ink)

    disabled = QPalette.ColorGroup.Disabled
    colours.setColor(disabled, QPalette.ColorRole.Window, QColor(THEME.chrome))
    colours.setColor(disabled, QPalette.ColorRole.Base, QColor(THEME.chrome))
    colours.setColor(disabled, QPalette.ColorRole.Button, QColor(THEME.raised))
    for role in (
        QPalette.ColorRole.WindowText,
        QPalette.ColorRole.Text,
        QPalette.ColorRole.ButtonText,
        QPalette.ColorRole.HighlightedText,
    ):
        colours.setColor(disabled, role, QColor(THEME.faint))
    colours.setColor(disabled, QPalette.ColorRole.Highlight, QColor(THEME.raised))
    return colours


def apply_theme(app: QApplication) -> None:
    """Put the whole application in the theme, once, at startup.

    Called from `gui.app.main` and from `ui-review/drive.py`. The review script
    builds its own `QApplication` and never goes through `main`, so without the
    second call the screenshots it captures would be of an untouched window —
    which is the sort of thing that gets noticed only after the screenshots have
    been read as evidence that the change worked.

    Fusion rather than the native style, because the Windows style paints
    several widgets through the OS theme engine and ignores the palette while
    doing it. Left native, the tables and the menu bar would keep their system
    colours while everything around them changed, which is a more confusing
    result than not having tried.
    """
    app.setStyle("Fusion")
    app.setPalette(palette())
    app.setFont(ui_font(app.font()))
