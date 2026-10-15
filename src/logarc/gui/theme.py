"""Dressing the window in the theme `logarc.style` decides.

The Qt half of a split `logarc.style` makes on purpose: what a colour *means* is
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
from PyQt6.QtWidgets import QProxyStyle, QStyle

from logarc.style import THEME

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication, QStyleOption, QWidget

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

#: The type scale, relative to a readable UI base. Larger system text is kept.
#:
#: Some desktops supply a tiny default font. Set a minimum without overriding
#: a reader who already chose larger system text.
_UI_POINTS: Final = 13.0
_MONO_POINTS: Final = 12.0
_TITLE_STEP: Final = 3.0
_HEADING_STEP: Final = 1.0
_CAPTION_STEP: Final = -1.0
#: No smaller than this, whatever the arithmetic says. A caption on a machine
#: set to a small base font was arriving at 6pt, which is not a quiet label but
#: an unreadable one.
_FLOOR: Final = 11.0


class _ReadableStyle(QProxyStyle):
    """Keep narrow controls usable independently of the text size."""

    def pixelMetric(  # noqa: N802 - Qt's naming
        self,
        metric: QStyle.PixelMetric,
        option: QStyleOption | None = None,
        widget: QWidget | None = None,
    ) -> int:
        minimums = {
            QStyle.PixelMetric.PM_ScrollBarExtent: 20,
            QStyle.PixelMetric.PM_ScrollBarSliderMin: 42,
            QStyle.PixelMetric.PM_SplitterWidth: 5,
            QStyle.PixelMetric.PM_TextCursorWidth: 2,
        }
        value = super().pixelMetric(metric, option, widget)
        minimum = minimums.get(metric)
        return max(value, minimum) if minimum is not None else value


_CONTROLS: Final = f"""
QScrollBar {{ background: {THEME.surface}; border: 1px solid {THEME.edge}; }}
QScrollBar:vertical {{ width: 20px; margin: 2px; }}
QScrollBar:horizontal {{ height: 20px; margin: 2px; }}
QScrollBar::handle {{
    background: {THEME.faint};
    border: 1px solid {THEME.muted};
    border-radius: 6px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{ min-height: 42px; }}
QScrollBar::handle:horizontal {{ min-width: 42px; }}
QScrollBar::handle:hover {{ background: {THEME.muted}; }}
QScrollBar::handle:pressed {{ background: {THEME.accent}; }}
QScrollBar::handle:disabled {{ background: {THEME.edge}; border-color: {THEME.edge}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
"""


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
    """The interface face, at least 13pt and respecting larger system text."""
    font = QFont(base) if base is not None else QFont()
    font.setFamilies(list(UI_FAMILIES))
    font.setPointSizeF(max(font.pointSizeF(), _UI_POINTS))
    return font


def mono_font(point_size: float) -> QFont:
    """The evidence face, with a readable minimum for raw log lines."""
    font = QFont()
    font.setFamilies(list(MONO_FAMILIES))
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSizeF(max(point_size, _MONO_POINTS))
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
    app.setStyle(_ReadableStyle("Fusion"))
    app.setPalette(palette())
    app.setFont(ui_font(app.font()))
    app.setStyleSheet(_CONTROLS)
