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

import weakref
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QEvent, QObject, Qt
from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import (
    QApplication,
    QListWidget,
    QProxyStyle,
    QStyle,
    QTableWidget,
    QTreeWidget,
    QTreeWidgetItemIterator,
)

from logarc.gui.text_size import MIN_POINTS, automatic_points, clamped
from logarc.style import THEME

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QStyleOption, QWidget

__all__ = [
    "FLOOR",
    "GAP",
    "MONO_FAMILIES",
    "PAD",
    "ROOM",
    "STEP",
    "TIGHT",
    "UI_FAMILIES",
    "apply_theme",
    "automatic_points_for",
    "caption_font",
    "colour_text",
    "heading_font",
    "on_font_change",
    "set_text_points",
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

#: Minimum for callers outside the themed launcher. The size itself is the
#: reader's zoom; role fonts follow it as steps above or below.
_UI_POINTS: Final = float(MIN_POINTS)
_TITLE_STEP: Final = 3.0
_HEADING_STEP: Final = 1.0
_CAPTION_STEP: Final = -1.0
#: The smallest any role may go: the lowest step (-1.5, the progress card's
#: note) at the smallest zoom. Nothing clamps inside the zoom range, which is
#: what lets a live zoom move every font by the same amount and back again.
FLOOR: Final = MIN_POINTS - 1.5

#: The platform's own font size, read before the theme first replaces it.
_system_points: float | None = None


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
QTabBar::tab:selected {{ color: {THEME.accent}; }}
"""


def colour_text(widget: QWidget, colour: str) -> None:
    """Colour a text role without making disabled controls look enabled.

    Palette roles cover labels, fields and buttons. Explicit widget stylesheets
    still take precedence; those should use the theme role in their own rules.
    """
    colours = widget.palette()
    for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
        for role in (
            QPalette.ColorRole.WindowText,
            QPalette.ColorRole.Text,
            QPalette.ColorRole.ButtonText,
        ):
            colours.setColor(group, role, QColor(colour))
    widget.setPalette(colours)


def _sized(base: QFont, step: float, *, weight: QFont.Weight | None = None) -> QFont:
    """`base` moved one role up or down the scale."""
    font = QFont(base)
    font.setPointSizeF(max(base.pointSizeF() + step, FLOOR))
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
    """The interface face, inheriting the chosen application text size."""
    font = QFont(base) if base is not None else QFont()
    font.setFamilies(list(UI_FAMILIES))
    font.setPointSizeF(max(font.pointSizeF(), _UI_POINTS))
    return font


def mono_font(point_size: float | None = None) -> QFont:
    """Monospace follows the interface size, never forcing table text larger.

    Pass the size of the table or field it sits in; with none it is the
    caption size, one step below the interface text.
    """
    font = QFont()
    font.setFamilies(list(MONO_FAMILIES))
    font.setStyleHint(QFont.StyleHint.Monospace)
    caption = font.pointSizeF() + _CAPTION_STEP
    font.setPointSizeF(max(caption if point_size is None else point_size, caption, FLOOR))
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


def automatic_points_for(app: QApplication) -> float:
    """The default text size for this desktop: what Reset zoom returns to.

    Measured against the system font as it was before the theme replaced it,
    so asking again after a zoom gives the same answer.
    """
    system_points = _system_points_of(app)
    screen = app.primaryScreen()
    area = screen.availableGeometry() if screen is not None else None
    return automatic_points(
        width=area.width() if area is not None else 0,
        height=area.height() if area is not None else 0,
        system_points=system_points,
    )


def _system_points_of(app: QApplication) -> float:
    """The platform's font size, read the first time it is asked for.

    Both entry points ask before the theme sets a font of its own, so a fixed
    starting size never becomes what Reset zoom measures against.
    """
    global _system_points
    if _system_points is None:
        _system_points = app.font().pointSizeF()
    return _system_points


def apply_theme(app: QApplication, *, points: float | None = None) -> None:
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

    `points` is the interface text size; `None` means `automatic_points_for`.
    """
    _system_points_of(app)
    chosen = automatic_points_for(app) if points is None else points
    app.setStyle(_ReadableStyle("Fusion"))
    app.setPalette(palette())
    # The stylesheet before the font: on Windows, setting a stylesheet refills
    # the per-class fonts from the system (9 pt Segoe UI for every table and
    # header), and only a later application font clears them again.
    app.setStyleSheet(_CONTROLS)
    font = ui_font(app.font())
    font.setPointSizeF(chosen)
    app.setFont(font)


def set_text_points(app: QApplication, points: float) -> float:
    """Change the interface text size while windows are open; return the size now in force.

    `points` is clamped to the zoom range. Widgets on the application font
    follow it. Fonts set explicitly (captions, headings, monospace runs and
    item fonts in tables, trees and lists) move by the same number of points,
    so every role keeps its step from the body text. The graph's own fonts are
    graphics items, not widgets, and stay with the graph's zoom.
    """
    chosen = clamped(points)
    delta = chosen - app.font().pointSizeF()
    if delta == 0:
        return chosen
    # Read before anything changes: setting the stylesheet again puts each
    # explicitly set widget font back to what it was when first styled.
    explicit = [
        (widget, _moved(widget.font(), delta))
        for widget in QApplication.allWidgets()
        if widget.testAttribute(Qt.WidgetAttribute.WA_SetFont)
    ]
    # Items first, so a table refitting its columns on the font change below
    # measures them at the new size.
    for widget in QApplication.allWidgets():
        _move_items(widget, delta)
    font = QFont(app.font())
    font.setPointSizeF(chosen)
    app.setFont(font)
    # With a stylesheet in force Qt does not pass an application font change
    # on to widgets that already exist; setting the sheet again re-polishes
    # them. A re-polish gives children their parent's font as it stands, so
    # the second round hands the children of explicitly set widgets the moved
    # size rather than the restored one.
    for _round in range(2):
        app.setStyleSheet(app.styleSheet())
        for widget, moved in explicit:
            widget.setFont(moved)
    return chosen


def _moved(font: QFont, delta: float) -> QFont:
    moved = QFont(font)
    moved.setPointSizeF(font.pointSizeF() + delta)
    return moved


def _move_items(widget: QWidget, delta: float) -> None:
    """Shift the item fonts a table, tree or list was given one by one."""
    role = Qt.ItemDataRole.FontRole
    if isinstance(widget, QTableWidget):
        cells = (
            widget.item(r, c) for r in range(widget.rowCount()) for c in range(widget.columnCount())
        )
        for cell in cells:
            if cell is not None and cell.data(role) is not None:
                cell.setFont(_moved(cell.font(), delta))
    elif isinstance(widget, QListWidget):
        for row in range(widget.count()):
            entry = widget.item(row)
            if entry is not None and entry.data(role) is not None:
                entry.setFont(_moved(entry.font(), delta))
    elif isinstance(widget, QTreeWidget):
        found = QTreeWidgetItemIterator(widget)
        while (node := found.value()) is not None:
            for column in range(widget.columnCount()):
                if node.data(column, role) is not None:
                    node.setFont(column, _moved(node.font(column), delta))
            found += 1


def on_font_change(widget: QWidget, react: Callable[[], None]) -> None:
    """Call `react` whenever `widget`'s font changes, as a zoom changes it.

    For a size measured from text once at construction: a minimum width that
    must keep fitting its text after the reader zooms. `react` must be a bound
    method of a Qt object built in Python; it is held weakly, so the watch never
    keeps that object alive.
    """
    _FontWatch(widget, react)


class _FontWatch(QObject):
    def __init__(self, widget: QWidget, react: Callable[[], None]) -> None:
        # Parented to the method's owner rather than to `widget`. A widget Qt
        # made itself, such as a table's header, has only a passing Python
        # wrapper, and the Python half of a watch parented to it goes with that
        # wrapper, leaving a filter that never calls back.
        owner = getattr(react, "__self__", None)
        if not isinstance(owner, QObject):
            raise TypeError("on_font_change needs a bound method of a QObject")
        super().__init__(owner)
        self._react = weakref.WeakMethod(react)
        widget.installEventFilter(self)

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # noqa: N802 - Qt's naming
        if event is not None and event.type() == QEvent.Type.FontChange:
            react = self._react()
            if react is not None:
                react()
        return False
