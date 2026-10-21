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

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath, QPalette, QPen
from PyQt6.QtWidgets import QDialogButtonBox, QProxyStyle, QPushButton, QStyle

from logarc.gui.text_size import TextSize, points_for
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
    "colour_text",
    "controls_sheet",
    "heading_font",
    "settle_buttons",
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

#: Minimum for callers outside the themed launcher. The selected startup size
#: comes from text_size; role fonts follow it instead of enforcing 14/13pt.
_UI_POINTS: Final = 11.0
_TITLE_STEP: Final = 3.0
_HEADING_STEP: Final = 1.0
_CAPTION_STEP: Final = -1.0
_FLOOR: Final = 9.0


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

    def drawPrimitive(  # noqa: N802 - Qt's naming
        self,
        element: QStyle.PrimitiveElement,
        option: QStyleOption | None,
        painter: QPainter | None,
        widget: QWidget | None = None,
    ) -> None:
        """Draw check boxes as boxes.

        Fusion strokes the box in a shade of the window and fills it with the
        base colour, which on this ground is the ground: a ticked setting showed
        a bare tick and an unticked one showed nothing at all. Drawn here rather
        than in the stylesheet, which can only paint a tick from an image file,
        and here it reaches the rules table's On column too.
        """
        if element in _CHECKS and option is not None and painter is not None:
            _draw_check(option, painter)
            return
        super().drawPrimitive(element, option, painter, widget)


_CHECKS: Final = (
    QStyle.PrimitiveElement.PE_IndicatorCheckBox,
    QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck,
)


def _draw_check(option: QStyleOption, painter: QPainter) -> None:
    """A rounded box: outlined when off, filled with the accent and ticked when on."""
    area = QRectF(option.rect).adjusted(1.5, 1.5, -1.5, -1.5)
    side = min(area.width(), area.height(), 16.0)
    box = QRectF(area.center().x() - side / 2, area.center().y() - side / 2, side, side)
    on = bool(option.state & QStyle.StateFlag.State_On)
    enabled = bool(option.state & QStyle.StateFlag.State_Enabled)
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    if on:
        fill = THEME.accent if enabled else THEME.edge
        painter.setPen(QPen(QColor(fill), 1.0))
        painter.setBrush(QColor(fill))
    else:
        painter.setPen(QPen(QColor(THEME.muted if enabled else THEME.edge), 1.2))
        painter.setBrush(QColor(THEME.surface))
    painter.drawRoundedRect(box, 3, 3)
    if on:
        tick = QPainterPath()
        tick.moveTo(box.left() + side * 0.24, box.top() + side * 0.52)
        tick.lineTo(box.left() + side * 0.43, box.top() + side * 0.70)
        tick.lineTo(box.left() + side * 0.77, box.top() + side * 0.32)
        pen = QPen(QColor(THEME.on_accent if enabled else THEME.faint), max(1.6, side / 8))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(tick)
    painter.restore()


def controls_sheet(points: float) -> str:
    """The one stylesheet every control is drawn with.

    Each screen used to style its own buttons, edits and tabs, close enough to
    look like a system and different enough not to be one. `points` is the
    interface size, which the menus are told outright: the platform hands them
    its own smaller menu font otherwise (Windows: 9 pt under an 11 pt window).

    The default button is filled but never bold. Bold set under `:default`
    widens the label after the button was sized, and "Restore Defaults" lost
    its last letters to it.

    Scroll bars keep the 20 px the readable style insists on.
    """
    return f"""
QToolTip {{ background: {THEME.raised}; color: {THEME.ink}; border: 1px solid {THEME.edge};
    padding: 6px 8px; }}
QMenuBar, QMenu {{ font-size: {points}pt; }}
QMenuBar {{ background: {THEME.chrome}; border-bottom: 1px solid {THEME.line}; }}
QMenuBar::item {{ padding: 6px 10px; background: transparent; border-radius: 4px; }}
QMenuBar::item:selected {{ background: {THEME.raised}; }}
QMenu {{ background: {THEME.raised}; border: 1px solid {THEME.edge}; padding: 4px; }}
QMenu::item {{ padding: 6px 32px 6px 26px; border-radius: 4px; }}
QMenu::item:selected {{ background: {THEME.tint}; }}
QMenu::item:disabled {{ color: {THEME.faint}; }}
QMenu::separator {{ height: 1px; background: {THEME.line}; margin: 4px 8px; }}
QPushButton {{ background: {THEME.raised}; color: {THEME.ink}; border: 1px solid {THEME.edge};
    border-radius: 4px; padding: 5px 16px; min-height: 20px; }}
QPushButton:hover {{ border-color: {THEME.muted}; }}
QPushButton:pressed {{ background: {THEME.tint}; }}
QPushButton:default {{ background: {THEME.accent}; color: {THEME.on_accent};
    border-color: {THEME.accent}; }}
QPushButton[primary="true"] {{ background: {THEME.accent}; color: {THEME.on_accent};
    border-color: {THEME.accent}; }}
QPushButton:disabled {{ color: {THEME.faint}; background: transparent;
    border-color: {THEME.line}; }}
QLineEdit, QPlainTextEdit, QDateTimeEdit {{ background: {THEME.surface};
    border: 1px solid {THEME.edge}; border-radius: 4px; padding: 4px 6px;
    selection-background-color: {THEME.tint}; }}
QLineEdit:focus, QPlainTextEdit:focus, QDateTimeEdit:focus {{ border-color: {THEME.accent}; }}
QTabWidget::pane {{ border: none; border-top: 1px solid {THEME.line}; top: -1px; }}
QTabBar {{ qproperty-drawBase: 0; }}
QTabBar::tab {{ background: transparent; color: {THEME.muted}; border: none;
    border-bottom: 2px solid transparent; padding: 6px 14px; margin-right: 4px; }}
QTabBar::tab:hover {{ color: {THEME.ink}; }}
QTabBar::tab:selected {{ color: {THEME.ink}; border-bottom: 2px solid {THEME.accent}; }}
QHeaderView::section {{ background: {THEME.raised}; color: {THEME.muted}; border: none;
    border-right: 1px solid {THEME.line}; border-bottom: 1px solid {THEME.edge};
    padding: 4px 8px; }}
QTableView, QTreeView, QListView {{ border: 1px solid {THEME.line};
    gridline-color: {THEME.line}; }}
QListView::item {{ padding: 3px 6px; }}
QListView::item:selected {{ background: {THEME.tint}; color: {THEME.ink}; }}
QStatusBar {{ background: {THEME.chrome}; border-top: 1px solid {THEME.line}; }}
QStatusBar QLabel {{ color: {THEME.muted}; }}
QScrollBar {{ background: transparent; border: none; }}
QScrollBar:vertical {{ width: 20px; margin: 3px; }}
QScrollBar:horizontal {{ height: 20px; margin: 3px; }}
QScrollBar::handle {{ background: {THEME.edge}; border: none; border-radius: 5px; margin: 1px; }}
QScrollBar::handle:vertical {{ min-height: 42px; }}
QScrollBar::handle:horizontal {{ min-width: 42px; }}
QScrollBar::handle:hover {{ background: {THEME.faint}; }}
QScrollBar::handle:pressed {{ background: {THEME.accent}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
"""


def settle_buttons(buttons: QDialogButtonBox) -> None:
    """Make the accepting button the default, and nothing else ever.

    A push button in a dialog becomes the default when it takes focus unless it
    is told not to, so Restore Defaults could end up filled like OK — and the
    Enter key with it.
    """
    chosen = False
    for button in buttons.buttons():
        if not isinstance(button, QPushButton):  # pragma: no cover - a box holds push buttons
            continue
        accepting = (
            not chosen and buttons.buttonRole(button) == QDialogButtonBox.ButtonRole.AcceptRole
        )
        chosen = chosen or accepting
        button.setAutoDefault(accepting)
        button.setDefault(accepting)


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
    """The interface face, inheriting the chosen application text size."""
    font = QFont(base) if base is not None else QFont()
    font.setFamilies(list(UI_FAMILIES))
    font.setPointSizeF(max(font.pointSizeF(), _UI_POINTS))
    return font


def mono_font(point_size: float) -> QFont:
    """Monospace follows the interface size, never forcing table text larger."""
    font = QFont()
    font.setFamilies(list(MONO_FAMILIES))
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSizeF(max(point_size, font.pointSizeF() - 1.0, _FLOOR))
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


def apply_theme(app: QApplication, *, text_size: TextSize = TextSize.AUTOMATIC) -> None:
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
    screen = app.primaryScreen()
    area = screen.availableGeometry() if screen is not None else None
    font = ui_font(app.font())
    font.setPointSizeF(
        points_for(
            text_size,
            width=area.width() if area is not None else 0,
            height=area.height() if area is not None else 0,
            system_points=app.font().pointSizeF(),
        )
    )
    app.setFont(font)
    app.setStyleSheet(controls_sheet(font.pointSizeF()))
