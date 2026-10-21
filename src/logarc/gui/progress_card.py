"""The card that says how far an ingest has got.

Renders a `Progress` and works nothing out for itself: every number on it comes
from the snapshot it was handed, so the figures the window shows and the figures
`gui.progress` is tested against cannot drift apart.

It sits over the window rather than in a corner of it. Reading a gigabyte takes
minutes, and for all of them the window behind has nothing to show — its canvas
is still inviting you to open a case while one is being built.

**Drawn as a readout rather than a dashboard card.** The first version led with
a large accent-coloured percentage over a rounded bar, with three statistics
under small capitalised labels beneath it — a shape common enough in generated
interfaces that this project's own design notes name it as one to avoid, and it
was picked up here without that being checked. What replaced it is a
fixed-width readout: one figure per row, every value starting at the same
column, square corners, hairline rules. Digits that line up under one another
are read at a glance, which is the entire job of a panel somebody watches for
several minutes and does nothing with.

**The words are in the interface face, the figures in monospace.** Until
2026-10-21 the labels were monospace too, in lower case, under a heading in
capitals, which made this the one screen in the application that looked like a
terminal. Only the figures need one width to line up; the grid keeps every
value starting at the same column either way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from logarc.gui.theme import FLOOR, MONO_FAMILIES, PAD, ROOM, TIGHT, colour_text, ui_font
from logarc.style import THEME

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtGui import QCloseEvent, QKeyEvent

    from logarc.gui.progress import Progress

__all__ = ["IngestCard"]

#: Shown where a figure is not available. An em dash rather than a zero: nothing
#: is known yet, which is a different statement from nothing having happened.
UNKNOWN: Final = "—"

#: The rows of the readout, in the order they are read. The keys are what each
#: line is called; the values are filled in from a `Progress`.
_ROWS: Final = ("source", "read", "parsed", "rate", "remaining")

#: What each row is called on the face.
_NAMES: Final = {
    "source": "File",
    "read": "Read",
    "parsed": "Lines",
    "rate": "Speed",
    "remaining": "Time left",
}


def _mono(step: float = 0.0, *, bold: bool = False) -> QFont:
    """The evidence face, which is also the right face for a readout.

    A column of figures only lines up if the digits are the same width, and
    lining up is what makes five numbers readable without reading them.
    """
    font = QFont()
    font.setFamilies(list(MONO_FAMILIES))
    font.setPointSizeF(max(FLOOR, ui_font().pointSizeF() + step))
    if bold:
        font.setWeight(QFont.Weight.DemiBold)
    return font


def _words(step: float = 0.0, *, bold: bool = False) -> QFont:
    """The interface face, for everything on the card that is not a figure."""
    font = ui_font()
    font.setPointSizeF(font.pointSizeF() + step)
    if bold:
        font.setWeight(QFont.Weight.DemiBold)
    return font


def _label(text: str, font: QFont, colour: str) -> QLabel:
    item = QLabel(text)
    item.setFont(font)
    item.setStyleSheet("background: transparent;")
    colour_text(item, colour)
    return item


def _rule(colour: str) -> QFrame:
    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: {colour}; border: none;")
    return line


class IngestCard(QDialog):
    """What is being read, how far in, how fast, and how much longer."""

    def __init__(self, parent: QWidget | None, *, on_cancel: Callable[[], None]) -> None:
        super().__init__(parent)
        self._on_cancel = on_cancel

        self.setObjectName("ingestCard")
        self.setWindowTitle("Reading logs")
        self.setModal(True)
        # No close button. There is one way out of this and it is Cancel, which
        # says what it will do to the case; a card dismissed by its cross would
        # leave the ingest running with nothing on screen about it.
        self.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint
        )
        self.setStyleSheet(
            f"QDialog#ingestCard {{ background: {THEME.chrome}; border: 1px solid {THEME.edge}; }}"
        )
        self.setFixedWidth(600)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)

        column.addWidget(self._build_head())
        column.addWidget(_rule(THEME.edge))
        column.addWidget(self._build_readout())
        column.addWidget(self._build_track())
        column.addWidget(self._build_consequence())
        column.addWidget(_rule(THEME.line))
        column.addWidget(self._build_foot())

    # -- construction ------------------------------------------------------

    def _build_head(self) -> QWidget:
        head = QWidget()
        head.setStyleSheet(f"background: {THEME.surface};")
        row = QHBoxLayout(head)
        row.setContentsMargins(ROOM, PAD + 2, ROOM, PAD + 2)
        self._state = _label("Reading logs", _words(bold=True), THEME.accent)
        row.addWidget(self._state)
        row.addStretch(1)
        self._which = _label("", _mono(-0.5), THEME.faint)
        row.addWidget(self._which)
        return head

    def _build_readout(self) -> QWidget:
        body = QWidget()
        body.setStyleSheet("background: transparent;")
        grid = QGridLayout(body)
        grid.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        grid.setHorizontalSpacing(ROOM)
        grid.setVerticalSpacing(TIGHT + 1)

        self._names: dict[str, QLabel] = {}
        self._values: dict[str, QLabel] = {}
        for index, key in enumerate(_ROWS):
            name = _label(_NAMES[key], _words(-0.5), THEME.faint)
            grid.addWidget(name, index, 0)
            self._names[key] = name
            # `read` carries the weight: it is the one figure the whole panel
            # exists to report, and the others explain it.
            colour = THEME.timestamp if key == "remaining" else THEME.ink
            value = _label(UNKNOWN, _mono(bold=key == "read"), colour)
            grid.addWidget(value, index, 1)
            self._values[key] = value
        grid.setColumnStretch(1, 1)
        return body

    def _build_track(self) -> QWidget:
        holder = QWidget()
        holder.setStyleSheet("background: transparent;")
        row = QHBoxLayout(holder)
        row.setContentsMargins(ROOM, 0, ROOM, ROOM)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(10)
        # Square, like everything else on the face. A rounded pill would be the
        # only soft edge in the panel, and it would be the loudest thing in it.
        self._bar.setStyleSheet(
            f"QProgressBar {{ background: {THEME.stripe}; border: none; }}"
            f"QProgressBar::chunk {{ background: {THEME.accent}; }}"
        )
        row.addWidget(self._bar)
        return holder

    def _build_consequence(self) -> QWidget:
        """What cancelling costs, said where it can be read without hovering.

        It nearly became a tooltip on the Cancel button. A tooltip appears only
        if somebody happens to rest the pointer on the control, and the whole
        point of this sentence is to be read *before* that control is pressed.
        """
        holder = QWidget()
        holder.setStyleSheet("background: transparent;")
        row = QHBoxLayout(holder)
        row.setContentsMargins(ROOM, 0, ROOM, PAD)
        self._consequence = _label(
            "Cancelling leaves the case unfinished.", _words(-1), THEME.faint
        )
        row.addWidget(self._consequence)
        row.addStretch(1)
        return holder

    def _build_foot(self) -> QWidget:
        foot = QWidget()
        foot.setStyleSheet("background: transparent;")
        row = QHBoxLayout(foot)
        row.setContentsMargins(ROOM, PAD, ROOM, PAD)

        self._percent = _label("", _mono(1, bold=True), THEME.accent)
        row.addWidget(self._percent)
        row.addStretch(1)

        # Drawn by the application stylesheet, like every other button.
        self._cancel = QPushButton("Cancel")
        # Never the default: Enter would throw the read away.
        self._cancel.setAutoDefault(False)
        self._cancel.clicked.connect(self._cancelled)
        self._cancel.setToolTip(
            "Stop reading. The case is left unfinished, so a partial read can never "
            "be analysed as if it were complete."
        )
        row.addWidget(self._cancel)
        return foot

    # -- what it says ------------------------------------------------------

    def text(self) -> str:
        """Everything the card says, for tests and anything reading it whole."""
        parts = [self._state.text(), self._which.text(), self._percent.text()]
        parts.extend(f"{_NAMES[key]} {self._values[key].text()}" for key in _ROWS)
        return " ".join(part for part in parts if part)

    def update_progress(self, progress: Progress) -> None:
        """Draw `progress`. Nothing here is worked out, only shown."""
        self._values["source"].setText(progress.file_name)
        self._values["parsed"].setText(f"{progress.lines:,}")
        self._values["rate"].setText(progress.rate or UNKNOWN)
        # `remaining` is None until the read has settled and again once it is
        # done. A dash rather than a guess: the seam withheld it on purpose, and
        # inventing one here puts back the number that guard exists to keep out.
        self._values["remaining"].setText(progress.remaining or UNKNOWN)
        self._which.setText(
            f"{progress.file_index}/{progress.file_count}" if progress.file_count > 1 else ""
        )

        fraction = progress.fraction
        if fraction is None:
            # Nothing to draw a position from. Qt's (0, 0) range is the moving
            # bar, which says "working" without claiming to know where it is.
            self._bar.setRange(0, 0)
            self._percent.setText("")
            self._values["read"].setText(UNKNOWN)
            return

        self._bar.setRange(0, 1000)
        self._bar.setValue(int(fraction * 1000))
        self._percent.setText(progress.percent or "")
        self._values["read"].setText(
            f"{_megabytes(progress.bytes_done)} / {_megabytes(progress.bytes_total)} MB"
        )

    def stopping(self) -> None:
        """Say the cancel has been heard and is being waited on."""
        self._cancel.setEnabled(False)
        self._state.setText("Stopping\u2026")
        colour_text(self._state, THEME.warning)

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        """Not from the system. Alt+F4 arrives as a spontaneous close, and would
        hide the card with its job still running; the window that owns the
        card closes it in code when the job ends, and that close goes through."""
        if event is not None and event.spontaneous():
            event.ignore()
            return
        super().closeEvent(event)

    def keyPressEvent(self, event: QKeyEvent | None) -> None:  # noqa: N802
        """Escape is not a way out. A dialog hides on it, and this card hidden
        is a job still running with nothing on screen about it."""
        if event is not None and event.key() == Qt.Key.Key_Escape:
            event.accept()
            return
        super().keyPressEvent(event)

    def _cancelled(self) -> None:
        self.stopping()
        self._on_cancel()


def _megabytes(count: int) -> str:
    """Megabytes without their unit, so a pair of them can share one."""
    return f"{count / 1_000_000:,.0f}"
