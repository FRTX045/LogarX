"""The card that says how far an ingest has got.

Renders a `Progress` and works nothing out for itself: every number on it comes
from the snapshot it was handed, so the figures the window shows and the figures
`gui.progress` is tested against cannot drift apart.

It sits over the window rather than in a corner of it. Reading a gigabyte takes
minutes, and for all of them the window behind has nothing to show — its canvas
is still inviting you to open a case while one is being built.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from logarc.gui.style import THEME
from logarc.gui.theme import GAP, PAD, STEP, caption_font, heading_font, title_font, ui_font

if TYPE_CHECKING:
    from collections.abc import Callable

    from logarc.gui.progress import Progress

__all__ = ["IngestCard"]

_UNKNOWN = "—"


def _figure(value: str, note: str) -> tuple[QWidget, QLabel]:
    """One number with its label beneath, and a handle on the number."""
    holder = QWidget()
    holder.setStyleSheet("background: transparent;")
    column = QVBoxLayout(holder)
    column.setContentsMargins(0, 0, 0, 0)
    column.setSpacing(2)

    number = QLabel(value)
    number.setFont(heading_font(ui_font()))
    number.setStyleSheet(
        f"color: {THEME.ink}; background: transparent; font-variant-numeric: tabular-nums;"
    )
    caption = QLabel(note.upper())
    caption.setFont(caption_font(ui_font()))
    caption.setStyleSheet(f"color: {THEME.faint}; background: transparent;")

    column.addWidget(number)
    column.addWidget(caption)
    return holder, number


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
            f"QDialog#ingestCard {{ background: {THEME.raised}; border: 1px solid {THEME.edge}; }}"
        )
        self.setFixedWidth(560)

        column = QVBoxLayout(self)
        column.setContentsMargins(STEP, STEP, STEP, STEP)
        column.setSpacing(GAP)

        self._subject = QLabel("")
        self._subject.setFont(title_font(ui_font()))
        self._subject.setStyleSheet(f"color: {THEME.ink}; background: transparent;")
        column.addWidget(self._subject)

        self._note = QLabel("Reading…")
        self._note.setFont(caption_font(ui_font()))
        self._note.setStyleSheet(f"color: {THEME.muted}; background: transparent;")
        column.addWidget(self._note)

        headline = QHBoxLayout()
        headline.setSpacing(PAD)
        self._percent = QLabel("")
        self._percent.setStyleSheet(
            f"color: {THEME.accent}; background: transparent; font-size: 30pt;"
            " font-variant-numeric: tabular-nums;"
        )
        headline.addWidget(self._percent)
        headline.addStretch(1)
        self._volume = QLabel("")
        self._volume.setFont(caption_font(ui_font()))
        self._volume.setStyleSheet(f"color: {THEME.muted}; background: transparent;")
        headline.addWidget(self._volume)
        column.addLayout(headline)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(10)
        self._bar.setStyleSheet(
            f"QProgressBar {{ background: {THEME.surface}; border: 1px solid {THEME.line};"
            " border-radius: 5px; }"
            f"QProgressBar::chunk {{ background: {THEME.accent}; border-radius: 5px; }}"
        )
        column.addWidget(self._bar)

        figures = QHBoxLayout()
        figures.setSpacing(STEP)
        lines_box, self._lines = _figure("0", "lines parsed")
        rate_box, self._rate = _figure(_UNKNOWN, "rate")
        left_box, self._left = _figure(_UNKNOWN, "left")
        for box in (lines_box, rate_box, left_box):
            figures.addWidget(box)
        figures.addStretch(1)
        column.addLayout(figures)

        column.addSpacing(PAD)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self._cancel = QPushButton("Cancel")
        self._cancel.setFont(caption_font(ui_font()))
        self._cancel.clicked.connect(self._cancelled)
        buttons.addWidget(self._cancel)
        column.addLayout(buttons)

        self._consequence = QLabel(
            "A cancelled ingest leaves the case un-finalised, so a partial read can "
            "never be analysed as if it were complete."
        )
        self._consequence.setFont(caption_font(ui_font()))
        self._consequence.setStyleSheet(f"color: {THEME.faint}; background: transparent;")
        self._consequence.setWordWrap(True)
        column.addWidget(self._consequence)

    def text(self) -> str:
        """Everything the card says, for tests and for anything reading it whole."""
        return " ".join(
            part
            for part in (
                self._subject.text(),
                self._note.text(),
                self._percent.text(),
                self._volume.text(),
                self._lines.text(),
                self._rate.text(),
                self._left.text(),
            )
            if part
        )

    def update_progress(self, progress: Progress) -> None:
        """Draw `progress`. Nothing here is worked out, only shown."""
        self._subject.setText(progress.subject)
        self._lines.setText(f"{progress.lines:,}")
        self._rate.setText(progress.rate or _UNKNOWN)
        # `remaining` is None until the read has settled and again once it is
        # done. A dash rather than a guess: the seam withheld it on purpose, and
        # inventing one here would put the number back that it exists to keep out.
        self._left.setText(progress.remaining or _UNKNOWN)

        fraction = progress.fraction
        if fraction is None:
            # Nothing to draw a position from. Qt's (0, 0) range is the moving
            # bar, which says "working" without claiming to know where it is.
            self._bar.setRange(0, 0)
            self._percent.setText("")
            self._volume.setText("")
            return

        self._bar.setRange(0, 1000)
        self._bar.setValue(int(fraction * 1000))
        self._percent.setText(progress.percent or "")
        self._volume.setText(
            f"{_megabytes(progress.bytes_done)} of {_megabytes(progress.bytes_total)}"
        )

    def stopping(self) -> None:
        """Say the cancel has been heard and is being waited on."""
        self._cancel.setEnabled(False)
        self._note.setText("Stopping after the batch in flight…")

    def _cancelled(self) -> None:
        self.stopping()
        self._on_cancel()


def _megabytes(count: int) -> str:
    return f"{count / 1_000_000:,.0f} MB"
