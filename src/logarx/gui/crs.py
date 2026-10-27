"""Showing CRS running after a scan, and saying so when it cannot run.

Two faces, and the reasoning behind each is in its class. There used to be a
third, a dialog asking whether to run CRS at all; since 2026-10-05 it runs by
itself and the question is a preference (`prefs.RUN_CRS`), whose note carries
what the dialog said about the trade.

The rule that dialog left behind still holds: no figure on a face. An early
draft of it quoted "SSRF recall 0.600 to 0.800" — three detections becoming
four — and a false-alarm count measured on a corpus since replaced. The numbers
appear on the card instead, where they are counts from the reader's own log.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from logarx.gui._qt import required
from logarx.gui.theme import GAP, PAD, ROOM, caption_font, colour_text, heading_font, mono_font
from logarx.style import THEME

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtGui import QCloseEvent, QKeyEvent

    from logarx.enrich import EnrichProgress

__all__ = ["CrsCard", "CrsUnavailable"]


#: The two sides, in the order a reader weighs them. Green for what is gained,
#: amber for what it costs — not red, which would read as an error rather than
#: as the other half of a trade the reader is being invited to make.
_GAIN = "#7bcfa0"
_COST = "#e8a35c"


def _wrapped(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    return label


def _quiet(text: str) -> QLabel:
    label = _wrapped(text)
    label.setFont(caption_font(label.font()))
    label.setStyleSheet(f"color: {THEME.muted};")
    return label


def _titled(text: str, colour: str = THEME.ink) -> QLabel:
    label = QLabel(text)
    label.setFont(heading_font(label.font()))
    colour_text(label, colour)
    return label


def _side(mark: str, colour: str, text: str) -> QWidget:
    """One half of the trade: a marker and a line.

    Not a bordered card with a heading, which is what this was first. Two boxes
    of equal weight read as a list of features; a plus against a minus reads as
    a balance, which is what the reader is actually being shown.
    """
    holder = QWidget()
    row = QHBoxLayout(holder)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(PAD)

    glyph = QLabel(mark)
    glyph.setFixedWidth(14)
    glyph.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
    weighted = glyph.font()
    weighted.setBold(True)
    glyph.setFont(weighted)
    glyph.setStyleSheet(f"color: {colour};")

    row.addWidget(glyph)
    row.addWidget(_wrapped(text), 1)
    return holder


class _Spoken(QDialog):
    """A dialog that can say what is written on it.

    Tests assert about wording rather than about widget trees, because the
    wording is the part with the judgement in it. Walking children for every
    `QLabel` keeps that check honest: a sentence moved between widgets still
    counts, a sentence deleted does not.
    """

    def spoken(self) -> str:
        return "\n".join(
            [
                *(label.text() for label in self.findChildren(QLabel) if label.text()),
                *(box.text() for box in self.findChildren(QCheckBox)),
            ]
        )


class CrsUnavailable(_Spoken):
    """The sidecar is not on this machine, which is the usual state.

    Worded as a finished case rather than a failure, and in that order: the
    reassurance comes before the instructions, because somebody who reads only
    the first line should come away knowing nothing is broken.
    """

    def __init__(self, reason: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("CRS is not installed")
        self.setFixedWidth(400)
        self.setModal(True)

        self._quiet_it = QCheckBox("Don't mention this again")

        buttons = QDialogButtonBox()
        carry_on = required(buttons.addButton("Continue", QDialogButtonBox.ButtonRole.AcceptRole))
        carry_on.setDefault(True)
        buttons.accepted.connect(self.accept)

        stack = QVBoxLayout(self)
        stack.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        stack.setSpacing(GAP)
        stack.addWidget(_titled("CRS is not installed", THEME.warning))
        stack.addWidget(
            _wrapped(
                "The case is complete without it — CRS is an optional second ruleset "
                "and only adds extra findings."
            )
        )
        stack.addWidget(_quiet(reason))
        stack.addWidget(self._quiet_it)
        stack.addWidget(buttons)

    def remembered(self) -> bool:
        return self._quiet_it.isChecked()


class CrsCard(_Spoken):
    """How far in, and what has been found so far.

    The bar is determinate because `EnrichProgress` carries a denominator from
    the manifest. Without one this would be a spinner, which is what the command
    line already has and the reason this screen exists at all.
    """

    def __init__(self, parent: QWidget | None, *, on_stop: Callable[[], None]) -> None:
        super().__init__(parent)
        self._on_stop = on_stop
        self.setWindowTitle("Running OWASP CRS")
        self.setFixedWidth(400)
        self.setModal(True)
        # No close button: Stop is the one way out, and it says what it does.
        self.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint
        )

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(4)
        self._bar.setStyleSheet(
            f"QProgressBar {{ background: {THEME.stripe}; border: none; }}"
            f"QProgressBar::chunk {{ background: {THEME.accent}; }}"
        )

        self._counts = QLabel("Starting…")
        self._counts.setFont(mono_font())
        self._counts.setStyleSheet(f"color: {THEME.muted};")

        self._buttons = QDialogButtonBox()
        self._stop = required(
            self._buttons.addButton("Stop", QDialogButtonBox.ButtonRole.RejectRole)
        )
        # Never the default: Enter would stop the run.
        self._stop.setAutoDefault(False)
        self._stop.clicked.connect(self.press_stop)

        stack = QVBoxLayout(self)
        stack.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        stack.setSpacing(GAP)
        stack.addWidget(_titled("Running OWASP CRS", THEME.accent))
        stack.addWidget(self._bar)
        stack.addWidget(self._counts)
        stack.addWidget(
            _quiet(
                "Stopping keeps everything found so far, unless the case was "
                "already checked in full: then it keeps that."
            )
        )
        stack.addWidget(self._buttons)

    def bar(self) -> QProgressBar:
        return self._bar

    def update_progress(self, progress: EnrichProgress) -> None:
        self._bar.setRange(0, progress.total)
        self._bar.setValue(progress.replayed)
        self._counts.setText(f"{progress.replayed:,} of {progress.total:,} requests")

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

    def press_stop(self) -> None:
        """Ask once. A second press cannot un-ask, and the run ends at the next
        request either way, so the button says what is happening and stops
        being pressable."""
        if not self._stop.isEnabled():
            return
        self._stop.setEnabled(False)
        self._stop.setText("Stopping…")
        self._on_stop()
