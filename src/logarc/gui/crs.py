"""Offering CRS when a scan finishes, and showing it running.

Three faces, and the reasoning behind each is in its class. What they share is
what the offer deliberately does *not* do: quote a figure. An earlier draft
carried two, "SSRF recall 0.600 to 0.800" and "false alarms 1 to 81". The first
has a denominator of five records, so it is three detections becoming four; the
second was measured on a corpus that had since been replaced. Both read as
solid, and a figure in a dialog gets no footnote and no reader who knows what it
was measured on.

So the offer describes the *shape* of the trade in words, and the numbers appear
afterwards on the card, where they are counts from the reader's own log.
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

from logarc.gui._qt import required
from logarc.gui.theme import GAP, PAD, ROOM, TIGHT, caption_font, heading_font, mono_font
from logarc.style import THEME

if TYPE_CHECKING:
    from collections.abc import Callable

    from logarc.enrich import EnrichProgress

__all__ = ["CrsCard", "CrsOffer", "CrsUnavailable"]

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


def _titled(text: str) -> QLabel:
    label = QLabel(text)
    label.setFont(heading_font(label.font()))
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
            label.text() for label in self.findChildren(QLabel) if label.text()
        ) + "\n".join(box.text() for box in self.findChildren(QCheckBox))


class CrsOffer(_Spoken):
    """Asked once, when a scan finishes."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Also run OWASP CRS?")
        self.setFixedWidth(430)
        # Modal to the reader, non-blocking to the caller — `setModal` plus
        # `show()`, the way IngestCard does it. `exec()` would block the
        # thread that just finished an ingest, and every test that drives one
        # would stop dead on a dialog it never asked for.
        self.setModal(True)

        self._remember = QCheckBox("Remember this choice")

        buttons = QDialogButtonBox()
        run = required(buttons.addButton("Run CRS", QDialogButtonBox.ButtonRole.AcceptRole))
        run.setDefault(True)
        buttons.addButton("Skip", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        trade = QVBoxLayout()
        trade.setSpacing(TIGHT)
        trade.addWidget(_side("+", _GAIN, "Catches attacks logarc's own rules miss"))
        # A true minus sign rather than a hyphen, and the ambiguity warning is
        # accepted knowingly: it is set directly under a plus, and a hyphen
        # there reads as a dash rather than as the other half of the pair.
        cost = "\N{MINUS SIGN}"
        trade.addWidget(_side(cost, _COST, "Calls more ordinary traffic suspicious"))

        stack = QVBoxLayout(self)
        stack.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        stack.setSpacing(GAP)
        stack.addWidget(_titled("Also run OWASP CRS?"))
        stack.addWidget(_wrapped("A second ruleset, the one most web application firewalls use."))
        stack.addLayout(trade)
        stack.addWidget(_quiet("About 5 minutes. You can run it later instead."))
        stack.addWidget(self._remember)
        stack.addWidget(buttons)

    def remembered(self) -> bool:
        """Whether this answer should be used for every case from now on."""
        return self._remember.isChecked()

    def tick_remember(self) -> None:
        self._remember.setChecked(True)


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
        stack.addWidget(_titled("CRS is not installed"))
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
        self._counts.setFont(mono_font(9.0))
        self._counts.setStyleSheet(f"color: {THEME.muted};")

        self._buttons = QDialogButtonBox()
        self._stop = required(
            self._buttons.addButton("Stop", QDialogButtonBox.ButtonRole.RejectRole)
        )
        self._stop.clicked.connect(self.press_stop)

        stack = QVBoxLayout(self)
        stack.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        stack.setSpacing(GAP)
        stack.addWidget(_titled("Running OWASP CRS"))
        stack.addWidget(self._bar)
        stack.addWidget(self._counts)
        stack.addWidget(_quiet("Stopping keeps everything found so far."))
        stack.addWidget(self._buttons)

    def bar(self) -> QProgressBar:
        return self._bar

    def update_progress(self, progress: EnrichProgress) -> None:
        self._bar.setRange(0, progress.total)
        self._bar.setValue(progress.replayed)
        self._counts.setText(f"{progress.replayed:,} of {progress.total:,} requests")

    def press_stop(self) -> None:
        """Ask once. A second press cannot un-ask, and the run ends at the next
        request either way, so the button says what is happening and stops
        being pressable."""
        if not self._stop.isEnabled():
            return
        self._stop.setEnabled(False)
        self._stop.setText("Stopping…")
        self._on_stop()
