"""Showing that a case is short of what its logs held.

Holds no wording and no judgement — `gui.quarantine_notice` decides both, and
this renders the result at the weight that notice asks for. The split is the one
`gui.style` exists for: what to say is testable without a display, and only the
drawing of it needs Qt.

A strip rather than a dialog for ordinary damage, because the count is read from
the manifest on every open: it is a property of the case in front of you, not an
event that happened once while you happened to be watching. A dialog *as well*
when a log produced nothing, because then a whole file is missing from the case
and the window behind would otherwise show a short client list — which is
exactly what a quiet day of traffic looks like.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from logarc.core.activity import Severity
from logarc.gui.style import NOTICE_TINT, THEME
from logarc.gui.theme import GAP, PAD, ROOM, caption_font, heading_font

if TYPE_CHECKING:
    from pathlib import Path

    from logarc.gui.quarantine_notice import Notice

__all__ = ["QuarantineBanner", "warn_about_dead_files"]

#: Warning, not failure. The strip reports a case that is short of its logs,
#: which is a thing to look into rather than a thing that broke.
_AMBER: Final = THEME.severity[Severity.MEDIUM]


class QuarantineBanner(QFrame):
    """An amber strip under the menu bar. Hidden until there is something to say."""

    def __init__(self) -> None:
        super().__init__()
        # Addressed by name. `QLabel` inherits `QFrame`, so a bare
        # `QFrame { ... }` rule paints this border round every label inside the
        # strip as well — which is what the first draft did, drawing a box
        # around the warning glyph and a rule beneath the caption. Found by
        # looking at a screenshot; nothing about the code says it.
        self.setObjectName("quarantineBanner")
        self.setStyleSheet(
            f"QFrame#quarantineBanner {{ background: {NOTICE_TINT};"
            f" border: none; border-bottom: 1px solid {_AMBER}; }}"
        )

        mark = QLabel("⚠")
        mark.setStyleSheet(f"color: {_AMBER}; background: transparent;")

        self._headline = QLabel("")
        self._headline.setFont(heading_font(self._headline.font()))
        self._headline.setStyleSheet(f"color: {THEME.ink}; background: transparent;")

        self._detail = QLabel("")
        self._detail.setFont(caption_font(self._detail.font()))
        self._detail.setStyleSheet(f"color: {THEME.muted}; background: transparent;")
        self._detail.setWordWrap(True)

        self._reveal = QPushButton("Show the quarantined lines")
        self._reveal.setFont(caption_font(self._reveal.font()))
        self._reveal.clicked.connect(self._open_quarantine)
        self._reveal.setToolTip(
            "Open the folder holding unparsed.jsonl, which records every refused "
            "line with the reason it was refused."
        )

        close = QToolButton()
        close.setText("✕")
        close.setToolTip("Dismiss until this case is opened again.")
        close.setStyleSheet(
            f"QToolButton {{ color: {THEME.faint}; background: transparent;"
            " border: none; padding: 4px 8px; }"
        )
        close.clicked.connect(self.dismiss)

        words = QVBoxLayout()
        words.setSpacing(0)
        words.addWidget(self._headline)
        words.addWidget(self._detail)

        row = QHBoxLayout(self)
        row.setContentsMargins(ROOM, PAD, PAD, PAD)
        row.setSpacing(GAP)
        row.addWidget(mark, 0, Qt.AlignmentFlag.AlignTop)
        row.addLayout(words, 1)
        row.addWidget(self._reveal, 0, Qt.AlignmentFlag.AlignTop)
        row.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)

        self._quarantine_dir: Path | None = None
        self.hide()

    def text(self) -> str:
        """Both lines, for tests and for anything needing the whole message."""
        return f"{self._headline.text()} {self._detail.text()}".strip()

    def show_notice(self, notice: Notice | None, *, quarantine_dir: Path | None = None) -> None:
        """Show `notice`, or hide the strip when there is none.

        Called on every case open, the clean ones included — passing `None` has
        to *hide* an already-visible strip, or a damaged case followed by a
        clean one leaves the first case's numbers standing over the second
        case's evidence.
        """
        self._quarantine_dir = quarantine_dir
        if notice is None:
            self.hide()
            return
        self._headline.setText(notice.headline)
        # The dialog gets the whole paragraph; the strip gets its first
        # sentence, so that a two-line strip does not become a five-line one and
        # take a third of the window with it.
        self._detail.setText(notice.detail.split("\n\n")[0])
        self._reveal.setVisible(quarantine_dir is not None)
        self.show()

    def dismiss(self) -> None:
        """Hide until the next case open, which fills the strip again."""
        self.hide()

    def _open_quarantine(self) -> None:
        if self._quarantine_dir is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._quarantine_dir)))


def warn_about_dead_files(parent: QWidget, notice: Notice) -> None:
    """Interrupt, because a log in this case produced nothing at all.

    The strip alone is not enough here. With no events from a file, the window
    behind shows a short client list or an empty one — and that is precisely
    what a quiet day of traffic looks like, so there is nothing on screen that
    tells a working case from a broken ingest.
    """
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle("A log in this case could not be read")
    box.setText(notice.headline)
    box.setInformativeText(notice.detail)
    box.exec()
