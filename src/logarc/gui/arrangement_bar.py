"""Offering to keep how the graph has been arranged.

Holds no wording and no judgement — `gui.arrangement` decides both, and this
renders the result. The split is the one `gui.quarantine_notice` and
`gui.notice_bar` already use: what to say is testable without a display, and
only the drawing of it needs Qt.

A strip below the canvas rather than anything floating on it. The note beside
the Edit menu in `gui.app` says why the undo controls were kept off the canvas
— a strip over the graph "covers a patch of it, has to be moved on every
resize, and swallows clicks meant for whatever node is underneath" — and none
of that stopped being true for this message.
"""

from __future__ import annotations

from typing import Final

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton

from logarc.gui.arrangement import notice
from logarc.gui.theme import GAP, PAD, caption_font
from logarc.style import THEME

__all__ = ["ArrangementBar"]

#: The accent, not the amber the quarantine strip carries. Nothing is wrong
#: here: a moved graph is something the reader did on purpose, and this is an
#: offer to keep it rather than a warning about it. Amber would put the two on
#: the same footing, and one of them is a case that is short of its logs.
_MARK: Final = THEME.accent


class ArrangementBar(QFrame):
    """A strip under the canvas. Hidden until something has been moved."""

    save_requested = pyqtSignal()
    """`Save arrangement` was pressed. What saving *is* belongs to the window,
    which already does it for the menu entry and for the shortcut."""

    reset_requested = pyqtSignal()
    """`Reset` was pressed. Likewise: it forgets a stored arrangement as well as
    putting the nodes back, and only the window can reach the store."""

    def __init__(self) -> None:
        super().__init__()
        # Addressed by name. `QLabel` inherits `QFrame`, so a bare `QFrame` rule
        # paints this border round every label inside the strip as well — the
        # same trap `NoticeBanner` records having fallen into, found there
        # by looking at a screenshot because nothing in the code says it.
        self.setObjectName("arrangementBar")
        self.setStyleSheet(
            f"QFrame#arrangementBar {{ background: {THEME.tint};"
            f" border: 1px solid {_MARK}; border-radius: 4px; }}"
        )

        mark = QLabel("●")
        mark.setStyleSheet(f"color: {_MARK}; background: transparent; border: none;")

        self._words = QLabel("")
        self._words.setFont(caption_font(self._words.font()))
        self._words.setStyleSheet(f"color: {THEME.ink}; background: transparent; border: none;")

        self._reset = QPushButton("Reset")
        self._reset.setFont(caption_font(self._reset.font()))
        self._reset.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset.clicked.connect(self.reset_requested)
        self._reset.setToolTip(
            "Put every activity back where it was laid out, and forget the saved layout."
        )

        self._save = QPushButton("Save layout")
        self._save.setFont(caption_font(self._save.font()))
        self._save.setCursor(Qt.CursorShape.PointingHandCursor)
        self._save.setDefault(True)
        self._save.clicked.connect(self.save_requested)
        self._save.setToolTip("Remember where you have put the activities on this graph.")

        row = QHBoxLayout(self)
        row.setContentsMargins(GAP, PAD, PAD, PAD)
        row.setSpacing(GAP)
        row.addWidget(mark)
        row.addWidget(self._words)
        row.addStretch(1)
        row.addWidget(self._reset)
        row.addWidget(self._save)

        self.hide()

    def text(self) -> str:
        """What the strip is saying, which is nothing until something has moved."""
        return self._words.text()

    def show_moved(self, count: int) -> None:
        """Offer to keep `count` moved activities, or go away if there are none.

        One method for both, because the two are the same question asked at the
        same moments. Split in two, every caller would have to decide which to
        call, and the one that forgot would leave the strip offering to save an
        arrangement that had just been saved.
        """
        if count <= 0:
            self.hide()
            return
        self._words.setText(notice(count))
        self.show()
