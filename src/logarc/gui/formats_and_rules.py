"""Formats and rules in one dialog: whether a line can be read, and what it means.

Two tabs rather than one list (chosen from the preview, 2026-10-21): each list
stays short, the formats tab is the screen readers already know, and the two
tab names carry the difference between the halves without a paragraph.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QTabWidget, QVBoxLayout, QWidget

from logarc.gui.format_editor import FormatEditor
from logarc.gui.rules_editor import RulesEditor
from logarc.gui.theme import GAP

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["FORMATS_TAB", "RULES_TAB", "FormatsAndRules"]

FORMATS_TAB: Final = "Log formats: can a line be read?"
RULES_TAB: Final = "Detection rules: what does a line mean?"

#: The preview's size, measured with the rules tab's YAML and counts in sight.
_WIDTH: Final = 860
_HEIGHT: Final = 760


class FormatsAndRules(QDialog):
    """Modal. Each tab writes what the reader saves as they save it."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        case_path: Path | None = None,
        on_rules: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Formats and rules")

        self.formats = FormatEditor(self)
        self.formats.setWindowFlags(Qt.WindowType.Widget)
        # FormatEditor's Close rejects itself, which as a widget inside a tab
        # only hides the tab's contents. Closing what the reader sees is
        # rejecting this.
        self.formats.rejected.connect(self.reject)
        self.rules = RulesEditor(case_path)
        self.rules.close_requested.connect(self.reject)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.formats, FORMATS_TAB)
        self.tabs.addTab(self.rules, RULES_TAB)
        self.tabs.setCurrentIndex(1 if on_rules else 0)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, GAP, 0, 0)
        layout.addWidget(self.tabs)
        self.resize(_WIDTH, _HEIGHT)

    def done(self, result: int) -> None:
        self.rules.shutdown()
        super().done(result)
