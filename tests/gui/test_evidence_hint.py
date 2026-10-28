"""What the evidence panel says while it is empty and Triage is in front.

Triage is where a case opens, and the evidence panel beside it was an empty
table under its headings with nothing to say what fills it. While Triage is in
front and nothing is shown, the panel says where its lines come from.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from logarx.gui.app import MainWindow
from logarx.gui.evidence_panel import TRIAGE_HINT, EvidencePanel


def test_an_empty_panel_says_where_its_lines_come_from_while_triage_is_in_front(
    qt_app: QApplication,
) -> None:
    panel = EvidencePanel()
    panel.clear(prompt=False)

    panel.triage_in_front(True)
    assert panel._heading.text() == TRIAGE_HINT

    panel.triage_in_front(False)
    assert panel._heading.text() == ""


def test_away_from_triage_the_panel_says_what_it_said_before(qt_app: QApplication) -> None:
    panel = EvidencePanel()
    panel.clear()
    panel.triage_in_front(True)

    panel.triage_in_front(False)

    assert panel._heading.text() == "Select an activity."


def test_the_window_tells_the_panel_which_tab_is_in_front(qt_app: QApplication) -> None:
    window = MainWindow()
    tabs = window._workspace

    tabs.setCurrentWidget(window._triage)
    assert window._evidence._heading.text() == TRIAGE_HINT

    tabs.setCurrentIndex(1)
    assert window._evidence._heading.text() != TRIAGE_HINT
    window.close()
