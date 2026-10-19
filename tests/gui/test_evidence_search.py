"""The evidence panel's filter: the box, the strip that says a view is filtered,
and what an empty result says.

Run without a display. The panel is driven directly with what the window would
hand it; which lines match is the window's to work out, and is tested there.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QSize
from PyQt6.QtGui import QResizeEvent
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QPushButton

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import GraphNode
from logarc.evidence import EvidenceLine
from logarc.gui.evidence_panel import EvidencePanel
from logarc.gui.evidence_view import Filtered

START = datetime(2026, 3, 11, 0, 50, tzinfo=UTC)


def sweep(requests: int = 33) -> GraphNode:
    return GraphNode(
        node_id="198.51.100.31#1/1",
        label="Directory Enumeration",
        category=ActivityCategory.ENUMERATION,
        severity=Severity.MEDIUM,
        outcome=Outcome.MIXED,
        request_count=requests,
        distinct_paths=requests,
        bytes_total=1,
        start=START,
        end=START + timedelta(seconds=requests),
        owasp=None,
        top_targets=("/a",),
        rule_ids=("directory_enumeration",),
        evidence=(),
        evidence_total=requests,
        episode_ids=("198.51.100.31#1/1",),
    )


def lines(count: int, status: int = 404) -> list[EvidenceLine]:
    return [
        EvidenceLine(
            ref=EvidenceRef("access.log", index + 1),
            source_path="access.log",
            text=f"line {index}",
            event=NormalizedEvent(
                timestamp=START + timedelta(seconds=index),
                client_ip="198.51.100.31",
                evidence=EvidenceRef("access.log", index + 1),
                method="GET",
                path=f"/guess/{index}",
                status=status,
            ),
            verified=True,
        )
        for index in range(count)
    ]


@pytest.fixture
def panel(qt_app: QApplication) -> EvidencePanel:
    shown = EvidencePanel()
    shown.resize(700, 600)
    shown.show()
    QApplication.processEvents()
    return shown


def rows(panel: EvidencePanel) -> int:
    return panel._table.rowCount()


# -- unfiltered ---------------------------------------------------------------------


def test_without_a_filter_nothing_new_shows(panel: EvidencePanel) -> None:
    panel.show_evidence(sweep(), lines(33))

    assert panel.strip.isHidden()
    assert panel.no_results.isHidden()
    assert "Showing 33 of 33 lines" in panel._heading.text()


# -- filtered -------------------------------------------------------------------------


def test_a_filtered_view_says_so_in_place_of_the_line_count(panel: EvidencePanel) -> None:
    panel.show_evidence(sweep(), lines(2, 200), filtered=Filtered("status:200", 2, 33))

    assert not panel.strip.isHidden()
    assert "Filtered \N{MIDDLE DOT} 2 of 33 lines match status:200" in panel.strip.text()
    # Kept on one line: a link broken across two reads as two words, one of
    # them a stray "filter" at the start of a line.
    assert ">Clear&nbsp;filter</a>" in panel.strip.text()
    assert "Showing" not in panel._heading.text()
    assert "33 requests" in panel._heading.text(), "the activity is still described whole"
    assert rows(panel) == 2
    assert panel.no_results.isHidden()


def test_more_matches_than_loaded_says_which_are_shown(panel: EvidencePanel) -> None:
    panel.show_evidence(sweep(), lines(10), filtered=Filtered("status:404", 20, 33))

    assert "showing the first 10" in panel.strip.text()


def test_no_match_says_no_results_found_in_the_table(panel: EvidencePanel) -> None:
    panel.show_evidence(sweep(), [], filtered=Filtered("status:401", 0, 33))

    assert not panel.no_results.isHidden()
    words = " ".join(label.text() for label in panel.no_results.findChildren(type(panel._heading)))
    assert "No results found" in words
    assert "None of the 33 lines in this activity match status:401." in words
    assert panel.no_results.findChild(QPushButton).text() == "Clear filter"
    assert "</a>" not in panel.strip.text(), "one way to clear, not two"
    assert panel.no_results.geometry() == panel._table.viewport().rect()


def test_a_later_unfiltered_view_takes_the_strip_and_the_message_away(
    panel: EvidencePanel,
) -> None:
    panel.show_evidence(sweep(), [], filtered=Filtered("status:401", 0, 33))

    panel.show_evidence(sweep(), lines(33))

    assert panel.strip.isHidden()
    assert panel.no_results.isHidden()


def test_a_query_is_shown_as_text_not_markup(panel: EvidencePanel) -> None:
    """The query is the reader's, but a path filter can hold anything a path does."""
    panel.show_evidence(sweep(), [], filtered=Filtered("<b>x</b>", 0, 33))

    assert "&lt;b&gt;" in panel.strip.text()


# -- the box --------------------------------------------------------------------------


def test_typing_is_heard_once_it_rests(panel: EvidencePanel) -> None:
    heard: list[str] = []
    panel.filter_changed.connect(heard.append)

    QTest.keyClicks(panel.filter_box.edit, "status:404")
    assert heard == [], "not on every key"
    QTest.qWait(EvidencePanel.FILTER_DELAY_MS + 80)

    assert heard == ["status:404"]


def test_clear_filter_empties_the_box_at_once(panel: EvidencePanel) -> None:
    panel.set_filter_text("status:200")
    panel.show_evidence(sweep(), lines(2, 200), filtered=Filtered("status:200", 2, 33))
    heard: list[str] = []
    panel.filter_changed.connect(heard.append)

    panel.strip.linkActivated.emit("clear")

    assert panel.filter_text() == ""
    assert heard == [""]


def test_the_message_button_clears_too(panel: EvidencePanel) -> None:
    panel.set_filter_text("status:401")
    panel.show_evidence(sweep(), [], filtered=Filtered("status:401", 0, 33))
    heard: list[str] = []
    panel.filter_changed.connect(heard.append)

    panel.no_results.findChild(QPushButton).click()

    assert panel.filter_text() == ""
    assert heard == [""]


def test_setting_the_filter_from_outside_is_silent(panel: EvidencePanel) -> None:
    """The window sets it when it opens a client, and draws straight after."""
    heard: list[str] = []
    panel.filter_changed.connect(heard.append)

    panel.set_filter_text("status:404 path:/admin")
    QTest.qWait(EvidencePanel.FILTER_DELAY_MS + 80)

    assert panel.filter_text() == "status:404 path:/admin"
    assert panel.filter_box.chips() == ("status:404", "path:/admin")
    assert heard == []


def test_the_box_offers_this_activitys_values(panel: EvidencePanel) -> None:
    panel.set_suggestion_values({"status": [("404", "31 lines")]})

    assert panel.filter_box._values_title == "VALUES IN THIS ACTIVITY"
    assert panel.filter_box._values == {"status": [("404", "31 lines")]}


def test_an_empty_panel_offers_no_values(panel: EvidencePanel) -> None:
    """With no activity on show there is nothing for "values in this activity" to be."""
    panel.set_suggestion_values({"status": [("404", "31 lines")]})

    panel.clear()

    assert panel.filter_box._values == {}


def test_an_event_after_the_panel_lets_go_of_its_table_is_ignored(
    panel: EvidencePanel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The collector clears a panel's attributes while Qt is still delivering its
    table's last events. The filter assumed `_table` was there and raised inside
    Qt, which PyQt answers by ending the process: the window's tests aborted in a
    teardown once garbage was collected there."""
    raised: list[object] = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc: raised.append(exc))
    table = panel._table
    port = table.viewport()
    del panel._table
    try:
        QApplication.sendEvent(port, QResizeEvent(QSize(10, 10), QSize(5, 5)))
    finally:
        panel._table = table

    assert raised == []
