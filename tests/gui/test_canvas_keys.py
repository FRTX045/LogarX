"""Reading the graph from the keyboard: moving the ring from activity to activity.

A click on a circle was the only way to open an activity's evidence. With the
canvas focused, the arrow keys move to the next or previous activity in the
order the graph draws them, which on a trace is the order they happened, and
Home and End go to the first and last.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarc.gui.canvas import ActivityCanvas

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def _node(index: int) -> GraphNode:
    return GraphNode(
        node_id=f"n{index}",
        label=f"step {index}",
        category=ActivityCategory.ENUMERATION,
        severity=Severity.MEDIUM,
        outcome=Outcome.BLOCKED,
        request_count=5,
        distinct_paths=5,
        bytes_total=1,
        start=START + timedelta(minutes=index),
        end=START + timedelta(minutes=index, seconds=30),
        owasp=None,
        top_targets=("/a",),
        rule_ids=("r",),
        evidence=(EvidenceRef("access.log", index),),
        evidence_total=5,
        episode_ids=(f"1.2.3.4#1/{index}",),
    )


def _three() -> ActivityGraph:
    nodes = (_node(0), _node(1), _node(2))
    return ActivityGraph(
        kind=GraphKind.TRACE,
        client_ip="1.2.3.4",
        nodes=nodes,
        edges=(GraphEdge("n0", "n1", gap_seconds=30.0), GraphEdge("n1", "n2", gap_seconds=30.0)),
    )


@pytest.fixture
def canvas(qt_app: QApplication) -> ActivityCanvas:
    """A canvas on show, wired as the window wires it: a selection is ringed."""
    shown = ActivityCanvas()
    shown.resize(600, 480)
    shown.node_selected.connect(shown.highlight)
    shown.show_graph(_three())
    shown.show()
    shown.setFocus()
    QApplication.processEvents()
    return shown


def _press(canvas: ActivityCanvas, key: Qt.Key) -> list[str]:
    chosen: list[str] = []
    canvas.node_selected.connect(chosen.append)
    QTest.keyClick(canvas, key)
    canvas.node_selected.disconnect(chosen.append)
    return chosen


def test_the_canvas_can_be_reached_by_tab(canvas: ActivityCanvas) -> None:
    assert canvas.focusPolicy() & Qt.FocusPolicy.TabFocus


def test_right_opens_the_first_activity_then_the_next(canvas: ActivityCanvas) -> None:
    assert _press(canvas, Qt.Key.Key_Right) == ["n0"]
    assert _press(canvas, Qt.Key.Key_Right) == ["n1"]
    assert _press(canvas, Qt.Key.Key_Down) == ["n2"]


def test_left_goes_back_and_the_ends_stop(canvas: ActivityCanvas) -> None:
    assert _press(canvas, Qt.Key.Key_End) == ["n2"]
    assert _press(canvas, Qt.Key.Key_Left) == ["n1"]
    assert _press(canvas, Qt.Key.Key_Up) == ["n0"]
    assert _press(canvas, Qt.Key.Key_Left) == [], "nothing before the first"
    assert _press(canvas, Qt.Key.Key_Home) == []


def test_the_canvas_names_the_activity_it_has_ringed(canvas: ActivityCanvas) -> None:
    """For a screen reader: the circles themselves are not in the accessibility
    tree, so the canvas says which one is selected."""
    assert canvas.accessibleName()

    _press(canvas, Qt.Key.Key_Right)

    assert "step 0" in canvas.accessibleDescription()


def test_a_new_graph_or_none_says_nothing_is_ringed(canvas: ActivityCanvas) -> None:
    _press(canvas, Qt.Key.Key_Right)

    canvas.show_graph(_three())
    assert canvas.accessibleDescription() == ""

    _press(canvas, Qt.Key.Key_Right)
    canvas.show_graph_placeholder()
    assert canvas.accessibleDescription() == ""
