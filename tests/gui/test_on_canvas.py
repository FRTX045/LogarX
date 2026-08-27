"""Finding what is on the canvas by its name, rather than by when it was drawn.

`on_canvas` exists so that a test asking for one arrow says which arrow it
means. Indexing `_edge_art` said *third drawn*, which is a different thing that
happened to agree — and the tests that did it wrote a premise assertion
underneath to check the two had not parted company. The lookup here is that
assertion, so the premise no longer needs writing out.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from on_canvas import edge_between, node_item, node_items
from PyQt6.QtWidgets import QApplication

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarc.gui.canvas import ActivityCanvas

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def _node(index: int) -> GraphNode:
    return GraphNode(
        node_id=f"n{index}",
        label="directory enumeration",
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


def _both_ways() -> ActivityGraph:
    """One reciprocal pair: the two arrows differ only in which way they point."""
    return ActivityGraph(
        kind=GraphKind.BEHAVIOUR,
        client_ip="1.2.3.4",
        nodes=(_node(0), _node(1)),
        edges=(
            GraphEdge(source="n0", target="n1", weight=3, gap_seconds=12.0),
            GraphEdge(source="n1", target="n0", weight=2, gap_seconds=40.0),
        ),
    )


def test_the_two_arrows_of_a_reciprocal_pair_are_told_apart(qt_app: QApplication) -> None:
    """The case an index cannot answer.

    Both arrows join the same two activities, so a lookup that matched a *pair*
    rather than a direction would hand back whichever was drawn first for both
    questions — and every assertion about the way back would then be made
    against the way there.
    """
    canvas = ActivityCanvas()
    canvas.show_graph(_both_ways())

    there = edge_between(canvas, "n0", "n1")
    back = edge_between(canvas, "n1", "n0")

    assert (there.source_id, there.target_id) == ("n0", "n1")
    assert (back.source_id, back.target_id) == ("n1", "n0")
    assert there is not back, "two arrows, not one found twice"
    assert there.weight != back.weight, "and they carry what their own edge carried"


def test_asking_for_an_arrow_nobody_drew_says_which_one(qt_app: QApplication) -> None:
    """A miss has to name the arrow. `_edge_art[3]` raised `IndexError`, which
    says a list was too short and leaves the reader to work out whose list."""
    canvas = ActivityCanvas()
    canvas.show_graph(_both_ways())

    with pytest.raises(AssertionError, match="n1 -> n9"):
        edge_between(canvas, "n1", "n9")


def test_an_activity_is_found_by_the_id_it_was_given(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.show_graph(_both_ways())

    item = node_item(canvas, "n1")

    assert (item.pos().x(), item.pos().y()) == canvas.positions["n1"]


def test_asking_for_an_activity_nobody_drew_says_which_one(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.show_graph(_both_ways())

    with pytest.raises(AssertionError, match="n9"):
        node_item(canvas, "n9")


def test_every_drawn_activity_comes_back_once(qt_app: QApplication) -> None:
    """For the questions that are about the drawing rather than the position —
    how big a caption came out, whether two circles overlap — and which need
    the item itself, not the point it sits on."""
    canvas = ActivityCanvas()
    canvas.show_graph(_both_ways())

    items = node_items(canvas)

    assert len(items) == 2
    assert {(i.pos().x(), i.pos().y()) for i in items} == set(canvas.positions.values())
