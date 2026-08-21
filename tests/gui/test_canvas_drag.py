"""Nodes that can be dragged, and everything that has to move with them.

Run without a display. What is checked here is geometry — where a path ends,
which items a move touched, what colour a pen is — none of which the offscreen
platform's missing fonts can hide. Caption *sizes* would be a different matter,
and are not asserted on here.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QPointF
from PyQt6.QtGui import QPainterPath
from PyQt6.QtWidgets import QApplication

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarc.gui.canvas import ActivityCanvas, _edge_shape

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    return QApplication.instance() or QApplication([])


def node(index: int, label: str = "directory enumeration") -> GraphNode:
    return GraphNode(
        node_id=f"n{index}",
        label=label,
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
        episode_ids=(f"n{index}",),
    )


def chain(count: int = 4) -> ActivityGraph:
    """A trace: n0 -> n1 -> ... Each middle node carries two edges."""
    nodes = tuple(node(index) for index in range(count))
    edges = tuple(
        GraphEdge(source=first.node_id, target=second.node_id, gap_seconds=30.0)
        for first, second in pairwise(nodes)
    )
    return ActivityGraph(kind=GraphKind.TRACE, client_ip="1.2.3.4", nodes=nodes, edges=edges)


def both_ways() -> ActivityGraph:
    """A behaviour map with one reciprocal pair, which is drawn bowed."""
    nodes = (node(0), node(1))
    edges = (
        GraphEdge(source="n0", target="n1", weight=3, gap_seconds=12.0),
        GraphEdge(source="n1", target="n0", weight=2, gap_seconds=40.0),
    )
    return ActivityGraph(kind=GraphKind.BEHAVIOUR, client_ip="1.2.3.4", nodes=nodes, edges=edges)


def points(path: QPainterPath) -> list[tuple[float, float]]:
    return [(path.elementAt(i).x, path.elementAt(i).y) for i in range(path.elementCount())]


# -- the geometry, on its own ---------------------------------------------


def test_an_arrow_starts_and_ends_on_the_rims_not_the_centres() -> None:
    """The arrowhead has to land where the eye expects it: against the circle,
    not buried under it."""
    start, end = QPointF(0.0, 0.0), QPointF(400.0, 0.0)

    shape = _edge_shape(start, end, source_radius=20.0, target_radius=35.0, paired=False)

    first, last = shape.path.elementAt(0), shape.path.elementAt(shape.path.elementCount() - 1)
    assert QPointF(first.x, first.y) == QPointF(20.0, 0.0)
    assert QPointF(last.x, last.y) == QPointF(365.0, 0.0)


def test_a_lone_transition_is_drawn_straight() -> None:
    shape = _edge_shape(
        QPointF(0.0, 0.0), QPointF(400.0, 0.0), source_radius=20.0, target_radius=20.0, paired=False
    )

    assert shape.path.elementCount() == 2


def test_a_pair_that_leads_both_ways_is_drawn_bowed() -> None:
    """Straight, the second arrow lands exactly on the first and hides it along
    with its label, so the map shows one transition where there are two."""
    shape = _edge_shape(
        QPointF(0.0, 0.0), QPointF(400.0, 0.0), source_radius=20.0, target_radius=20.0, paired=True
    )

    assert shape.path.elementCount() > 2
    assert shape.anchor.y() != 0.0, "the label sits off the straight line, on the bow"
    assert shape.label_at.y() != shape.anchor.y(), "and clear of the arrow itself"


def test_the_two_arrows_of_a_pair_bow_to_opposite_sides() -> None:
    """Symmetrically, and without either edge needing to know the other exists."""
    there = _edge_shape(
        QPointF(0.0, 0.0), QPointF(400.0, 0.0), source_radius=20.0, target_radius=20.0, paired=True
    )
    back = _edge_shape(
        QPointF(400.0, 0.0), QPointF(0.0, 0.0), source_radius=20.0, target_radius=20.0, paired=True
    )

    assert there.anchor.y() * back.anchor.y() < 0


# -- reshaping an arrow that is already on the canvas ----------------------


def test_reshaping_an_arrow_puts_it_back_exactly_where_it_was_drawn(
    qt_app: QApplication,
) -> None:
    """Two code paths now put an arrow on the canvas: the one that draws a graph,
    and the one that follows a node being dragged. Left to compute their own
    geometry they would drift, and the drift would show as arrows that snap into
    a different shape the moment the mouse is let go.

    Reshaped away and reshaped back, an arrow has to land on the path the
    drawing code gave it. Anything else means the two have already parted."""
    canvas = ActivityCanvas()
    canvas.show_graph(chain(2))
    art = canvas._edge_art[0]
    at_rest = points(art.line.path())
    head_at_rest = [(p.x(), p.y()) for p in art.head.polygon()]
    was = QPointF(canvas._nodes["n0"].pos()), QPointF(canvas._nodes["n1"].pos())

    art.reshape(was[0], QPointF(500.0, -300.0))
    # Both premises, separately. An arrowhead that is never touched comes back
    # matching by never having left, and the round trip alone cannot tell that
    # apart from one that moved and came home.
    assert points(art.line.path()) != at_rest, "premise: the line moved"
    assert [(p.x(), p.y()) for p in art.head.polygon()] != head_at_rest, "premise: the head moved"
    art.reshape(*was)

    assert points(art.line.path()) == at_rest
    assert [(p.x(), p.y()) for p in art.head.polygon()] == head_at_rest


def test_every_arrow_is_filed_under_both_ends(qt_app: QApplication) -> None:
    """A node being dragged has to find its own arrows without walking the whole
    graph on every mouse move."""
    canvas = ActivityCanvas()
    canvas.show_graph(chain(4))

    assert len(canvas._edges_by_node["n0"]) == 1
    assert len(canvas._edges_by_node["n1"]) == 2
    assert len(canvas._edges_by_node["n3"]) == 1


def test_a_reciprocal_pair_files_two_arrows_under_each_node(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.show_graph(both_ways())

    assert len(canvas._edges_by_node["n0"]) == 2
    assert len(canvas._edges_by_node["n1"]) == 2
