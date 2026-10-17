"""A box round each session of a trace: drawn, placed, and kept out of the way.

Run without a display. What is checked is geometry, colour and what takes the
mouse; caption sizes come from the platform's font, and nothing here asserts
on them.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from itertools import combinations, pairwise
from unittest.mock import patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from dragging import drag, mouse
from on_canvas import box_text, node_item, node_items, session_boxes
from PyQt6.QtCore import QEvent, QPoint, QRectF
from PyQt6.QtGui import QColor, QImage, QPainter
from PyQt6.QtWidgets import (
    QApplication,
    QGraphicsItem,
    QGraphicsRectItem,
    QGraphicsSimpleTextItem,
)

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarc.gui.canvas import ActivityCanvas
from logarc.style import PAPER, SESSION_GROUND

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def activity(
    session: int, index: int, *, requests: int = 5, label: str = "directory enumeration"
) -> GraphNode:
    start = START + timedelta(hours=session, minutes=index)
    return GraphNode(
        node_id=f"1.2.3.4#{session}/{index}",
        label=label,
        category=ActivityCategory.ENUMERATION,
        severity=Severity.MEDIUM,
        outcome=Outcome.BLOCKED,
        request_count=requests,
        distinct_paths=1,
        bytes_total=1,
        start=start,
        end=start + timedelta(seconds=30),
        owasp=None,
        top_targets=("/a",),
        rule_ids=("r",),
        evidence=(EvidenceRef("access.log", session * 100 + index),),
        evidence_total=requests,
        episode_ids=(f"1.2.3.4#{session}/{index}",),
    )


def trace(*sizes: int, requests: int = 5, label: str = "directory enumeration") -> ActivityGraph:
    """One session per size, that many activities long, chained within a session
    and never across one, as `build_trace_graph` does."""
    nodes = tuple(
        activity(session, index, requests=requests, label=label)
        for session, size in enumerate(sizes, start=1)
        for index in range(1, size + 1)
    )
    edges = tuple(
        GraphEdge(first.node_id, second.node_id, gap_seconds=30.0)
        for first, second in pairwise(nodes)
        if first.node_id.split("/")[0] == second.node_id.split("/")[0]
    )
    return ActivityGraph(kind=GraphKind.TRACE, client_ip="1.2.3.4", nodes=nodes, edges=edges)


def behaviour_map() -> ActivityGraph:
    nodes = (activity(1, 1), activity(2, 1))
    edges = (GraphEdge(nodes[0].node_id, nodes[1].node_id, weight=2, gap_seconds=1.0),)
    return ActivityGraph(kind=GraphKind.BEHAVIOUR, client_ip="1.2.3.4", nodes=nodes, edges=edges)


def drawn(graph: ActivityGraph) -> ActivityCanvas:
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show_graph(graph)
    return canvas


def held(item: QGraphicsItem) -> QRectF:
    """An activity with its caption, in scene units."""
    return item.sceneBoundingRect().united(item.mapRectToScene(item.childrenBoundingRect()))


def patches(canvas: ActivityCanvas) -> list[QGraphicsRectItem]:
    """Every patch a word is written on: captions, arrow numbers, box labels."""
    return [
        item
        for item in canvas.graph_scene.items()
        if isinstance(item, QGraphicsRectItem)
        and any(isinstance(child, QGraphicsSimpleTextItem) for child in item.childItems())
    ]


# -- what is drawn ---------------------------------------------------------


def test_each_session_of_a_trace_gets_a_labelled_box(qt_app: QApplication) -> None:
    canvas = drawn(trace(1, 3))

    boxes = session_boxes(canvas)

    assert [box_text(box) for box in boxes] == [
        "Session 1 of 2 · 1 activity · 01 May 13:01",
        "Session 2 of 2 · 3 activities · 01 May 14:01\u201314:03",
    ]
    assert [box.node_ids for box in boxes] == [
        ("1.2.3.4#1/1",),
        ("1.2.3.4#2/1", "1.2.3.4#2/2", "1.2.3.4#2/3"),
    ]


def test_a_behaviour_map_has_no_boxes(qt_app: QApplication) -> None:
    """One circle there folds many sessions together; a box round it would
    claim a session it does not have."""
    canvas = drawn(behaviour_map())

    assert session_boxes(canvas) == []
    assert all(ground.brush().color() == QColor(PAPER) for ground in patches(canvas))


def test_nothing_drawn_means_no_boxes(qt_app: QApplication) -> None:
    canvas = drawn(ActivityGraph(kind=GraphKind.TRACE, client_ip="1.2.3.4"))
    assert session_boxes(canvas) == []

    canvas.show_graph(trace(2))
    canvas.show_graph_placeholder()
    assert session_boxes(canvas) == []


# -- where it is drawn ----------------------------------------------------


@pytest.mark.parametrize("sizes", [(1,), (3,), (7,), (1, 7, 1, 12, 1)])
def test_every_activity_and_arrow_number_sits_inside_its_own_box(
    qt_app: QApplication, sizes: tuple[int, ...]
) -> None:
    canvas = drawn(trace(*sizes))

    for box in session_boxes(canvas):
        outline = box.shape.sceneBoundingRect()
        for node_id in box.node_ids:
            assert outline.contains(held(node_item(canvas, node_id))), node_id
    for art in canvas._edge_art:
        if art.label is not None and art.label.isVisible():
            owner = canvas._box_of[art.source_id]
            assert owner.shape.sceneBoundingRect().contains(art.label.sceneBoundingRect())


@pytest.mark.parametrize("sizes", [(1,), (3,), (1, 7, 1)])
def test_a_label_sits_inside_its_box_and_on_nothing_else(
    qt_app: QApplication, sizes: tuple[int, ...]
) -> None:
    """A one-activity session's label is wider than its activity; the box
    widens to hold it rather than letting it run out over the edge."""
    canvas = drawn(trace(*sizes))
    drawn_things = [held(item) for item in node_items(canvas)]

    for box in session_boxes(canvas):
        label = box.label.sceneBoundingRect()
        assert box.shape.sceneBoundingRect().contains(label)
        assert not any(label.intersects(thing) for thing in drawn_things)


@pytest.mark.parametrize("wrap", [True, False])
@pytest.mark.parametrize("requests", [1, 10_000])
def test_no_two_boxes_overlap(qt_app: QApplication, wrap: bool, requests: int) -> None:
    """The worst cases the layout can be handed: one-activity sessions beside
    wrapped ones, the smallest and the largest circles, captions on two lines."""
    canvas = ActivityCanvas()
    canvas.set_wrap(wrap)
    canvas.show_graph(
        trace(
            1,
            7,
            1,
            12,
            1,
            2,
            requests=requests,
            label="an activity whose name is long enough to need a second line",
        )
    )

    outlines = [box.shape.sceneBoundingRect() for box in session_boxes(canvas)]
    assert len(outlines) == 6
    for one, other in combinations(outlines, 2):
        assert not one.intersects(other)


# -- how it is drawn ------------------------------------------------------


def test_every_word_inside_a_box_sits_on_the_box_ground(qt_app: QApplication) -> None:
    """A patch in the paper's colour on a blue box is a dark square behind
    every caption: the fault in the first mockup."""
    canvas = drawn(trace(1, 4))

    found = patches(canvas)
    assert len(found) == 5 + 3 + 2, "premise: captions, arrow numbers, box labels"
    for ground in found:
        assert ground.brush().color() == QColor(SESSION_GROUND)
    for box in session_boxes(canvas):
        assert box.shape.brush().color() == QColor(SESSION_GROUND)
        assert box.shape.brush().color().alpha() == 255, "opaque, so the patches match it"


def test_the_fill_is_painted_where_the_export_paints(qt_app: QApplication) -> None:
    """`Export -> PNG` renders the scene on the paper; the box has to come
    through it in its own colour."""
    canvas = drawn(trace(4))
    (box,) = session_boxes(canvas)
    inside = box.shape.sceneBoundingRect()
    label = box.label.sceneBoundingRect()
    # Right of the label, above the activities: box and nothing else.
    probe = QRectF(label.right() + 30, label.top(), 4, 4)
    assert all(item is box.shape for item in canvas.graph_scene.items(probe)), "premise"

    scene = canvas.graph_scene.sceneRect()
    image = QImage(int(scene.width()), int(scene.height()), QImage.Format.Format_ARGB32)
    image.fill(QColor(PAPER))
    painter = QPainter(image)
    canvas.graph_scene.render(painter)
    painter.end()

    at = probe.center() - scene.topLeft()
    assert inside.contains(probe)
    assert image.pixelColor(int(at.x()), int(at.y())) == QColor(SESSION_GROUND)


def test_the_selection_ring_is_drawn_over_the_box(qt_app: QApplication) -> None:
    canvas = drawn(trace(3))
    canvas.highlight("1.2.3.4#1/2")

    (box,) = session_boxes(canvas)
    assert canvas._halo is not None
    assert canvas._halo.zValue() > box.shape.zValue()
    assert box.shape.zValue() < 0, "under the arrows, which sit at zero"


# -- what it does to the mouse --------------------------------------------


def test_a_press_inside_a_box_off_an_activity_pans(qt_app: QApplication) -> None:
    """The box fills the space round the activities, and that space is where a
    reader grabs the paper to move it."""
    canvas = ActivityCanvas()
    canvas.resize(420, 320)
    canvas.show()
    canvas.set_wrap(False)
    canvas.show_graph(trace(14))
    (box,) = session_boxes(canvas)
    label = box.label.sceneBoundingRect()
    spot = QRectF(label.right() + 200, label.top(), 2, 2).center()
    canvas.centerOn(spot)
    at = canvas.viewport().mapFrom(canvas, canvas.mapFromScene(spot))
    assert canvas.itemAt(at) is box.shape, "premise: the press lands on the box"
    assert not box.shape.hasCursor(), "the paper's open hand, not a cursor of the box's own"
    before = canvas.horizontalScrollBar().value()

    mouse(canvas, QEvent.Type.MouseButtonPress, at, held=True)
    mouse(canvas, QEvent.Type.MouseMove, at + QPoint(90, 0), held=True)
    mouse(canvas, QEvent.Type.MouseButtonRelease, at + QPoint(90, 0), held=False)

    assert canvas.horizontalScrollBar().value() != before
    canvas.close()


# -- a box follows its activities -----------------------------------------


def outline_of(canvas: ActivityCanvas, node_id: str) -> QRectF:
    return canvas._box_of[node_id].shape.sceneBoundingRect()


def test_a_box_follows_an_activity_dragged_out_of_it(qt_app: QApplication) -> None:
    canvas = drawn(trace(3, 2))
    moved = "1.2.3.4#1/3"
    before = outline_of(canvas, moved)

    drag(canvas, moved, QPoint(160, 0))

    assert outline_of(canvas, moved).contains(held(node_item(canvas, moved)))
    assert outline_of(canvas, moved).width() > before.width()


def test_undo_and_reset_take_the_box_back(qt_app: QApplication) -> None:
    canvas = drawn(trace(3, 2))
    moved = "1.2.3.4#1/3"
    before = outline_of(canvas, moved)

    drag(canvas, moved, QPoint(160, 0))
    assert outline_of(canvas, moved) != before, "premise: the drag took the box with it"
    canvas.undo_move()
    assert outline_of(canvas, moved) == before

    drag(canvas, moved, QPoint(160, 0))
    assert outline_of(canvas, moved) != before, "premise: the drag took the box with it"
    canvas.reset_layout()
    assert outline_of(canvas, moved) == before


def test_a_saved_arrangement_opens_with_its_boxes_round_it(qt_app: QApplication) -> None:
    graph = trace(3)
    canvas = drawn(graph)
    far = (2_000.0, 600.0)

    canvas.show_graph(graph, positions={"1.2.3.4#1/2": far})

    assert outline_of(canvas, "1.2.3.4#1/2").contains(held(node_item(canvas, "1.2.3.4#1/2")))


def test_a_box_survives_a_redraw(qt_app: QApplication) -> None:
    """Redrawing clears the scene. A box kept from before it would be a
    wrapper round a deleted item, and the next drag would reach into it: the
    class of fault behind the Linux crash in PR #54."""
    graph = trace(3, 2)
    canvas = drawn(graph)
    canvas.show_graph(graph)
    canvas.set_wrap(False)

    drag(canvas, "1.2.3.4#2/2", QPoint(120, 40))

    assert len(session_boxes(canvas)) == 2
    assert outline_of(canvas, "1.2.3.4#2/2").contains(held(node_item(canvas, "1.2.3.4#2/2")))


def test_a_drag_reshapes_only_the_box_it_moved_in(qt_app: QApplication) -> None:
    """A busy client has a hundred and fifty boxes. A drag sends a position
    change per mouse-move event, and each one should touch one box."""
    from logarc.gui.canvas import _SessionBox

    canvas = drawn(trace(*([1] * 150)))
    seen: list[tuple[str, ...]] = []
    original = _SessionBox.reshape

    def counting(box: _SessionBox, around: QRectF) -> None:
        seen.append(box.node_ids)
        original(box, around)

    with patch.object(_SessionBox, "reshape", counting):
        node_item(canvas, "1.2.3.4#75/1").setPos(9_000.0, 9_000.0)

    assert seen == [("1.2.3.4#75/1",)]


def test_an_activity_dragged_onto_another_box_stays_in_its_own(qt_app: QApplication) -> None:
    canvas = drawn(trace(2, 2))
    target = canvas._box_of["1.2.3.4#2/1"].shape.sceneBoundingRect().center()

    node_item(canvas, "1.2.3.4#1/2").setPos(target)

    assert outline_of(canvas, "1.2.3.4#1/2").contains(held(node_item(canvas, "1.2.3.4#1/2")))
    for patch_item in patches(canvas):
        assert patch_item.brush().color() == QColor(SESSION_GROUND)
