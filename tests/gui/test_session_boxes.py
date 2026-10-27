"""A box round each session of a trace: drawn, placed, and kept out of the way.

Run without a display. What is checked is geometry, colour and what takes the
mouse; caption sizes come from the platform's font, and nothing here asserts
on them.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterable, Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import combinations, pairwise
from pathlib import Path
from unittest.mock import patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from dragging import drag, mouse
from on_canvas import box_detail, node_item, node_items, session_boxes
from PyQt6.QtCore import QEvent, QPoint, QPointF, QRectF
from PyQt6.QtGui import QColor, QHelpEvent, QImage, QPainter
from PyQt6.QtWidgets import (
    QApplication,
    QGraphicsItem,
    QGraphicsRectItem,
    QGraphicsSimpleTextItem,
    QToolTip,
)

from conftest import settled
from logarx.analysis import analyse_ip
from logarx.case import Case
from logarx.core.activity import ActivityCategory, Outcome, Severity
from logarx.core.evidence import EvidenceRef
from logarx.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarx.gui.app import MainWindow
from logarx.gui.canvas import _SESSION_EDGE_WIDTH, _SESSION_PAD, ActivityCanvas
from logarx.sessionize.segmenter import SessionPolicy
from logarx.style import PAPER, RENAME_HINT, SESSION_GROUND, session_rule

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
    return chained(
        activity(session, index, requests=requests, label=label)
        for session, size in enumerate(sizes, start=1)
        for index in range(1, size + 1)
    )


def chained(activities: Iterable[GraphNode]) -> ActivityGraph:
    """A trace of these activities, each linked to the next in its own session."""
    nodes = tuple(activities)
    edges = tuple(
        GraphEdge(first.node_id, second.node_id, gap_seconds=30.0)
        for first, second in pairwise(nodes)
        if first.node_id.split("/")[0] == second.node_id.split("/")[0]
    )
    return ActivityGraph(kind=GraphKind.TRACE, client_ip="1.2.3.4", nodes=nodes, edges=edges)


def mixed() -> ActivityGraph:
    """Sessions whose activities differ in everything that sizes them: a caption
    of one word and one of two lines, the smallest circle and the largest. Then
    two three-activity sessions, one of small circles and one of large."""
    long_name = "an activity whose name is long enough to need a second line"
    return chained(
        (
            activity(1, 1, requests=1, label="probe"),
            activity(2, 1, requests=10_000, label=long_name),
            activity(3, 1, requests=40, label="directory enumeration"),
            *(activity(4, index, requests=1, label="probe") for index in (1, 2, 3)),
            *(activity(5, index, requests=10_000, label=long_name) for index in (1, 2, 3)),
        )
    )


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

    assert [box_detail(box) for box in boxes] == [
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


@pytest.mark.parametrize("wrap", [True, False])
def test_boxes_in_a_column_share_their_left_edge(qt_app: QApplication, wrap: bool) -> None:
    """Each box used to start where its own widest caption did, so a column of
    boxes was ragged by the difference in caption widths: 16 pixels across the
    README's three sessions."""
    canvas = ActivityCanvas()
    canvas.set_wrap(wrap)
    canvas.show_graph(mixed())

    lefts = {round(box.shape.sceneBoundingRect().left(), 3) for box in session_boxes(canvas)}

    assert len(lefts) == 1, lefts


def test_one_activity_boxes_are_all_one_width(qt_app: QApplication) -> None:
    """A one-activity box was as wide as its own label or caption, so a column
    of them was ragged on the right."""
    canvas = drawn(mixed())

    single = [box.shape.sceneBoundingRect() for box in session_boxes(canvas)[:3]]
    widths = {round(rect.width(), 3) for rect in single}

    assert len(widths) == 1, widths


def test_a_small_activity_is_not_given_a_large_ones_height(qt_app: QApplication) -> None:
    """Width is shared so that a column lines up. Height is not: given the
    largest activity's height, a one-request activity with a one-line caption
    sat in a box as tall as a 46-request one with three lines, with empty
    ground above and below it (192.0.2.31, measured)."""
    canvas = drawn(mixed())
    small, large = (box.shape.sceneBoundingRect() for box in session_boxes(canvas)[:2])

    assert small.height() < large.height()
    content = held(node_item(canvas, "1.2.3.4#1/1"))
    head = session_boxes(canvas)[0].label.rect().height()
    assert small.height() == pytest.approx(
        content.height() + 2 * _SESSION_PAD + head + _SESSION_EDGE_WIDTH, abs=0.01
    )


def test_one_activity_boxes_are_one_width_whatever_their_dates_say(
    qt_app: QApplication,
) -> None:
    """The label is wider than a one-activity session's activity, so it sets
    the box's width, and a label carrying a time range is longer than one
    carrying a single time. Sized each by its own label, a column of them was
    ragged on the right."""
    spread = activity(2, 1, requests=1, label="probe")
    canvas = drawn(
        chained(
            (
                activity(1, 1, requests=1, label="probe"),
                replace(spread, end=spread.start + timedelta(hours=2)),
                activity(3, 1, requests=1, label="probe"),
            )
        )
    )
    labels = {round(box.label.rect().width(), 3) for box in session_boxes(canvas)}
    assert len(labels) == 2, "premise: the labels are two widths"

    widths = {round(box.shape.sceneBoundingRect().width(), 3) for box in session_boxes(canvas)}

    assert len(widths) == 1, widths


def test_a_longer_label_on_a_wider_box_does_not_widen_the_rest(qt_app: QApplication) -> None:
    """A three-activity session's label is the longest here, and its box is
    wider than that label anyway. Taken as everyone's floor, it widened every
    one-activity box past what any of their own labels asked for: 19 units on
    192.0.2.231, measured."""
    canvas = drawn(trace(1, 1, 3, label="probe"))
    *single, wide = session_boxes(canvas)
    assert wide.label.rect().width() > max(box.label.rect().width() for box in single), "premise"
    assert canvas._session_content(wide).width() > wide.label.rect().width(), "premise"

    needed = max(box.label.rect().width() for box in single)

    for box in single:
        assert box.shape.sceneBoundingRect().width() == pytest.approx(
            needed + 2 * _SESSION_PAD + _SESSION_EDGE_WIDTH, abs=0.01
        )


def test_a_box_drawn_together_still_holds_its_own_label(qt_app: QApplication) -> None:
    """The floor leaves out labels their boxes were wide enough for. Drag that
    box's activities on top of one another and it is not wide enough any more,
    and its label must not run out over the edge."""
    canvas = drawn(trace(1, 1, 3, label="probe"))
    wide = session_boxes(canvas)[2]
    first = node_item(canvas, "1.2.3.4#3/1").pos()

    for index in (2, 3):
        node_item(canvas, f"1.2.3.4#3/{index}").setPos(first)

    assert wide.shape.sceneBoundingRect().contains(wide.label.sceneBoundingRect())


def test_boxes_holding_the_same_columns_are_the_same_width(qt_app: QApplication) -> None:
    """Three small circles and three large ones are the same three columns of
    the layout, and their boxes line up on both sides."""
    canvas = drawn(mixed())

    small, large = (box.shape.sceneBoundingRect() for box in session_boxes(canvas)[3:])

    assert round(small.left(), 3) == round(large.left(), 3)
    assert round(small.right(), 3) == round(large.right(), 3)


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


# -- what a label explains ------------------------------------------------


def hover(canvas: ActivityCanvas, spot: QPointF) -> str:
    """What the reader is shown on resting the pointer at `spot`, in scene units."""
    no_tip_showing()
    at = canvas.mapFromScene(spot)
    QApplication.sendEvent(
        canvas.viewport(), QHelpEvent(QEvent.Type.ToolTip, at, canvas.viewport().mapToGlobal(at))
    )
    shown = QToolTip.text() if QToolTip.isVisible() else ""
    no_tip_showing()
    return shown


def no_tip_showing() -> None:
    """Wait for any tip on screen to go.

    `hideText` only starts a timer, and so does a hover over nothing with a tip
    still up: an earlier test's tip lingers into the next for a moment, and read
    then it looks like one the hover raised.
    """
    QToolTip.hideText()
    deadline = time.monotonic() + 5.0
    while QToolTip.isVisible():
        assert time.monotonic() < deadline, "a tip that would not go"
        QApplication.processEvents()
        time.sleep(0.01)


def tips(canvas: ActivityCanvas) -> set[str]:
    return {box.label.toolTip() for box in session_boxes(canvas)}


def explained(policy: SessionPolicy) -> str:
    """The tip on a heading LogarX named: what a session is, then how to rename."""
    return session_rule(policy) + "\n\n" + RENAME_HINT


def test_hovering_a_box_label_says_what_a_session_is(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show()
    canvas.show_graph(trace(2, 2), session_policy=SessionPolicy())

    for box in session_boxes(canvas):
        canvas.centerOn(box.label)
        spot = box.label.sceneBoundingRect().center()
        assert hover(canvas, spot) == explained(SessionPolicy())
    canvas.close()


def test_the_explanation_is_of_the_rules_the_trace_was_cut_with(qt_app: QApplication) -> None:
    """Not the engine's defaults: whatever the trace was handed over with."""
    policy = SessionPolicy(idle_timeout=timedelta(minutes=5), max_duration=timedelta(hours=2))
    canvas = ActivityCanvas()

    canvas.show_graph(trace(1, 3), session_policy=policy)

    assert tips(canvas) == {explained(policy)}


def test_a_canvas_not_told_the_rules_does_not_guess_them(qt_app: QApplication) -> None:
    canvas = drawn(trace(1, 3))

    assert tips(canvas) == {RENAME_HINT}


def test_hovering_the_paper_inside_a_box_says_nothing(qt_app: QApplication) -> None:
    """The boxes cover most of a trace. A tip over the whole of one would chase
    the pointer wherever the reader moved it."""
    canvas = ActivityCanvas()
    canvas.resize(420, 320)
    canvas.show()
    canvas.set_wrap(False)
    canvas.show_graph(trace(14), session_policy=SessionPolicy())
    (box,) = session_boxes(canvas)
    label = box.label.sceneBoundingRect()
    spot = QRectF(label.right() + 200, label.top(), 2, 2).center()
    canvas.centerOn(spot)
    assert canvas.itemAt(canvas.mapFromScene(spot)) is box.shape, "premise: it rests on the box"

    assert hover(canvas, spot) == ""
    canvas.close()


def test_the_explanation_survives_a_wrap_toggle(qt_app: QApplication) -> None:
    policy = SessionPolicy(idle_timeout=timedelta(minutes=5))
    canvas = ActivityCanvas()
    canvas.show_graph(trace(7, 2), session_policy=policy)

    canvas.set_wrap(False)

    assert tips(canvas) == {explained(policy)}


def test_the_explanation_survives_the_boxes_going_off_and_on(qt_app: QApplication) -> None:
    policy = SessionPolicy(idle_timeout=timedelta(minutes=5))
    canvas = ActivityCanvas()
    canvas.show_graph(trace(7, 2), session_policy=policy)

    canvas.set_sessions(False)
    canvas.set_sessions(True)

    assert tips(canvas) == {explained(policy)}


def test_the_window_explains_the_rules_its_reconstruction_used(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """Two visits two hours apart, opened the way a reader opens them."""
    agent = "Mozilla/5.0 (X11; Linux x86_64)"
    lines = [
        f"10.0.0.9 - - [{(START + timedelta(seconds=at)):%d/%b/%Y:%H:%M:%S +0000}]"
        f' "GET /page/{at} HTTP/1.1" 200 512 "-" "{agent}"'
        for at in (0, 20, 40, 7_200, 7_220)
    ]
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    window = MainWindow()
    window.show()
    window._load_case(tmp_path / "case")
    settled(qt_app)
    window._clients._table.selectRow(0)
    settled(qt_app)
    assert window._result is not None, "premise: the client is being read"
    assert len(session_boxes(window._canvas)) == 2, "premise: two visits, two boxes"

    assert tips(window._canvas) == {explained(window._result.policy.session)}
    window.close()


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
    from logarx.gui.canvas import _SessionBox

    canvas = drawn(trace(*([1] * 150)))
    seen: list[tuple[str, ...]] = []
    original = _SessionBox.reshape

    def counting(box: _SessionBox, around: QRectF, *, at_least: float) -> None:
        seen.append(box.node_ids)
        original(box, around, at_least=at_least)

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


# -- the switch ------------------------------------------------------------


def test_turning_the_boxes_off_takes_them_away_and_nothing_else(qt_app: QApplication) -> None:
    canvas = drawn(trace(3, 2))
    drag(canvas, "1.2.3.4#1/2", QPoint(60, 30))
    canvas.highlight("1.2.3.4#2/1")
    where = canvas.positions
    zoom = canvas.transform()
    centre = canvas.mapToScene(canvas.viewport().rect().center())

    canvas.set_sessions(False)

    assert canvas.sessions is False
    assert session_boxes(canvas) == []
    assert not [i for i in canvas.graph_scene.items() if i.zValue() < 0], "a box left behind"
    words = [i.text() for i in canvas.graph_scene.items() if isinstance(i, QGraphicsSimpleTextItem)]
    assert not [w for w in words if w.startswith("Session ")], "a label left behind"
    assert all(ground.brush().color() == QColor(PAPER) for ground in patches(canvas))
    assert canvas.positions == where
    assert canvas.transform() == zoom
    assert canvas.mapToScene(canvas.viewport().rect().center()) == centre
    assert canvas.can_undo, "the drag can still be taken back"
    assert canvas._selected == "1.2.3.4#2/1"


def test_turning_them_back_on_boxes_the_activities_where_they_are(qt_app: QApplication) -> None:
    canvas = drawn(trace(3, 2))
    canvas.set_sessions(False)
    drag(canvas, "1.2.3.4#1/2", QPoint(160, 0))

    canvas.set_sessions(True)

    assert len(session_boxes(canvas)) == 2
    assert outline_of(canvas, "1.2.3.4#1/2").contains(held(node_item(canvas, "1.2.3.4#1/2")))
    assert all(ground.brush().color() == QColor(SESSION_GROUND) for ground in patches(canvas))


def test_a_graph_drawn_with_the_boxes_off_has_none(qt_app: QApplication) -> None:
    """The window restores the choice while it is being built, before any
    graph exists; it has to hold for every graph drawn after."""
    canvas = ActivityCanvas()
    canvas.set_sessions(False)

    canvas.show_graph(trace(2, 2))

    assert session_boxes(canvas) == []
    assert all(ground.brush().color() == QColor(PAPER) for ground in patches(canvas))


def test_a_wrap_toggle_keeps_the_boxes(qt_app: QApplication) -> None:
    canvas = drawn(trace(7, 2))

    canvas.set_wrap(False)

    assert len(session_boxes(canvas)) == 2


# -- measured on the shopfront excerpt ------------------------------------

EXCERPT = Path(__file__).parent.parent / "data" / "apache-shopfront" / "excerpt.log"


@pytest.fixture(scope="module")
def shopfront(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Case]:
    case_dir = tmp_path_factory.mktemp("shopfront") / "case"
    with Case.create(case_dir) as case:
        case.ingest([EXCERPT])
    with Case.open(case_dir) as case:
        yield case


@pytest.mark.parametrize("client", ["192.0.2.231", "203.0.113.6"])
def test_the_busiest_shopfront_clients_boxes_stand_apart(
    qt_app: QApplication, shopfront: Case, client: str
) -> None:
    """The two clients the mockups were judged on: 69 sessions of up to seven
    activities, and 150 sessions of one. Measured by hand with no overlap: 91
    units at the closest on 2026-10-17, 90 once every activity was given the
    widest one's room across on 2026-10-18, 48 once each box was headed by a
    name over its old label on 2026-10-25. This holds them apart."""
    result = analyse_ip(shopfront.store, client)
    canvas = ActivityCanvas()
    canvas.show_graph(result.trace)

    boxes = session_boxes(canvas)
    total = len(result.sessions)
    assert len(boxes) == total, "a box for every session the header counts"
    assert box_detail(boxes[-1]).startswith(f"Session {total} of {total} · ")
    outlines = [box.shape.sceneBoundingRect() for box in boxes]
    for one, other in combinations(outlines, 2):
        assert not one.intersects(other)
