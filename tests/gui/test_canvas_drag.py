"""Nodes that can be dragged, and everything that has to move with them.

Run without a display. What is checked here is geometry — where a path ends,
which items a move touched, what colour a pen is — none of which the offscreen
platform's missing fonts can hide. Caption *sizes* would be a different matter,
and are not asserted on here.
"""

from __future__ import annotations

import math
import os
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from unittest.mock import patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from dragging import drag, hold, let_go, mouse, press_on
from on_canvas import edge_between, node_item
from PyQt6.QtCore import QEvent, QPoint, QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QPainterPath
from PyQt6.QtWidgets import QApplication

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarc.gui.canvas import _EDGE_COLOUR, ActivityCanvas, _edge_shape, _EdgeArt
from logarc.style import SELECTION_COLOUR

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)

#: Room added to the window after the graph has been fitted into it, in
#: pixels. Bigger than a node so one can be moved clear of the others and
#: stay on screen; smaller than the ground the scene keeps around a graph,
#: so claiming that ground still runs out of window.
_SLACK = 120


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
        # One session, deliberately. `_chronological_layout` reads the session
        # off the part of the episode id before the slash and gives each one its
        # own block, so ids without one make every node a session of its own and
        # the trace comes out stacked in a column instead of running in a row.
        episode_ids=(f"1.2.3.4#1/{index}",),
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


def two_weights() -> ActivityGraph:
    """One node carrying a one-off and a habit, so the two come out at widths
    the floor for a lit arrow sits between."""
    nodes = (node(0), node(1), node(2))
    edges = (
        GraphEdge(source="n0", target="n1", weight=1, gap_seconds=12.0),
        GraphEdge(source="n0", target="n2", weight=12, gap_seconds=40.0),
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
    art = edge_between(canvas, "n0", "n1")
    at_rest = points(art.line.path())
    head_at_rest = [(p.x(), p.y()) for p in art.head.polygon()]
    was = QPointF(node_item(canvas, "n0").pos()), QPointF(node_item(canvas, "n1").pos())

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


# -- dragging a node ------------------------------------------------------


def ready(count: int = 4) -> ActivityCanvas:
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show_graph(chain(count))
    return canvas


def pannable() -> ActivityCanvas:
    """A canvas with somewhere to pan to.

    A graph that fits the window has scrollbars with no range at all, so a pan
    moves nothing and a test that watches for movement passes or fails on the
    window size rather than on the code. A long trace clamps at the fit floor
    and is wider than the view by construction.
    """
    canvas = ActivityCanvas()
    canvas.resize(420, 320)
    canvas.show()
    canvas.set_wrap(False)
    canvas.show_graph(chain(14))
    bar = canvas.horizontalScrollBar()
    assert bar.minimum() < bar.maximum(), "premise: there is room to pan"
    return canvas


def gap(one: QPointF, other: QPointF) -> float:
    return math.hypot(one.x() - other.x(), one.y() - other.y())


def path_end(art: _EdgeArt) -> QPointF:
    path = art.line.path()
    last = path.elementAt(path.elementCount() - 1)
    return QPointF(last.x, last.y)


def test_a_node_follows_the_mouse(qt_app: QApplication) -> None:
    canvas = ready(2)
    was = QPointF(node_item(canvas, "n1").pos())

    moved = drag(canvas, "n1", QPoint(70, -40))

    assert gap(node_item(canvas, "n1").pos(), was + moved) < 0.5


def test_the_arrows_on_a_dragged_node_follow_it(qt_app: QApplication) -> None:
    """The whole point. Left behind, the arrows say the client went somewhere it
    did not, and a graph that lies about the order of events is worse than one
    nobody can rearrange.
    """
    canvas = ready(2)
    was = QPointF(node_item(canvas, "n1").pos())
    art = edge_between(canvas, "n0", "n1")
    radius = art.target_radius

    drag(canvas, "n1", QPoint(90, -60))

    now = QPointF(node_item(canvas, "n1").pos())
    assert gap(path_end(art), now) == pytest.approx(radius, abs=0.5)
    assert gap(path_end(art), was) > radius * 2, "and is nowhere near where it used to be"


def test_the_number_on_an_arrow_follows_it_too(qt_app: QApplication) -> None:
    """The gap between two activities is written beside the arrow it belongs to.
    Left where the arrow used to be, it labels whatever the eye finds there.
    """
    canvas = ready(2)
    art = edge_between(canvas, "n0", "n1")
    assert art.label is not None, "premise: this arrow carries a number"
    was = QPointF(art.label.pos())

    drag(canvas, "n1", QPoint(90, -60))

    assert art.label.pos() != was


def test_only_the_arrows_on_the_dragged_node_are_reshaped(qt_app: QApplication) -> None:
    """A node asks for its own arrows, not for the whole graph.

    Not a speed claim — measured, reshaping everything costs the same, because
    the cost of one of these events is Qt's. It is a claim about what the code
    means: `_light_edges` asks the same question for a reason that has nothing
    to do with speed, and the two must not answer it differently.

    Counted rather than compared: an arrow reshaped from two node positions that
    did not change comes out on exactly the path it was already on, so the
    picture cannot tell the wasted work from none at all.
    """
    canvas = ready(4)
    near = edge_between(canvas, "n0", "n1")
    far = edge_between(canvas, "n2", "n3")

    with patch.object(_EdgeArt, "reshape", autospec=True) as reshaped:
        drag(canvas, "n0", QPoint(80, 50))

    touched = {call.args[0] for call in reshaped.call_args_list}
    assert near in touched
    assert far not in touched


def test_the_selection_ring_follows_a_dragged_node(qt_app: QApplication) -> None:
    """The evidence panel goes on showing the same episode, so a ring left at the
    old coordinates marks whichever node the reader drags into that space.
    """
    canvas = ready(2)
    canvas.highlight("n1")

    drag(canvas, "n1", QPoint(80, 50))

    assert canvas._halo is not None
    assert canvas._halo.pos() == node_item(canvas, "n1").pos()


def test_a_ring_on_another_node_is_not_dragged_along(qt_app: QApplication) -> None:
    canvas = ready(2)
    canvas.highlight("n0")
    assert canvas._halo is not None
    ringed = QPointF(canvas._halo.pos())

    drag(canvas, "n1", QPoint(80, 50))

    assert canvas._halo is not None
    assert canvas._halo.pos() == ringed


# -- and what dragging must not break -------------------------------------


def test_dragging_a_node_does_not_pan_the_canvas(qt_app: QApplication) -> None:
    """The view is in ScrollHandDrag, so a left press on empty ground scrolls it.
    A press on a node has to be taken by the node instead, or the graph slides
    under the hand and nothing moves relative to anything else.
    """
    canvas = pannable()
    canvas.centerOn(canvas.graph_scene.sceneRect().center())
    before = (canvas.horizontalScrollBar().value(), canvas.verticalScrollBar().value())

    drag(canvas, "n7", QPoint(70, 40))

    assert (canvas.horizontalScrollBar().value(), canvas.verticalScrollBar().value()) == before


def test_dragging_empty_ground_still_pans_the_canvas(qt_app: QApplication) -> None:
    """The other half of the same bargain."""
    canvas = pannable()
    canvas.centerOn(canvas.graph_scene.sceneRect().center())
    at = QPoint(4, 4)
    assert canvas.itemAt(at) is None, "premise: there is nothing here"
    before = canvas.horizontalScrollBar().value()

    mouse(canvas, QEvent.Type.MouseButtonPress, at, held=True)
    mouse(canvas, QEvent.Type.MouseMove, at + QPoint(90, 0), held=True)
    mouse(canvas, QEvent.Type.MouseButtonRelease, at + QPoint(90, 0), held=False)

    assert canvas.horizontalScrollBar().value() != before


def test_a_click_still_opens_the_activity(qt_app: QApplication) -> None:
    canvas = ready(2)
    opened: list[str] = []
    canvas.node_selected.connect(opened.append)

    drag(canvas, "n1", QPoint(0, 0))

    assert opened == ["n1"]


def test_holding_a_node_says_so_with_the_cursor(qt_app: QApplication) -> None:
    """Not the closed hand: that is what ScrollHandDrag already puts up for
    panning, so the two gestures would look identical while doing different
    things.
    """
    canvas = ready(2)
    item = node_item(canvas, "n1")

    press_on(canvas, "n1")

    assert item.cursor().shape() == Qt.CursorShape.SizeAllCursor
    mouse(canvas, QEvent.Type.MouseButtonRelease, QPoint(0, 0), held=False)
    assert item.cursor().shape() != Qt.CursorShape.SizeAllCursor


def test_the_canvas_reports_where_the_layout_put_things(qt_app: QApplication) -> None:
    """The baseline an unsaved arrangement is measured against.

    Reached through `_base` by hand, the window would be reading a private
    attribute whose shape is not the one `positions` hands back: that one holds
    `Point`, which is the layout's type and not this one, so every comparison
    would be between a tuple and an object and every activity would read as
    moved.
    """
    canvas = ready(3)
    laid_out = canvas.laid_out

    assert set(laid_out) == set(canvas.positions), "every drawn activity is in it"
    assert laid_out == canvas.positions, "nothing has been moved yet"

    node_item(canvas, "n1").setPos(500.0, 400.0)

    assert canvas.positions["n1"] == (500.0, 400.0)
    assert laid_out["n1"] != (500.0, 400.0), "the layout is not rewritten by a drag"
    assert canvas.laid_out["n1"] != (500.0, 400.0), "nor is it on the next ask"


# -- the room to drag into ------------------------------------------------


def test_the_paper_grows_to_hold_a_node_that_lands_beyond_it(qt_app: QApplication) -> None:
    """The view clamps scrolling to the scene rectangle, so a node past it
    cannot be followed. It is simply gone, with no way to bring it back.

    Placed rather than dragged. A drag cannot reach past the paper any more -
    the paper is a screenful wide on every side and the hand never leaves the
    window — but an arrangement saved from a larger window is read back
    verbatim, and that can put a node anywhere at all.
    """
    canvas = ready(2)
    item = node_item(canvas, "n1")
    was = canvas.graph_scene.sceneRect()

    item.setPos(was.bottomRight().x() + 600.0, was.bottomRight().y() + 400.0)

    assert canvas.graph_scene.sceneRect() != was, "premise: it had to grow"
    assert canvas.graph_scene.sceneRect().contains(item.sceneBoundingRect())


def test_the_scene_keeps_room_for_the_caption_as_well(qt_app: QApplication) -> None:
    """The words hang below the circle. Room made for the circle alone cuts them
    off at exactly the moment someone drags a node aside to read it.
    """
    canvas = ready(2)
    item = node_item(canvas, "n1")

    item.setPos(canvas.graph_scene.sceneRect().bottomRight() + QPointF(600.0, 400.0))

    caption = item.mapRectToScene(item.childrenBoundingRect())
    assert not caption.isEmpty(), "premise: this node has a caption"
    assert canvas.graph_scene.sceneRect().contains(caption)


def test_the_scene_does_not_shrink_while_the_hand_is_still_down(
    qt_app: QApplication,
) -> None:
    """Shrinking mid-drag moves the scrollbars under the hand, and the graph
    jumps away from the cursor that is holding it.
    """
    canvas = ready(2)
    at = press_on(canvas, "n1")
    mouse(canvas, QEvent.Type.MouseMove, at + QPoint(400, 340), held=True)
    stretched = canvas.graph_scene.sceneRect()

    mouse(canvas, QEvent.Type.MouseMove, at, held=True)

    assert canvas.graph_scene.sceneRect() == stretched


def test_the_scene_settles_once_the_hand_lets_go(qt_app: QApplication) -> None:
    """Grown and never given back, the empty ground a node was carried across
    stays on the paper for good, and every later drag starts from a surface
    that only ever got larger.
    """
    canvas = ready(2)
    item = node_item(canvas, "n1")
    home = QPointF(item.pos())
    # Out past the paper and back again, which is the one way left to stretch
    # it: `_grow_scene_for` only ever grows, so the ground it claimed on the
    # way out is still claimed once the node is home.
    item.setPos(canvas.graph_scene.sceneRect().bottomRight() + QPointF(600.0, 400.0))
    item.setPos(home)
    grown = canvas.graph_scene.sceneRect()
    assert grown != canvas.graph_scene.itemsBoundingRect()

    at = press_on(canvas, "n1")
    mouse(canvas, QEvent.Type.MouseMove, at + QPoint(20, 20), held=True)
    let_go(canvas, at + QPoint(20, 20))

    settled = canvas.graph_scene.sceneRect()
    assert settled.contains(canvas.graph_scene.itemsBoundingRect())
    # Said as "smaller than it was", not as a width copied out of the margin.
    # Written as `items + 2 * _SCENE_MARGIN` this pinned one particular way of
    # arriving at the answer, and went red twice for changes that left the
    # behaviour it was written for exactly as it was.
    assert settled.width() < grown.width(), "the ground it was carried across is still there"
    assert settled.height() < grown.height()


def as_opened(count: int = 12) -> ActivityCanvas:
    """A canvas on screen with a graph in it, in the state a reader drags from.

    Two things matter, and both were got wrong first.

    The window is shaped like the graph, so the fit binds on both axes and
    frames it almost exactly. Given a window of some other shape, the fit
    letterboxes and the spare band swallows anything a drag adds — written that
    way, every mutation of this work survived while the tests stayed green.

    And the graph is long enough to wrap, so it is a block rather than a strip.
    A three-node trace is wide and flat whatever window it is put in.
    """
    shape = ActivityCanvas()
    shape.show_graph(chain(count))
    graph = shape.graph_scene.itemsBoundingRect()

    # Roughly life size. Shrunk to some fixed number of pixels instead, these
    # captions — which the offscreen platform draws far wider than any real
    # font — drive the fit under `MIN_FIT_SCALE`, and it clamps and puts up the
    # very bars the premise is about.
    canvas = ActivityCanvas()
    canvas.resize(round(graph.width()) + 60, round(graph.height()) + 60)
    canvas.show()
    QApplication.processEvents()
    canvas.show_graph(chain(count))
    QApplication.processEvents()

    # `show_graph` fits, so at this point the window frames the graph exactly
    # and there is nowhere to drag a node that is not already inside it. The
    # slack is added afterwards, where no fit will take it back: enough for a
    # node to be moved out past the others and still be on screen, and little
    # enough that the ground kept around the graph no longer has room to fit.
    canvas.resize(canvas.width() + _SLACK, canvas.height() + _SLACK)
    QApplication.processEvents()

    assert not canvas.verticalScrollBar().isVisible(), "premise: nothing to scroll to begin with"
    assert not canvas.horizontalScrollBar().isVisible(), "premise: nothing to scroll to begin with"
    return canvas


def test_opening_a_graph_frames_the_graph_not_the_last_view(qt_app: QApplication) -> None:
    """`show_graph` rescales the view around what it has just set, so the
    region on screen beforehand says nothing about the region that will be on
    screen after. Framed to the old one, a graph small enough to sit inside it
    opens at whatever scale happened to be in force rather than filling the
    window it was given.
    """
    canvas = ActivityCanvas()
    canvas.resize(1600, 1200)
    canvas.show()
    QApplication.processEvents()

    canvas.show_graph(chain(2))
    QApplication.processEvents()

    on_screen = canvas.mapFromScene(canvas.graph_scene.itemsBoundingRect()).boundingRect()
    room = canvas.viewport().rect()

    assert on_screen.width() > room.width() * 0.7, (
        f"the graph fills {on_screen.width()} of {room.width()} px"
    )
    canvas.close()


def whole_of(canvas: ActivityCanvas, node_id: str) -> QRectF:
    """A node and its caption, in scene units.

    The caption is a child item, so `sceneBoundingRect` alone is the circle and
    nothing else. Asked that way, a node whose caption had slid off the edge
    still answered that it was on screen — and the test built on it was
    checking the opposite of what it said.
    """
    node = node_item(canvas, node_id)
    return node.sceneBoundingRect().united(node.mapRectToScene(node.childrenBoundingRect()))


def in_sight(canvas: ActivityCanvas, node_id: str) -> bool:
    """Whether the node, caption and all, is still wholly on screen."""
    seen = canvas.mapToScene(canvas.viewport().rect()).boundingRect()
    return seen.contains(whole_of(canvas, node_id))


#: How much clear window to leave beyond the node, in pixels. Small: the point
#: is to put its far edge as near the frame as it will go while keeping it
#: wholly on screen, because that is the state the fault appears in.
_SPARE = 4


def toward_the_corner(canvas: ActivityCanvas, node_id: str = "n0") -> QPoint:
    """Where to put the cursor to bring the node's far edge up to the frame.

    Backed off by the distance from the cursor to that edge, not by the node's
    whole width and height. The cursor holds the node by its centre and the
    caption reaches about half its width past that, so backing off by the whole
    of it stops half a node short — which on a window with only a little room
    to spare is the difference between a drag that reaches the frame and one
    that never leaves the graph it started in.
    """
    node = node_item(canvas, node_id)
    whole = canvas.mapFromScene(whole_of(canvas, node_id)).boundingRect()
    held = canvas.mapFromScene(node.scenePos())
    room = canvas.viewport().rect()
    return QPoint(
        room.right() - (whole.right() - held.x()) - _SPARE,
        room.bottom() - (whole.bottom() - held.y()) - _SPARE,
    )


def test_a_node_still_on_screen_is_not_chased_by_the_scene(qt_app: QApplication) -> None:
    """Nothing has gone anywhere, so there is nothing to follow.

    The scene grows so that a node dragged out of view can still be scrolled
    to. Applied to a node that never left, it hands the reader two bars while
    the thing they are dragging is in front of them the whole time.
    """
    canvas = as_opened()
    before = canvas.sceneRect()
    press_on(canvas, "n0")

    mouse(canvas, QEvent.Type.MouseMove, toward_the_corner(canvas), held=True)
    QApplication.processEvents()

    assert in_sight(canvas, "n0"), "premise: it never left the screen"
    # Said as "the scene did not move", not as "no bars appeared". Whether the
    # ground it claims is enough to raise a bar depends on how near the frame
    # the graph already was, so the bars answer this question only from a few
    # pixels' worth of starting positions — and the version of this test that
    # asked them let the fault through.
    assert canvas.sceneRect() == before, "the scene chased a node that never left"
    assert not canvas.verticalScrollBar().isVisible(), "a bar while nothing is off screen"
    assert not canvas.horizontalScrollBar().isVisible(), "a bar while nothing is off screen"
    canvas.close()


def test_a_node_dropped_inside_the_frame_raises_no_scrollbars(qt_app: QApplication) -> None:
    """And it stays that way once the hand lets go.

    Measured full screen, a node dropped 90px inside the corner — 55px of clear
    room still beyond its caption — put up both bars. The graph fitted the view
    by 6 units across; what did not fit was the ground kept around it.
    """
    canvas = as_opened()
    press_on(canvas, "n0")
    corner = toward_the_corner(canvas)
    mouse(canvas, QEvent.Type.MouseMove, corner, held=True)

    let_go(canvas, corner)
    QApplication.processEvents()

    assert in_sight(canvas, "n0"), "premise: it never left the screen"
    # The paper is still paper afterwards. Re-laid around the graph on release,
    # it has to come back reaching past the view on every side — collapsed onto
    # what the window shows, the drop would leave a canvas that cannot be
    # pushed until something is dragged again.
    seen = canvas.mapToScene(canvas.viewport().rect()).boundingRect()
    paper = canvas.sceneRect()
    assert paper.left() < seen.left(), "no paper left to push into"
    assert paper.top() < seen.top(), "no paper left to push into"
    assert paper.right() > seen.right(), "no paper left to push into"
    assert paper.bottom() > seen.bottom(), "no paper left to push into"
    assert not canvas.verticalScrollBar().isVisible(), "a bar to scroll into empty ground"
    assert not canvas.horizontalScrollBar().isVisible(), "a bar to scroll into empty ground"
    canvas.close()


def test_a_node_dragged_out_of_sight_can_still_be_reached(qt_app: QApplication) -> None:
    """The other direction, and the reason the scene grows at all.

    The cheapest way to stop bars appearing during a drag is to stop the scene
    growing — and then a node pushed past the edge is simply gone, because the
    view clamps scrolling to the scene and there is nothing out there to
    scroll to.
    """
    canvas = as_opened()
    press_on(canvas, "n0")
    room = canvas.viewport().rect()
    beyond = QPoint(room.right() + 400, room.bottom() + 400)

    mouse(canvas, QEvent.Type.MouseMove, beyond, held=True)
    QApplication.processEvents()

    assert not in_sight(canvas, "n0"), "premise: it has left the screen"
    assert canvas.graph_scene.sceneRect().contains(node_item(canvas, "n0").sceneBoundingRect()), (
        "it cannot be scrolled to"
    )
    let_go(canvas, beyond)
    canvas.close()


def test_a_node_dragged_hard_into_the_corner_raises_no_bars(qt_app: QApplication) -> None:
    """The gesture the fault was reported from: to the edge, as far as it goes.

    Every fix before this one tuned where the scene stopped, and this drag
    always crossed it. A node held against the frame is half past it by
    definition, so the scene grew to follow — and the bars came up over a node
    the reader was looking straight at.
    """
    canvas = as_opened()
    room = canvas.viewport().rect()
    press_on(canvas, "n0")
    corner = QPoint(room.right() - 2, room.bottom() - 2)

    mouse(canvas, QEvent.Type.MouseMove, corner, held=True)
    QApplication.processEvents()

    assert not canvas.verticalScrollBar().isVisible(), "a bar while the node is still held"
    assert not canvas.horizontalScrollBar().isVisible(), "a bar while the node is still held"

    let_go(canvas, corner)
    QApplication.processEvents()

    assert not canvas.verticalScrollBar().isVisible(), "a bar once the hand let go"
    assert not canvas.horizontalScrollBar().isVisible(), "a bar once the hand let go"
    canvas.close()


def test_there_is_paper_to_push_from_the_moment_a_graph_opens(qt_app: QApplication) -> None:
    """A whiteboard reaches past what you can see, in every direction.

    Framed to the graph and no further, there is nowhere to push it to: the
    view clamps every scroll to the scene, so a graph that fits its window
    cannot be moved at all.
    """
    canvas = as_opened()
    seen = canvas.mapToScene(canvas.viewport().rect()).boundingRect()
    paper = canvas.sceneRect()

    assert paper.left() < seen.left(), "no paper to the left"
    assert paper.top() < seen.top(), "no paper above"
    assert paper.right() > seen.right(), "no paper to the right"
    assert paper.bottom() > seen.bottom(), "no paper below"
    canvas.close()


def test_a_graph_that_fits_its_window_can_still_be_pushed_around(qt_app: QApplication) -> None:
    """And the paper moves when pushed.

    `pannable` has to lay out a trace too wide for its window before it can
    find anywhere to pan to. That is the tell: panning worked only where the
    graph had already overflowed. On a whiteboard the paper moves whatever is
    drawn on it.
    """
    canvas = as_opened()
    at = QPoint(4, 4)
    assert canvas.itemAt(at) is None, "premise: there is nothing here to pick up"
    before = canvas.mapToScene(canvas.viewport().rect()).boundingRect()

    mouse(canvas, QEvent.Type.MouseButtonPress, at, held=True)
    mouse(canvas, QEvent.Type.MouseMove, at + QPoint(90, 60), held=True)
    mouse(canvas, QEvent.Type.MouseButtonRelease, at + QPoint(90, 60), held=False)
    QApplication.processEvents()

    assert canvas.mapToScene(canvas.viewport().rect()).boundingRect() != before, (
        "the paper did not move"
    )
    canvas.close()


def test_fitting_frames_the_graph_not_the_paper_it_lies_on(qt_app: QApplication) -> None:
    """The other half of giving the graph paper to lie on.

    The paper reaches a screenful past the graph on every side. Framed instead
    of the graph, `Fit to window` would shrink the graph to a third of the
    window and call it fitted.
    """
    canvas = as_opened()
    room = canvas.viewport().rect()
    press_on(canvas, "n0")
    beyond = QPoint(room.right() + 400, room.bottom() + 400)
    mouse(canvas, QEvent.Type.MouseMove, beyond, held=True)
    let_go(canvas, beyond)
    QApplication.processEvents()

    canvas.fit()
    QApplication.processEvents()

    graph = canvas.graph_scene.itemsBoundingRect()
    assert canvas.sceneRect().width() > graph.width() * 1.4, "premise: the paper is far larger"

    on_screen = canvas.mapFromScene(graph).boundingRect()
    room = canvas.viewport().rect()
    filled = max(on_screen.width() / room.width(), on_screen.height() / room.height())
    assert filled > 0.8, f"the graph fills only {filled:.0%} of the window it was fitted to"
    canvas.close()


def pushed_to_the_far_left(canvas: ActivityCanvas) -> QRectF:
    """Shove the paper right until the view stops moving. Returns what it shows."""
    at = QPoint(6, 6)
    assert canvas.itemAt(at) is None, "premise: there is nothing here to pick up"
    last, shoves = None, 0
    while last != canvas.mapToScene(canvas.viewport().rect()).boundingRect().left():
        last = canvas.mapToScene(canvas.viewport().rect()).boundingRect().left()
        mouse(canvas, QEvent.Type.MouseButtonPress, at, held=True)
        mouse(canvas, QEvent.Type.MouseMove, at + QPoint(400, 0), held=True)
        mouse(canvas, QEvent.Type.MouseButtonRelease, at + QPoint(400, 0), held=False)
        QApplication.processEvents()
        shoves += 1
        assert shoves < 40, "the view never stopped moving"
    return canvas.mapToScene(canvas.viewport().rect()).boundingRect()


def test_re_laying_the_paper_never_pulls_it_from_under_the_view(
    qt_app: QApplication,
) -> None:
    """The paper is laid around the graph, and the graph moves.

    Laid around the graph and nothing else, a reader who has followed a node
    out to the far edge is standing on ground the next re-laying leaves out —
    and the view is hauled back to the graph without being asked, which
    mid-drag means the graph jumping out from under the hand holding it.

    Measured: with the graph pulled 2,400 units left and the view pushed out
    after it, the paper that fitted the graph afterwards ran -1228 to 2128
    while the view was showing -2516 to -1379. Nowhere near.
    """
    canvas = ActivityCanvas()
    canvas.resize(1000, 700)
    canvas.show()
    QApplication.processEvents()
    canvas.show_graph(chain(8))
    QApplication.processEvents()

    left_most = node_item(canvas, min(canvas.positions, key=lambda n: canvas.positions[n][0]))
    home = QPointF(left_most.pos())
    left_most.setPos(home.x() - 2400.0, home.y())
    QApplication.processEvents()

    pushed_to_the_far_left(canvas)
    left_most.setPos(home)
    before = canvas.mapToScene(canvas.viewport().rect()).boundingRect()
    assert not before.intersects(canvas.graph_scene.itemsBoundingRect()), (
        "premise: the reader is looking at empty paper, well away from the graph"
    )

    canvas.reset_layout()
    QApplication.processEvents()

    after = canvas.mapToScene(canvas.viewport().rect()).boundingRect()
    assert after == before, f"the view was hauled {abs(after.left() - before.left()):.0f} units"
    canvas.close()


# -- what lights up while a node is moving --------------------------------


def pen_colour(art: _EdgeArt) -> str:
    return art.line.pen().color().name()


def test_the_arrows_on_a_node_light_up_while_it_is_moving(qt_app: QApplication) -> None:
    """On a branching behaviour map it is not obvious which transitions a node
    carries until it is picked up. Lit, the answer is the thing being moved."""
    canvas = ready(4)
    near = edge_between(canvas, "n0", "n1")
    far = edge_between(canvas, "n2", "n3")

    hold(canvas, "n0", QPoint(60, 40))

    assert pen_colour(near) == QColor(SELECTION_COLOUR).name()
    assert pen_colour(far) == QColor(_EDGE_COLOUR).name()


def test_the_arrowhead_lights_up_with_its_line(qt_app: QApplication) -> None:
    """Filled, not stroked. A head left grey on a lit line reads as a rendering
    fault rather than as an arrow."""
    canvas = ready(2)
    art = edge_between(canvas, "n0", "n1")

    hold(canvas, "n0", QPoint(60, 40))

    assert art.head.brush().color().name() == QColor(SELECTION_COLOUR).name()
    assert art.head.pen().color().name() == QColor(SELECTION_COLOUR).name()


def test_the_light_goes_out_when_the_hand_lets_go(qt_app: QApplication) -> None:
    canvas = ready(2)
    art = edge_between(canvas, "n0", "n1")

    at = hold(canvas, "n0", QPoint(60, 40))
    assert pen_colour(art) == QColor(SELECTION_COLOUR).name(), "premise: it lit"
    let_go(canvas, at)

    assert pen_colour(art) == QColor(_EDGE_COLOUR).name()
    assert art.head.brush().color().name() == QColor(_EDGE_COLOUR).name()


def test_each_arrow_comes_back_at_the_width_its_own_weight_earned(
    qt_app: QApplication,
) -> None:
    """A transition seen many times is drawn heavier, and that is the only thing
    separating a habit from a one-off on the behaviour map. Given back a single
    width, a dragged node quietly rewrites how often its transitions happened.

    Two weights, one either side of the floor a lit arrow gets: the light has to
    thicken the thin one and leave the heavy one alone, and the release has to
    put both back where they were.
    """
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show_graph(two_weights())
    once = edge_between(canvas, "n0", "n1")
    often = edge_between(canvas, "n0", "n2")
    at_rest = (once.line.pen().widthF(), often.line.pen().widthF())
    assert at_rest[0] < at_rest[1], "premise: weight decides the width"

    at = hold(canvas, "n0", QPoint(60, 40))
    assert once.line.pen().widthF() > at_rest[0], "premise: the light thickens the thin one"
    assert often.line.pen().widthF() == at_rest[1], "premise: and leaves the heavy one"
    let_go(canvas, at)

    assert (once.line.pen().widthF(), often.line.pen().widthF()) == at_rest


def test_a_click_that_moves_nothing_lights_nothing(qt_app: QApplication) -> None:
    """Otherwise every click on an activity flashes the arrows around it, and
    the light stops meaning "this is what you are moving"."""
    canvas = ready(2)
    art = edge_between(canvas, "n0", "n1")

    press_on(canvas, "n0")

    assert pen_colour(art) == QColor(_EDGE_COLOUR).name()


def test_picking_up_a_second_node_puts_out_the_first(qt_app: QApplication) -> None:
    """A release that never arrives — the window losing focus mid-drag will do
    it — leaves an activity lit with nothing holding it. The next thing picked
    up is where that gets noticed, so it is where it gets cleared."""
    canvas = ready(4)
    first = edge_between(canvas, "n0", "n1")
    second = edge_between(canvas, "n2", "n3")
    hold(canvas, "n0", QPoint(60, 40))
    assert pen_colour(first) == QColor(SELECTION_COLOUR).name(), "premise: the first lit"
    # What losing the window mid-drag does: the grab goes, and the release that
    # would have put the light out never arrives.
    node_item(canvas, "n0").ungrabMouse()

    hold(canvas, "n3", QPoint(60, 40))

    assert pen_colour(second) == QColor(SELECTION_COLOUR).name()
    assert pen_colour(first) == QColor(_EDGE_COLOUR).name()


# -- taking it back -------------------------------------------------------


def test_nothing_to_undo_before_anything_has_been_moved(qt_app: QApplication) -> None:
    canvas = ready(2)

    assert not canvas.can_undo


def test_a_click_is_not_something_to_undo(qt_app: QApplication) -> None:
    """A drag of zero distance. Recorded, `Undo` would look broken until it had
    been pressed as many times as the reader had clicked."""
    canvas = ready(2)

    drag(canvas, "n1", QPoint(0, 0))

    assert not canvas.can_undo


def test_undo_puts_a_node_back_exactly_where_it_was(qt_app: QApplication) -> None:
    canvas = ready(2)
    was = QPointF(node_item(canvas, "n1").pos())
    drag(canvas, "n1", QPoint(70, -40))
    assert node_item(canvas, "n1").pos() != was, "premise: it moved"

    canvas.undo_move()

    assert node_item(canvas, "n1").pos() == was
    assert not canvas.can_undo


def test_undo_brings_the_arrows_and_the_ring_back_with_it(qt_app: QApplication) -> None:
    """Undo that moves the circle and leaves everything else where the drag put
    it is worse than no undo at all: the reader now has two wrong pictures to
    reconcile instead of one arrangement they chose."""
    canvas = ready(2)
    canvas.highlight("n1")
    art = edge_between(canvas, "n0", "n1")
    at_rest = points(art.line.path())
    drag(canvas, "n1", QPoint(70, -40))

    canvas.undo_move()

    assert points(art.line.path()) == at_rest
    assert canvas._halo is not None
    assert canvas._halo.pos() == node_item(canvas, "n1").pos()


def test_undo_goes_back_one_drag_at_a_time(qt_app: QApplication) -> None:
    canvas = ready(4)
    home = dict(canvas.positions)
    for node_id in ("n0", "n1", "n2"):
        drag(canvas, node_id, QPoint(40, 30))

    canvas.undo_move()
    assert canvas.positions["n2"] == home["n2"]
    assert canvas.positions["n1"] != home["n1"], "and no further"
    canvas.undo_move()
    canvas.undo_move()

    assert canvas.positions == home


def test_undoing_past_the_beginning_does_nothing_and_does_not_raise(
    qt_app: QApplication,
) -> None:
    canvas = ready(2)
    drag(canvas, "n1", QPoint(40, 30))
    canvas.undo_move()
    settled = QPointF(node_item(canvas, "n1").pos())

    canvas.undo_move()

    assert node_item(canvas, "n1").pos() == settled


# -- back to the beginning ------------------------------------------------


def test_reset_returns_every_node_to_the_layout(qt_app: QApplication) -> None:
    canvas = ready(4)
    home = dict(canvas.positions)
    for node_id in ("n0", "n2", "n3"):
        drag(canvas, node_id, QPoint(40, 30))

    canvas.reset_layout()

    assert canvas.positions == home


def test_reset_leaves_nothing_to_undo(qt_app: QApplication) -> None:
    """Undoing back across a reset would step through arrangements the reader
    has just said they are finished with."""
    canvas = ready(2)
    drag(canvas, "n1", QPoint(40, 30))

    canvas.reset_layout()

    assert not canvas.can_undo


def test_reset_goes_to_the_layout_not_to_what_was_opened(qt_app: QApplication) -> None:
    """A saved arrangement is applied when the graph is drawn. Reset that only
    reached back that far could not undo the arrangement itself, and there
    would be no way to get the computed layout again."""
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show_graph(chain(2))
    layout = dict(canvas.positions)

    canvas.show_graph(chain(2), positions={"n1": (900.0, -400.0)})
    canvas.reset_layout()

    assert canvas.positions == layout


# -- opening a graph somewhere other than the layout ----------------------


def test_a_graph_can_be_opened_at_positions_it_is_given(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.resize(600, 480)

    canvas.show_graph(chain(2), positions={"n1": (900.0, -400.0)})

    assert node_item(canvas, "n1").pos() == QPointF(900.0, -400.0)


def test_a_node_the_saved_arrangement_never_heard_of_keeps_its_place(
    qt_app: QApplication,
) -> None:
    """A case re-ingested with a different rule pack has different activities in
    it. The arrangement saved against the old ones must not leave the new ones
    stacked on the origin."""
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show_graph(chain(4))
    # The third, deliberately. The layout puts the first node of a trace on the
    # origin, so a node dropped there for want of a saved position is
    # indistinguishable from one that kept its place.
    layout = QPointF(node_item(canvas, "n2").pos())
    assert layout != QPointF(0.0, 0.0), "premise: this node is not laid out on the origin"

    canvas.show_graph(chain(4), positions={"n1": (900.0, -400.0), "gone": (5.0, 5.0)})

    assert node_item(canvas, "n2").pos() == layout


def test_the_arrows_are_drawn_where_the_given_positions_put_the_nodes(
    qt_app: QApplication,
) -> None:
    """Drawn at the layout and reshaped afterwards would look the same at rest
    and cost a full second pass over every arrow on every open."""
    canvas = ActivityCanvas()
    canvas.resize(600, 480)

    canvas.show_graph(chain(2), positions={"n1": (900.0, -400.0)})

    art = edge_between(canvas, "n0", "n1")
    assert gap(path_end(art), QPointF(900.0, -400.0)) == pytest.approx(art.target_radius, abs=0.5)


def test_what_the_canvas_reports_is_what_it_can_be_reopened_with(
    qt_app: QApplication,
) -> None:
    """The window saves `positions` and hands it back on the next open. If the
    two disagree, a saved arrangement comes back as a different picture."""
    canvas = ready(4)
    drag(canvas, "n1", QPoint(70, -40))
    saved = canvas.positions

    again = ActivityCanvas()
    again.resize(600, 480)
    again.show_graph(chain(4), positions=saved)

    assert again.positions == canvas.positions


def test_a_new_graph_leaves_nothing_to_undo(qt_app: QApplication) -> None:
    """The nodes the history names are gone. Undoing onto their replacements
    would move whichever activity happened to inherit the id."""
    canvas = ready(2)
    drag(canvas, "n1", QPoint(40, 30))

    canvas.show_graph(chain(4))

    assert not canvas.can_undo


# -- telling the window ---------------------------------------------------


def test_the_window_is_told_when_the_arrangement_changes(qt_app: QApplication) -> None:
    """`Undo` and `Reset` are menu entries that have to grey out when there is
    nothing for them to do, and the canvas is the only thing that knows."""
    canvas = ready(2)
    told: list[int] = []
    canvas.arrangement_changed.connect(lambda: told.append(1))

    drag(canvas, "n1", QPoint(40, 30))
    assert told, "a drag"
    told.clear()

    canvas.undo_move()
    assert told, "an undo"
    told.clear()

    drag(canvas, "n1", QPoint(40, 30))
    told.clear()
    canvas.reset_layout()
    assert told, "a reset"


def test_a_click_tells_the_window_nothing(qt_app: QApplication) -> None:
    canvas = ready(2)
    told: list[int] = []
    canvas.arrangement_changed.connect(lambda: told.append(1))

    drag(canvas, "n1", QPoint(0, 0))

    assert not told


# -- when the number no longer fits on the arrow --------------------------


def crowded(art: _EdgeArt) -> float:
    """A distance between two centres that leaves the arrow half as long as its
    number's patch: crowded at any text size.

    A fixed nudge was not. The layout spreads with its captions, and once they
    grew from 7.5pt to 8pt the two activities started 411 units apart on Windows,
    so moving one 250 closer left an arrow 99 long, more than the 88 its number
    needs, and the number rightly stayed.
    """
    assert art.label is not None
    return art.source_radius + art.target_radius + art.label.rect().width() / 2


def test_a_number_is_written_on_an_arrow_that_has_room_for_it(
    qt_app: QApplication,
) -> None:
    canvas = ready(2)
    art = edge_between(canvas, "n0", "n1")

    assert art.label is not None
    assert art.label.isVisible()


def test_the_number_gets_out_of_the_way_when_the_arrow_gets_short(
    qt_app: QApplication,
) -> None:
    """The number is drawn on a patch of ground so an arrow passing behind it
    cannot cross the text. Dragged close together, two activities leave an arrow
    shorter than that patch is wide — and the patch hides the whole arrow.

    Structure before detail: the transition still has to read as an arrow, and
    the number is what gives way. Found by looking at a real drag, not by
    reading the code: the geometry was right and the picture was wrong.
    """
    canvas = ready(2)
    art = edge_between(canvas, "n0", "n1")
    assert art.label is not None
    start = node_item(canvas, "n0").pos()

    node_item(canvas, "n1").setPos(start.x() + crowded(art), start.y())

    assert not art.label.isVisible()


def test_the_number_comes_back_when_the_arrow_does(qt_app: QApplication) -> None:
    canvas = ready(2)
    art = edge_between(canvas, "n0", "n1")
    assert art.label is not None
    home = QPointF(node_item(canvas, "n1").pos())
    start = node_item(canvas, "n0").pos()
    node_item(canvas, "n1").setPos(start.x() + crowded(art), start.y())
    assert not art.label.isVisible(), "premise: it got out of the way"

    node_item(canvas, "n1").setPos(home)

    assert art.label.isVisible()


def test_a_graph_opened_on_a_crowded_arrangement_hides_the_number_too(
    qt_app: QApplication,
) -> None:
    """A saved arrangement puts nodes wherever the reader left them, which may
    be close together. Applied only when a node moves, the rule would miss every
    arrangement that opens that way."""
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    laid_out = ActivityCanvas()
    laid_out.show_graph(chain(2))
    start = laid_out.positions["n0"]
    close = crowded(edge_between(laid_out, "n0", "n1"))

    canvas.show_graph(chain(2), positions={"n1": (start[0] + close, start[1])})

    art = edge_between(canvas, "n0", "n1")
    assert art.label is not None
    assert not art.label.isVisible()


def test_each_number_of_a_pair_sits_beyond_its_own_bow(qt_app: QApplication) -> None:
    """Centred on the apex, half of each number reached back towards the other
    arrow, and 192.0.2.231's pair read `x45 · 18s x41 · 9s` as one label. Each
    now lies wholly on its own arrow's side, past the apex of its curve."""
    canvas = ActivityCanvas()
    canvas.show_graph(both_ways())
    first, second = node_item(canvas, "n0").pos(), node_item(canvas, "n1").pos()
    along = second - first
    length = math.hypot(along.x(), along.y())
    across = QPointF(-along.y() / length, along.x() / length)

    for source, target in (("n0", "n1"), ("n1", "n0")):
        label = edge_between(canvas, source, target).label
        assert label is not None and label.isVisible()
        box = label.sceneBoundingRect()
        corners = (box.topLeft(), box.topRight(), box.bottomLeft(), box.bottomRight())
        reach = [QPointF.dotProduct(corner - first, across) for corner in corners]
        assert min(reach) > 0 or max(reach) < 0, f"{source}->{target} crosses the middle"
        nearest = min(abs(r) for r in reach)
        assert nearest >= 30, f"{source}->{target} reaches within {nearest:.0f} of the middle"
