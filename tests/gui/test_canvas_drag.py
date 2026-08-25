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
from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt
from PyQt6.QtGui import QColor, QPainterPath
from PyQt6.QtWidgets import QApplication

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarc.gui.canvas import (
    _EDGE_COLOUR,
    _SCENE_MARGIN,
    ActivityCanvas,
    _edge_shape,
    _EdgeArt,
)
from logarc.gui.style import SELECTION_COLOUR

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
    was = QPointF(canvas._nodes["n1"].pos())

    moved = drag(canvas, "n1", QPoint(70, -40))

    assert gap(canvas._nodes["n1"].pos(), was + moved) < 0.5


def test_the_arrows_on_a_dragged_node_follow_it(qt_app: QApplication) -> None:
    """The whole point. Left behind, the arrows say the client went somewhere it
    did not, and a graph that lies about the order of events is worse than one
    nobody can rearrange.
    """
    canvas = ready(2)
    was = QPointF(canvas._nodes["n1"].pos())
    art = canvas._edge_art[0]
    radius = art.target_radius

    drag(canvas, "n1", QPoint(90, -60))

    now = QPointF(canvas._nodes["n1"].pos())
    assert gap(path_end(art), now) == pytest.approx(radius, abs=0.5)
    assert gap(path_end(art), was) > radius * 2, "and is nowhere near where it used to be"


def test_the_number_on_an_arrow_follows_it_too(qt_app: QApplication) -> None:
    """The gap between two activities is written beside the arrow it belongs to.
    Left where the arrow used to be, it labels whatever the eye finds there.
    """
    canvas = ready(2)
    art = canvas._edge_art[0]
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
    near, far = canvas._edge_art[0], canvas._edge_art[2]
    assert {near.source_id, near.target_id} == {"n0", "n1"}, "premise: attached"
    assert {far.source_id, far.target_id} == {"n2", "n3"}, "premise: not attached"

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
    assert canvas._halo.pos() == canvas._nodes["n1"].pos()


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
    item = canvas._nodes["n1"]

    press_on(canvas, "n1")

    assert item.cursor().shape() == Qt.CursorShape.SizeAllCursor
    mouse(canvas, QEvent.Type.MouseButtonRelease, QPoint(0, 0), held=False)
    assert item.cursor().shape() != Qt.CursorShape.SizeAllCursor


# -- the room to drag into ------------------------------------------------


def test_the_scene_grows_to_hold_a_node_pulled_off_the_edge(qt_app: QApplication) -> None:
    """The view clamps scrolling to the scene rectangle, so a node dragged past
    it cannot be followed. It is simply gone, with no way to bring it back.
    """
    canvas = ready(2)
    item = canvas._nodes["n1"]
    was = canvas.graph_scene.sceneRect()

    hold(canvas, "n1", QPoint(400, 340))

    assert canvas.graph_scene.sceneRect() != was, "premise: it had to grow"
    assert canvas.graph_scene.sceneRect().contains(item.sceneBoundingRect())


def test_the_scene_keeps_room_for_the_caption_as_well(qt_app: QApplication) -> None:
    """The words hang below the circle. Room made for the circle alone cuts them
    off at exactly the moment someone drags a node aside to read it.
    """
    canvas = ready(2)
    item = canvas._nodes["n1"]

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
    """Grown and never given back, the empty ground a node was dragged across
    stays in the scene for good — and `Fit to window` frames the emptiness along
    with the graph, for the rest of the session.
    """
    canvas = ready(2)
    at = press_on(canvas, "n1")
    mouse(canvas, QEvent.Type.MouseMove, at + QPoint(400, 340), held=True)
    mouse(canvas, QEvent.Type.MouseMove, at, held=True)
    assert canvas.graph_scene.sceneRect() != canvas.graph_scene.itemsBoundingRect()

    let_go(canvas, at)

    assert canvas.graph_scene.sceneRect().contains(canvas.graph_scene.itemsBoundingRect())
    # From the constant, not from a number copied out of it. Written as 160.0,
    # this said nothing about what it meant and went red the day the margin
    # changed for a reason that had nothing to do with dragging.
    assert canvas.graph_scene.sceneRect().width() == pytest.approx(
        canvas.graph_scene.itemsBoundingRect().width() + 2 * _SCENE_MARGIN
    )


# -- what lights up while a node is moving --------------------------------


def pen_colour(art: _EdgeArt) -> str:
    return art.line.pen().color().name()


def test_the_arrows_on_a_node_light_up_while_it_is_moving(qt_app: QApplication) -> None:
    """On a branching behaviour map it is not obvious which transitions a node
    carries until it is picked up. Lit, the answer is the thing being moved."""
    canvas = ready(4)
    near, far = canvas._edge_art[0], canvas._edge_art[2]

    hold(canvas, "n0", QPoint(60, 40))

    assert pen_colour(near) == QColor(SELECTION_COLOUR).name()
    assert pen_colour(far) == QColor(_EDGE_COLOUR).name()


def test_the_arrowhead_lights_up_with_its_line(qt_app: QApplication) -> None:
    """Filled, not stroked. A head left grey on a lit line reads as a rendering
    fault rather than as an arrow."""
    canvas = ready(2)
    art = canvas._edge_art[0]

    hold(canvas, "n0", QPoint(60, 40))

    assert art.head.brush().color().name() == QColor(SELECTION_COLOUR).name()
    assert art.head.pen().color().name() == QColor(SELECTION_COLOUR).name()


def test_the_light_goes_out_when_the_hand_lets_go(qt_app: QApplication) -> None:
    canvas = ready(2)
    art = canvas._edge_art[0]

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
    once, often = canvas._edge_art[0], canvas._edge_art[1]
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
    art = canvas._edge_art[0]

    press_on(canvas, "n0")

    assert pen_colour(art) == QColor(_EDGE_COLOUR).name()


def test_picking_up_a_second_node_puts_out_the_first(qt_app: QApplication) -> None:
    """A release that never arrives — the window losing focus mid-drag will do
    it — leaves an activity lit with nothing holding it. The next thing picked
    up is where that gets noticed, so it is where it gets cleared."""
    canvas = ready(4)
    first, second = canvas._edge_art[0], canvas._edge_art[2]
    hold(canvas, "n0", QPoint(60, 40))
    assert pen_colour(first) == QColor(SELECTION_COLOUR).name(), "premise: the first lit"
    # What losing the window mid-drag does: the grab goes, and the release that
    # would have put the light out never arrives.
    canvas._nodes["n0"].ungrabMouse()

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
    was = QPointF(canvas._nodes["n1"].pos())
    drag(canvas, "n1", QPoint(70, -40))
    assert canvas._nodes["n1"].pos() != was, "premise: it moved"

    canvas.undo_move()

    assert canvas._nodes["n1"].pos() == was
    assert not canvas.can_undo


def test_undo_brings_the_arrows_and_the_ring_back_with_it(qt_app: QApplication) -> None:
    """Undo that moves the circle and leaves everything else where the drag put
    it is worse than no undo at all: the reader now has two wrong pictures to
    reconcile instead of one arrangement they chose."""
    canvas = ready(2)
    canvas.highlight("n1")
    art = canvas._edge_art[0]
    at_rest = points(art.line.path())
    drag(canvas, "n1", QPoint(70, -40))

    canvas.undo_move()

    assert points(art.line.path()) == at_rest
    assert canvas._halo is not None
    assert canvas._halo.pos() == canvas._nodes["n1"].pos()


def test_undo_goes_back_one_drag_at_a_time(qt_app: QApplication) -> None:
    canvas = ready(4)
    home = {node_id: QPointF(item.pos()) for node_id, item in canvas._nodes.items()}
    for node_id in ("n0", "n1", "n2"):
        drag(canvas, node_id, QPoint(40, 30))

    canvas.undo_move()
    assert canvas._nodes["n2"].pos() == home["n2"]
    assert canvas._nodes["n1"].pos() != home["n1"], "and no further"
    canvas.undo_move()
    canvas.undo_move()

    assert {node_id: QPointF(item.pos()) for node_id, item in canvas._nodes.items()} == home


def test_undoing_past_the_beginning_does_nothing_and_does_not_raise(
    qt_app: QApplication,
) -> None:
    canvas = ready(2)
    drag(canvas, "n1", QPoint(40, 30))
    canvas.undo_move()
    settled = QPointF(canvas._nodes["n1"].pos())

    canvas.undo_move()

    assert canvas._nodes["n1"].pos() == settled


# -- back to the beginning ------------------------------------------------


def test_reset_returns_every_node_to_the_layout(qt_app: QApplication) -> None:
    canvas = ready(4)
    home = {node_id: QPointF(item.pos()) for node_id, item in canvas._nodes.items()}
    for node_id in ("n0", "n2", "n3"):
        drag(canvas, node_id, QPoint(40, 30))

    canvas.reset_layout()

    assert {node_id: QPointF(item.pos()) for node_id, item in canvas._nodes.items()} == home


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
    layout = {node_id: QPointF(item.pos()) for node_id, item in canvas._nodes.items()}

    canvas.show_graph(chain(2), positions={"n1": (900.0, -400.0)})
    canvas.reset_layout()

    assert {node_id: QPointF(item.pos()) for node_id, item in canvas._nodes.items()} == layout


# -- opening a graph somewhere other than the layout ----------------------


def test_a_graph_can_be_opened_at_positions_it_is_given(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.resize(600, 480)

    canvas.show_graph(chain(2), positions={"n1": (900.0, -400.0)})

    assert canvas._nodes["n1"].pos() == QPointF(900.0, -400.0)


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
    layout = QPointF(canvas._nodes["n2"].pos())
    assert layout != QPointF(0.0, 0.0), "premise: this node is not laid out on the origin"

    canvas.show_graph(chain(4), positions={"n1": (900.0, -400.0), "gone": (5.0, 5.0)})

    assert canvas._nodes["n2"].pos() == layout


def test_the_arrows_are_drawn_where_the_given_positions_put_the_nodes(
    qt_app: QApplication,
) -> None:
    """Drawn at the layout and reshaped afterwards would look the same at rest
    and cost a full second pass over every arrow on every open."""
    canvas = ActivityCanvas()
    canvas.resize(600, 480)

    canvas.show_graph(chain(2), positions={"n1": (900.0, -400.0)})

    art = canvas._edge_art[0]
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

    assert {node_id: QPointF(item.pos()) for node_id, item in again._nodes.items()} == {
        node_id: QPointF(item.pos()) for node_id, item in canvas._nodes.items()
    }


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


def test_a_number_is_written_on_an_arrow_that_has_room_for_it(
    qt_app: QApplication,
) -> None:
    canvas = ready(2)
    art = canvas._edge_art[0]

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
    art = canvas._edge_art[0]
    assert art.label is not None
    home = QPointF(canvas._nodes["n1"].pos())

    canvas._nodes["n1"].setPos(home.x() - 250.0, home.y())

    assert not art.label.isVisible()


def test_the_number_comes_back_when_the_arrow_does(qt_app: QApplication) -> None:
    canvas = ready(2)
    art = canvas._edge_art[0]
    assert art.label is not None
    home = QPointF(canvas._nodes["n1"].pos())
    canvas._nodes["n1"].setPos(home.x() - 250.0, home.y())
    assert not art.label.isVisible(), "premise: it got out of the way"

    canvas._nodes["n1"].setPos(home)

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
    home = laid_out.positions["n1"]

    canvas.show_graph(chain(2), positions={"n1": (home[0] - 250.0, home[1])})

    art = canvas._edge_art[0]
    assert art.label is not None
    assert not art.label.isVisible()
