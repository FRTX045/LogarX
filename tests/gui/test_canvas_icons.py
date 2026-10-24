"""An icon for its kind inside every activity, so a reader knows it without reading.

Run without a display.
"""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from dragging import drag, mouse
from on_canvas import node_item
from PyQt6.QtCore import QEvent, QPoint, QPointF
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QApplication, QGraphicsPixmapItem
from test_session_boxes import activity, chained

from logarc.core.activity import ActivityCategory, Severity
from logarc.core.graph import ActivityGraph, GraphKind, GraphNode
from logarc.gui._qt import required
from logarc.gui.canvas import ActivityCanvas
from logarc.gui.icon_set import DEFAULT_ICONS, IconChoice
from logarc.gui.icons import first_drawable, ink_for
from logarc.style import style_for

PROBE, PAGE = "1.2.3.4#1/1", "1.2.3.4#1/2"


def _graph() -> ActivityGraph:
    """An injection named after `sqli_union_probe`, then a page read."""
    return chained(
        (
            replace(
                activity(1, 1, requests=40, label="SQL injection probe"),
                category=ActivityCategory.INJECTION,
                severity=Severity.CRITICAL,
                named_by="sqli_union_probe",
                rule_ids=("browse", "sqli_union_probe"),
            ),
            replace(
                activity(1, 2, label="Browsing"),
                category=ActivityCategory.BROWSING,
                severity=Severity.INFO,
                named_by="browse",
            ),
        )
    )


def drawn(graph: ActivityGraph | None = None) -> ActivityCanvas:
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show()
    canvas.show_graph(graph or _graph())
    return canvas


def node_of(graph: ActivityGraph, node_id: str) -> GraphNode:
    (found,) = [node for node in graph.nodes if node.node_id == node_id]
    return found


def icon(name: str, node: GraphNode) -> QPixmap:
    """`name` as the canvas would draw it on `node`."""
    return first_drawable([name], ink_for(style_for(node).fill))


def shown(canvas: ActivityCanvas, node_id: str) -> QGraphicsPixmapItem:
    return required(canvas.icon_of(node_id), "icon")


def same_image(item: QGraphicsPixmapItem, pixmap: QPixmap) -> bool:
    return item.pixmap().toImage() == pixmap.toImage()


def test_every_activity_carries_its_kinds_icon(qt_app: QApplication) -> None:
    graph = _graph()
    canvas = drawn(graph)
    for node in graph.nodes:
        assert same_image(shown(canvas, node.node_id), icon(DEFAULT_ICONS[node.category], node))


def test_behaviour_draws_icons_too(qt_app: QApplication) -> None:
    graph = replace(_graph(), kind=GraphKind.BEHAVIOUR)
    canvas = drawn(graph)
    probe = node_of(graph, PROBE)
    assert same_image(shown(canvas, PROBE), icon("syringe", probe))


def test_the_ink_follows_the_fill(qt_app: QApplication) -> None:
    """White on the critical red, near-black on nothing here: both are light-inked
    fills, so the two icons differ only by shape. The ink itself is pinned in
    `test_icons.py`; this pins that the canvas asks for it by the node's fill."""
    graph = _graph()
    canvas = drawn(graph)
    probe = node_of(graph, PROBE)
    assert same_image(
        shown(canvas, PROBE), first_drawable(["syringe"], ink_for(style_for(probe).fill))
    )
    assert not same_image(shown(canvas, PROBE), first_drawable(["syringe"], "#16181c"))


def test_the_icon_sits_inside_its_circle(qt_app: QApplication) -> None:
    canvas = drawn()
    for node_id in (PROBE, PAGE):
        circle = node_item(canvas, node_id)
        box = shown(canvas, node_id).sceneBoundingRect()
        radius = circle.rect().width() / 2
        assert box.width() == pytest.approx(radius * 1.05, rel=0.01)
        assert box.height() == pytest.approx(radius * 1.05, rel=0.01)
        assert box.center().x() == pytest.approx(circle.scenePos().x(), abs=0.5)
        assert box.center().y() == pytest.approx(circle.scenePos().y(), abs=0.5)


def test_a_rule_icon_wins_then_a_kind_choice_then_the_default(qt_app: QApplication) -> None:
    graph = _graph()
    canvas = drawn(graph)
    probe = node_of(graph, PROBE)

    canvas.set_icons(
        IconChoice(
            kinds={ActivityCategory.INJECTION: "bug"},
            rules={"sqli_union_probe": "skull"},
        )
    )
    assert same_image(shown(canvas, PROBE), icon("skull", probe))

    canvas.set_icons(IconChoice(kinds={ActivityCategory.INJECTION: "bug"}))
    assert same_image(shown(canvas, PROBE), icon("bug", probe))

    canvas.set_icons(IconChoice())
    assert same_image(shown(canvas, PROBE), icon("syringe", probe))


def test_a_rule_that_only_matched_does_not_lend_its_icon(qt_app: QApplication) -> None:
    """`browse` matched in the probe too, but the probe is named after the
    injection rule; only the naming rule's icon counts."""
    graph = _graph()
    canvas = drawn(graph)
    canvas.set_icons(IconChoice(rules={"browse": "shopping-cart"}))
    assert same_image(shown(canvas, PROBE), icon("syringe", node_of(graph, PROBE)))
    assert same_image(shown(canvas, PAGE), icon("shopping-cart", node_of(graph, PAGE)))


def test_icons_handed_over_before_a_graph_are_used_when_it_comes(qt_app: QApplication) -> None:
    graph = _graph()
    canvas = ActivityCanvas()
    canvas.set_icons(IconChoice(kinds={ActivityCategory.INJECTION: "bug"}))
    canvas.show_graph(graph)
    assert same_image(shown(canvas, PROBE), icon("bug", node_of(graph, PROBE)))


def test_a_missing_file_icon_falls_back_on_the_canvas(qt_app: QApplication) -> None:
    graph = _graph()
    canvas = drawn(graph)
    canvas.set_icons(IconChoice(kinds={ActivityCategory.INJECTION: "file:gone.svg"}))
    assert same_image(shown(canvas, PROBE), icon("syringe", node_of(graph, PROBE)))


def test_changing_icons_moves_nothing(qt_app: QApplication) -> None:
    canvas = drawn()
    drag(canvas, PAGE, QPoint(60, 30))
    canvas.highlight(PROBE)
    before = canvas.positions
    undo = canvas.can_undo

    canvas.set_icons(IconChoice(kinds={ActivityCategory.INJECTION: "bug"}))

    assert canvas.positions == before
    assert canvas.selected_node_id() == PROBE
    assert canvas.can_undo == undo


@pytest.mark.parametrize("zoom", [None, 1.0, 1.2, 1.5])
def test_dragging_by_the_icon_moves_the_activity(qt_app: QApplication, zoom: float | None) -> None:
    """The icon covers the middle of the circle, which is where a reader grabs it.

    At several zooms, not only the one a graph opens at: that one rests on the
    platform's fonts, and the icon is drawn in strokes with gaps between them.
    """
    canvas = drawn()
    if zoom is not None:
        canvas.resetTransform()
        canvas.scale(zoom, zoom)
        canvas.centerOn(node_item(canvas, PROBE).scenePos())
    selected: list[str] = []
    canvas.node_selected.connect(selected.append)
    circle = node_item(canvas, PROBE)
    at = on_the_icon(canvas, PROBE)
    was = QPointF(circle.pos())

    mouse(canvas, QEvent.Type.MouseButtonPress, at, held=True)
    mouse(canvas, QEvent.Type.MouseMove, at + QPoint(50, 40), held=True)
    mouse(canvas, QEvent.Type.MouseButtonRelease, at + QPoint(50, 40), held=False)
    moved = canvas.mapToScene(at + QPoint(50, 40)) - canvas.mapToScene(at)

    assert (circle.pos() - (was + moved)).manhattanLength() < 1
    assert selected == [PROBE]


def on_the_icon(canvas: ActivityCanvas, node_id: str) -> QPoint:
    """The point nearest an activity's centre where its icon is drawn.

    Not the centre itself: the syringe is drawn in strokes, its barrel hollow,
    and the press would fall through a gap onto the circle at most zooms. That
    still drags, so a test pressing there passed while testing nothing about
    the icon on any machine whose fonts set that zoom.
    """
    icon = canvas.icon_of(node_id)
    centre = canvas.viewport().mapFrom(
        canvas, canvas.mapFromScene(node_item(canvas, node_id).scenePos())
    )
    for reach in range(12):
        for dx in range(-reach, reach + 1):
            for dy in range(-reach, reach + 1):
                at = centre + QPoint(dx, dy)
                if max(abs(dx), abs(dy)) == reach and canvas.itemAt(at) is icon:
                    return at
    raise AssertionError("premise: the icon is drawn within 12 pixels of the centre")


def test_the_tooltip_names_the_kind(qt_app: QApplication) -> None:
    canvas = drawn()
    lines = node_item(canvas, PROBE).toolTip().splitlines()
    assert lines[:2] == ["SQL injection probe", "kind: Injection"]
    assert "kind: Browsing" in node_item(canvas, PAGE).toolTip().splitlines()


def test_an_exported_image_carries_the_icons(qt_app: QApplication) -> None:
    """Export renders the scene, and the icon is in it, so a PNG shows what the
    window shows."""
    canvas = drawn()
    assert shown(canvas, PROBE).scene() is canvas.graph_scene
