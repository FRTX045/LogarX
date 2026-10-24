"""A session's heading: its name on top, the box's old label underneath.

Run without a display, so nothing here asserts on how wide a caption came out;
the offscreen platform has no fonts. What is checked is which words are drawn,
in which colour, what the tip says, and that nothing moves.
"""

from __future__ import annotations

import os
from itertools import combinations

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from on_canvas import box_detail, box_name, has_pencil, node_items, session_boxes
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication
from test_session_boxes import activity, chained, drawn, trace

from logarc.gui.canvas import ActivityCanvas
from logarc.sessionize.segmenter import SessionPolicy
from logarc.style import THEME, display_safe, session_heading_tip, session_rule

ENUMERATION = "directory enumeration"


def part(box, tag: str):  # type: ignore[no-untyped-def]
    (found,) = [item for item in box.label.childItems() if item.data(0) == tag]
    return found


def test_each_box_is_headed_by_logarcs_name(qt_app: QApplication) -> None:
    canvas = drawn(
        chained(
            (
                activity(1, 1, label="probe"),
                activity(2, 1, requests=5, label="fewer requests"),
                activity(2, 2, requests=9, label="more requests"),
            )
        )
    )

    assert [box_name(box) for box in session_boxes(canvas)] == ["probe", "more requests"]


def test_the_second_line_is_todays_label(qt_app: QApplication) -> None:
    canvas = drawn(trace(1, 3))

    assert [box_detail(box) for box in session_boxes(canvas)] == [
        "Session 1 of 2 · 1 activity · 01 May 13:01",
        "Session 2 of 2 · 3 activities · 01 May 14:01\u201314:03",
    ]


def test_the_name_is_ink_and_the_detail_muted(qt_app: QApplication) -> None:
    """The name is read first; the line under it is the box's old label."""
    canvas = drawn(trace(2))
    (box,) = session_boxes(canvas)

    assert part(box, "session-name").brush().color() == QColor(THEME.ink)
    assert part(box, "session-detail").brush().color() == QColor(THEME.muted)


def test_a_readers_name_replaces_logarcs_with_a_pencil(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.show_graph(trace(1, 3), session_names={"1.2.3.4#2": "Mine"})

    first, second = session_boxes(canvas)
    assert (box_name(first), has_pencil(first)) == (ENUMERATION, False)
    assert (box_name(second), has_pencil(second)) == ("Mine", True)
    assert box_detail(second) == "Session 2 of 2 · 3 activities · 01 May 14:01\u201314:03"


def test_a_readers_tip_names_logarcs_name(qt_app: QApplication) -> None:
    policy = SessionPolicy()
    canvas = ActivityCanvas()
    canvas.show_graph(trace(1, 3), session_policy=policy, session_names={"1.2.3.4#2": "Mine"})

    first, second = session_boxes(canvas)
    rule = session_rule(policy)
    assert first.label.toolTip() == session_heading_tip(rule, ENUMERATION, renamed=False)
    assert second.label.toolTip() == session_heading_tip(rule, ENUMERATION, renamed=True)


def test_a_name_for_a_session_not_drawn_changes_nothing(qt_app: QApplication) -> None:
    plain = drawn(trace(1, 3))
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show_graph(trace(1, 3), session_names={"9.9.9.9#1": "Someone else's"})

    assert [box_name(box) for box in session_boxes(canvas)] == [ENUMERATION, ENUMERATION]
    assert not any(has_pencil(box) for box in session_boxes(canvas))
    assert [box.shape.sceneBoundingRect() for box in session_boxes(canvas)] == [
        box.shape.sceneBoundingRect() for box in session_boxes(plain)
    ]


def test_naming_moves_no_activity_and_keeps_the_view(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.resize(500, 400)
    canvas.show()
    canvas.show_graph(trace(2, 3, 1))
    canvas.scale(1.4, 1.4)
    canvas.horizontalScrollBar().setValue(canvas.horizontalScrollBar().value() + 30)
    where = {item.node_id: item.pos() for item in node_items(canvas)}
    zoom = canvas.transform()
    scrolled = (canvas.horizontalScrollBar().value(), canvas.verticalScrollBar().value())

    canvas.set_session_names({"1.2.3.4#2": "Mine"})

    assert box_name(session_boxes(canvas)[1]) == "Mine"
    assert {item.node_id: item.pos() for item in node_items(canvas)} == where
    assert canvas.transform() == zoom
    assert (canvas.horizontalScrollBar().value(), canvas.verticalScrollBar().value()) == scrolled
    canvas.close()


def test_a_readers_name_can_be_taken_back(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.show_graph(trace(2), session_names={"1.2.3.4#1": "Mine"})

    canvas.set_session_names({})

    (box,) = session_boxes(canvas)
    assert (box_name(box), has_pencil(box)) == (ENUMERATION, False)


def test_names_survive_the_boxes_going_off_and_on(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.show_graph(trace(1, 3), session_names={"1.2.3.4#2": "Mine"})

    canvas.set_sessions(False)
    canvas.set_sessions(True)

    second = session_boxes(canvas)[1]
    assert (box_name(second), has_pencil(second)) == ("Mine", True)


def test_names_given_before_anything_is_drawn_are_used(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.set_session_names({"1.2.3.4#1": "Mine"})

    canvas.show_graph(trace(2))

    (box,) = session_boxes(canvas)
    assert box_name(box) == "Mine"


def test_a_readers_name_cannot_forge_the_heading(qt_app: QApplication) -> None:
    """The file can be edited by hand or come with a case from someone else."""
    forged = "‮evil"
    canvas = ActivityCanvas()
    canvas.show_graph(trace(2), session_names={"1.2.3.4#1": forged})

    (box,) = session_boxes(canvas)
    assert box_name(box) == display_safe(forged)
    assert box_name(box) != forged


def test_sixty_character_names_widen_the_boxes_and_none_overlap(qt_app: QApplication) -> None:
    """One-activity boxes share the widest heading, as they do today."""
    long_name = "W" * 60
    canvas = ActivityCanvas()
    canvas.show_graph(trace(1, 1, 1, 3), session_names={"1.2.3.4#1": long_name})

    boxes = session_boxes(canvas)
    single = [box.shape.sceneBoundingRect().width() for box in boxes[:3]]
    assert box_name(boxes[0]) == long_name
    assert single == [single[0]] * 3
    assert single[0] > boxes[0].label.rect().width()
    for one, other in combinations(boxes, 2):
        assert not one.shape.sceneBoundingRect().intersects(other.shape.sceneBoundingRect())


def test_the_heading_sits_inside_its_box(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    canvas.show_graph(trace(1, 3), session_names={"1.2.3.4#1": "Mine", "1.2.3.4#2": "Too"})

    for box in session_boxes(canvas):
        outline = box.shape.sceneBoundingRect()
        for tag in ("session-name", "session-detail", "pencil"):
            assert outline.contains(part(box, tag).sceneBoundingRect()), tag
