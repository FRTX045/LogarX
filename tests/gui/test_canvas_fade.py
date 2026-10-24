"""Fading the activities a filter does not reach, so the ones it does stand out.

Run without a display.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from on_canvas import node_item
from PyQt6.QtWidgets import QApplication, QGraphicsItem
from test_session_boxes import trace

from logarc.gui._qt import required
from logarc.gui.canvas import FADED, ActivityCanvas

FIRST, SECOND, THIRD = "1.2.3.4#1/1", "1.2.3.4#1/2", "1.2.3.4#1/3"


def drawn(**kwargs: object) -> ActivityCanvas:
    canvas = ActivityCanvas()
    canvas.resize(600, 480)
    canvas.show_graph(trace(3), **kwargs)  # type: ignore[arg-type]
    return canvas


def opacity(canvas: ActivityCanvas, node_id: str) -> float:
    return node_item(canvas, node_id).opacity()


def ink(patch: QGraphicsItem) -> QGraphicsItem:
    """The words on a patch of ground: a caption's, or an arrow's number."""
    (words,) = patch.childItems()
    return words


def arrow(canvas: ActivityCanvas, source: str, target: str) -> float:
    (art,) = [a for a in canvas._edge_art if (a.source_id, a.target_id) == (source, target)]
    parts = [art.line, art.head, *([ink(art.label)] if art.label is not None else [])]
    (seen,) = {part.effectiveOpacity() for part in parts}
    return seen


def test_what_no_line_matches_fades(qt_app: QApplication) -> None:
    canvas = drawn(matching=frozenset({SECOND}))

    assert opacity(canvas, SECOND) == 1.0
    assert opacity(canvas, FIRST) == FADED
    assert opacity(canvas, THIRD) == FADED


def test_an_arrow_fades_unless_both_its_ends_match(qt_app: QApplication) -> None:
    canvas = drawn(matching=frozenset({FIRST, SECOND}))

    assert arrow(canvas, FIRST, SECOND) == 1.0
    assert arrow(canvas, SECOND, THIRD) == FADED


def test_no_filter_fades_nothing(qt_app: QApplication) -> None:
    canvas = drawn(matching=frozenset({SECOND}))

    canvas.set_matching(None)

    assert {opacity(canvas, node) for node in (FIRST, SECOND, THIRD)} == {1.0}
    assert arrow(canvas, FIRST, SECOND) == 1.0


def test_the_fade_can_change_without_a_redraw(qt_app: QApplication) -> None:
    canvas = drawn()
    item = node_item(canvas, FIRST)

    canvas.set_matching(frozenset({THIRD}))

    assert node_item(canvas, FIRST) is item, "the same item, not a new drawing"
    assert opacity(canvas, FIRST) == FADED
    assert opacity(canvas, THIRD) == 1.0


def test_a_wrap_toggle_keeps_the_fade(qt_app: QApplication) -> None:
    canvas = drawn(matching=frozenset({SECOND}))

    canvas.set_wrap(False)

    assert opacity(canvas, FIRST) == FADED
    assert opacity(canvas, SECOND) == 1.0


def test_a_new_graph_starts_unfaded(qt_app: QApplication) -> None:
    """Ids from the last client name nothing in the next: carried over, they
    would fade the whole of a client nobody filtered."""
    canvas = drawn(matching=frozenset({SECOND}))

    canvas.show_graph(trace(3))

    assert {opacity(canvas, node) for node in (FIRST, SECOND, THIRD)} == {1.0}


def test_only_the_ink_fades_not_the_ground_under_it(qt_app: QApplication) -> None:
    """A caption's patch of ground hides an arrow's number that passes under
    it. Faded with its words, the patch let the number through, and two faint
    words drawn through each other read as a smudge. The words fade; the
    ground under them stays solid, so what covers what does not change."""
    canvas = drawn(matching=frozenset())
    patches = [patch for patch in canvas._patches if patch.scene() is not None]
    assert patches, "premise: captions to look at"

    for patch in patches:
        assert patch.effectiveOpacity() == 1.0
        assert ink(patch).effectiveOpacity() == pytest.approx(FADED)


def test_the_ring_on_a_faded_activity_stays_bright(qt_app: QApplication) -> None:
    canvas = drawn(matching=frozenset({SECOND}))

    canvas.highlight(FIRST)

    assert canvas._halo is not None
    assert canvas._halo.opacity() == 1.0


def test_a_faded_activity_fades_its_icon(qt_app: QApplication) -> None:
    """The icon is a child of its activity with no words on it. Fading once took
    every child for a caption and unpacked its words, which an icon does not
    have: the filter raised inside a slot and took the window with it."""
    canvas = drawn(matching=frozenset({SECOND}))

    assert required(canvas.icon_of(FIRST), "icon").effectiveOpacity() == pytest.approx(FADED)
    assert required(canvas.icon_of(SECOND), "icon").effectiveOpacity() == 1.0

    canvas.set_matching(None)
    assert required(canvas.icon_of(FIRST), "icon").effectiveOpacity() == 1.0
