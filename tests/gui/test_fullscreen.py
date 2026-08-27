"""Giving the whole screen to the graph, and taking it back again.

Two halves: the button that floats on the canvas, and what the window does when
it is pressed. Run without a display — what is checked is which widgets are on
screen and where the button sits, neither of which needs one.

The floating button is what this project turned down once already for the
arrangement controls, and the comment that turned it down named the reasons:
it covers a patch of the graph, it has to be moved on every resize, and it
swallows clicks meant for whatever is underneath. The first was accepted with
open eyes. The other two are faults, and the tests for them are here.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QKeyEvent
from PyQt6.QtWidgets import QApplication

from colours import contrast
from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarc.gui.app import MainWindow
from logarc.gui.canvas import (
    _EXPAND_ICON,
    _EXPAND_SIDE,
    MIN_FIT_SCALE,
    PAPER,
    ActivityCanvas,
)

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def a_trace(count: int = 6) -> ActivityGraph:
    """A trace with something on it, so `fitInView` has a shape to fit."""
    nodes = tuple(
        GraphNode(
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
            # One session, so the layout runs them along a row rather than
            # stacking each in a column of its own.
            episode_ids=(f"1.2.3.4#1/{index}",),
        )
        for index in range(count)
    )
    edges = tuple(
        GraphEdge(source=first.node_id, target=second.node_id, gap_seconds=30.0)
        for first, second in pairwise(nodes)
    )
    return ActivityGraph(kind=GraphKind.TRACE, client_ip="1.2.3.4", nodes=nodes, edges=edges)


def shown(size: tuple[int, int]) -> ActivityCanvas:
    """A canvas the size it would be on screen, and actually on it.

    Shown, because Qt delivers no resize event to a hidden widget and the
    button follows the canvas by hearing about its resizes. A hidden canvas is
    not a state the application is ever in, so testing one would be checking a
    case that cannot happen while missing the one that does.
    """
    canvas = ActivityCanvas()
    canvas.resize(*size)
    canvas.show()
    QApplication.processEvents()
    return canvas


# -- the button on the canvas ---------------------------------------------


def test_the_canvas_carries_a_button(qt_app: QApplication) -> None:
    canvas = shown((600, 400))

    assert canvas._expand.parent() is canvas
    canvas.close()


def test_pressing_it_asks_for_the_screen(qt_app: QApplication) -> None:
    canvas = ActivityCanvas()
    asked: list[int] = []
    canvas.expand_requested.connect(lambda: asked.append(1))

    canvas._expand.click()

    assert asked == [1]


def test_it_moves_when_the_canvas_does(qt_app: QApplication) -> None:
    """The second of the three objections to a floating control, and a real
    one: going full screen resizes the canvas by definition, so a button that
    did not follow would end up floating over the middle of the graph — or off
    the edge of it."""
    canvas = shown((600, 400))
    small = canvas._expand.geometry()

    canvas.resize(1400, 900)
    qt_app.processEvents()

    assert canvas._expand.geometry() != small
    canvas.close()


#: The last two are the ones that matter. The button is a fixed 30x30 and sits
#: 12px in, so it fits everything larger with room to spare and none of those
#: sizes ever reaches the clamp in `_place_expand`: 36px wide drives the
#: horizontal arithmetic negative, 32px tall the vertical one.
#:
#: Those two numbers are tied to `_EXPAND_SIDE` and `_EXPAND_INSET`. When the
#: button was resized they stopped biting — 60px wide had been narrow enough
#: for the old 57px button and is roomy for this one — and the horizontal
#: clamp went unguarded until a mutation said so.
#:
#: Nothing smaller than the button itself is asked for. A canvas narrower than
#: its own control cannot hold it, the splitter never gets there, and a test
#: demanding the impossible only forces the code to pretend.
@pytest.mark.parametrize(
    "size", [(200, 150), (600, 400), (1920, 1080), (120, 90), (36, 45), (200, 32)]
)
def test_it_stays_inside_the_canvas_at_any_size(
    qt_app: QApplication, size: tuple[int, int]
) -> None:
    """Including sizes nobody would choose. A button placed by arithmetic off
    the near edge is a button that cannot be pressed, and the way out of full
    screen would then be the way out of full screen."""
    canvas = shown(size)

    assert canvas.rect().contains(canvas._expand.geometry()), (
        f"the button is outside a {size[0]}x{size[1]} canvas: {canvas._expand.geometry()}"
    )
    canvas.close()


def test_it_stays_in_the_corner(qt_app: QApplication) -> None:
    """Where the graph is not.

    Said as a corner rather than as "not the exact centre": that weaker form is
    satisfied by almost anywhere, including squarely over the graph a hand's
    breadth from the middle. A patch is given up on purpose, and which patch is
    the whole of the decision.
    """
    canvas = shown((900, 600))
    where = canvas._expand.geometry()
    room = canvas.rect()

    assert room.right() - where.right() < 40, f"not against the right edge: {where}"
    assert where.top() < 40, f"not against the top edge: {where}"
    canvas.close()


def test_pressing_it_does_not_start_dragging_the_canvas(qt_app: QApplication) -> None:
    """The third objection, and the one that would be a bug rather than a
    trade: the canvas pans on a press, so a press on the button must not also
    take hold of the graph behind it and slide it."""
    canvas = shown((900, 600))
    canvas.show_graph(a_trace(6))
    qt_app.processEvents()
    before = canvas.mapToScene(canvas.viewport().rect().center())

    canvas._expand.click()
    qt_app.processEvents()

    assert canvas.mapToScene(canvas.viewport().rect().center()) == before


def test_the_button_says_which_way_it_goes(qt_app: QApplication) -> None:
    """One control, two meanings. Offering `Full screen` while already full
    screen is a control lying about what it does."""
    canvas = ActivityCanvas()

    canvas.set_expanded(True)
    expanded = canvas._expand.toolTip()
    canvas.set_expanded(False)

    assert expanded != canvas._expand.toolTip()
    assert expanded, "it says nothing at all"


def test_the_button_can_be_seen_against_the_paper_it_sits_on() -> None:
    """It shipped measured against the wrong ground.

    `raised` on `surface` is 1.08:1. The button was drawn, was on top, and took
    its own press — and still could not be found, because the colours were
    chosen for the window chrome while the button sits on the canvas. Nothing
    in the code said so: the ground it was reasoned about was never the ground
    behind it.
    """
    from logarc.gui import canvas as canvas_module

    assert contrast(canvas_module._EXPAND_EDGE, PAPER) >= 3.0, (
        "the edge of a control has to carry 3:1 against what is behind it"
    )
    assert contrast(canvas_module._EXPAND_INK, canvas_module._EXPAND_GROUND) >= 4.5


def test_the_button_draws_its_own_mark(qt_app: QApplication) -> None:
    """Not a glyph.

    U+26F6 falls to the colour emoji face on Windows, which refuses the pen and
    paints a multicoloured speck instead of the theme's ink. The Linux runners
    have no such face at all and render something else again. A drawn mark
    takes its colour from the theme and is the same on both.
    """
    canvas = ActivityCanvas()

    assert canvas._expand.text() == "", "a glyph is at the mercy of the font"
    assert not canvas._expand.icon().isNull()


def test_the_mark_is_drawn_in_the_ink_it_was_measured_with(qt_app: QApplication) -> None:
    """Measuring `_EXPAND_INK` proves nothing if the pen reaches for something
    else. Only fully covered pixels are read — the rest are antialiasing."""
    from logarc.gui import canvas as canvas_module

    image = canvas_module._expand_mark(canvas_module._EXPAND_INK).toImage()
    opaque = {
        image.pixelColor(x, y).name()
        for x in range(image.width())
        for y in range(image.height())
        if image.pixelColor(x, y).alpha() == 255
    }

    assert opaque, "the mark is blank"
    assert opaque == {canvas_module._EXPAND_INK}


def test_the_button_is_the_size_it_was_drawn_for(qt_app: QApplication) -> None:
    """Fixed, not fitted to its contents.

    A button that sizes itself is sized by the platform's style metrics, and
    this suite runs on two platforms whose numbers differ — the same button was
    57x27 here and something else again on the runners. Pinning it keeps the
    mark's proportion inside the frame and makes the sizes the clamp is tested
    at mean the same thing on both.
    """
    canvas = ActivityCanvas()

    assert canvas._expand.size() == QSize(_EXPAND_SIDE, _EXPAND_SIDE)
    assert canvas._expand.iconSize() == QSize(_EXPAND_ICON, _EXPAND_ICON)


def test_the_mark_changes_when_its_meaning_does(qt_app: QApplication) -> None:
    """The tooltip already says which way it goes, but a tooltip has to be
    waited for. The mark is the part that is read at a glance."""
    canvas = ActivityCanvas()

    canvas.set_expanded(False)
    outward = canvas._expand.icon().pixmap(_EXPAND_ICON, _EXPAND_ICON).toImage()
    canvas.set_expanded(True)
    inward = canvas._expand.icon().pixmap(_EXPAND_ICON, _EXPAND_ICON).toImage()

    assert outward != inward, "one mark for both meanings says nothing"


# -- what the window does with it -----------------------------------------


def _shown(window: MainWindow) -> dict[str, bool]:
    """What is on screen around the canvas."""
    bar = window.menuBar()
    status = window.statusBar()
    return {
        "clients": not window._clients.isHidden(),
        "evidence": not window._evidence.isHidden(),
        "filter": not window._time_filter.isHidden(),
        "tabs": not window._tabs.isHidden(),
        "heading": not window._heading.isHidden(),
        "legend": not window._legend.isHidden(),
        "menu": bar is not None and not bar.isHidden(),
        "status": status is not None and not status.isHidden(),
    }


def test_going_full_screen_leaves_the_graph_alone_on_it(qt_app: QApplication) -> None:
    """The shape the reader chose: nothing but the canvas."""
    window = MainWindow()
    window.show()
    qt_app.processEvents()

    window._full_screen.apply(True)
    qt_app.processEvents()

    assert not any(_shown(window).values()), f"still on screen: {_shown(window)}"
    assert not window._canvas.isHidden()
    window._full_screen.apply(False)
    window.close()


def test_coming_back_puts_the_window_back(qt_app: QApplication) -> None:
    window = MainWindow()
    window.show()
    qt_app.processEvents()
    before = _shown(window)

    window._full_screen.apply(True)
    qt_app.processEvents()
    window._full_screen.apply(False)
    qt_app.processEvents()

    assert _shown(window) == before
    window.close()


def test_coming_back_does_not_undo_a_preference(qt_app: QApplication) -> None:
    """The easiest mistake to make here.

    A reader who turned the traffic band off in Preferences must not find it
    back on because they used full screen. Full screen hides things; it does
    not decide what is shown afterwards — what was hidden before stays hidden.
    """
    window = MainWindow()
    window.show()
    window._apply_preferences({**window._prefs, "view/traffic_band": False})
    qt_app.processEvents()
    assert window._time_filter._band.isHidden(), "premise: the band is off"

    window._full_screen.apply(True)
    window._full_screen.apply(False)
    qt_app.processEvents()

    assert window._time_filter._band.isHidden()
    window.close()


def test_fitting_into_more_room_draws_the_graph_larger(qt_app: QApplication) -> None:
    """The property full screen leans on, checked where it can be seen.

    `fit` has a floor — below `MIN_FIT_SCALE` it stops shrinking and scrolls
    instead — so a graph big enough to hit that floor comes out the same size
    at any width, and a test using one would pass whether the refit happened or
    not. Two nodes stay well clear of it.
    """
    narrow = shown((600, 400))
    narrow.show_graph(a_trace(2))
    narrow.fit()
    qt_app.processEvents()
    small = narrow.transform().m11()
    narrow.close()

    wide = shown((1400, 900))
    wide.show_graph(a_trace(2))
    wide.fit()
    qt_app.processEvents()

    assert wide.transform().m11() > small
    wide.close()


def test_the_graph_is_refitted_when_it_is_given_the_screen(qt_app: QApplication) -> None:
    """Otherwise full screen hands over the room and the graph stays the size
    it was — more space, no more readable, which is the whole reason for it.

    Two nodes and a wide window, for the reason above: with a graph at the
    scale floor this passes without the refit, and there is no point in a test
    that cannot fail.
    """
    window = MainWindow()
    window.resize(1400, 800)
    window.show()
    window._canvas.show_graph(a_trace(2))
    qt_app.processEvents()
    window._canvas.fit()
    qt_app.processEvents()
    before = window._canvas.transform().m11()
    assert before > MIN_FIT_SCALE, "premise: the fit is not sitting on its floor"

    window._full_screen.apply(True)
    qt_app.processEvents()

    assert window._canvas.transform().m11() != before
    window._full_screen.apply(False)
    window.close()


# -- the ways in and out ---------------------------------------------------


def test_the_corner_button_follows_the_window_into_full_screen(qt_app: QApplication) -> None:
    """The button says which way it goes, and full screen is the other way.

    It was only ever checked by calling `set_expanded` on the canvas directly.
    Nothing followed the window's own route, so a full screen that forgot to
    tell the canvas would have left the button offering to do the thing it had
    just done.
    """
    window = MainWindow()
    window.show()
    QApplication.processEvents()
    before = window._canvas._expand.toolTip()

    window._full_screen.apply(True)
    QApplication.processEvents()

    assert window._canvas._expand.toolTip() != before, "the button was never told"
    assert "Leave" in window._canvas._expand.toolTip()
    window._full_screen.apply(False)
    window.close()


def test_escape_comes_back(qt_app: QApplication) -> None:
    window = MainWindow()
    window.show()
    window._full_screen.apply(True)
    qt_app.processEvents()

    window.keyPressEvent(
        QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier)
    )

    assert not window._full_screen.on
    window.close()


def test_escape_is_passed_on_when_there_is_nothing_to_leave(qt_app: QApplication) -> None:
    """It is a key with a meaning elsewhere, so it has to reach elsewhere.

    Checked by whether the event was accepted rather than by what changed on
    screen. Swallowing it changes nothing visible — `_apply_fullscreen` returns
    at once when asked for the state it is already in — so a test watching the
    window would pass over a key quietly taken from everything below.
    """
    window = MainWindow()
    window.show()
    qt_app.processEvents()
    press = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier)

    window.keyPressEvent(press)

    assert not press.isAccepted(), "escape was swallowed by a window that is not full screen"
    assert not window._full_screen.on
    window.close()


def test_escape_is_taken_when_there_is_something_to_leave(qt_app: QApplication) -> None:
    """The other half: while full screen the key is answered here and goes no
    further, or it would also reach whatever else listens for it."""
    window = MainWindow()
    window.show()
    window._full_screen.apply(True)
    qt_app.processEvents()
    press = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier)

    window.keyPressEvent(press)

    assert press.isAccepted()
    assert not window._full_screen.on
    window.close()


def test_the_menu_offers_it_with_the_key_every_application_uses(qt_app: QApplication) -> None:
    window = MainWindow()
    found = [
        action for action in window.actions() if action.text().replace("&", "") == "Full screen"
    ]

    assert found, "F11 is not on the window itself"
    assert found[0].shortcut().toString() == "F11"
    window.close()


def test_the_shortcut_still_works_with_the_menu_bar_hidden(qt_app: QApplication) -> None:
    """Full screen hides the menu bar, and a shortcut that lived only on a
    hidden menu is a shortcut that stops answering exactly when it is the only
    way back."""
    window = MainWindow()
    window.show()
    window._full_screen.apply(True)
    qt_app.processEvents()
    bar = window.menuBar()
    assert bar is not None and bar.isHidden(), "premise: the menu bar is hidden"

    on_the_window = [a.text().replace("&", "") for a in window.actions()]

    assert "Full screen" in on_the_window
    window._full_screen.apply(False)
    window.close()


def test_the_button_and_the_menu_agree(qt_app: QApplication) -> None:
    """Two ways in, one state. A menu entry that stays ticked after the button
    brought the window back is the window disagreeing with itself."""
    window = MainWindow()
    window.show()
    qt_app.processEvents()

    window._canvas.expand_requested.emit()
    qt_app.processEvents()
    ticked = window._fullscreen_action.isChecked()
    window._canvas.expand_requested.emit()
    qt_app.processEvents()

    assert ticked is True
    assert window._fullscreen_action.isChecked() is False
    window.close()
