"""Naming what a test wants off the canvas, so it stops naming where it sits.

One place knows that the canvas keeps activities in a dict and arrows in a
list. Before this, thirty-odd tests each knew it, and an arrow was asked for by
the position it was drawn in — a number that means *third drawn*, not *the one
from n2 to n3*. The two agreed, so nothing was wrong; but nothing kept them
agreeing either, and the tests that leaned hardest on it wrote a premise
assertion underneath to check.

A plain module rather than fixtures, for the reason `dragging` is one: several
test modules need these, and the lookup copied into each is another chance to
be handed the wrong arrow and assert confidently about it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QGraphicsItem

    from logarc.gui.canvas import ActivityCanvas, _EdgeArt, _NodeItem, _SessionBox

__all__ = [
    "box_detail",
    "box_name",
    "edge_between",
    "has_pencil",
    "node_item",
    "node_items",
    "session_boxes",
]


def node_item(canvas: ActivityCanvas, node_id: str) -> _NodeItem:
    """The drawn activity with this id."""
    item = canvas._nodes.get(node_id)
    assert item is not None, f"no activity {node_id} on the canvas; drawn: {sorted(canvas._nodes)}"
    return item


def node_items(canvas: ActivityCanvas) -> list[_NodeItem]:
    """Every drawn activity, for the questions that need the item and not the
    point it sits on — how big a caption came out, whether two circles touch."""
    return list(canvas._nodes.values())


def edge_between(canvas: ActivityCanvas, source_id: str, target_id: str) -> _EdgeArt:
    """The arrow drawn from one activity to another, in that direction.

    Direction is part of the question, not a detail of it. A behaviour map may
    carry both ways between the same two activities, drawn bowed apart, and the
    two differ in everything a test asks about — weight, label, which way the
    head points. Matching a *pair* would answer both questions with whichever
    was drawn first.
    """
    drawn = [
        art for art in canvas._edge_art if (art.source_id, art.target_id) == (source_id, target_id)
    ]
    assert drawn, (
        f"no arrow {source_id} -> {target_id} on the canvas; drawn: "
        f"{[f'{art.source_id} -> {art.target_id}' for art in canvas._edge_art]}"
    )
    assert len(drawn) == 1, f"{len(drawn)} arrows {source_id} -> {target_id}, expected one"
    return drawn[0]


def session_boxes(canvas: ActivityCanvas) -> list[_SessionBox]:
    """Every session's box, in the order the sessions are drawn."""
    return list(canvas._boxes)


def _parts(box: _SessionBox, tag: str) -> list[QGraphicsItem]:
    """The parts of a box's heading tagged `tag`: a name, a detail line, a pencil."""
    return [part for part in box.label.childItems() if part.data(0) == tag]


def box_name(box: _SessionBox) -> str:
    """The name a box's heading gives its session: the first line."""
    (name,) = _parts(box, "session-name")
    return name.text()  # type: ignore[attr-defined]


def box_detail(box: _SessionBox) -> str:
    """The line under the name: which session, how much, and when."""
    (detail,) = _parts(box, "session-detail")
    return detail.text()  # type: ignore[attr-defined]


def has_pencil(box: _SessionBox) -> bool:
    """Whether the heading carries the pencil a reader's own name is marked with."""
    return bool(_parts(box, "pencil"))
