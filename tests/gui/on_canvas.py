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
    from logarc.gui.canvas import ActivityCanvas, _EdgeArt, _NodeItem

__all__ = ["edge_between", "node_item", "node_items"]


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
