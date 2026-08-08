"""Assigning coordinates to graph nodes.

Pure Python, no Graphviz. See ADR-0004: a native dependency conflicts with
shipping a single self-contained Windows build, and trace graphs are chains,
which is the case where `dot`'s sophistication buys least.

Layout returns coordinates and nothing else. Renderers — the Qt canvas, the HTML
report — only draw them, which keeps this testable without a display and keeps
layout logic out of the interface layers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.core.graph import GraphKind

if TYPE_CHECKING:
    from logarc.core.graph import ActivityGraph

__all__ = ["Point", "layout_graph"]

#: Spacing in abstract units. Renderers scale from here.
_COLUMN: Final = 220.0
_ROW: Final = 130.0


@dataclass(frozen=True, slots=True)
class Point:
    x: float
    y: float


def layout_graph(graph: ActivityGraph) -> dict[str, Point]:
    """Position every node in `graph`.

    Deterministic by construction. A forensic tool that draws the same evidence
    differently on each run invites doubt about whether anything else changed,
    so no layout here depends on random state or dictionary ordering.
    """
    if not graph.nodes:
        return {}
    if graph.kind is GraphKind.TRACE:
        return _chronological_layout(graph)
    return _radial_layout(graph)


def _chronological_layout(graph: ActivityGraph) -> dict[str, Point]:
    """One row per session, running left to right in time.

    The trace is already in chronological order, and its only edges are between
    consecutive episodes of one session, so position follows directly from
    order — no topological sort required.
    """
    positions: dict[str, Point] = {}
    rows: dict[str, int] = {}
    column = 0

    for node in graph.nodes:
        session = node.episode_ids[0].split("/")[0] if node.episode_ids else ""
        if session not in rows:
            rows[session] = len(rows)
            column = 0
        positions[node.node_id] = Point(x=column * _COLUMN, y=rows[session] * _ROW)
        column += 1

    return positions


def _radial_layout(graph: ActivityGraph) -> dict[str, Point]:
    """Arrange activity types around a circle.

    A circle rather than a force-directed layout because the node count is tiny
    — one per activity category — and every pair may be connected. A circle
    keeps every node visible and every edge short, and it cannot vary between
    runs the way an iterative solver can.

    Ordering is by request volume so the dominant activity always lands in the
    same place, making two clients' maps comparable at a glance.
    """
    ordered = sorted(graph.nodes, key=lambda node: (-node.request_count, node.node_id))
    count = len(ordered)
    if count == 1:
        return {ordered[0].node_id: Point(0.0, 0.0)}

    radius = max(_COLUMN, _COLUMN * count / 4)
    return {
        node.node_id: Point(
            x=radius * math.cos(2 * math.pi * index / count - math.pi / 2),
            y=radius * math.sin(2 * math.pi * index / count - math.pi / 2),
        )
        for index, node in enumerate(ordered)
    }
