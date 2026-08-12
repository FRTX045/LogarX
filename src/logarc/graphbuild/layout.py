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

#: Gap between one session's block and the next, as a multiple of the row height.
#: Larger than a wrap on purpose: once a trace wraps, a session boundary drawn at
#: the same spacing is indistinguishable from a line break, and the graph would
#: report two visits where the log holds one.
_SESSION_GAP: Final = 2

#: Shortest chain that is allowed to wrap, and the narrowest a wrap may be.
#: Below this a trace already fits, and wrapping would cost the straight timeline
#: while buying no readability.
#:
#: Four rather than five because width is what binds. Five columns span 1,040
#: units, which a ~950px canvas can only fit at 0.91; four span 820 and fit at
#: 1.16. The difference is a 7.5pt caption drawn at 6.8pt against 8.7pt — the
#: line between squinting and reading.
_MIN_WRAP: Final = 4


@dataclass(frozen=True, slots=True)
class Point:
    x: float
    y: float


def layout_graph(graph: ActivityGraph, *, wrap: bool = True) -> dict[str, Point]:
    """Position every node in `graph`.

    Deterministic by construction. A forensic tool that draws the same evidence
    differently on each run invites doubt about whether anything else changed,
    so no layout here depends on random state or dictionary ordering.

    `wrap` folds a long trace onto further rows. It defaults to on because that
    is the legible layout, and it is a parameter rather than a fixed rule because
    the fold costs the straight timeline to buy those captions back — which of
    the two matters more depends on the trace being read. It has no meaning for a
    behaviour map: a circle has no rows to fold.
    """
    if not graph.nodes:
        return {}
    if graph.kind is GraphKind.TRACE:
        return _chronological_layout(graph, wrap=wrap)
    return _radial_layout(graph)


def _wrap_width(count: int) -> int:
    """How many nodes to put on a row before starting the next.

    A chain drawn on one row is as wide as it is long and barely taller than one
    node, so fitting it to a roughly square canvas shrinks the whole scene until
    the captions stop being legible — measured at 0.64 on a seven-episode trace,
    which renders a 7.5pt caption at under 5pt.

    The width that fixes it is the one that makes the block roughly square in
    drawn units, and since a row is about half the width of a column that is
    near enough the square root of the count. Never below `_MIN_WRAP`: a short
    trace already fits, and breaking it would give up the straight timeline for
    nothing.
    """
    if count <= _MIN_WRAP:
        return count or 1
    return max(_MIN_WRAP, math.ceil(math.sqrt(count)))


def _chronological_layout(graph: ActivityGraph, *, wrap: bool = True) -> dict[str, Point]:
    """Each session in its own block, running left to right in time.

    The trace is already in chronological order, and its only edges are between
    consecutive episodes of one session, so position follows directly from
    order — no topological sort required.

    A long chain wraps onto further rows, and those rows alternate direction.
    Serpentine rather than every row left to right: a chain that always restarts
    at the left sends one line the full width of the block backwards on every
    wrap, crossing everything between. Alternating keeps every join short, and
    the eye follows a fold naturally.

    With `wrap` off a session is one unbroken row however long it runs, which is
    what the reader asked for: the timeline stays straight and the graph is
    panned rather than fitted.
    """
    positions: dict[str, Point] = {}
    by_session: dict[str, list[str]] = {}

    for node in graph.nodes:
        session = node.episode_ids[0].split("/")[0] if node.episode_ids else ""
        by_session.setdefault(session, []).append(node.node_id)

    row = 0
    for index, node_ids in enumerate(by_session.values()):
        if index:
            row += _SESSION_GAP
        width = _wrap_width(len(node_ids)) if wrap else len(node_ids)
        for position, node_id in enumerate(node_ids):
            line, offset = divmod(position, width)
            # Odd rows run right to left, so the last node of one row sits above
            # the first of the next.
            column = offset if line % 2 == 0 else width - 1 - offset
            positions[node_id] = Point(x=column * _COLUMN, y=(row + line) * _ROW)
        row += (len(node_ids) - 1) // width

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
