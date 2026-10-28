"""Draw the desktop's graph vocabulary as static, accessible SVG, without Qt.

Positions and visual meaning come from the same plain-data helpers as the GUI.
The report uses fixed SVG text sizes and extra row clearance, so large circles,
wrapped captions and session headings fit without depending on a desktop font
measurement. The surrounding scroll region keeps dense graphs at readable size.
"""

from __future__ import annotations

import html
import math
import textwrap
from typing import TYPE_CHECKING, Final

from logarx.core.graph import GraphKind, reciprocal_pairs
from logarx.graphbuild.layout import COLUMN, Point, layout_graph, sessions_in
from logarx.gui.icon_set import DEFAULT_ICONS, lucide
from logarx.style import (
    edge_label,
    node_radius,
    outcome_border,
    session_caption,
    session_name,
    severity_colour,
    summarise,
)

if TYPE_CHECKING:
    from logarx.core.graph import ActivityGraph, GraphEdge, GraphNode

_MARGIN: Final = 24.0
_CAPTION_REACH: Final = 150.0
_LINE: Final = 19.0
# A 62-unit radius plus a three-line caption must clear the next row's circle.
_ROW_SCALE: Final = 1.5
_PAIR_BOW: Final = 44.0


def _text_width(text: str, pixels: float) -> float:
    """Conservative em estimates keep wide labels apart without loading Qt/fonts."""
    units = 0.0
    for char in text:
        if char in " ilj.,:;!'|":
            units += 0.4
        elif char in "MWmw@%&" or ord(char) > 127:
            units += 1.2
        elif char.islower():
            units += 0.7
        else:
            units += 0.9
    return units * pixels


def _icon(node: GraphNode, x: float, y: float) -> str:
    """Only embed the shipped category icon, never a user-supplied SVG or path."""
    icon = lucide()[DEFAULT_ICONS[node.category]].svg
    fill = severity_colour(node.severity)
    channels = [int(fill[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    luminance = sum(c * weight for c, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True))
    ink = "#ffffff" if 1.05 / (luminance + 0.05) >= 3 else "#16181c"
    size = node_radius(node.request_count) * 1.05
    return (
        f'<g aria-hidden="true" transform="translate({x - size / 2:.2f} '
        f'{y - size / 2:.2f}) scale({size / 24:.4f})" color="{ink}">{icon}</g>'
    )


def _node(node: GraphNode, point: Point, reach: float) -> str:
    x, y = point.x, point.y
    radius = node_radius(node.request_count)
    border = outcome_border(node.outcome)
    dash = {
        "solid": "",
        "dashed": f"{border.width * 4} {border.width * 2}",
        "dotted": f"{border.width} {border.width * 2}",
    }[border.style]
    dashed = f' stroke-dasharray="{dash}"' if dash else ""
    caption = summarise(node).splitlines()
    parts = [
        f'<g class="activity" data-node-id="{html.escape(node.node_id, quote=True)}">',
        f"<title>{html.escape(node.label)} — {node.request_count:,} requests; "
        f"{node.severity.name.title()} severity; {html.escape(node.outcome.value)}</title>",
        f'<circle class="activity-node" cx="{x:.2f}" cy="{y:.2f}" r="{radius:.2f}" '
        f'fill="{severity_colour(node.severity)}" stroke-width="{border.width}"'
        f'{dashed} data-outcome="{node.outcome.value}"/>',
        _icon(node, x, y),
        f'<rect class="caption-ground" x="{x - reach:.2f}" '
        f'y="{y + radius + 8:.2f}" width="{2 * reach:.2f}" '
        f'height="{len(caption) * _LINE + 8:.2f}" rx="4"/>',
    ]
    for index, line in enumerate(caption):
        role = "node-meta" if index == len(caption) - 1 else "node-title"
        parts.append(
            f'<text x="{x:.2f}" y="{y + radius + 25 + index * _LINE:.2f}" '
            f'class="{role}" text-anchor="middle">{html.escape(line)}</text>'
        )
    parts.append("</g>")
    return "".join(parts)


def _edge(
    graph: ActivityGraph,
    edge: GraphEdge,
    positions: dict[str, Point],
    nodes: dict[str, GraphNode],
    *,
    paired: bool,
    reach: float,
) -> str:
    start, end = positions[edge.source], positions[edge.target]
    r1 = node_radius(nodes[edge.source].request_count)
    r2 = node_radius(nodes[edge.target].request_count)
    thickness = min(1 + edge.weight * 0.6, 6)
    if edge.source == edge.target:
        # A loop leaves and returns to the upper rim, clear of its caption.
        x1, y1 = start.x + r1 * 0.7, start.y - r1 * 0.7
        x2, y2 = start.x - r1 * 0.7, y1
        c1x, c1y = start.x + r1 + 65, start.y - r1 - 70
        c2x, c2y = start.x - r1 - 65, c1y
    elif start.x == end.x:
        # Row wraps travel round the right of the caption below the first node.
        direction = 1 if end.y > start.y else -1
        x1, y1 = start.x + direction * r1, start.y
        x2, y2 = end.x + direction * r2, end.y
        c1x = c2x = start.x + direction * (reach + 60) * 4 / 3
        c1y, c2y = y1, y2
    else:
        dx, dy = end.x - start.x, end.y - start.y
        length = math.hypot(dx, dy)
        ux, uy = dx / length, dy / length
        x1, y1 = start.x + ux * r1, start.y + uy * r1
        x2, y2 = end.x - ux * r2, end.y - uy * r2
        bow = _PAIR_BOW if paired else 0.0
        c1x, c1y = x1 + (x2 - x1) / 3 - uy * bow, y1 + (y2 - y1) / 3 + ux * bow
        c2x, c2y = x2 - (x2 - x1) / 3 - uy * bow, y2 - (y2 - y1) / 3 + ux * bow
    path = (
        f'<path d="M{x1:.2f},{y1:.2f} C{c1x:.2f},{c1y:.2f} '
        f'{c2x:.2f},{c2y:.2f} {x2:.2f},{y2:.2f}" class="edge" fill="none" '
        f'stroke-width="{thickness:.1f}" marker-end="url(#{graph.kind.value}-arrow)"/>'
    )
    label = edge_label(graph.kind, weight=edge.weight, gap_seconds=edge.gap_seconds)
    if label:
        # The actual midpoint of the cubic, including the reciprocal/loop bow.
        lx = (x1 + 3 * c1x + 3 * c2x + x2) / 8
        ly = (y1 + 3 * c1y + 3 * c2y + y2) / 8 - 10
        path += (
            f'<text x="{lx:.2f}" y="{ly:.2f}" class="edge-label" '
            f'text-anchor="middle">{html.escape(label)}</text>'
        )
    return path


def render_graph(graph: ActivityGraph) -> str:
    if not graph.nodes:
        return '<p class="empty">No activity to draw.</p>'
    groups = sessions_in(graph) if graph.kind is GraphKind.TRACE else ()
    # Widen columns for unusually wide labels instead of shrinking their font.
    reach = max(
        _CAPTION_REACH,
        max(
            _text_width(line, 15) / 2 + 12
            for node in graph.nodes
            for line in summarise(node).splitlines()
        ),
    )
    column_scale = max(1.0, (2 * reach + 24) / COLUMN)
    side = max(230.0, reach + 90)
    positions = {
        key: Point(point.x * column_scale, point.y * (_ROW_SCALE if groups else 1.0))
        for key, point in layout_graph(graph).items()
    }
    # Stack session frames with a clear 32-unit gap, including their headings
    # and captions, instead of stretching the abstract inter-session gap too.
    next_row = 0.0
    for group in groups:
        first_row = min(positions[node.node_id].y for node in group)
        for node in group:
            point = positions[node.node_id]
            positions[node.node_id] = Point(point.x, point.y - first_row + next_row)
        next_row = max(positions[node.node_id].y for node in group) + 360
    nodes = {node.node_id: node for node in graph.nodes}
    # Header space also contains self-loops; side clearance contains row-wrap arrows.
    left = min(p.x for p in positions.values()) - side
    right = max(p.x for p in positions.values()) + side
    top = min(p.y for p in positions.values()) - 174
    bottom = max(p.y for p in positions.values()) + 154
    boxes = []
    for group in groups:
        points = [positions[n.node_id] for n in group]
        x = min(p.x for p in points) - reach - 30
        y = min(p.y for p in points) - 174
        heading = textwrap.wrap(session_name(group), width=56, max_lines=2, placeholder="…")
        width = max(
            640.0,
            max(_text_width(line, 18) for line in heading) + 48,
            max(p.x for p in points) - x + side,
        )
        height = max(p.y for p in points) - y + 154
        boxes.append((x, y, width, height))
        right = max(right, x + width)
    ox, oy = _MARGIN - left, _MARGIN - top
    width, height = right - left + 2 * _MARGIN, bottom - top + 2 * _MARGIN
    positions = {key: Point(p.x + ox, p.y + oy) for key, p in positions.items()}
    name = "Chronological reconstruction" if groups else "Behaviour map"
    parts = [
        f'<svg viewBox="0 0 {width:.2f} {height:.2f}" '
        f'width="{width:.2f}" height="{height:.2f}" class="{graph.kind.value}" role="img" '
        f'aria-labelledby="{graph.kind.value}-title {graph.kind.value}-description">',
        f'<title id="{graph.kind.value}-title">{name} for {html.escape(graph.client_ip)}</title>',
        f'<desc id="{graph.kind.value}-description">Colour shows severity; circle size shows '
        "request count. Solid heavy outlines mean served, dashed mean mixed, dotted mean "
        "refused and thin solid mean unknown. Read the activity table for full details.</desc>",
        f'<defs><marker id="{graph.kind.value}-arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" class="arrow-head"/></marker></defs>',
    ]
    for index, (group, box) in enumerate(zip(groups, boxes, strict=True), start=1):
        x, y, w, h = box
        x, y = x + ox, y + oy
        parts.append(
            f'<g class="session"><rect class="session-box" x="{x:.2f}" y="{y:.2f}" '
            f'width="{w:.2f}" height="{h:.2f}" rx="12"/>'
        )
        full_name = session_name(group)
        # Fixed-width wrapping keeps long rule labels inside the session box.
        heading = textwrap.wrap(full_name, width=56, max_lines=2, placeholder="…")
        for line_index, line in enumerate(heading):
            parts.append(
                f'<text x="{x + 24:.2f}" y="{y + 32 + line_index * 23:.2f}" '
                f'class="session-title"><title>{html.escape(full_name)}</title>'
                f"{html.escape(line)}</text>"
            )
        parts.append(
            f'<text x="{x + 24:.2f}" y="{y + 44 + len(heading) * 23:.2f}" '
            f'class="session-meta">{html.escape(session_caption(index, len(groups), group))} UTC</text></g>'
        )
    paired = reciprocal_pairs(graph)
    for edge in graph.edges:
        if edge.source in positions and edge.target in positions:
            parts.append(
                _edge(
                    graph,
                    edge,
                    positions,
                    nodes,
                    paired=frozenset((edge.source, edge.target)) in paired,
                    reach=reach,
                )
            )
    parts.extend(_node(node, positions[node.node_id], reach) for node in graph.nodes)
    parts.append("</svg>")
    return "".join(parts)
