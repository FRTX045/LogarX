"""A self-contained HTML report.

One file, no external requests: it can be attached to an email, archived
alongside the evidence, or opened on a machine with no network. The graph is
inline SVG rather than a script-drawn canvas so it survives being printed to PDF
and stays readable in ten years.

The manifest is embedded rather than referenced, so the report states on its own
face which files, which ruleset and which thresholds produced it.
"""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING, Final

from logarc.core.activity import Outcome, Severity
from logarc.core.graph import GraphKind, reciprocal_pairs
from logarc.graphbuild.layout import layout_graph
from logarc.gui.style import edge_label, severity_colour, severity_legend

if TYPE_CHECKING:
    from logarc.analysis import AnalysisResult
    from logarc.core.graph import ActivityGraph, GraphEdge
    from logarc.storage.case import CaseManifest

__all__ = ["render_report"]

# Severity colours come from `logarc.gui.style`, which holds them as plain data
# with no Qt import for exactly this reason — the module says on its own face
# that its judgements are "reused by the HTML report". They were copied here
# instead, and the copy drifted: every one of the five differed, so a critical
# finding was one red on screen and a brighter one in the file handed to
# somebody who never opened the application. Importing them makes the drift
# impossible rather than merely discouraged.

_OUTCOME_NOTE: Final[dict[Outcome, str]] = {
    Outcome.BLOCKED: "every request refused",
    Outcome.SUCCESS: "every request served",
    Outcome.MIXED: "some requests served",
    Outcome.UNKNOWN: "outcome unknown",
}

_NODE_WIDTH: Final = 180.0
_NODE_HEIGHT: Final = 74.0
_MARGIN: Final = 60.0

#: How far apart the two halves of a reciprocal pair are pushed, in SVG units.
#: Applied to the control points rather than the ends, so both arrows still meet
#: the boxes they join.
_PAIR_BOW: Final = 40.0


def render_report(result: AnalysisResult, manifest: CaseManifest | None = None) -> str:
    """Render a complete report for one client as a single HTML document."""
    return _DOCUMENT.format(
        ip=html.escape(result.client_ip),
        style=_STYLE,
        summary=_summary(result),
        legend=_legend(),
        trace=_svg(result.trace),
        behaviour=_svg(result.behaviour),
        episodes=_episode_table(result),
        provenance=_provenance(result, manifest),
        payload=html.escape(json.dumps(result.to_dict(), indent=2)),
    )


def _summary(result: AnalysisResult) -> str:
    hostile = result.hostile_episodes
    worst = max((e.severity for e in result.episodes), default=Severity.INFO)
    breached = any(e.outcome in {Outcome.SUCCESS, Outcome.MIXED} for e in hostile)

    cards = [
        ("Requests", f"{result.request_count:,}"),
        ("Sessions", str(len(result.sessions))),
        ("Activities", str(len(result.episodes))),
        ("Hostile activities", str(len(hostile))),
        ("Highest severity", worst.name.title()),
        ("Any hostile request served", "Yes" if breached else "No"),
    ]
    return "".join(
        f'<div class="card"><div class="card-label">{label}</div>'
        f'<div class="card-value">{value}</div></div>'
        for label, value in cards
    )


def _legend() -> str:
    """The key to the drawing: what colour, outline and size each mean.

    A report is read by someone who never opened the application and cannot ask
    it. Left unexplained, the encoding that makes the graph worth drawing —
    colour is severity, a dashed outline means refused, size is volume — is
    decoration the reader has to guess at.

    Built from the tables the SVG is drawn from, so it cannot name a colour the
    drawing no longer uses.
    """
    severities = "".join(
        f'<span class="key"><i style="background:{item.colour}"></i>'
        f"{html.escape(item.label)}</span>"
        for item in severity_legend()
    )
    outcomes = "".join(
        f'<span class="key"><i class="outline'
        f'{" dashed" if outcome is Outcome.BLOCKED else ""}"></i>'
        f"{html.escape(note)}</span>"
        for outcome, note in _OUTCOME_NOTE.items()
    )
    return (
        f'<p class="legend"><b>Severity</b> {severities}'
        f"<b>Outcome</b> {outcomes}"
        '<span class="key">Box size is fixed here; the request count is printed '
        "inside each one.</span></p>"
    )


def _edge_label(kind: GraphKind, edge: GraphEdge) -> str:
    """What to write beside an arrow — the same words the window writes.

    A thin adapter over `gui.style.edge_label`, which takes the fields rather
    than the edge. This file used to hold a second copy of the rule with a
    duration formatter of its own, and the two had drifted: nine of eleven
    sample gaps disagreed, so one transition read `1h 0m` in the window and
    `60m` in the report, and half a second was reported as no gap at all.

    `gui.style` says on its own face that its judgements are reused by the HTML
    report. Reusing them is what makes screen and paper unable to disagree, the
    same reason the severity colours are taken from there rather than restated.
    """
    return edge_label(kind, weight=edge.weight, gap_seconds=edge.gap_seconds)


def _svg(graph: ActivityGraph) -> str:
    if not graph.nodes:
        return '<p class="empty">No activity to draw.</p>'

    positions = layout_graph(graph)
    xs = [point.x for point in positions.values()]
    ys = [point.y for point in positions.values()]
    offset_x = _MARGIN - min(xs)
    offset_y = _MARGIN - min(ys)
    width = max(xs) - min(xs) + _NODE_WIDTH + 2 * _MARGIN
    height = max(ys) - min(ys) + _NODE_HEIGHT + 2 * _MARGIN

    # Resolved once for the graph: the answer cannot change while drawing it,
    # and asking per edge would be quadratic in the edge count.
    paired = reciprocal_pairs(graph)

    parts = [
        f'<svg viewBox="0 0 {width:.0f} {height:.0f}" '
        f'style="max-width:100%;height:auto" role="img">',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/></marker></defs>',
    ]

    for edge in graph.edges:
        start, end = positions.get(edge.source), positions.get(edge.target)
        if start is None or end is None:  # pragma: no cover - edges follow nodes
            continue
        # Anchored on the side each box faces the other from. A trace wraps onto
        # further rows and those rows alternate direction, so an edge may run
        # right to left; anchoring both ends as though it always ran left to
        # right sends the line back across the two boxes it connects.
        if end.x > start.x:
            x1 = start.x + offset_x + _NODE_WIDTH
            x2 = end.x + offset_x
        elif end.x < start.x:
            x1 = start.x + offset_x
            x2 = end.x + offset_x + _NODE_WIDTH
        else:  # directly below: leave from the middle rather than either side
            x1 = x2 = start.x + offset_x + _NODE_WIDTH / 2
        y1 = start.y + offset_y + _NODE_HEIGHT / 2
        y2 = end.y + offset_y + _NODE_HEIGHT / 2
        thickness = min(1 + edge.weight * 0.6, 6)
        if edge.source == edge.target:
            parts.append(
                f'<path d="M{x1:.0f},{y1 - 20:.0f} c 40,-30 40,30 0,20" fill="none" '
                f'stroke="#94a3b8" stroke-width="{thickness:.1f}" marker-end="url(#arrow)"/>'
            )
            continue
        midpoint = (x1 + x2) / 2
        # An edge each way between the same two boxes is one cubic traced
        # backwards, so the second drawn lands exactly on the first and its
        # label is written over the first's. Pushing the control points aside in
        # the direction of travel separates them symmetrically, without either
        # edge needing to know the other exists. The sign comes from the
        # endpoints rather than from the order the graph lists its edges, so two
        # renders of one case do not differ.
        bow = _PAIR_BOW if frozenset((edge.source, edge.target)) in paired else 0.0
        bow *= 1.0 if (x2, y2) > (x1, y1) else -1.0
        parts.append(
            f'<path d="M{x1:.0f},{y1:.0f} C{midpoint:.0f},{y1 + bow:.0f} '
            f'{midpoint:.0f},{y2 + bow:.0f} {x2:.0f},{y2:.0f}" fill="none" stroke="#94a3b8" '
            f'stroke-width="{thickness:.1f}" marker-end="url(#arrow)"/>'
        )
        if label := _edge_label(graph.kind, edge):
            # Three quarters of the way out to the control points, which is
            # close to where a cubic actually passes at its midpoint.
            parts.append(
                f'<text x="{midpoint:.0f}" y="{(y1 + y2) / 2 + bow * 0.75 - 6:.0f}" '
                f'class="edge-label" text-anchor="middle">{html.escape(label)}</text>'
            )

    for node in graph.nodes:
        point = positions[node.node_id]
        x, y = point.x + offset_x, point.y + offset_y
        colour = severity_colour(node.severity)
        dashed = ' stroke-dasharray="6 3"' if node.outcome is Outcome.BLOCKED else ""
        parts.append(
            f'<g><rect x="{x:.0f}" y="{y:.0f}" width="{_NODE_WIDTH:.0f}" '
            f'height="{_NODE_HEIGHT:.0f}" rx="10" fill="#ffffff" stroke="{colour}" '
            f'stroke-width="2.5"{dashed}/>'
            f'<rect x="{x:.0f}" y="{y:.0f}" width="6" height="{_NODE_HEIGHT:.0f}" '
            f'rx="3" fill="{colour}"/>'
            f'<text x="{x + 16:.0f}" y="{y + 26:.0f}" class="node-title">'
            f"{html.escape(_truncate(node.label, 22))}</text>"
            f'<text x="{x + 16:.0f}" y="{y + 46:.0f}" class="node-meta">'
            f"{node.request_count:,} requests</text>"
            f'<text x="{x + 16:.0f}" y="{y + 62:.0f}" class="node-meta">'
            f"{html.escape(_OUTCOME_NOTE[node.outcome])}</text></g>"
        )

    parts.append("</svg>")
    return "".join(parts)


def _episode_table(result: AnalysisResult) -> str:
    if not result.episodes:
        return '<p class="empty">No activity reconstructed.</p>'

    rows = []
    for episode in result.episodes:
        colour = severity_colour(episode.severity)
        targets = ", ".join(html.escape(target) for target in episode.top_targets[:3])
        evidence = ", ".join(str(ref) for ref in episode.evidence[:5])
        if episode.evidence_total > len(episode.evidence[:5]):
            evidence += f" (+{episode.evidence_total - 5:,} more)"
        rows.append(
            "<tr>"
            f'<td class="mono">{episode.start:%H:%M:%S}</td>'
            f"<td><strong>{html.escape(episode.label)}</strong><br>"
            f'<span class="muted">{html.escape(episode.category.value)}</span></td>'
            f'<td><span class="pill"><i style="background:{colour}"></i>'
            f"{episode.severity.name.title()}</span></td>"
            f"<td>{html.escape(episode.activity.owasp or '—')}</td>"
            f"<td>{episode.request_count:,}</td>"
            f"<td>{html.escape(_OUTCOME_NOTE[episode.outcome])}</td>"
            f'<td class="mono small">{targets}</td>'
            f'<td class="mono small">{html.escape(evidence)}</td>'
            "</tr>"
        )
    return "".join(rows)


def _provenance(result: AnalysisResult, manifest: CaseManifest | None) -> str:
    rows = [("Ruleset fingerprint", result.ruleset_fingerprint)]
    if manifest is not None:
        rows.append(("Case", manifest.case_id))
        rows.append(("Tool version", manifest.tool_version))
        rows.append(("Ingested", manifest.created_at.isoformat()))
        for source in manifest.sources:
            rows.append((f"Source: {source.file_id}", source.original_path))
            rows.append((f"SHA-256: {source.file_id}", source.sha256))
            rows.append(
                (
                    f"Parsed: {source.file_id}",
                    f"{source.events_parsed:,} events from {source.lines_read:,} lines "
                    f"({source.lines_quarantined:,} unparseable), format {source.log_format}",
                )
            )
    rows.extend((key, str(value)) for key, value in sorted(result.policy.as_config().items()))

    return "".join(
        f'<tr><td>{html.escape(label)}</td><td class="mono small">{html.escape(value)}</td></tr>'
        for label, value in rows
    )


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


_STYLE: Final = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 2.5rem 1.5rem; background: #f8fafc; color: #0f172a;
  font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 2.5rem 0 .75rem; }
.subtitle { color: #64748b; margin: 0 0 2rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: .75rem; }
.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: .9rem 1rem; }
.card-label { color: #64748b; font-size: .78rem; text-transform: uppercase;
  letter-spacing: .04em; }
.card-value { font-size: 1.35rem; font-weight: 600; margin-top: .2rem; }
.panel { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
  padding: 1rem; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; background: #fff;
  border: 1px solid #e2e8f0; border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: .6rem .75rem; border-bottom: 1px solid #f1f5f9;
  vertical-align: top; }
th { background: #f1f5f9; font-size: .8rem; text-transform: uppercase;
  letter-spacing: .04em; color: #475569; }
tr:last-child td { border-bottom: none; }
.mono { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
.small { font-size: .82rem; }
.muted { color: #64748b; font-size: .85rem; }
/* A dot beside the word, not white text on the colour. Three of the five
   severities failed contrast painted as a solid pill, and the canvas has no
   such problem because it draws no text on the fill at all — the same
   encoding, and one less thing a palette change can quietly break. */
.pill { display: inline-flex; align-items: center; gap: 6px; border-radius: 999px;
  padding: .1rem .55rem; font-size: .78rem; background: #f1f5f9; color: #0f172a; }
.pill i { width: 10px; height: 10px; border-radius: 999px; display: inline-block; }
.empty { color: #64748b; font-style: italic; }
.node-title { font: 600 14px system-ui, sans-serif; fill: #0f172a; }
.node-meta { font: 12px system-ui, sans-serif; fill: #64748b; }
.legend{font-size:12px;color:#475569;margin:0 0 10px}
.legend b{color:#0f172a;margin-right:6px}
.key{display:inline-flex;align-items:center;gap:5px;margin-right:12px}
.key i{width:14px;height:11px;display:inline-block;border-radius:2px}
.key i.outline{background:#fff;border:2px solid #64748b}
.key i.outline.dashed{border-style:dashed}
.edge-label { font: 11px ui-monospace, monospace; fill: #94a3b8; }
details { margin-top: 2.5rem; }
pre { background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 10px;
  overflow-x: auto; font-size: .8rem; }
footer { margin-top: 3rem; color: #94a3b8; font-size: .82rem; }
"""

_DOCUMENT: Final = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>logarc — activity reconstruction for {ip}</title>
<style>{style}</style></head>
<body><main>
<h1>Activity reconstruction: {ip}</h1>
<p class="subtitle">Reconstructed from web server access logs. Every activity below
links back to the log lines that produced it.</p>

<div class="cards">{summary}</div>

<h2>What happened, in order</h2>
<div class="panel">{legend}{trace}</div>

<h2>How this client behaved</h2>
<div class="panel">{behaviour}</div>

<h2>Activities</h2>
<table><thead><tr>
<th>Time</th><th>Activity</th><th>Severity</th><th>OWASP</th>
<th>Requests</th><th>Outcome</th><th>Top targets</th><th>Evidence</th>
</tr></thead><tbody>{episodes}</tbody></table>

<h2>Provenance</h2>
<table><thead><tr><th>Item</th><th>Value</th></tr></thead>
<tbody>{provenance}</tbody></table>

<details><summary>Machine-readable data</summary><pre>{payload}</pre></details>

<footer>Generated by logarc. Dashed borders mark activities where every request
was refused.</footer>
</main></body></html>
"""
