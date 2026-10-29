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

from logarx.bookmarks import newest_first
from logarx.client_names import labelled
from logarx.core.activity import Outcome, Severity
from logarx.core.graph import GraphKind
from logarx.report.graph import render_graph as _svg
from logarx.report.presentation import DOCUMENT, STYLE
from logarx.style import SIZE_NOTE, edge_label, outcome_border, severity_colour, severity_legend
from logarx.timerange import spoken

if TYPE_CHECKING:
    from collections.abc import Mapping

    from logarx.analysis import AnalysisResult
    from logarx.bookmarks import Shelf
    from logarx.core.evidence import EvidenceRef
    from logarx.core.graph import GraphEdge
    from logarx.evidence import EvidenceLine
    from logarx.storage.case import CaseManifest

__all__ = ["render_report"]

# Severity colours come from `logarx.style`, which holds them as plain data
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


def render_report(
    result: AnalysisResult,
    manifest: CaseManifest | None = None,
    *,
    shelf: Shelf | None = None,
    lines: Mapping[EvidenceRef, EvidenceLine] | None = None,
    client_name: str | None = None,
) -> str:
    """Render a complete report for one client as a single HTML document.

    `shelf` is the case's bookmarks; the ones on this client are listed, with
    the raw log line from `lines` under each request, and the evidence reader's
    warning under any line whose source it could not verify. `client_name` is
    the name a reader gave the client: the report names it with the address
    beside it, never instead of it. The embedded data stays the reconstruction
    alone.
    """
    return DOCUMENT.format(
        ip=html.escape(labelled(result.client_ip, client_name)),
        style=STYLE,
        summary=_summary(result),
        legend=_legend(),
        trace=_svg(result.trace, client_name=client_name),
        behaviour=_svg(result.behaviour, client_name=client_name),
        episodes=_episode_table(result),
        bookmarks=_bookmarks(result, shelf, lines or {}),
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
    if not result.window.is_open:
        # Only when there is one. A card saying `whole case` on every report
        # anyone has ever exported is noise, and it would push the finding that
        # matters one place further along the row.
        cards.append(("Time range", spoken(result.window)))
    if result.crs_coverage is not None:
        # On the front, not only in the provenance: the requests CRS never
        # reached look exactly like requests it read and passed.
        replayed, requests = result.crs_coverage
        cards.append(("CRS coverage", f"Partial: {replayed:,} of {requests:,} requests"))
    return "".join(
        f'<div class="card"><div class="card-label">{label}</div>'
        f'<div class="card-value">{value}</div></div>'
        for label, value in cards
    )


def _legend() -> str:
    """The key to the drawing: what colour, outline and size each mean.

    A report is read by someone who never opened the application and cannot ask
    it. Left unexplained, the encoding that makes the graph worth drawing —
    colour is severity, the outline is outcome, size is volume — is
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
        f'<span class="key"><i class="outline" style="border-style:{outcome_border(outcome).style};'
        f'border-width:{outcome_border(outcome).width}px"></i>{html.escape(note)}</span>'
        for outcome, note in _OUTCOME_NOTE.items()
    )
    return (
        f'<div class="legend"><b>Severity</b> {severities}'
        f'<b>Outcome</b> {outcomes}<span class="key">{SIZE_NOTE}</span></div>'
    )


def _edge_label(kind: GraphKind, edge: GraphEdge) -> str:
    """What to write beside an arrow — the same words the window writes.

    A thin adapter over `logarx.style.edge_label`, which takes the fields rather
    than the edge. This file used to hold a second copy of the rule with a
    duration formatter of its own, and the two had drifted: nine of eleven
    sample gaps disagreed, so one transition read `1h 0m` in the window and
    `60m` in the report, and half a second was reported as no gap at all.

    `logarx.style` says on its own face that its judgements are reused by the HTML
    report. Reusing them is what makes screen and paper unable to disagree, the
    same reason the severity colours are taken from there rather than restated.
    """
    return edge_label(kind, weight=edge.weight, gap_seconds=edge.gap_seconds)


def _episode_table(result: AnalysisResult) -> str:
    if not result.episodes:
        return '<tr><td colspan="8" class="empty">No activity reconstructed.</td></tr>'

    rows = []
    for episode in result.episodes:
        colour = severity_colour(episode.severity)
        targets = ", ".join(html.escape(target) for target in episode.top_targets[:3])
        evidence = ", ".join(str(ref) for ref in episode.evidence[:5])
        if episode.evidence_total > len(episode.evidence[:5]):
            evidence += f" (+{episode.evidence_total - 5:,} more)"
        rows.append(
            "<tr>"
            f'<td class="mono time">{episode.start:%Y-%m-%d}<br>{episode.start:%H:%M:%S}</td>'
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


def _bookmarks(
    result: AnalysisResult, shelf: Shelf | None, lines: Mapping[EvidenceRef, EvidenceLine]
) -> str:
    """The reader's own marks on this client, newest first; nothing when there are none.

    Everything here was typed by a reader or written by the client being
    investigated, so all of it is escaped. A category's colour was picked for the
    window's dark ground and can be pale on this page, so its swatch is outlined
    and the category is named beside it: the colour never carries the meaning
    alone.
    """
    if shelf is None:
        return ""
    theirs = newest_first(mark for mark in shelf.bookmarks if mark.client == result.client_ip)
    if not theirs:
        return ""
    rows = []
    for mark in theirs:
        raw = lines.get(mark.line) if mark.line is not None else None
        what = (
            html.escape(mark.said) or f'<span class="muted">{html.escape(mark.kind.value)}</span>'
        )
        if raw is not None:
            if raw.text is not None:
                what += f"<pre>{html.escape(raw.text)}</pre>"
            # Under the line, in the report itself: printed alone it would sit
            # beside the ingest hash as though it were the line the hash covers.
            if raw.warning is not None:
                said = "Not verified" if raw.text is not None else "Not available"
                what += f'<p class="warn">{said}: {html.escape(raw.warning)}</p>'
        rows.append(
            "<tr>"
            f'<td><span class="pill"><i class="swatch" style="background:'
            f'{shelf.colour_of(mark.category)}"></i>{html.escape(mark.category)}</span></td>'
            f"<td>{html.escape(mark.kind.value.title())}</td>"
            f"<td>{what}</td>"
            f"<td>{html.escape(mark.note)}</td>"
            f'<td class="mono small">{mark.saved:%Y-%m-%d %H:%M} UTC</td>'
            "</tr>"
        )
    return (
        '<section><div class="section-heading"><h2>Bookmarks</h2></div>'
        '<div class="table-wrap" tabindex="0" role="region" aria-label="Bookmarks table">'
        '<table class="bookmarks"><thead><tr><th>Category</th><th>Kind</th><th>What</th>'
        "<th>Note</th><th>Saved</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div></section>"
    )


def _provenance(result: AnalysisResult, manifest: CaseManifest | None) -> str:
    rows = [("Ruleset fingerprint", result.ruleset_fingerprint)]
    if result.rules_in_force:
        rows.append(("Rules", result.rules_in_force))
    rows.append(("CRS configuration", result.crs_fingerprint or "not consulted"))
    if result.crs_coverage is not None:
        replayed, requests = result.crs_coverage
        rows.append(("CRS coverage", f"stopped after {replayed:,} of {requests:,} requests"))
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
