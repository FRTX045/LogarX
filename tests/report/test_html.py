"""Tests for the HTML report.

This is the artefact that leaves the building. Everything else can be rerun by
whoever doubts it; the report is what gets attached to a case file and read by
someone who will never run the tool. It had no tests until the window started
offering it as an export, which is a thin place for a deliverable to be.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import pytest

from conftest import contrast
from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.graphbuild.layout import Point
from logarc.gui.style import severity_colour
from logarc.report.html import render_report

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
ATTACKER = "203.0.113.66"
AGENT = "Mozilla/5.0 (X11; Linux x86_64)"


def line(seconds: int, target: str, *, status: int = 200, size: int = 512) -> str:
    when = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ATTACKER} - - [{when}] "GET {target} HTTP/1.1" {status} {size} "-" "{AGENT}"'


def build_case(tmp_path: Path, lines: list[str]) -> Case:
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return Case.open(tmp_path / "case")


@pytest.fixture
def campaign(tmp_path: Path) -> Case:
    lines = [line(0, "/"), line(20, "/products")]
    at = 60
    for index in range(25):
        lines.append(line(at, f"/admin/{index}", status=404))
        at += 1
    lines.append(line(at, "/p?id=1%20UNION%20SELECT%20pw%20FROM%20users", size=1_400_000))
    return build_case(tmp_path, lines)


def test_the_report_names_the_client_and_what_it_did(campaign: Case) -> None:
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    assert ATTACKER in page
    for episode in result.episodes:
        assert episode.label in page


def test_the_report_carries_the_provenance_of_the_case(campaign: Case) -> None:
    """A finding without the manifest behind it cannot be reproduced."""
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    assert campaign.manifest.tool_version in page
    assert campaign.manifest.sources[0].sha256 in page


def test_the_report_needs_no_network_to_read(campaign: Case) -> None:
    """It gets opened on machines that have no internet, and years later, when
    whatever it might have linked to is gone."""
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    assert not re.search(r'(?:src|href)\s*=\s*["\']https?://', page)
    assert "<iframe" not in page


def test_a_hostile_log_line_is_shown_not_executed(tmp_path: Path) -> None:
    """The report embeds strings an attacker chose. If they are not escaped,
    opening the report of an attack runs the attacker's script — in the
    investigator's browser, on the investigator's machine."""
    payload = "/<script>alert(1)</script>?x=%22onerror%3D%22alert(2)"
    case = build_case(tmp_path, [line(0, "/"), line(5, payload, status=404)])
    result = analyse_ip(case.store, ATTACKER)

    page = render_report(result, case.manifest)

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    # Every script tag in the document is one the template put there.
    assert not re.search(r"<script[^>]*>(?!\s*</script>)", page)


def test_the_embedded_data_is_the_same_graph_the_cli_writes(campaign: Case) -> None:
    """`export --format html` and `export --format json` must not disagree
    about what happened; the report carries the JSON so the two cannot drift."""
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    embedded = page.split("<details><summary>Machine-readable data</summary><pre>")[1]
    embedded = embedded.split("</pre>")[0]
    unescaped = embedded.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    unescaped = unescaped.replace("&#x27;", "'").replace("&quot;", '"')
    assert json.loads(unescaped) == result.to_dict()


def test_a_client_with_nothing_to_report_still_renders(campaign: Case) -> None:
    result = analyse_ip(campaign.store, "192.0.2.99")

    page = render_report(result, campaign.manifest)

    assert page.startswith("<!doctype html>") or page.lstrip().startswith("<!")
    assert "192.0.2.99" in page


def test_the_report_renders_without_a_manifest(campaign: Case) -> None:
    """`analyse_ip` output can be reported on its own, so the argument is
    optional; that path must not be the one nobody ever ran."""
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result)

    assert ATTACKER in page


def test_an_edge_that_runs_backwards_leaves_from_the_left_of_its_node(tmp_path: Path) -> None:
    """A wrapped trace alternates direction, so on odd rows the target sits to
    the *left* of its source. Anchoring every line to the right edge regardless
    would draw it back across both nodes it connects.
    """
    from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
    from logarc.report.html import _NODE_WIDTH, _svg

    def node(node_id: str) -> GraphNode:
        return GraphNode(
            node_id=node_id,
            label="Directory Enumeration",
            category=ActivityCategory.ENUMERATION,
            severity=Severity.MEDIUM,
            outcome=Outcome.BLOCKED,
            request_count=5,
            distinct_paths=5,
            start=START,
            end=START + timedelta(seconds=5),
            episode_ids=("s/1",),
            bytes_total=0,
            owasp=None,
            top_targets=(),
            rule_ids=(),
            evidence=(),
            evidence_total=5,
        )

    # `right` sits further along the x axis; the edge runs from it back to `left`.
    graph = ActivityGraph(
        kind=GraphKind.TRACE,
        client_ip="1.2.3.4",
        nodes=(node("right"), node("left")),
        edges=(GraphEdge(source="right", target="left"),),
    )
    positions = {"right": Point(x=440.0, y=0.0), "left": Point(x=0.0, y=0.0)}

    with mock.patch("logarc.report.html.layout_graph", return_value=positions):
        svg = _svg(graph)

    # Anchored on the cubic, not on any `<path>`: the arrowhead in `<defs>` is
    # also a path and starts at M0,0, which would satisfy any bound asked of it.
    path = re.search(r'<path d="M([\d.]+),[\d.]+ C', svg)
    assert path is not None
    # 440 + offset is the source's own x — its left edge, facing the target.
    # Adding _NODE_WIDTH would anchor the line to the right edge, pointing away.
    assert float(path.group(1)) < 440.0 + _NODE_WIDTH


def test_the_report_writes_how_often_a_transition_was_seen(campaign: Case) -> None:
    """The behaviour map's weights carried no label at all in the report — only
    line thickness, which a reader cannot turn back into a number. A report is
    read by someone who never opened the application, so it is the copy that
    most needs the arrow to say what it means."""
    from logarc.core.graph import GraphEdge, GraphKind
    from logarc.report.html import _edge_label

    assert "x2" in _edge_label(GraphKind.BEHAVIOUR, GraphEdge("a", "b", weight=2, gap_seconds=9.0))
    assert "x" not in _edge_label(GraphKind.BEHAVIOUR, GraphEdge("a", "b", weight=1, gap_seconds=9))
    assert "x" not in _edge_label(GraphKind.TRACE, GraphEdge("a", "b", weight=1, gap_seconds=9.0))


def test_the_report_paints_a_finding_the_colour_the_window_paints_it(campaign: Case) -> None:
    """Screen and paper must agree about what a severity looks like.

    The two renderers are deliberately separate — ADR-0006 keeps a browser
    engine out of the application — but `logarc.gui.style` says on its own face
    that its judgements are "reused by the HTML report", and the report had
    quietly grown a second table. Every colour in it differed, so a critical
    finding was one red on screen and another in the file handed to someone who
    never opened the tool.
    """
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    assert result.episodes, "the fixture must produce something to colour"
    for episode in result.episodes:
        assert severity_colour(episode.severity) in page


def test_the_report_never_prints_a_severity_on_a_colour_it_cannot_be_read_against(
    campaign: Case,
) -> None:
    """The severity pill printed white on the severity colour, and three of the
    five failed WCAG AA — medium was 2.94:1. The canvas has no such problem
    because it stopped drawing text on the fill; the report should not
    reintroduce the constraint the canvas dropped.
    """
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    for painted in re.findall(r'<span class="pill"[^>]*background:(#[0-9a-f]{6})', page):
        assert contrast("#ffffff", painted) >= 4.5, f"white on {painted} is unreadable"
    # Non-vacuous: the severities must still be named, however they are drawn.
    for episode in result.episodes:
        assert episode.severity.name.title() in page
