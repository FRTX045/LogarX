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

from colours import contrast
from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.window import TimeWindow
from logarc.graphbuild.layout import Point
from logarc.report.html import render_report
from logarc.style import severity_colour

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


def test_two_transitions_between_the_same_pair_are_drawn_apart(tmp_path: Path) -> None:
    """A behaviour map folds by activity type, so a client alternating between
    two of them has an edge each way. Drawn between the same two boxes, the
    second cubic is the first traced backwards: one line, two arrowheads, and
    two labels written on the same point. The report is the copy with no pan or
    zoom to work around it.
    """
    from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
    from logarc.report.html import _svg

    def node(node_id: str) -> GraphNode:
        return GraphNode(
            node_id=node_id,
            label=node_id,
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

    graph = ActivityGraph(
        kind=GraphKind.BEHAVIOUR,
        client_ip="1.2.3.4",
        nodes=(node("enumeration"), node("injection")),
        edges=(
            GraphEdge("enumeration", "injection", weight=3, gap_seconds=1.0),
            GraphEdge("injection", "enumeration", weight=2, gap_seconds=2.0),
        ),
    )
    positions = {"enumeration": Point(x=0.0, y=0.0), "injection": Point(x=440.0, y=0.0)}

    with mock.patch("logarc.report.html.layout_graph", return_value=positions):
        svg = _svg(graph)

    # Control points, not endpoints: reversing an edge already swaps the ends,
    # so comparing whole `d` strings would pass on the very bug this is about.
    controls = re.findall(r'<path d="M[\d.-]+,[\d.-]+ C[\d.-]+,([\d.-]+) ', svg)
    assert len(controls) == 2, "premise: an edge each way is drawn"
    assert controls[0] != controls[1]

    labels = re.findall(r'<text x="[\d.-]+" y="([\d.-]+)" class="edge-label"', svg)
    assert len(labels) == 2, "premise: both transitions are labelled"
    assert labels[0] != labels[1], "and neither label is written over the other"


def test_every_outcome_has_words_to_print_it_in() -> None:
    """Indexed rather than `.get`, so an outcome missing from the table raises
    `KeyError` while rendering — halfway through writing the artefact that
    leaves the building. The same table also fills the report's key, so an
    unlisted outcome would be drawn on the graph and absent from the legend
    explaining it."""
    from logarc.core.activity import Outcome
    from logarc.report.html import _OUTCOME_NOTE

    assert set(_OUTCOME_NOTE) == set(Outcome)


def test_an_arrow_is_labelled_the_same_on_paper_as_on_screen(tmp_path: Path) -> None:
    """The report had grown its own copy of the label, and the two had drifted.

    Nine of eleven sample gaps disagreed. The same transition read `1h 0m` in
    the window and `60m` in the report; `5h 33m` against `5.6h`; half a second
    was `0.5s` on screen and `0s` on paper, which is a gap reported as no gap.
    Both describe one edge of one graph, and an investigator comparing what
    they saw with what they attached to the case file finds two answers.

    Asserted against the rendered document rather than against a helper, so it
    keeps holding however the report chooses to produce the text.
    """
    from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
    from logarc.report.html import _svg
    from logarc.style import edge_label

    def node(node_id: str) -> GraphNode:
        return GraphNode(
            node_id=node_id,
            label=node_id,
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

    gaps = (0.5, 65.0, 100.0, 900.0, 3600.0, 5000.0, 7200.0)
    names = [f"a{index}" for index in range(len(gaps) + 1)]
    graph = ActivityGraph(
        kind=GraphKind.BEHAVIOUR,
        client_ip="203.0.113.5",
        nodes=tuple(node(name) for name in names),
        edges=tuple(
            GraphEdge(names[index], names[index + 1], weight=index + 2, gap_seconds=gap)
            for index, gap in enumerate(gaps)
        ),
    )
    positions = {name: Point(x=index * 400.0, y=0.0) for index, name in enumerate(names)}

    with mock.patch("logarc.report.html.layout_graph", return_value=positions):
        svg = _svg(graph)

    drawn = re.findall(r'class="edge-label"[^>]*>([^<]+)</text>', svg)
    expected = [
        edge_label(GraphKind.BEHAVIOUR, weight=index + 2, gap_seconds=gap)
        for index, gap in enumerate(gaps)
    ]
    assert drawn == expected


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
    engine out of the application — but `logarc.style` says on its own face
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


# -- saying what stretch of time the report covers -------------------------


def test_a_report_of_the_whole_case_says_nothing_about_a_range(campaign: Case) -> None:
    """Unfiltered is the ordinary state. A card announcing `whole case` on every
    report anyone has ever exported is noise."""
    assert "Time range" not in render_report(analyse_ip(campaign.store, ATTACKER))


def test_a_report_of_one_stretch_names_it_where_a_person_will_read_it(
    campaign: Case,
) -> None:
    """The identifiers already stop two reports being mistaken for one another.
    This is what lets a person tell them apart without comparing them."""
    window = TimeWindow(START, START + timedelta(minutes=1))

    page = render_report(analyse_ip(campaign.store, ATTACKER, window=window))

    assert "Time range" in page
    assert "12:00" in page


def test_the_range_travels_in_the_machine_readable_payload_too(campaign: Case) -> None:
    """A tool reading the JSON has the same problem a person does."""
    window = TimeWindow(START, START + timedelta(minutes=1))

    narrowed = analyse_ip(campaign.store, ATTACKER, window=window)

    assert narrowed.to_dict()["window"] == window.tag
    assert analyse_ip(campaign.store, ATTACKER).to_dict()["window"] == ""
