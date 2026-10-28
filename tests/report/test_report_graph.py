"""Report graphs retain the canvas's meanings without needing a Qt renderer."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import combinations
from xml.etree import ElementTree as ET

import pytest

from logarx.core.activity import ActivityCategory, Outcome, Severity
from logarx.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarx.graphbuild.layout import sessions_in
from logarx.report.graph import render_graph
from logarx.style import node_radius, outcome_border, severity_colour

START = datetime(2026, 10, 28, tzinfo=UTC)


def node(index: int, session: int = 1, **changes: object) -> GraphNode:
    result = GraphNode(
        node_id=f"node-{index}",
        label="Directory Enumeration",
        category=ActivityCategory.ENUMERATION,
        severity=Severity.MEDIUM,
        outcome=Outcome.BLOCKED,
        request_count=10_000,
        distinct_paths=1,
        bytes_total=512,
        start=START + timedelta(seconds=index),
        end=START + timedelta(seconds=index + 1),
        owasp=None,
        top_targets=(),
        rule_ids=(),
        evidence=(),
        evidence_total=10_000,
        episode_ids=(f"client#{session}/{index}",),
    )
    return replace(result, **changes)


@pytest.mark.parametrize("outcome", list(Outcome))
@pytest.mark.parametrize("count", [1, 40, 10_000])
def test_circle_volume_and_outcome_match_the_desktop(outcome: Outcome, count: int) -> None:
    activity = node(1, outcome=outcome, request_count=count)
    graph = ActivityGraph(GraphKind.TRACE, "192.0.2.1", (activity,))
    svg = ET.fromstring(render_graph(graph))
    circle = svg.find('.//circle[@class="activity-node"]')
    assert circle is not None
    assert float(circle.attrib["r"]) == pytest.approx(node_radius(count), abs=0.01)
    assert circle.attrib["fill"] == severity_colour(activity.severity)
    assert float(circle.attrib["stroke-width"]) == outcome_border(outcome).width
    dash = circle.attrib.get("stroke-dasharray", "")
    if outcome_border(outcome).style == "solid":
        assert not dash
    else:
        on, off = map(float, dash.split())
        assert (on < off) == (outcome_border(outcome).style == "dotted")
    assert outcome.value in "".join(svg.itertext())


def bounds(element: ET.Element) -> tuple[float, float, float, float]:
    x, y, width, height = (float(element.attrib[key]) for key in ("x", "y", "width", "height"))
    return x, y, x + width, y + height


def overlaps(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> bool:
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


@pytest.mark.parametrize("label", ["An activity whose name needs a second caption line", "W" * 120])
def test_dense_sessions_and_captions_do_not_cover_each_other(label: str) -> None:
    activities = tuple(
        node(index, session, label=label)
        for session, count in enumerate([1, 7, 1, 12, 1, 2], start=1)
        for index in range(session * 100, session * 100 + count)
    )
    graph = ActivityGraph(GraphKind.TRACE, "192.0.2.1", activities)
    svg = ET.fromstring(render_graph(graph))
    boxes = [bounds(el) for el in svg.findall('.//rect[@class="session-box"]')]
    captions = [bounds(el) for el in svg.findall('.//rect[@class="caption-ground"]')]
    circles = [
        (
            float(el.attrib["cx"]) - float(el.attrib["r"]),
            float(el.attrib["cy"]) - float(el.attrib["r"]),
            float(el.attrib["cx"]) + float(el.attrib["r"]),
            float(el.attrib["cy"]) + float(el.attrib["r"]),
        )
        for el in svg.findall('.//circle[@class="activity-node"]')
    ]
    assert len(boxes) == len(sessions_in(graph)) == 6
    assert len(captions) == len(circles) == len(activities)
    assert all(not overlaps(a, b) for a, b in combinations(boxes, 2))
    assert all(not overlaps(a, b) for a, b in combinations(captions, 2))
    assert all(not overlaps(a, b) for a in captions for b in circles)
    width, height = float(svg.attrib["width"]), float(svg.attrib["height"])
    for x1, y1, x2, y2 in boxes + captions + circles:
        assert 0 <= x1 < x2 <= width
        assert 0 <= y1 < y2 <= height
    for caption in captions:
        assert any(
            b[0] <= caption[0] < caption[2] <= b[2] and b[1] <= caption[1] < caption[3] <= b[3]
            for b in boxes
        )


def test_behaviour_map_has_no_session_boxes_and_self_loop_keeps_its_label() -> None:
    graph = ActivityGraph(
        GraphKind.BEHAVIOUR,
        "192.0.2.1",
        (node(1),),
        (GraphEdge("node-1", "node-1", weight=4, gap_seconds=60),),
    )
    svg = ET.fromstring(render_graph(graph))
    assert not svg.findall('.//rect[@class="session-box"]')
    edges = svg.findall('.//path[@class="edge"]')
    assert len(edges) == 1
    assert edges[0].attrib["marker-end"] == "url(#behaviour-arrow)"
    assert "x4" in "".join(svg.itertext())
    assert svg.find(".//marker").attrib["id"] == "behaviour-arrow"


def test_report_icons_and_graph_text_cannot_load_a_user_supplied_svg() -> None:
    payload = '</text><script>alert(1)</script><image href="https://attacker.invalid/"/>'
    graph = ActivityGraph(
        GraphKind.TRACE, payload, (node(1, label=payload, named_by="file:untrusted.svg"),)
    )
    raw = render_graph(graph)
    svg = ET.fromstring(raw)
    assert not svg.findall(".//script")
    assert not svg.findall(".//image")
    assert payload in "".join(svg.itertext())
    assert "file:untrusted.svg" not in raw
    # An icon still exists: only the bundled category icon is embedded.
    assert svg.findall(".//{http://www.w3.org/2000/svg}svg")


def test_both_graphs_have_distinct_marker_and_accessible_title_ids() -> None:
    graphs = [
        ET.fromstring(render_graph(ActivityGraph(kind, "192.0.2.1", (node(1),))))
        for kind in GraphKind
    ]
    ids = [el.attrib["id"] for svg in graphs for el in svg.iter() if "id" in el.attrib]
    assert len(ids) == len(set(ids))
    for svg in graphs:
        assert all(ident in ids for ident in svg.attrib["aria-labelledby"].split())
