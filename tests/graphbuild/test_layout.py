"""Tests for graph layout."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from logarc.core.activity import ActivityCategory, ActivityLabel, Outcome, Severity
from logarc.core.episode import Episode
from logarc.core.evidence import EvidenceRef
from logarc.graphbuild.build import build_behaviour_map, build_trace_graph
from logarc.graphbuild.layout import layout_graph

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def episode(
    category: ActivityCategory, *, index: int, session: str = "1.2.3.4#1", requests: int = 10
) -> Episode:
    return Episode(
        episode_id=f"{session}/{index}",
        session_id=session,
        client_ip="1.2.3.4",
        activity=ActivityLabel(
            rule_id="r",
            name=category.value,
            category=category,
            severity=Severity.MEDIUM,
            confidence=0.9,
        ),
        start=START + timedelta(minutes=index),
        end=START + timedelta(minutes=index, seconds=30),
        request_count=requests,
        distinct_paths=1,
        bytes_total=1,
        status_histogram={200: requests},
        top_targets=("/a",),
        rule_ids=("r",),
        outcome=Outcome.SUCCESS,
        evidence=(EvidenceRef("access.log", index),),
        evidence_total=requests,
    )


def test_an_empty_graph_has_no_positions() -> None:
    assert layout_graph(build_trace_graph([], client_ip="1.2.3.4")) == {}


def test_every_node_is_positioned() -> None:
    graph = build_trace_graph(
        [episode(ActivityCategory.INJECTION, index=n) for n in range(1, 4)],
        client_ip="1.2.3.4",
    )

    positions = layout_graph(graph)

    assert set(positions) == {node.node_id for node in graph.nodes}


def test_a_trace_runs_left_to_right_in_time() -> None:
    graph = build_trace_graph(
        [episode(ActivityCategory.INJECTION, index=n) for n in range(1, 4)],
        client_ip="1.2.3.4",
    )

    positions = layout_graph(graph)
    xs = [positions[node.node_id].x for node in graph.nodes]

    assert xs == sorted(xs)
    assert len(set(xs)) == 3


def test_each_session_gets_its_own_row() -> None:
    graph = build_trace_graph(
        [
            episode(ActivityCategory.INJECTION, index=1, session="1.2.3.4#1"),
            episode(ActivityCategory.INJECTION, index=2, session="1.2.3.4#1"),
            episode(ActivityCategory.RECONNAISSANCE, index=1, session="1.2.3.4#2"),
        ],
        client_ip="1.2.3.4",
    )

    positions = layout_graph(graph)

    assert positions["1.2.3.4#1/1"].y == positions["1.2.3.4#1/2"].y
    assert positions["1.2.3.4#2/1"].y != positions["1.2.3.4#1/1"].y
    assert positions["1.2.3.4#2/1"].x == positions["1.2.3.4#1/1"].x


def _trace(count: int, *, session: str = "1.2.3.4#1"):
    return build_trace_graph(
        [
            episode(ActivityCategory.INJECTION, index=n, session=session)
            for n in range(1, count + 1)
        ],
        client_ip="1.2.3.4",
    )


def test_a_long_trace_wraps_instead_of_running_off_the_canvas() -> None:
    """A chain laid out on one row is 1,480 units wide and 290 tall in a canvas
    that is roughly square, so fitting it shrinks the whole scene to ~0.64 and
    the captions become a smudge. Wrapping is what buys the scale back."""
    positions = layout_graph(_trace(12))

    assert len({point.y for point in positions.values()}) > 1


def test_a_short_trace_still_reads_as_one_line() -> None:
    """Wrapping a four-step trace would cost the straight timeline and buy no
    readability, because it already fits."""
    positions = layout_graph(_trace(4))

    assert len({point.y for point in positions.values()}) == 1


def test_wrapping_leaves_the_block_closer_to_square() -> None:
    """The point of the exercise, stated as the shape it produces."""
    positions = layout_graph(_trace(16)).values()
    width = max(p.x for p in positions) - min(p.x for p in positions)
    height = max(p.y for p in positions) - min(p.y for p in positions)

    assert height > 0
    assert width / height < 6.0


def test_wrapped_rows_alternate_direction() -> None:
    """Serpentine, so the join between rows is short. Laying every row
    left-to-right would send a line the whole width of the block backwards on
    every wrap, crossing everything in between."""
    graph = _trace(12)
    positions = layout_graph(graph)
    rows: dict[float, list[float]] = {}
    for node in graph.nodes:
        point = positions[node.node_id]
        rows.setdefault(point.y, []).append(point.x)

    ordered = [rows[y] for y in sorted(rows)]
    assert ordered[0] == sorted(ordered[0])
    assert ordered[1] == sorted(ordered[1], reverse=True)


def test_reading_the_serpentine_recovers_chronological_order() -> None:
    """The trace is a timeline. If the wrap reordered it, the graph would be
    telling a different story from the one the log holds."""
    graph = _trace(12)
    positions = layout_graph(graph)
    # Row *index*, not the y coordinate: the direction alternates by row, and
    # y is a multiple of the row height rather than a counter.
    row_of = {y: index for index, y in enumerate(sorted({p.y for p in positions.values()}))}

    def where(node_id: str) -> tuple[int, float]:
        point = positions[node_id]
        row = row_of[point.y]
        return (row, point.x if row % 2 == 0 else -point.x)

    ids = [node.node_id for node in graph.nodes]
    assert sorted(ids, key=where) == ids
    assert len(row_of) > 1  # otherwise this proves nothing about wrapping


def test_sessions_stay_further_apart_than_the_rows_within_one() -> None:
    """Otherwise a session boundary is indistinguishable from a wrap, and the
    graph says two visits where the log holds one."""
    first = [
        episode(ActivityCategory.INJECTION, index=n, session="1.2.3.4#1") for n in range(1, 13)
    ]
    second = [episode(ActivityCategory.RECONNAISSANCE, index=1, session="1.2.3.4#2")]
    graph = build_trace_graph([*first, *second], client_ip="1.2.3.4")

    positions = layout_graph(graph)
    within = sorted({positions[node.node_id].y for node in graph.nodes if "#1" in node.node_id})
    between = positions["1.2.3.4#2/1"].y - within[-1]

    assert between > (within[1] - within[0])


def test_a_behaviour_map_spreads_its_nodes_out() -> None:
    graph = build_behaviour_map(
        [
            episode(ActivityCategory.INJECTION, index=1),
            episode(ActivityCategory.RECONNAISSANCE, index=2),
            episode(ActivityCategory.ENUMERATION, index=3),
        ],
        client_ip="1.2.3.4",
    )

    positions = layout_graph(graph)

    assert len({(p.x, p.y) for p in positions.values()}) == 3


def test_a_single_node_map_is_centred() -> None:
    graph = build_behaviour_map([episode(ActivityCategory.INJECTION, index=1)], client_ip="1.2.3.4")

    (point,) = layout_graph(graph).values()

    assert (point.x, point.y) == (0.0, 0.0)


def test_layout_is_identical_across_runs() -> None:
    """A tool that draws the same evidence differently each time invites doubt
    about what else changed."""
    graph = build_behaviour_map(
        [
            episode(ActivityCategory.INJECTION, index=1),
            episode(ActivityCategory.RECONNAISSANCE, index=2),
            episode(ActivityCategory.BROWSING, index=3),
        ],
        client_ip="1.2.3.4",
    )

    assert layout_graph(graph) == layout_graph(graph)


def test_the_busiest_activity_always_lands_in_the_same_place() -> None:
    """So two clients' maps can be compared at a glance."""
    first = build_behaviour_map(
        [
            episode(ActivityCategory.INJECTION, index=1, requests=100),
            episode(ActivityCategory.BROWSING, index=2, requests=1),
        ],
        client_ip="1.2.3.4",
    )
    second = build_behaviour_map(
        [
            episode(ActivityCategory.BROWSING, index=1, requests=1),
            episode(ActivityCategory.INJECTION, index=2, requests=100),
        ],
        client_ip="5.6.7.8",
    )

    assert layout_graph(first)["injection"] == layout_graph(second)["injection"]
