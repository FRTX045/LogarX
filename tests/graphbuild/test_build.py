"""Tests for turning episodes into activity graphs."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from logarc.core.activity import ActivityCategory, ActivityLabel, Outcome, Severity
from logarc.core.episode import Episode
from logarc.core.evidence import EvidenceRef
from logarc.graphbuild.build import build_behaviour_map, build_trace_graph

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def episode(
    category: ActivityCategory,
    *,
    index: int = 1,
    session: str = "1.2.3.4#1",
    minutes: float = 0,
    duration_minutes: float = 1,
    requests: int = 10,
    severity: Severity = Severity.MEDIUM,
    outcome: Outcome = Outcome.BLOCKED,
) -> Episode:
    start = START + timedelta(minutes=minutes)
    return Episode(
        episode_id=f"{session}/{index}",
        session_id=session,
        client_ip="1.2.3.4",
        activity=ActivityLabel(
            rule_id=f"rule_{category.value}",
            name=category.value.replace("_", " ").title(),
            category=category,
            severity=severity,
            confidence=0.9,
            owasp="A03:2021",
        ),
        start=start,
        end=start + timedelta(minutes=duration_minutes),
        request_count=requests,
        distinct_paths=3,
        bytes_total=1024,
        status_histogram={200: requests},
        top_targets=("/a", "/b"),
        rule_ids=(f"rule_{category.value}",),
        outcome=outcome,
        evidence=(EvidenceRef("access.log", index),),
        evidence_total=requests,
    )


# -- trace graph ----------------------------------------------------------


def test_an_empty_trace_graph_has_no_nodes() -> None:
    graph = build_trace_graph([], client_ip="1.2.3.4")

    assert graph.nodes == ()
    assert graph.edges == ()


def test_each_episode_becomes_a_node() -> None:
    episodes = [
        episode(ActivityCategory.RECONNAISSANCE, index=1, minutes=0),
        episode(ActivityCategory.INJECTION, index=2, minutes=5),
    ]

    graph = build_trace_graph(episodes, client_ip="1.2.3.4")

    assert len(graph.nodes) == 2
    assert graph.nodes[0].label == "Reconnaissance"


def test_consecutive_episodes_are_linked_in_order() -> None:
    episodes = [
        episode(ActivityCategory.RECONNAISSANCE, index=1, minutes=0),
        episode(ActivityCategory.ENUMERATION, index=2, minutes=5),
        episode(ActivityCategory.INJECTION, index=3, minutes=10),
    ]

    graph = build_trace_graph(episodes, client_ip="1.2.3.4")

    assert [(e.source, e.target) for e in graph.edges] == [
        ("1.2.3.4#1/1", "1.2.3.4#1/2"),
        ("1.2.3.4#1/2", "1.2.3.4#1/3"),
    ]


def test_episodes_in_different_sessions_are_not_linked() -> None:
    """A session boundary is a break in the story, not a transition."""
    episodes = [
        episode(ActivityCategory.RECONNAISSANCE, index=1, session="1.2.3.4#1", minutes=0),
        episode(ActivityCategory.INJECTION, index=1, session="1.2.3.4#2", minutes=90),
    ]

    graph = build_trace_graph(episodes, client_ip="1.2.3.4")

    assert graph.edges == ()


def test_an_edge_records_the_time_between_episodes() -> None:
    episodes = [
        episode(ActivityCategory.RECONNAISSANCE, index=1, minutes=0, duration_minutes=1),
        episode(ActivityCategory.INJECTION, index=2, minutes=6),
    ]

    graph = build_trace_graph(episodes, client_ip="1.2.3.4")

    assert graph.edges[0].gap_seconds == 300


def test_a_node_carries_what_a_report_needs() -> None:
    graph = build_trace_graph(
        [episode(ActivityCategory.INJECTION, severity=Severity.CRITICAL, outcome=Outcome.MIXED)],
        client_ip="1.2.3.4",
    )

    node = graph.nodes[0]
    assert node.category is ActivityCategory.INJECTION
    assert node.severity is Severity.CRITICAL
    assert node.outcome is Outcome.MIXED
    assert node.owasp == "A03:2021"
    assert node.request_count == 10
    assert node.evidence_total == 10
    assert node.evidence[0] == EvidenceRef("access.log", 1)


# -- behaviour map --------------------------------------------------------


def test_the_behaviour_map_has_one_node_per_category() -> None:
    episodes = [
        episode(ActivityCategory.INJECTION, index=1, minutes=0),
        episode(ActivityCategory.RECONNAISSANCE, index=2, minutes=5),
        episode(ActivityCategory.INJECTION, index=3, minutes=10),
    ]

    graph = build_behaviour_map(episodes, client_ip="1.2.3.4")

    assert len(graph.nodes) == 2


def test_the_behaviour_map_sums_requests_across_episodes() -> None:
    episodes = [
        episode(ActivityCategory.INJECTION, index=1, minutes=0, requests=10),
        episode(ActivityCategory.INJECTION, index=2, minutes=10, requests=15),
    ]

    graph = build_behaviour_map(episodes, client_ip="1.2.3.4")

    assert graph.nodes[0].request_count == 25
    assert graph.nodes[0].episode_count == 2


def test_repeated_transitions_accumulate_weight() -> None:
    """This is what makes the map a map: the thicker arrow is the habit."""
    episodes = [
        episode(ActivityCategory.RECONNAISSANCE, index=1, minutes=0),
        episode(ActivityCategory.INJECTION, index=2, minutes=5),
        episode(ActivityCategory.RECONNAISSANCE, index=3, minutes=10),
        episode(ActivityCategory.INJECTION, index=4, minutes=15),
    ]

    graph = build_behaviour_map(episodes, client_ip="1.2.3.4")

    (edge,) = [e for e in graph.edges if e.source == "reconnaissance"]
    assert edge.target == "injection"
    assert edge.weight == 2


def test_a_repeated_category_produces_a_self_loop() -> None:
    """Returning to the same activity after a break is a real transition."""
    episodes = [
        episode(ActivityCategory.INJECTION, index=1, minutes=0),
        episode(ActivityCategory.INJECTION, index=2, minutes=60),
    ]

    graph = build_behaviour_map(episodes, client_ip="1.2.3.4")

    assert graph.edges[0].source == graph.edges[0].target == "injection"


def test_the_behaviour_map_keeps_the_worst_severity_seen() -> None:
    episodes = [
        episode(ActivityCategory.INJECTION, index=1, minutes=0, severity=Severity.LOW),
        episode(ActivityCategory.INJECTION, index=2, minutes=10, severity=Severity.CRITICAL),
    ]

    graph = build_behaviour_map(episodes, client_ip="1.2.3.4")

    assert graph.nodes[0].severity is Severity.CRITICAL


def test_the_behaviour_map_does_not_link_across_sessions() -> None:
    episodes = [
        episode(ActivityCategory.RECONNAISSANCE, index=1, session="1.2.3.4#1"),
        episode(ActivityCategory.INJECTION, index=1, session="1.2.3.4#2", minutes=90),
    ]

    graph = build_behaviour_map(episodes, client_ip="1.2.3.4")

    assert graph.edges == ()


# -- serialisation --------------------------------------------------------


def test_a_graph_serialises_to_plain_data() -> None:
    graph = build_trace_graph(
        [
            episode(ActivityCategory.RECONNAISSANCE, index=1, minutes=0),
            episode(ActivityCategory.INJECTION, index=2, minutes=5),
        ],
        client_ip="1.2.3.4",
    )

    payload = graph.to_dict()

    assert payload["kind"] == "trace"
    assert payload["client_ip"] == "1.2.3.4"
    assert len(payload["nodes"]) == 2
    assert len(payload["edges"]) == 1
    assert payload["nodes"][0]["evidence"][0] == "access.log:1"


def test_serialised_timestamps_are_iso_utc() -> None:
    graph = build_trace_graph([episode(ActivityCategory.INJECTION)], client_ip="1.2.3.4")

    assert graph.to_dict()["nodes"][0]["start"].endswith("+00:00")


# -- which rule named a node ----------------------------------------------


def _named(base: Episode, rule_id: str, *also: str) -> Episode:
    """`base`, named after `rule_id`, with `also` matching in it too."""
    return replace(
        base,
        activity=replace(base.activity, rule_id=rule_id),
        rule_ids=tuple(sorted({rule_id, *also})),
    )


def test_a_trace_node_knows_the_rule_that_named_it() -> None:
    """`rule_ids` is every rule that matched in the episode, sorted, so it cannot
    say which one the episode is named after; the icon of a reader's own rule
    needs exactly that."""
    named = _named(episode(ActivityCategory.INJECTION), "sqli_union_probe", "browse")

    (node,) = build_trace_graph([named], client_ip="1.2.3.4").nodes

    assert node.named_by == "sqli_union_probe"
    assert node.rule_ids == ("browse", "sqli_union_probe")


def test_a_behaviour_node_is_named_by_its_worst_episode() -> None:
    episodes = [
        _named(episode(ActivityCategory.INJECTION, index=1, severity=Severity.LOW), "xss_probe"),
        _named(
            episode(ActivityCategory.INJECTION, index=2, minutes=10, severity=Severity.CRITICAL),
            "sqli_union_probe",
        ),
        _named(episode(ActivityCategory.INJECTION, index=3, minutes=20), "lfi_probe"),
    ]

    (node,) = build_behaviour_map(episodes, client_ip="1.2.3.4").nodes

    assert node.named_by == "sqli_union_probe"
    assert node.label == episodes[1].label, "named by the episode its label comes from"


def test_named_by_is_not_exported() -> None:
    """The exported graph stays as it was: nothing about icons leaves the window."""
    named = _named(episode(ActivityCategory.INJECTION), "sqli_union_probe")
    (node,) = build_trace_graph([named], client_ip="1.2.3.4").nodes

    assert "named_by" not in node.to_dict()
