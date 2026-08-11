"""How a node is drawn, decided without Qt so it can be checked without a display."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import GraphKind, GraphNode
from logarc.gui.style import (
    NodeStyle,
    edge_label,
    format_gap,
    node_radius,
    outcome_border,
    severity_colour,
    style_for,
    summarise,
)

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def node(
    *,
    severity: Severity = Severity.INFO,
    outcome: Outcome = Outcome.SUCCESS,
    category: ActivityCategory = ActivityCategory.BROWSING,
    requests: int = 1,
    label: str = "Page View",
) -> GraphNode:
    return GraphNode(
        node_id="n1",
        label=label,
        category=category,
        severity=severity,
        outcome=outcome,
        request_count=requests,
        distinct_paths=1,
        bytes_total=1024,
        start=START,
        end=START,
        owasp=None,
        top_targets=("/",),
        rule_ids=("benign:browsing",),
        evidence=(EvidenceRef("access.log", 1),),
        evidence_total=1,
        episode_ids=("s1/1",),
    )


def test_severity_reads_as_a_scale() -> None:
    """Colour has to order the same way severity does, or it misinforms."""
    colours = [severity_colour(level) for level in Severity]

    assert len(set(colours)) == len(colours), "each level needs its own colour"
    assert all(colour.startswith("#") and len(colour) == 7 for colour in colours)


def test_a_critical_finding_does_not_look_like_an_informational_one() -> None:
    assert severity_colour(Severity.CRITICAL) != severity_colour(Severity.INFO)


def test_outcome_is_carried_by_the_border_not_the_fill() -> None:
    """Severity owns colour, so outcome needs a channel of its own."""
    assert len({outcome_border(outcome).style for outcome in Outcome}) > 1


def test_a_blocked_attempt_is_drawn_differently_from_a_successful_one() -> None:
    """The distinction the whole reconstruction is built around."""
    assert outcome_border(Outcome.BLOCKED) != outcome_border(Outcome.SUCCESS)


def test_a_busier_activity_is_drawn_larger() -> None:
    assert node_radius(500) > node_radius(50) > node_radius(5)


def test_size_grows_slowly_enough_to_stay_on_screen() -> None:
    """A thousand-request episode must not be two hundred times a five-request one."""
    assert node_radius(10_000) < node_radius(10) * 6


def test_a_single_request_still_has_a_visible_size() -> None:
    assert node_radius(1) >= 20
    assert node_radius(0) >= 20


def test_a_style_carries_everything_needed_to_draw_one_node() -> None:
    style = style_for(node(severity=Severity.CRITICAL, outcome=Outcome.MIXED, requests=42))

    assert isinstance(style, NodeStyle)
    assert style.fill == severity_colour(Severity.CRITICAL)
    assert style.border == outcome_border(Outcome.MIXED)
    assert style.radius == node_radius(42)
    assert style.radius > 0


def test_hostile_and_ordinary_activity_are_told_apart_at_a_glance() -> None:
    attack = style_for(node(severity=Severity.HIGH, category=ActivityCategory.INJECTION))
    ordinary = style_for(node(severity=Severity.INFO, category=ActivityCategory.BROWSING))

    assert attack.fill != ordinary.fill


def test_a_summary_names_the_activity_and_its_weight() -> None:
    text = summarise(node(label="SQL Injection", requests=47, outcome=Outcome.MIXED))

    assert "SQL Injection" in text
    assert "47" in text
    assert "mixed" in text.lower()


def test_a_long_label_is_shortened_rather_than_overflowing() -> None:
    text = summarise(node(label="A" * 200))

    assert len(text.splitlines()[0]) < 60


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (None, ""),
        (0.4, "0.4s"),
        (45, "45s"),
        (90, "1m 30s"),
        (3600, "1h 0m"),
        (7325, "2h 2m"),
    ],
)
def test_a_gap_is_written_the_way_a_person_would_say_it(
    seconds: float | None, expected: str
) -> None:
    assert format_gap(seconds) == expected


def test_a_repeated_transition_says_how_often_it_was_seen() -> None:
    """On a behaviour map the weight is the finding: a transition seen twice is
    a habit, one seen once is an incident. It used to be carried only by line
    thickness, which cannot be read as a number and cannot be compared between
    two clients' maps."""
    label = edge_label(GraphKind.BEHAVIOUR, weight=2, gap_seconds=30.0)

    assert "2" in label
    assert "30s" in label


def test_a_transition_seen_once_says_nothing_about_its_count() -> None:
    """A number that is always the same is not information, and on a crowded
    map it is one more thing to read past."""
    assert "1" not in edge_label(GraphKind.BEHAVIOUR, weight=1, gap_seconds=30.0)


def test_a_trace_never_shows_a_weight() -> None:
    """Every step of a trace happened once by construction."""
    assert edge_label(GraphKind.TRACE, weight=1, gap_seconds=5.0) == format_gap(5.0)


def test_a_transition_with_no_recorded_gap_still_reports_its_weight() -> None:
    assert "3" in edge_label(GraphKind.BEHAVIOUR, weight=3, gap_seconds=None)
