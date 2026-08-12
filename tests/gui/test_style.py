"""How a node is drawn, decided without Qt so it can be checked without a display."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise

import pytest

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import GraphKind, GraphNode
from logarc.gui.style import (
    EVIDENCE_INK,
    EVIDENCE_MUTED,
    SIZE_NOTE,
    NodeStyle,
    edge_label,
    format_gap,
    format_requests,
    highlight_spans,
    node_radius,
    outcome_border,
    outcome_legend,
    severity_colour,
    severity_legend,
    status_colour,
    style_for,
    summarise,
)

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)

COMBINED = (
    "100.66.0.118 - - [01/May/2024:04:06:02 +0000] "
    '"GET /product.php?id=1%27%20UNION%20SELECT%20pw%20FROM%20users-- HTTP/1.1" 200 1400 '
    '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)


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


def test_the_legend_explains_every_severity_the_taxonomy_has() -> None:
    """The encoding is the product: colour is severity, border is outcome, size
    is volume. None of that was written anywhere a user could see it, so a
    dotted grey circle meant nothing to whoever was looking at one.

    Read from the same tables the renderer draws from, so adding a severity
    without explaining it fails here rather than quietly producing a colour
    nobody can name."""
    explained = {item.label for item in severity_legend()}

    assert explained == {level.name.title() for level in Severity}


def test_the_legend_explains_every_outcome() -> None:
    explained = {item.label for item in outcome_legend()}

    assert explained == {outcome.value.title() for outcome in Outcome}


def test_a_legend_entry_carries_what_it_takes_to_draw_the_sample() -> None:
    """A legend that describes a colour in words rather than showing it asks the
    reader to match a name against a picture, which is the work it exists to
    save."""
    for item in severity_legend():
        assert item.colour.startswith("#")
    for item in outcome_legend():
        assert item.border is not None
        assert item.border.style in {"solid", "dashed", "dotted"}


def test_the_legend_says_what_size_means() -> None:
    """Volume is the third channel and the only one with no swatch, so it has to
    be said in words or it is not explained at all."""
    assert "request" in SIZE_NOTE.lower()


# -- reading the raw evidence line ------------------------------------------


def _text_of(line: str, role: str) -> str:
    """The characters a span of this role covers, taken from the line itself."""
    span = next(s for s in highlight_spans(line) if s.role == role)
    return line[span.start : span.end]


def test_the_request_target_is_marked() -> None:
    """The payload is the evidence. In a 330px panel the line is cut off at
    `"GET` and every visible character is boilerplate the reader already knows —
    the client they picked and the time already in the heading."""
    assert _text_of(COMBINED, "target") == (
        "/product.php?id=1%27%20UNION%20SELECT%20pw%20FROM%20users--"
    )


def test_the_status_is_marked() -> None:
    assert _text_of(COMBINED, "status") == "200"


def test_spans_stay_inside_the_line_and_never_overlap() -> None:
    """They are offsets into the original text, applied to it rather than to a
    string rebuilt from it. An overlap or an out-of-range span would mean the
    panel is formatting something other than what it was handed."""
    spans = sorted(highlight_spans(COMBINED), key=lambda s: s.start)

    assert spans
    for span in spans:
        assert 0 <= span.start < span.end <= len(COMBINED)
    for earlier, later in pairwise(spans):
        assert earlier.end <= later.start


def test_a_line_in_an_unrecognised_shape_is_left_plain() -> None:
    """logarc reads nginx, IIS and JSON too. A highlight guessed wrong is worse
    than none: it would point the eye at the wrong part of the evidence."""
    assert highlight_spans('{"remote_addr":"10.0.0.1","request":"GET / HTTP/1.1"}') == ()
    assert highlight_spans("") == ()
    assert highlight_spans("not a log line at all") == ()


def test_a_request_with_no_status_after_it_is_left_plain() -> None:
    """A truncated line must not have its user agent marked as a status code."""
    assert highlight_spans('1.2.3.4 - - [x] "GET /a HTTP/1.1"') == ()


def test_one_request_is_not_one_requests() -> None:
    """The panel wrote "1 requests" while the canvas beside it wrote "1 request",
    because each formatted the count itself."""
    assert format_requests(1) == "1 request"
    assert format_requests(0) == "0 requests"
    assert format_requests(1000) == "1,000 requests"


def test_a_served_request_stands_out_and_a_refused_one_recedes() -> None:
    """Traffic-light colours would invert the meaning here. A 200 on an
    injection is the alarm — it says the payload was served — and the 403 is
    the reassurance. Green-for-200 would tell the reader the opposite."""
    assert status_colour("200") == EVIDENCE_INK
    assert status_colour("302") == EVIDENCE_INK
    assert status_colour("403") == EVIDENCE_MUTED
    assert status_colour("500") == EVIDENCE_MUTED


def test_an_unreadable_status_is_not_guessed_at() -> None:
    assert status_colour("abc") == EVIDENCE_MUTED
