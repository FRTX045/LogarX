import re

import pytest
from PyQt6.QtCore import QUrl

from logarc.core.evidence import EvidenceRef
from logarc.triage.profile import (
    ClientProfile,
    PriorityReason,
    RankedClient,
    RequestExample,
)


def example(line, path="/login", note="Rule A", file="access.log"):
    return RequestExample(EvidenceRef(file, line), "POST", path, "2026-01-01T00:00:02+00:00", note)


def profile(**fields):
    return ClientProfile(
        client_ip="203.0.113.7",
        requests=48,
        severity=3,
        categories=("injection",),
        hostile_targets=2,
        hostile_requests=3,
        features={"requests": 48.0},
        coverage={"path": 48, "status": 48, "bytes_sent": 48},
        evidence={},
        statuses={"200": 2, "403": 1},
        **fields,
    )


def row(*reasons):
    return RankedClient(profile(), tuple(reasons), rank=3)


def matches(*examples):
    return PriorityReason(
        f"{len(examples)} rules matched on {len(examples)} requests.",
        tuple(item.evidence for item in examples),
        kind="distinct_rules",
        why="Distinct high-confidence rule matches provide support beyond repetition of one rule.",
        summary=f"{len(examples)} high-confidence rule matches",
        examples=examples,
    )


def test_log_fields_are_escaped_and_long_paths_kept_whole():
    from logarc.gui.recommendation import render_recommendation

    long_path = "/" + "a" * 400
    html = render_recommendation(
        row(matches(example(1, "/<b>x</b>", "<script>"), example(2, long_path)))
    )
    assert "<b>x</b>" not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html
    assert "<script>" not in html
    assert long_path in html


def test_every_block_answers_the_three_questions():
    from logarc.gui.recommendation import render_recommendation

    html = render_recommendation(row(matches(example(1), example(2))))
    assert "Observed:" in html
    assert "Why:" in html
    assert "Examples: 2 shown" in html
    assert 'href="example:0:0"' in html
    assert 'href="example:0:1"' in html
    assert "access.log:1" in html


def test_no_supporting_request_denominator_is_invented():
    from logarc.gui.recommendation import render_recommendation

    html = render_recommendation(row(matches(example(1), example(2), example(3))))
    assert not re.search(r"\bof \d+ (supporting )?requests\b", html)
    assert not re.search(r"showing \d+ of", html, re.IGNORECASE)


def test_an_unreadable_source_stays_visible_and_cannot_open():
    from logarc.gui.recommendation import SourceStatus, render_recommendation

    lost = example(7, file="missing.log")
    html = render_recommendation(
        row(matches(lost)),
        {lost.evidence: SourceStatus("missing.log is not part of this case", can_open=False)},
    )
    assert 'href="example:0:0"' not in html
    assert "missing.log:7" in html
    assert "Cannot open: missing.log is not part of this case" in html


def test_a_changed_source_opens_and_shows_its_warning():
    from logarc.gui.recommendation import SourceStatus, render_recommendation

    edited = example(8)
    html = render_recommendation(
        row(matches(edited)),
        {edited.evidence: SourceStatus("access.log changed since it was ingested", can_open=True)},
    )
    assert 'href="example:0:0"' in html
    assert "access.log changed since it was ingested" in html


def test_reasons_without_examples_list_their_source_lines():
    from logarc.gui.recommendation import SourceStatus, render_recommendation

    refs = (EvidenceRef("access.log", 4), EvidenceRef("gone.log", 5))
    support = PriorityReason(
        "3 of 48 requests have hostile detections (6%); strongest severity high.",
        refs,
        kind="support",
    )
    html = render_recommendation(
        row(support), {refs[1]: SourceStatus("gone.log is not part of this case", False)}
    )
    assert 'href="reason:0"' in html
    assert "access.log:4" in html
    assert "gone.log:5 (cannot open: gone.log is not part of this case)" in html


def test_responses_are_context_not_proof():
    from logarc.gui.recommendation import render_recommendation

    html = render_recommendation(row(matches(example(1))))
    assert "Responses: 200: 2, 403: 1." in html
    assert "A 200 response alone does not establish that an attack succeeded." in html


def test_the_table_shows_the_first_reasons_summary():
    from logarc.gui.recommendation import summary_for

    assert summary_for(row(matches(example(1), example(2)))) == "2 high-confidence rule matches"
    plain = PriorityReason("Injection indicators on 1 request; strongest high", ())
    assert summary_for(row(plain)) == plain.text
    assert summary_for(row()) == "No hostile detection"


@pytest.mark.parametrize(
    ("anchor", "parsed"),
    [
        ("example:1:2", ("example", 1, 2)),
        ("reason:3", ("reason", 3, -1)),
        ("reason:x", None),
        ("example:1", None),
        ("example:1:y", None),
        ("https://example.com", None),
    ],
)
def test_anchors_parse_back_to_what_they_name(anchor, parsed):
    from logarc.gui.recommendation import parse_anchor

    assert parse_anchor(QUrl(anchor)) == parsed


def test_unusual_reasons_render_without_a_why():
    from logarc.gui.recommendation import render_recommendation

    unusual = PriorityReason(
        "Requests: 480; above 97% of 700 comparable clients",
        (EvidenceRef("access.log", 1),),
        metric="requests",
    )
    html = render_recommendation(row(unusual))
    assert "Why:" not in html
    assert unusual.text in html
