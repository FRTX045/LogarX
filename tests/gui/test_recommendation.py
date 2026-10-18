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
        why="Distinct rule matches provide support beyond repetition of one rule.",
        summary=f"{len(examples)} distinct rule matches",
        examples=examples,
    )


def render_opened(row, status=None, **kwargs):
    """Inspect the full content after opening every finding and More context."""
    from logarc.gui.recommendation import render_recommendation

    return render_recommendation(
        row, status, opened=frozenset(range(len(row.reasons))), show_context=True, **kwargs
    )


def test_log_fields_are_escaped_and_long_paths_kept_whole():
    long_path = "/" + "a" * 400
    html = render_opened(row(matches(example(1, "/<b>x</b>", "<script>"), example(2, long_path))))
    assert "<b>x</b>" not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html
    assert "<script>" not in html
    assert long_path in html


def test_every_block_answers_the_three_questions():
    html = render_opened(row(matches(example(1), example(2))))
    assert "Observed:" in html
    assert "Why:" in html
    assert "Examples: 2 shown" in html
    assert 'href="example:0:0"' in html
    assert 'href="example:0:1"' in html
    assert "access.log:1" in html


def test_no_supporting_request_denominator_is_invented():
    html = render_opened(row(matches(example(1), example(2), example(3))))
    assert not re.search(r"\bof \d+ (supporting )?requests\b", html)
    assert not re.search(r"showing \d+ of", html, re.IGNORECASE)


def test_an_unreadable_source_stays_visible_and_cannot_open():
    from logarc.gui.recommendation import SourceStatus

    lost = example(7, file="missing.log")
    html = render_opened(
        row(matches(lost)),
        {lost.evidence: SourceStatus("missing.log is not part of this case", can_open=False)},
    )
    assert 'href="example:0:0"' not in html
    assert "missing.log:7" in html
    assert "Cannot open: missing.log is not part of this case" in html


def test_a_changed_source_opens_and_shows_its_warning():
    from logarc.gui.recommendation import SourceStatus

    edited = example(8)
    html = render_opened(
        row(matches(edited)),
        {edited.evidence: SourceStatus("access.log changed since it was ingested", can_open=True)},
    )
    assert 'href="example:0:0"' in html
    assert "access.log changed since it was ingested" in html


def test_reasons_without_examples_list_their_source_lines():
    from logarc.gui.recommendation import SourceStatus

    refs = (EvidenceRef("access.log", 4), EvidenceRef("gone.log", 5))
    support = PriorityReason(
        "3 of 48 requests flagged (6%); strongest severity high.",
        refs,
        kind="support",
    )
    html = render_opened(
        row(support), {refs[1]: SourceStatus("gone.log is not part of this case", False)}
    )
    assert 'href="reason:0"' in html
    assert "access.log:4" in html
    assert "gone.log:5 (cannot open: gone.log is not part of this case)" in html


def test_responses_are_context_not_proof():
    html = render_opened(row(matches(example(1))))
    assert "Responses: 200: 2, 403: 1." in html
    assert "A 200 response alone does not establish that an attack succeeded." in html


def test_the_table_shows_the_first_reasons_summary():
    from logarc.gui.recommendation import summary_for

    assert summary_for(row(matches(example(1), example(2)))) == "2 distinct rule matches"
    plain = PriorityReason("Injection indicators on 1 request; strongest high", ())
    assert summary_for(row(plain)) == plain.text
    assert summary_for(row()) == "No hostile detection"


@pytest.mark.parametrize(
    ("anchor", "parsed"),
    [
        ("example:1:2", ("example", 1, 2)),
        ("reason:3", ("reason", 3, -1)),
        ("details:2", ("details", 2, -1)),
        ("details:x", None),
        ("context:0", ("context", 0, -1)),
        ("context:1", None),
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
    unusual = PriorityReason(
        "Requests: 480; above 97% of 700 comparable clients",
        (EvidenceRef("access.log", 1),),
        metric="requests",
    )
    html = render_opened(row(unusual))
    assert "Why:" not in html
    assert unusual.text in html


def test_blocks_are_titled_for_what_they_count_and_explain_the_threshold():
    support = PriorityReason(
        "3 of 48 requests flagged (6%); strongest severity high.", (), kind="support"
    )
    html = render_opened(row(support, matches(example(1), example(2))))
    assert "1. Flagged requests" in html
    assert "2. Distinct rule matches" in html
    assert "high-confidence" not in html.lower()
    assert (
        "Counted: bundled rules rated at confidence 0.85 or above. "
        "The rating describes the rule, not the request."
    ) in html


def test_example_separates_request_rule_and_utc_source_metadata():
    late = RequestExample(
        EvidenceRef("access.log", 3), "GET", "/login", "2026-03-11T11:00:33+07:00", "Rule A"
    )
    html = render_opened(row(matches(late)))
    assert "2026-03-11 04:00:33 UTC" in html
    assert "2026-03-11T11:00:33+07:00" not in html
    assert re.search(r"GET /login</a><br><span[^>]*>Rule A</span><br>", html)
    assert "2026-03-11 04:00:33 UTC · access.log:3" in re.sub(r"<[^>]+>", "", html)


def test_a_long_path_is_cut_to_fit_and_can_be_expanded():
    long_path = "/catalog/" + "x" * 300
    html = render_opened(row(matches(example(1, long_path))), path_chars=60)
    assert long_path not in html
    assert long_path[:59] + "\u2026" in html
    assert 'href="expand:0:0"' in html
    assert "Show full request" in html
    opened = render_opened(
        row(matches(example(1, long_path))), path_chars=60, expanded=frozenset({(0, 0)})
    )
    assert long_path in opened
    assert 'href="expand:0:0"' not in opened


def test_a_short_path_is_never_cut():
    html = render_opened(row(matches(example(1, "/login"))), path_chars=60)
    assert "Show full request" not in html


def test_expand_anchors_parse():
    from logarc.gui.recommendation import parse_anchor

    assert parse_anchor(QUrl("expand:2:1")) == ("expand", 2, 1)
    assert parse_anchor(QUrl("expand:2")) is None


def test_the_full_request_includes_its_query():
    payload = RequestExample(
        EvidenceRef("access.log", 1),
        "GET",
        "/search",
        "2026-03-11T04:00:33+00:00",
        "SQL Injection",
        query="q=1 UNION SELECT " + "password," * 40 + " FROM users",
    )
    cut = render_opened(row(matches(payload)), path_chars=60)
    assert "GET /search?q=1 UNION SELECT" in cut
    assert "FROM users" not in cut
    whole = render_opened(row(matches(payload)), path_chars=60, expanded=frozenset({(0, 0)}))
    assert f"GET /search?{payload.query}" in whole


def test_exploit_evidence_is_titled_and_shows_its_request():
    from logarc.gui.recommendation import TITLES

    lead = PriorityReason(
        "Rule A matched a request to /login.",
        (EvidenceRef("access.log", 1),),
        kind="exploit_evidence",
        why="Inspect the request.",
        summary="Exploit evidence: Rule A",
        examples=(example(1),),
    )
    assert TITLES["exploit_evidence"] == "Exploit evidence"
    html = render_opened(row(lead))
    assert "1. Exploit evidence" in html
    assert "Rule A matched a request to /login." in html
    assert "Examples: 1 shown" in html


def test_findings_start_with_only_their_title_and_short_observation():
    from logarc.gui.recommendation import render_recommendation

    html = render_recommendation(row(matches(example(1), example(2))))
    assert "Distinct rule matches" in html
    assert "2 distinct rule matches" in html
    assert 'href="details:0"' in html
    assert "Why:" not in html
    assert "Examples:" not in html
    assert "access.log:1" not in html
    assert "Recorded measurements:" not in html
    assert "Field coverage:" not in html


def test_only_requested_findings_show_their_explanations_and_examples():
    from logarc.gui.recommendation import render_recommendation

    first = PriorityReason("First observation", (), why="First explanation", kind="support")
    second = matches(example(7))
    html = render_recommendation(row(first, second), opened=frozenset({1}))
    assert "First observation" in html
    assert "First explanation" not in html
    assert second.why in html
    assert 'href="example:1:0"' in html


def test_context_opens_independently_of_findings():
    from logarc.gui.recommendation import render_recommendation

    html = render_recommendation(row(matches(example(1))), show_context=True)
    assert "Responses: 200: 2, 403: 1." in html
    assert "Recorded measurements:" in html
    assert "Field coverage:" in html
    assert "Examples:" not in html


def test_source_warnings_are_visible_even_with_every_finding_closed():
    from logarc.gui.recommendation import SourceStatus, render_recommendation

    item = example(1)
    html = render_recommendation(
        row(matches(item)), {item.evidence: SourceStatus("source is missing", False)}
    )
    assert "Source warning:" in html
    assert "1 sample source line unavailable" in html
    assert "Examples:" not in html
