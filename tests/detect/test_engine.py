"""Tests for the detection engine."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarc.core.activity import ActivityCategory, Severity
from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.crs import CrsDetection
from logarc.detect.engine import RuleEngine
from logarc.detect.rules import load_rules

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)

PACK = """
version: 1
rules:
  - id: sqli_union
    name: SQL Injection (UNION SELECT)
    category: injection
    owasp: "A03:2021"
    severity: high
    confidence: 0.9
    match:
      any:
        - field: target_decoded
          regex: 'union\\s+select'

  - id: admin_probe
    name: Admin Panel Probe
    category: reconnaissance
    severity: low
    match:
      all:
        - field: path_decoded
          contains: '/admin'
        - field: status
          equals: '404'

  - id: server_error
    name: Server Error
    category: exploitation
    severity: critical
    match:
      any:
        - field: status
          min: 500

  - id: dir_enumeration
    name: Directory Enumeration
    category: enumeration
    owasp: "A01:2021"
    severity: medium
    window:
      span_seconds: 60
      min_requests: 5
      conditions:
        - metric: not_found_ratio
          op: ">="
          value: 0.8
        - metric: distinct_paths
          op: ">="
          value: 5
"""


@pytest.fixture
def engine(tmp_path: Path) -> RuleEngine:
    path = tmp_path / "pack.yaml"
    path.write_text(PACK, encoding="utf-8")
    return RuleEngine(load_rules([path]))


def event(
    seconds: float = 0,
    *,
    path: str = "/",
    query: str | None = None,
    status: int | None = 200,
    user_agent: str | None = "curl/8.0",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=START + timedelta(seconds=seconds),
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", int(seconds) + 1),
        method="GET",
        path=path,
        query=query,
        status=status,
        bytes_sent=100,
        user_agent=user_agent,
    )


def test_every_matchable_field_reads_its_own_value() -> None:
    """A rule names a field and gets its text. If an arm returns a neighbour's
    value, every rule written against that field silently matches the wrong
    data — and a detection tool that matches the wrong data is worse than one
    that matches nothing, because it looks like it worked.

    Driven from `MATCH_FIELDS` rather than a list written here, so a field added
    to the rule schema without a way to read it fails this test instead of
    quietly resolving to the empty string that the fallthrough returns. Each
    value is distinct, so returning the wrong one cannot look right.
    """
    from logarc.detect.engine import RequestView
    from logarc.detect.rules import MATCH_FIELDS

    view = RequestView(
        NormalizedEvent(
            timestamp=START,
            client_ip="203.0.113.5",
            evidence=EvidenceRef("access.log", 1),
            method="POST",
            path="/downloads/report.pdf",
            query="who=%2561dmin",
            protocol="HTTP/1.1",
            status=403,
            bytes_sent=4523,
            referer="http://referer.example/from",
            user_agent="ScannerAgent/9.9",
            host="shop.example.com",
        )
    )

    expected = {
        "method": "POST",
        "path": "/downloads/report.pdf",
        "query": "who=%2561dmin",
        "target": "/downloads/report.pdf?who=%2561dmin",
        "referer": "http://referer.example/from",
        "user_agent": "ScannerAgent/9.9",
        "protocol": "HTTP/1.1",
        "host": "shop.example.com",
        "extension": "pdf",
        "path_decoded": "/downloads/report.pdf",
        "query_decoded": "who=admin",
        "target_decoded": "/downloads/report.pdf?who=admin",
        "referer_decoded": "http://referer.example/from",
        "user_agent_decoded": "scanneragent/9.9",
        "status": "403",
        "bytes_sent": "4523",
        # Double-encoded above: `%2561dmin` is `%61dmin` is `admin`.
        "decode_depth": "2",
        "had_null": "0",
    }
    assert set(expected) == set(MATCH_FIELDS), "a field can be named but not read"
    assert {name: view.value(name) for name in sorted(MATCH_FIELDS)} == expected


def test_every_window_metric_measures_its_own_thing() -> None:
    """The same hazard as the field mapping, one layer up: a window rule names a
    metric and gets a number. If `client_error_ratio` were computing the 5xx
    share, a rule tuned to fire at 0.8 would fire on traffic that never had a
    4xx in it — and the finding would look ordinary.

    The window below is chosen so no two metrics share an answer: four requests,
    three distinct canonical paths, statuses 404, 403, 500 and 200 across two
    seconds. Any arm returning a neighbour's value is a different number.
    """
    from logarc.detect.engine import _metric
    from logarc.detect.rules import WINDOW_METRICS

    window = [
        event(0, path="/a", status=404),
        event(1, path="/a//", status=403),
        event(1, path="/b", status=500),
        event(2, path="/c", status=200),
    ]

    expected = {
        "request_count": 4.0,
        # `/a` and `/a//` canonicalise to one path, so three rather than four.
        "distinct_paths": 3.0,
        "distinct_statuses": 4.0,
        "not_found_ratio": 0.25,
        "client_error_ratio": 0.5,
        "server_error_ratio": 0.25,
        "success_ratio": 0.25,
        "requests_per_second": 2.0,
    }
    assert set(expected) == set(WINDOW_METRICS), "a metric can be named but not measured"
    assert {name: _metric(name, window, 2) for name in sorted(WINDOW_METRICS)} == expected


@pytest.mark.parametrize(
    ("op", "target", "fires"),
    [
        (">=", 4.0, True), (">=", 5.0, False),
        (">", 3.0, True), (">", 4.0, False),
        ("<=", 4.0, True), ("<=", 3.0, False),
        ("<", 5.0, True), ("<", 4.0, False),
        ("==", 4.0, True), ("==", 3.0, False),
        ("!=", 3.0, True), ("!=", 4.0, False),
    ],
)  # fmt: skip
def test_every_threshold_operator_compares_the_way_it_reads(
    op: str, target: float, fires: bool
) -> None:
    """Four of the six were never exercised. An operator that compares backwards
    turns a rule meant to catch a burst into one that fires on quiet traffic,
    and the rule pack would still load — these are validated by name at load
    time, never by behaviour.

    Both sides of each are asserted, because an arm hardwired to `True` passes
    every test that only checks the firing case.
    """
    from logarc.detect.engine import _metric_holds
    from logarc.detect.rules import WindowCondition

    window = [event(index) for index in range(4)]
    condition = WindowCondition(metric="request_count", op=op, value=target)

    assert _metric_holds(condition, window, 2) is fires


def test_a_matching_request_is_labelled(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events([event(query="id=1 UNION SELECT password")])

    assert labelled.label.rule_id == "sqli_union"
    assert labelled.label.category is ActivityCategory.INJECTION
    assert labelled.label.owasp == "A03:2021"


def test_an_encoded_payload_still_matches(engine: RuleEngine) -> None:
    """The rule is written once, against the decoded form; normalisation does
    the rest."""
    (labelled,) = engine.label_events([event(query="id=1%20%55NION%20SELECT%20x")])

    assert labelled.label.rule_id == "sqli_union"


def test_a_double_encoded_payload_still_matches(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events([event(query="id=1%2520union%2520select%2520x")])

    assert labelled.label.rule_id == "sqli_union"


def test_an_unmatched_request_falls_back_to_benign_classification(
    engine: RuleEngine,
) -> None:
    (labelled,) = engine.label_events([event(path="/index.html")])

    assert labelled.label.category is ActivityCategory.BROWSING
    assert labelled.label.severity is Severity.INFO


def test_static_assets_are_recognised(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events([event(path="/assets/app.css")])

    assert labelled.label.category is ActivityCategory.STATIC_ASSET


def test_all_conditions_must_hold_for_an_all_block(engine: RuleEngine) -> None:
    matched = engine.label_events([event(path="/admin", status=404)])[0]
    unmatched = engine.label_events([event(path="/admin", status=200)])[0]

    assert matched.label.rule_id == "admin_probe"
    assert unmatched.label.rule_id != "admin_probe"


def test_the_most_severe_match_becomes_the_primary_label(engine: RuleEngine) -> None:
    """A request can trip several rules; the report leads with the worst."""
    (labelled,) = engine.label_events([event(path="/admin", query="a=union select b", status=500)])

    assert labelled.label.rule_id == "server_error"
    assert labelled.label.severity is Severity.CRITICAL


def test_every_match_is_kept_as_evidence(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events([event(path="/admin", query="union select", status=500)])

    assert {label.rule_id for label in labelled.all_labels} >= {"server_error", "sqli_union"}


def test_a_window_rule_fires_across_requests_no_single_one_reveals(
    engine: RuleEngine,
) -> None:
    """Twenty 404s in a minute is enumeration; any one of them is a typo."""
    events = [event(seconds=n, path=f"/secret-{n}", status=404) for n in range(8)]

    labelled = engine.label_events(events)

    assert any(item.label.rule_id == "dir_enumeration" for item in labelled)


def test_a_window_rule_does_not_fire_below_its_thresholds(engine: RuleEngine) -> None:
    events = [event(seconds=n, path=f"/page-{n}", status=200) for n in range(8)]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id != "dir_enumeration" for item in labelled)


def test_one_resource_written_several_ways_is_not_enumeration(engine: RuleEngine) -> None:
    """Eight requests, but only two resources between them.

    Counted literally these are eight distinct paths and the rule fires, calling
    a client that reloaded two pages an enumeration. `distinct_paths` is a
    threshold, so how a path happens to be written decides whether a behaviour
    is detected — which is not a property this metric may have.
    """
    written = ["/a", "/a/", "//a", "/./a", "/b", "/b/", "//b", "/x/../b"]
    events = [event(seconds=n, path=path, status=404) for n, path in enumerate(written)]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id != "dir_enumeration" for item in labelled)


def test_genuinely_distinct_paths_still_reach_the_threshold(engine: RuleEngine) -> None:
    """The counterpart: canonicalising must not suppress real enumeration."""
    events = [event(seconds=n, path=f"/a/./secret-{n}", status=404) for n in range(8)]

    labelled = engine.label_events(events)

    assert any(item.label.rule_id == "dir_enumeration" for item in labelled)


def test_a_window_rule_needs_its_requests_inside_the_span(engine: RuleEngine) -> None:
    """The same requests spread over an hour are not a burst."""
    events = [event(seconds=n * 600, path=f"/secret-{n}", status=404) for n in range(8)]

    labelled = engine.label_events(events)

    assert all(item.label.rule_id != "dir_enumeration" for item in labelled)


def test_a_window_label_does_not_displace_a_more_severe_signature(
    engine: RuleEngine,
) -> None:
    events = [event(seconds=n, path=f"/x-{n}", status=404) for n in range(8)]
    events.append(event(seconds=8, path="/x", query="union select", status=404))

    labelled = engine.label_events(events)

    assert labelled[-1].label.rule_id == "sqli_union"


def test_labelling_no_events_produces_nothing(engine: RuleEngine) -> None:
    assert engine.label_events([]) == []


def test_an_engine_with_no_rules_still_classifies_benign_traffic() -> None:
    engine = RuleEngine([])

    (labelled,) = engine.label_events([event(path="/index.html")])

    assert labelled.label.category is ActivityCategory.BROWSING


def test_the_ruleset_reports_a_stable_fingerprint(tmp_path: Path) -> None:
    """A report has to be able to state which ruleset produced it."""
    path = tmp_path / "pack.yaml"
    path.write_text(PACK, encoding="utf-8")

    first = RuleEngine(load_rules([path])).fingerprint
    second = RuleEngine(load_rules([path])).fingerprint

    assert first == second
    assert len(first) == 64


def test_changing_a_rule_changes_the_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "pack.yaml"
    path.write_text(PACK, encoding="utf-8")
    before = RuleEngine(load_rules([path])).fingerprint

    path.write_text(PACK.replace("severity: high", "severity: low"), encoding="utf-8")
    after = RuleEngine(load_rules([path])).fingerprint

    assert before != after


def crs_detection(
    *,
    line_no: int = 1,
    rule_id: int = 942100,
    family: str | None = "attack-sqli",
    severity: str = "critical",
    msg: str = "SQL Injection Attack Detected via libinjection",
    matched_var: str = "ARGS:q",
) -> CrsDetection:
    return CrsDetection(
        source_file_id="access.log",
        line_no=line_no,
        rule_id=rule_id,
        severity=severity,
        msg=msg,
        matched_var=matched_var,
        transformed_value="1' UNION SELECT",
        attack_family=family,
    )


def crs_index(*detections: CrsDetection) -> dict[tuple[str, int], list[CrsDetection]]:
    index: dict[tuple[str, int], list[CrsDetection]] = {}
    for item in detections:
        index.setdefault((item.source_file_id, item.line_no), []).append(item)
    return index


def test_crs_does_not_displace_a_rule_that_examined_the_request(engine: RuleEngine) -> None:
    """The invariant the whole design rests on.

    CRS asserts no category of its own — a family tag is read through a mapping
    this project wrote. Where a rule looked at the request and made a claim, that
    claim stands, and CRS is kept as corroboration.
    """
    events = [event(query="id=1 UNION SELECT password")]

    (labelled,) = engine.label_events(events, crs=crs_index(crs_detection()))

    assert labelled.label.rule_id == "sqli_union"
    assert labelled.crs[0].rule_id == 942100


def test_crs_names_a_request_the_rules_had_no_answer_for(engine: RuleEngine) -> None:
    """The point of the feature.

    These rules catch 12.3% of the payload syntax CRS enumerates, so "no rule
    matched" says more about this project's coverage than about the request.
    """
    events = [event(path="/get", query="foo=for %variable in (set) do command")]
    detection = crs_detection(
        rule_id=932140,
        family="attack-rce",
        msg="Remote Command Execution: Windows FOR/IF Command Found",
    )

    (labelled,) = engine.label_events(events, crs=crs_index(detection))

    assert labelled.label.rule_id == "crs:932140"
    assert labelled.label.category is ActivityCategory.INJECTION
    assert labelled.label.severity is Severity.CRITICAL


def test_a_withheld_family_never_names_a_request(engine: RuleEngine) -> None:
    """`attack-protocol` is the largest group in CRS's request rules and fires on
    request lines that are unusual rather than hostile. Letting it override
    ordinary traffic would turn a benign corpus hostile in bulk."""
    detection = crs_detection(
        rule_id=920100, family="attack-protocol", msg="Invalid HTTP Request Line"
    )

    (labelled,) = engine.label_events([event(path="/index.html")], crs=crs_index(detection))

    assert labelled.label.category is ActivityCategory.BROWSING
    assert labelled.crs[0].rule_id == 920100


def test_an_observation_does_not_suppress_a_rescue(engine: RuleEngine) -> None:
    """Regression: a `curl` user-agent used to block a critical CRS detection.

    `Scripted Client` is INFO — it notices a scripted client without claiming an
    attack — but under the first cut of the rescue any rule firing at all was
    enough to keep CRS quiet, so the payload on the same request went unreported.
    """
    events = [event(path="/get", query="foo=payload", user_agent="curl/8.0")]
    detection = crs_detection(rule_id=932140, family="attack-rce", msg="Windows FOR/IF")

    (labelled,) = engine.label_events(events, crs=crs_index(detection))

    assert labelled.label.rule_id == "crs:932140"


def test_a_referer_match_does_not_name_the_request(engine: RuleEngine) -> None:
    """A referer says where the client came from, not what it just asked for.

    `GET /contact` returning 200 is navigation. When the referer carries a
    payload the *previous* request was the attack, and naming this one for it
    moves a finding onto the wrong line — the one place a forensic tool cannot
    afford to be approximate. Measured on a labelled corpus this accounted for
    five of the twelve rescues that were wrong, two of which overwrote a
    correct answer.

    The detection is still attached, because "this client had been somewhere
    hostile" is worth an investigator's attention. It just may not name the
    activity.
    """
    detection = crs_detection(
        rule_id=941101,
        family="attack-xss",
        msg="XSS Attack Detected via libinjection",
        matched_var="REQUEST_HEADERS:Referer",
    )

    (labelled,) = engine.label_events([event(path="/contact")], crs=crs_index(detection))

    assert labelled.label.category is ActivityCategory.BROWSING
    assert labelled.crs[0].rule_id == 941101


def test_a_referer_match_is_recognised_whatever_its_casing(engine: RuleEngine) -> None:
    """Coraza reports the header as written, so the same rule yields
    `REQUEST_HEADERS:Referer` on one request and a lowercased form on another."""
    detection = crs_detection(
        rule_id=930121, family="attack-lfi", matched_var="request_headers:referer"
    )

    (labelled,) = engine.label_events([event(path="/metrics")], crs=crs_index(detection))

    assert labelled.label.category is ActivityCategory.BROWSING


def test_a_payload_in_a_parameter_still_names_the_request(engine: RuleEngine) -> None:
    """The other side of it: the filter is per detection, not per request.

    A request carrying a referer-borne detection *and* one in its own query is
    still named by the second. Dropping the whole request because one of its
    detections came from a header would trade five false positives for an
    unknown number of missed attacks.
    """
    detections = crs_index(
        crs_detection(rule_id=941101, family="attack-xss", matched_var="REQUEST_HEADERS:Referer"),
        crs_detection(rule_id=932140, family="attack-rce", matched_var="ARGS:c"),
    )

    (labelled,) = engine.label_events([event(path="/get", query="c=uname")], crs=detections)

    assert labelled.label.rule_id == "crs:932140"
    assert labelled.label.category is ActivityCategory.INJECTION


def test_a_real_claim_still_outranks_crs(engine: RuleEngine) -> None:
    """The other side of that fix: LOW and above is a claim, and it keeps its
    precedence even against a critical CRS detection."""
    events = [event(path="/admin/panel", status=404)]
    detection = crs_detection(rule_id=932140, family="attack-rce", msg="Windows FOR/IF")

    (labelled,) = engine.label_events(events, crs=crs_index(detection))

    assert labelled.label.rule_id == "admin_probe"


def test_labelling_without_crs_is_unchanged(engine: RuleEngine) -> None:
    """A case nobody enriched must behave exactly as it did before CRS existed."""
    events = [event(query="id=1 UNION SELECT password"), event(path="/index.html")]

    with_none = engine.label_events(events)
    with_empty = engine.label_events(events, crs={})

    assert [item.label.rule_id for item in with_none] == ["sqli_union", "benign:browsing"]
    assert [item.label.rule_id for item in with_empty] == ["sqli_union", "benign:browsing"]


def test_the_most_severe_crs_detection_names_the_request(engine: RuleEngine) -> None:
    """Several rules fire on one payload routinely — the sample SQLi request
    matched four. They are resolved the way competing rule matches already are."""
    index = crs_index(
        crs_detection(rule_id=942190, severity="notice", msg="Quiet"),
        crs_detection(rule_id=942100, severity="critical", msg="Loud"),
    )

    (labelled,) = engine.label_events([event(path="/get", query="foo=x")], crs=index)

    assert labelled.label.rule_id == "crs:942100"
    assert len(labelled.crs) == 2


def test_the_most_confident_crs_account_names_the_request(engine: RuleEngine) -> None:
    """Regression: an arbitrary number used to decide what an analyst reads.

    At paranoia level 2, two SQLi rules fire alongside 932140 on
    `for %variable in (set) do command` — all three critical. Ranked on rule id
    alone, 942 beats 932 and the episode came out named "SQL Injection Attack"
    for a Windows command payload. CRS's paranoia levels encode how readily a
    rule fires, so the lowest one present wins.
    """
    index = crs_index(
        crs_detection(rule_id=942410, family="attack-sqli", msg="SQL Injection Attack"),
        crs_detection(
            rule_id=932140,
            family="attack-rce",
            msg="Remote Command Execution: Windows FOR/IF Command Found",
        ),
    )
    index[("access.log", 1)][0] = replace(index[("access.log", 1)][0], paranoia_level=2)
    index[("access.log", 1)][1] = replace(index[("access.log", 1)][1], paranoia_level=1)

    (labelled,) = engine.label_events([event(path="/get", query="foo=x")], crs=index)

    assert labelled.label.rule_id == "crs:932140"
    assert "Windows FOR/IF" in labelled.label.name
