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
from logarc.detect.engine import LabelledEvent, RuleEngine, _metric, _metric_holds
from logarc.detect.rules import WINDOW_METRICS, RulePackError, WindowCondition, load_rules

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
    referer: str | None = None,
    method: str = "GET",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=START + timedelta(seconds=seconds),
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", int(seconds) + 1),
        method=method,
        path=path,
        query=query,
        status=status,
        bytes_sent=100,
        referer=referer,
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
        # `referer.example` is not `shop.example.com`, so this request did
        # arrive from somewhere else.
        "referer_offsite": "1",
        # Nobody has said which hosts this site owns, so the off-site question
        # about a URL in a parameter has no answer and says so. The tests that
        # exercise it properly are at the foot of this file.
        "query_url_offsite": "0",
    }
    assert set(expected) == set(MATCH_FIELDS), "a field can be named but not read"
    assert {name: view.value(name) for name in sorted(MATCH_FIELDS)} == expected


def test_every_window_metric_measures_its_own_thing() -> None:
    """The same hazard as the field mapping, one layer up: a window rule names a
    metric and gets a number. If `client_error_ratio` were computing the 5xx
    share, a rule tuned to fire at 0.8 would fire on traffic that never had a
    4xx in it — and the finding would look ordinary.

    The window below has four requests, three distinct canonical paths, three
    distinct methods, and statuses 404, 403, 500 and 200 across two seconds.
    """
    window = [
        event(0, path="/a.css", status=404, referer="https://example.test/"),
        event(1, path="/a.css//", status=403, method="HEAD"),
        event(1, path="/b", status=500, method="OPTIONS"),
        event(2, path="/c", status=200),
    ]

    expected = {
        "request_count": 4.0,
        # `/a` and `/a//` canonicalise to one path, so three rather than four.
        "distinct_paths": 3.0,
        # GET twice, HEAD and OPTIONS once each.
        "distinct_methods": 3.0,
        "distinct_statuses": 4.0,
        "not_found_ratio": 0.25,
        "client_error_ratio": 0.5,
        "server_error_ratio": 0.25,
        "success_ratio": 0.25,
        "requests_per_second": 2.0,
        "static_asset_ratio": 0.25,
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
    window = [event(index) for index in range(4)]
    condition = WindowCondition(metric="request_count", op=op, value=target)

    assert _metric_holds(condition, window, 2) is fires


def test_custom_static_ratio_keeps_float_threshold_semantics(tmp_path: Path) -> None:
    pack = tmp_path / "ratio.yaml"
    pack.write_text(
        """
version: 1
rules:
  - id: custom_static_ratio
    name: Custom static ratio
    category: enumeration
    severity: medium
    window:
      span_seconds: 60
      min_requests: 3
      conditions:
        - metric: distinct_paths
          op: ">="
          value: 3
        - metric: static_asset_ratio
          op: "<="
          value: 0.3333333333333333
""",
        encoding="utf-8",
    )
    custom = RuleEngine(load_rules([pack]))
    events = [event(0, path="/one.png"), event(1, path="/two"), event(2, path="/three")]

    labelled = custom.label_events(events)

    assert all(item.label.rule_id == "custom_static_ratio" for item in labelled)


def _distinct_methods_engine(tmp_path: Path) -> RuleEngine:
    pack = tmp_path / "methods.yaml"
    pack.write_text(
        """
version: 1
rules:
  - id: many_methods
    name: Many methods
    category: access_control
    severity: medium
    window:
      span_seconds: 10
      min_requests: 3
      conditions:
        - metric: distinct_methods
          op: ">="
          value: 3
""",
        encoding="utf-8",
    )
    return RuleEngine(load_rules([pack]))


def test_distinct_methods_counts_the_methods_inside_the_window(tmp_path: Path) -> None:
    events = [
        event(0, method="POST"),
        event(1, method="HEAD"),
        event(2, method="OPTIONS"),
    ]

    labelled = _distinct_methods_engine(tmp_path).label_events(events)

    assert all(item.label.rule_id == "many_methods" for item in labelled)


def test_distinct_methods_forgets_a_method_that_slid_out(tmp_path: Path) -> None:
    """HEAD and OPTIONS at the start, then GET and POST long after. No window
    holds three methods; one that remembered the first two would see four."""
    events = [
        event(0, method="HEAD"),
        event(1, method="OPTIONS"),
        event(100, method="GET"),
        event(101, method="GET"),
        event(102, method="POST"),
    ]

    labelled = _distinct_methods_engine(tmp_path).label_events(events)

    assert all(item.label.rule_id != "many_methods" for item in labelled)


def test_a_request_with_no_method_is_not_a_method(tmp_path: Path) -> None:
    """A line too malformed to name a method has not used one."""
    events = [event(0, method="GET"), event(1, method="POST"), event(2), event(3)]
    events[2] = replace(events[2], method=None)
    events[3] = replace(events[3], method=None)

    labelled = _distinct_methods_engine(tmp_path).label_events(events)

    assert all(item.label.rule_id != "many_methods" for item in labelled)


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


DUMMY = "Apache/2.4.68 (Debian) PHP/8.3.33 (internal dummy connection)"


def _internal(client_ip: str, method: str, path: str, user_agent: str = DUMMY) -> NormalizedEvent:
    from dataclasses import replace

    return replace(event(path=path, user_agent=user_agent), client_ip=client_ip, method=method)


@pytest.mark.parametrize(
    ("client_ip", "method", "path"),
    [("127.0.0.1", "OPTIONS", "*"), ("127.0.0.1", "GET", "/"), ("::1", "OPTIONS", "*")],
)
def test_apaches_internal_connection_is_not_a_client_doing_anything(
    engine: RuleEngine, client_ip: str, method: str, path: str
) -> None:
    """Apache wakes its own worker processes by connecting to itself, and
    writes the connection to the access log like any other request. It is the
    server, not a visitor, so none of the activity categories applies.

    It was `API Call`, named `Non-idempotent Request` — 131 lines on
    `2026-10-04-medium`, which the truth calls `unknown` — and `OPTIONS` is
    idempotent, so the name was wrong on its face. CRS exempts exactly this
    traffic in 905110, and these are its three conditions: a loopback client,
    the agent's own marker, and one of the two request lines Apache sends."""
    (labelled,) = engine.label_events([_internal(client_ip, method, path)])

    assert labelled.label.category is ActivityCategory.UNKNOWN
    assert labelled.label.name == "Apache Internal Connection"


@pytest.mark.parametrize(
    ("client_ip", "method", "path", "user_agent"),
    [
        # The marker is a User-Agent, which anybody can send. From outside it
        # is a request like any other.
        ("203.0.113.5", "OPTIONS", "*", DUMMY),
        # Loopback, but not Apache saying so.
        ("127.0.0.1", "OPTIONS", "*", "curl/8.5.0"),
        # Loopback and the marker, asking for something Apache never asks for.
        ("127.0.0.1", "GET", "/admin", DUMMY),
    ],
)
def test_it_takes_all_three_conditions(
    engine: RuleEngine, client_ip: str, method: str, path: str, user_agent: str
) -> None:
    (labelled,) = engine.label_events([_internal(client_ip, method, path, user_agent)])

    assert labelled.label.name != "Apache Internal Connection"


def test_a_request_whose_line_could_not_be_read_is_not_called_a_page_view(
    engine: RuleEngine,
) -> None:
    """A malformed request line has no path, and `browsing` would be a claim.

    `parsers.base.split_request_line` returns all-`None` for a line it cannot
    split, and those lines are kept rather than discarded because attack traffic
    is where they come from: a TLS handshake sent to a plaintext port, a verb
    deliberately corrupted, a line truncated mid-write.

    Falling through every benign branch used to land them on `Page View`, which
    says the client browsed a page. Nothing here knows that. `unknown` is the
    honest answer, and it is what the truth format uses for the same thing.
    """
    unreadable = replace(event(), method=None, path=None, query=None, status=None)

    (labelled,) = engine.label_events([unreadable])

    assert labelled.label.category is ActivityCategory.UNKNOWN
    assert labelled.label.severity is Severity.INFO


def test_a_path_that_is_present_but_empty_is_also_unknown(engine: RuleEngine) -> None:
    """`%00` and friends can leave a request line that splits into nothing.

    An empty path is no more classifiable than a missing one, and the two arrive
    by different routes — one from a line that would not split, one from a line
    that split into emptiness.
    """
    (labelled,) = engine.label_events([replace(event(), path="")])

    assert labelled.label.category is ActivityCategory.UNKNOWN


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


def test_overlapping_windows_add_each_rule_only_once_per_request(engine: RuleEngine) -> None:
    """A long run satisfies many overlapping windows, but those windows are
    repeated evidence for one rule rather than distinct matches on a request.
    """
    events = [event(seconds=n, path=f"/secret-{n}", status=404) for n in range(8)]

    labelled = engine.label_events(events)

    for item in labelled:
        assert [label.rule_id for label in item.all_labels].count("dir_enumeration") == 1


# -- sequence rules: this, then that, unless something in between ------------

SEQUENCE_PACK = """
version: 1
rules:
  - id: reached_after_bounce
    name: Admin Page Reached Without Signing In
    category: access_control
    severity: high
    sequence:
      within_seconds: 300
      first:
        all:
          - {field: path_decoded, contains: '/admin'}
          - {field: status, any_of: ['302', '303']}
      then:
        all:
          - {field: path_decoded, contains: '/admin'}
          - {field: status, min: 200}
          - {field: status, max: 299}
      unless_between:
        all:
          - {field: path_decoded, contains: '/login'}
          - {field: status, any_of: ['302', '303']}
"""


@pytest.fixture
def sequence_engine(tmp_path: Path) -> RuleEngine:
    path = tmp_path / "sequence.yaml"
    path.write_text(SEQUENCE_PACK, encoding="utf-8")
    return RuleEngine(load_rules([path]))


def _sequenced(labelled: list[LabelledEvent]) -> list[int]:
    """Line numbers carrying the sequence rule's label."""
    return [
        item.event.evidence.line_no
        for item in labelled
        if "reached_after_bounce" in [label.rule_id for label in item.all_labels]
    ]


def test_a_sequence_rule_names_both_ends_of_what_it_saw(sequence_engine: RuleEngine) -> None:
    """Bounced from the admin area, then let into it, with nothing between:
    neither request says that alone, and both are part of it."""
    events = [
        event(0, path="/admin/", status=302),
        event(30, path="/c/garden"),
        event(60, path="/admin/ping", status=200),
    ]

    labelled = sequence_engine.label_events(events)

    assert _sequenced(labelled) == [1, 61]
    assert labelled[2].label.category is ActivityCategory.ACCESS_CONTROL


def test_what_comes_between_silences_it(sequence_engine: RuleEngine) -> None:
    """An administrator is bounced too, and signs in before being let in."""
    events = [
        event(0, path="/admin/", status=302),
        event(20, path="/login", status=302, method="POST"),
        event(30, path="/admin/", status=200),
    ]

    assert _sequenced(sequence_engine.label_events(events)) == []


def test_the_order_is_the_point(sequence_engine: RuleEngine) -> None:
    """Pages first and a bounce after is a session that ran out, not a way in."""
    events = [event(0, path="/admin/", status=200), event(30, path="/admin/users", status=302)]

    assert _sequenced(sequence_engine.label_events(events)) == []


def test_a_sequence_is_bounded_by_its_window(sequence_engine: RuleEngine) -> None:
    events = [event(0, path="/admin/", status=302), event(301, path="/admin/ping", status=200)]

    assert _sequenced(sequence_engine.label_events(events)) == []


def test_only_what_follows_the_silencing_request_can_start_a_sequence(
    sequence_engine: RuleEngine,
) -> None:
    """A sign-in clears the bounces before it; a bounce after it starts afresh."""
    events = [
        event(0, path="/admin/", status=302),
        event(10, path="/login", status=302, method="POST"),
        event(20, path="/admin/users", status=302),
        event(30, path="/admin/ping", status=200),
    ]

    assert _sequenced(sequence_engine.label_events(events)) == [21, 31]


def test_one_request_cannot_be_both_ends_of_a_sequence(tmp_path: Path) -> None:
    """A rule whose `first` and `then` overlap is legal; a single request that
    matches both is still one request, not a sequence."""
    path = tmp_path / "overlap.yaml"
    path.write_text(
        SEQUENCE_PACK.replace(
            "any_of: ['302', '303']}\n      then:", "any_of: ['200', '302']}\n      then:"
        ),
        encoding="utf-8",
    )
    overlapping = RuleEngine(load_rules([path]))

    assert _sequenced(overlapping.label_events([event(0, path="/admin/", status=200)])) == []
    assert _sequenced(
        overlapping.label_events([event(0, path="/admin/", status=200), event(9, path="/admin/x")])
    ) == [1, 10]


def test_a_rule_with_two_kinds_of_body_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "both.yaml"
    path.write_text(
        SEQUENCE_PACK.replace(
            "    sequence:",
            "    match:\n      any:\n        - {field: path, contains: x}\n    sequence:",
        ),
        encoding="utf-8",
    )

    with pytest.raises(RulePackError, match="exactly one of: match, window, sequence"):
        load_rules([path])


def test_failed_dense_window_scan_does_bounded_query_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing assets must not make every window rescan all its prefixes."""
    from logarc.detect.engine import _range_min_tree, _WindowMeasurements
    from logarc.detect.rulepacks import default_rules

    work = 0
    original = _WindowMeasurements.add
    original_tree = _range_min_tree

    def counted_add(self: _WindowMeasurements, item: NormalizedEvent) -> None:
        nonlocal work
        work += 1
        original(self, item)

    class CountingTree:
        def __init__(self, values: list[float]) -> None:
            self.values = values

        def __len__(self) -> int:
            return len(self.values)

        def __getitem__(self, index: int) -> float:
            nonlocal work
            work += 1
            return self.values[index]

    def counted_tree(values: list[int]) -> tuple[CountingTree, int]:
        tree, size = original_tree(values)
        return CountingTree(tree), size

    monkeypatch.setattr(_WindowMeasurements, "add", counted_add)
    monkeypatch.setattr("logarc.detect.engine._range_min_tree", counted_tree)
    events = [
        event(n / 10, path=f"/missing-{n}.png", status=404, user_agent="Mozilla/5.0")
        for n in range(500)
    ]

    labelled = RuleEngine(default_rules()).label_events(events)

    assert not any(item.label.category.is_hostile for item in labelled)
    assert work < len(events) * 30


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
    transformed_value: str = "1' UNION SELECT",
) -> CrsDetection:
    return CrsDetection(
        source_file_id="access.log",
        line_no=line_no,
        rule_id=rule_id,
        severity=severity,
        msg=msg,
        matched_var=matched_var,
        transformed_value=transformed_value,
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


def test_a_chained_rule_s_referer_match_is_still_hearsay(engine: RuleEngine) -> None:
    """A chained CRS rule reports its second match as `MATCHED_VARS:` + the
    variable, so the same Referer arrives as `MATCHED_VARS:REQUEST_HEADERS:Referer`.

    Found on `2026-10-04-small`: `GET /c/safety` from a page whose URL held a
    UNION SELECT was a false alarm, named by 942200's chained report while its
    plain `REQUEST_HEADERS:Referer` reports were correctly set aside.
    """
    for matched_var in (
        "MATCHED_VARS:REQUEST_HEADERS:Referer",
        # A chain inside a chain doubles it; the same tier carried
        # `MATCHED_VARS:MATCHED_VARS:ARGS`.
        "MATCHED_VARS:MATCHED_VARS:REQUEST_HEADERS:Referer",
    ):
        detection = crs_detection(
            rule_id=942200,
            family="attack-sqli",
            msg="Detects MySQL comment-/space-obfuscated injections and backtick termination",
            matched_var=matched_var,
        )

        (labelled,) = engine.label_events([event(path="/c/safety")], crs=crs_index(detection))

        assert labelled.label.category is ActivityCategory.BROWSING, matched_var
        assert labelled.crs[0].rule_id == 942200


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


def test_an_unfilled_template_slot_does_not_name_the_request(engine: RuleEngine) -> None:
    """A shop's front end sends `/api/stock?id=${id}&watch=1` with the slot
    unfilled, from ordinary browsers: 44 / 149 / 670 requests on the dataset's
    `2026-10-06` tiers, all `api_call` in the truth.

    `php_superglobal` stopped calling a bare `${name}` PHP on 2026-10-05. CRS
    did not: 933135 (PHP variable access) and 932130 (Unix shell expression)
    both match the parameter, at paranoia level 1 and critical, so with CRS on
    by default every one of them was named an injection again. Both are kept as
    evidence; neither may name the activity.
    """
    detections = crs_index(
        crs_detection(
            rule_id=933135,
            family="attack-injection-php",
            msg="PHP Injection Attack: Variable Access Found",
            matched_var="ARGS:id",
            transformed_value="${id}",
        ),
        crs_detection(
            rule_id=932130,
            family="attack-rce",
            msg="Remote Command Execution: Unix Shell Expression Found",
            matched_var="ARGS:id",
            transformed_value="${id}",
        ),
    )
    events = [event(path="/api/stock", query="id=${id}&watch=1", user_agent="Mozilla/5.0")]

    (labelled,) = engine.label_events(events, crs=detections)

    assert not labelled.label.category.is_hostile
    assert [item.rule_id for item in labelled.crs] == [933135, 932130]


def test_php_s_own_variable_syntax_still_names_the_request(engine: RuleEngine) -> None:
    """The other side: only a plain name in the braces is a template's slot.

    `${'ff'}` is a CRS 933135 attack case, and nothing a template writes has a
    quote, a `$` or a call inside — the same line `php_superglobal` draws.
    """
    for value in ("${'ff'}", "${$a}", "${id}(30)", "$ {id}", "x;${id}"):
        detection = crs_detection(
            rule_id=933135,
            family="attack-injection-php",
            msg="PHP Injection Attack: Variable Access Found",
            matched_var="ARGS:foo",
            transformed_value=value,
        )

        (labelled,) = engine.label_events(
            [event(path="/get", query="foo=x")], crs=crs_index(detection)
        )

        assert labelled.label.rule_id == "crs:933135", value


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


#: A benign rule and a hostile one that tie on severity, so only the precedence
#: between them decides. The names are synthetic so the fixture is not read as
#: a description of the bundled packs, whose categories are what decide there.
BENIGN_AND_HOSTILE = """
version: 1
rules:
  - id: hostile_guess
    name: Hostile Guess
    category: reconnaissance
    severity: info
    confidence: 0.4
    match:
      any:
        - field: user_agent
          contains: curl
  - id: benign_certainty
    name: Benign Certainty
    category: browsing
    severity: info
    confidence: 0.85
    match:
      any:
        - field: path
          equals: /page
"""


def test_an_action_label_does_not_take_the_lead_from_a_hostile_one(tmp_path: Path) -> None:
    """A rule describing ordinary use must never outrank one describing an
    attack, however sure of itself it is.

    Severity decides first and these two tie, so without this the more
    confident label wins, and the confident one is the benign description. A
    report that leads with it has buried the only part worth reading.
    """
    path = tmp_path / "pack.yaml"
    path.write_text(BENIGN_AND_HOSTILE, encoding="utf-8")
    engine = RuleEngine(load_rules([path]))

    (labelled,) = engine.label_events([event(path="/page", user_agent="curl/8.4.0")])

    assert {item.rule_id for item in labelled.all_labels} == {"hostile_guess", "benign_certainty"}
    assert labelled.label.rule_id == "hostile_guess", (
        "the hostile observation leads, even though the benign one is more confident"
    )


#: A request carrying a session identifier, which is the shape session fixation
#: takes. The URL is identical in both the attack and the harmless case; only
#: the Referer's host separates them, which is why no single-field rule can.
FIXATION = """
version: 1
rules:
  - id: session_fixation
    name: Session Fixation
    category: credential_attack
    severity: high
    confidence: 0.8
    match:
      all:
        - field: query_decoded
          regex: 'sessionid='
        - field: referer_offsite
          min: 1
"""


def _fixation_engine(tmp_path: Path) -> RuleEngine:
    path = tmp_path / "fixation.yaml"
    path.write_text(FIXATION, encoding="utf-8")
    return RuleEngine(load_rules([path]))


def _request(host: str | None, referer: str | None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=START,
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", 1),
        method="GET",
        path="/login",
        query="sessionid=abc123",
        status=200,
        bytes_sent=100,
        referer=referer,
        user_agent="Mozilla/5.0",
        host=host,
    )


def test_a_referer_from_another_host_is_offsite(tmp_path: Path) -> None:
    """The one comparison two whole CRS families turn on, and the only one the
    rule language could not make: `/login?sessionid=abc123` is harmless from
    your own page and session fixation from an attacker's."""
    engine = _fixation_engine(tmp_path)

    (labelled,) = engine.label_events([_request("myapp.com", "https://attacker.example.com/")])

    assert labelled.label.rule_id == "session_fixation"


def test_a_referer_from_the_same_host_is_not(tmp_path: Path) -> None:
    engine = _fixation_engine(tmp_path)

    (labelled,) = engine.label_events([_request("myapp.com", "https://myapp.com/previous")])

    assert not labelled.all_labels


def test_scheme_and_port_are_not_part_of_the_comparison(tmp_path: Path) -> None:
    """`http://example.com/x` is the same site as an https request to
    `example.com:443`. The corpus has exactly this pair as a harmless case."""
    engine = _fixation_engine(tmp_path)

    (labelled,) = engine.label_events([_request("example.com:443", "http://example.com/other")])

    assert not labelled.all_labels


def test_a_sibling_subdomain_is_offsite(tmp_path: Path) -> None:
    """`app.example.com` and `attacker.example.com` share a registrable domain
    and are not the same site. The corpus marks this one an attack explicitly —
    its description is "subdomain should not match" — so the comparison is of
    hosts, not of domains."""
    engine = _fixation_engine(tmp_path)

    (labelled,) = engine.label_events(
        [_request("app.example.com", "https://attacker.example.com/")]
    )

    assert labelled.label.rule_id == "session_fixation"


def test_a_log_that_records_no_host_stays_silent(tmp_path: Path) -> None:
    """The reach of this whole feature, pinned.

    `apache-combined` — the most common web log format there is, and the one
    this project's own headline corpus uses — does not record the Host header.
    Without it the comparison has no answer, and a rule with no answer must say
    nothing rather than guess. Guessing "offsite" would fire on every request in
    every combined log on earth; guessing "same site" would at least be quiet,
    but it would also be a claim nothing supports.
    """
    engine = _fixation_engine(tmp_path)

    (labelled,) = engine.label_events([_request(None, "https://attacker.example.com/")])

    assert not labelled.all_labels


def test_no_referer_at_all_is_not_offsite(tmp_path: Path) -> None:
    """Absence is not evidence of another host. CRS scores "no referrer" as its
    own, separate and weaker signal, and conflating the two would make every
    bookmarked visit a fixation attempt."""
    engine = _fixation_engine(tmp_path)

    (labelled,) = engine.label_events([_request("myapp.com", None)])

    assert not labelled.all_labels


#: A rule that asks only whether a URL in a query parameter points somewhere
#: this site does not own. Remote file inclusion is this shape and nothing else:
#: the request is `GET /page?url=…` either way, and only the destination differs.
OFFSITE = """
version: 1
rules:
  - id: rfi_offsite_url
    name: Remote File Inclusion (off-site URL in a parameter)
    category: ssrf
    severity: high
    confidence: 0.75
    match:
      all:
        - field: query_url_offsite
          min: 1
"""


def _offsite_engine(tmp_path: Path, *, site_hosts: tuple[str, ...] = ()) -> RuleEngine:
    path = tmp_path / "offsite.yaml"
    path.write_text(OFFSITE, encoding="utf-8")
    return RuleEngine(load_rules([path]), site_hosts=site_hosts)


def _fetching(query: str, host: str | None = "shop.example.com") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=START,
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", 1),
        method="GET",
        path="/page",
        query=query,
        status=200,
        bytes_sent=100,
        user_agent="Mozilla/5.0",
        host=host,
    )


def test_a_url_to_a_host_nobody_named_is_off_site(tmp_path: Path) -> None:
    """The detection this whole setting exists for."""
    engine = _offsite_engine(tmp_path, site_hosts=("shop.example.com",))

    (labelled,) = engine.label_events([_fetching("url=https://evil.test/shell.txt")])

    assert [item.rule_id for item in labelled.all_labels] == ["rfi_offsite_url"]


def test_a_url_to_a_host_the_reader_named_is_ordinary(tmp_path: Path) -> None:
    """The other half, and the reason the question is asked at all. A share
    link, an OAuth callback and a redirect all look exactly like the attack
    above; what separates them is that the destination is the reader's own."""
    engine = _offsite_engine(tmp_path, site_hosts=("shop.example.com", "www.shop.example.com"))

    events = [
        _fetching("url=https://shop.example.com/help"),
        _fetching("next=https://www.shop.example.com/cart"),
    ]

    assert all(not item.all_labels for item in engine.label_events(events))


def test_naming_nothing_means_the_rule_never_fires(tmp_path: Path) -> None:
    """**The whole design, in one test.** Unanswered, this field says nothing —
    it does not fall back to the request's own Host header and decide for
    itself.

    That was the choice on the table and it was made deliberately. A log that
    records `Host: localhost`, which is what sits behind most reverse proxies,
    would otherwise make every ordinary outbound link off-site. Measured against
    the OWASP corpus, guessing from the Host header cost two of the 134 requests
    it certifies as harmless; being told cost none, for the same eleven catches.
    """
    engine = _offsite_engine(tmp_path)

    (labelled,) = engine.label_events([_fetching("url=https://evil.test/shell.txt")])

    assert not labelled.all_labels


def test_a_host_that_merely_ends_with_the_site_is_still_off_site(tmp_path: Path) -> None:
    """`example.com.evil.com` is a domain bought to be misread as yours. The
    comparison is whole hosts, never a suffix, which is also why
    `www.shop.example.com` has to be named separately above."""
    engine = _offsite_engine(tmp_path, site_hosts=("example.com",))

    (labelled,) = engine.label_events(
        [_fetching("url=https://example.com.evil.com/", host="example.com")]
    )

    assert [item.rule_id for item in labelled.all_labels] == ["rfi_offsite_url"]


@pytest.mark.parametrize(
    "query",
    [
        # No URL at all — the commonest query string there is.
        "id=42&sort=price",
        # A bare host with no scheme is a name being passed around, not a fetch.
        "site=evil.test",
        # The reader's own site, reached by a different scheme and port.
        "url=http://shop.example.com:8080/help",
    ],
)
def test_queries_that_ask_for_nothing_off_site(tmp_path: Path, query: str) -> None:
    engine = _offsite_engine(tmp_path, site_hosts=("shop.example.com",))

    (labelled,) = engine.label_events([_fetching(query)])

    assert not labelled.all_labels, f"{query!r} was called hostile"


def test_the_named_hosts_are_compared_the_way_hosts_are(tmp_path: Path) -> None:
    """Whatever the reader types is put through the same reduction as the URL,
    so `HTTPS://Shop.Example.COM:443/` and `shop.example.com` are one site.
    Typing a URL into a box that asks for a domain is the ordinary mistake."""
    engine = _offsite_engine(tmp_path, site_hosts=("HTTPS://Shop.Example.COM:443/",))

    (labelled,) = engine.label_events([_fetching("url=https://shop.example.com/help")])

    assert not labelled.all_labels


# -- 931130 speaks only when CRS was told the site's real host -----------------


def _off_domain(line_no: int = 1) -> CrsDetection:
    return crs_detection(
        line_no=line_no,
        rule_id=931130,
        family="attack-rfi",
        msg="Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link",
        matched_var="ARGS:url",
    )


def _fetching_elsewhere() -> list[NormalizedEvent]:
    return [event(path="/admin/import-image", query="url=http://evil.test/shell.txt")]


def test_an_off_domain_verdict_names_the_request_when_crs_knew_the_host() -> None:
    """**What the host fix buys.** The case named `shop.test`, enrichment told CRS
    so, and a URL to somewhere else is now a finding CRS earned rather than one
    it would have reached about any URL at all."""
    engine = RuleEngine([], site_hosts=("shop.test",), crs_host="shop.test")

    (labelled,) = engine.label_events(_fetching_elsewhere(), crs=crs_index(_off_domain()))

    assert labelled.label.rule_id == "crs:931130"
    assert labelled.label.category is ActivityCategory.SSRF


def test_an_off_domain_verdict_reached_against_localhost_names_nothing() -> None:
    """Enriched before the domain question was answered, so CRS compared every
    URL against a placeholder. The detection stays attached as evidence; it does
    not get to accuse."""
    engine = RuleEngine([], site_hosts=("shop.test",), crs_host="localhost")

    (labelled,) = engine.label_events(_fetching_elsewhere(), crs=crs_index(_off_domain()))

    assert labelled.label.rule_id != "crs:931130"
    assert [item.rule_id for item in labelled.crs] == [931130], "still carried as evidence"


def test_an_off_domain_verdict_with_no_answer_at_all_names_nothing() -> None:
    """The state of every case before 2026-09-23, and of every case nobody asks.
    Nothing may change for it."""
    engine = RuleEngine([])

    (labelled,) = engine.label_events(_fetching_elsewhere(), crs=crs_index(_off_domain()))

    assert labelled.label.rule_id != "crs:931130"


def test_a_host_the_reader_has_since_withdrawn_is_not_trusted() -> None:
    """Enriched against `shop.test`, then the answer was changed. The stored
    verdicts were reached against a host that is no longer the site's, so they
    are treated like any other unconfigured run until enrichment is repeated —
    the check is membership, not merely "some host was given"."""
    engine = RuleEngine([], site_hosts=("other.test",), crs_host="shop.test")

    (labelled,) = engine.label_events(_fetching_elsewhere(), crs=crs_index(_off_domain()))

    assert labelled.label.rule_id != "crs:931130"


def test_a_site_with_two_unrelated_domains_keeps_931130_quiet() -> None:
    """**CRS can be told one host, and this site has two.**

    931130 reads a URL as its own site's when it ends with `.<the host>`, so
    told `shop.test` it covers `www.shop.test` and `cdn.shop.test` — and not
    `shopcdn.net`, which the reader also named. A link to the site's own second
    domain would be reported as remote file inclusion, and the reader has
    already said it is not. Withheld, the cost is findings, never false ones.
    """
    engine = RuleEngine([], site_hosts=("shop.test", "shopcdn.net"), crs_host="shop.test")
    own_second_domain = [
        event(path="/admin/import-image", query="url=https://shopcdn.net/logo.png")
    ]

    (labelled,) = engine.label_events(own_second_domain, crs=crs_index(_off_domain()))

    assert labelled.label.rule_id != "crs:931130"


def test_subdomains_of_the_host_crs_was_told_are_covered_by_it() -> None:
    """The ordinary shape of a site that answers to more than one name. CRS
    compares by suffix, so `shop.test` speaks for `www.shop.test` too, and the
    rule is as trustworthy as it is for a site with one name."""
    engine = RuleEngine([], site_hosts=("shop.test", "www.shop.test"), crs_host="shop.test")

    (labelled,) = engine.label_events(_fetching_elsewhere(), crs=crs_index(_off_domain()))

    assert labelled.label.rule_id == "crs:931130"


def test_names_activity_is_public_and_is_the_check_rescue_applies() -> None:
    from logarc.detect.engine import names_activity

    query = crs_detection()
    assert names_activity(query)
    assert not names_activity(replace(query, matched_var="REQUEST_HEADERS:Referer"))
    assert not names_activity(replace(query, matched_var="MATCHED_VARS:REQUEST_HEADERS:Referer"))
    assert not names_activity(replace(query, transformed_value="${id}"))


def test_crs_host_trusted_is_readable_from_the_engine() -> None:
    assert RuleEngine([], site_hosts=("shop.test",), crs_host="shop.test").crs_host_trusted
    assert not RuleEngine([], site_hosts=("shop.test",), crs_host="localhost").crs_host_trusted
