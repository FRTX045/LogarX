"""Tests for the detection engine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarc.core.activity import ActivityCategory, Severity
from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
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
